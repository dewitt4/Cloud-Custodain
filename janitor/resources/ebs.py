import itertools
import logging

from janitor.actions import ActionRegistry, BaseAction
from janitor.filters import FilterRegistry

from janitor.manager import ResourceManager, resources
from janitor.utils import local_session


log = logging.getLogger('maid.ebs')

filters = FilterRegistry('ebs.filters')
actions = ActionRegistry('ebs.actions')


@resources.register('ebs')
class EBS(ResourceManager):

    def __init__(self, ctx, data):
        super(EBS, self).__init__(ctx, data)
        self.filters = filters.parse(
            self.data.get('filters', []), self)
        self.actions = actions.parse(
            self.data.get('actions', []), self) 

    def resources(self):
        c = self.session_factory().client('ec2')
        query = self.resource_query()
        self.log.info("Querying ebs volumes")
        p = c.get_paginator('describe_volumes')
        results = p.paginate(Filters=query)
        volumes = list(itertools.chain(*[rp['Volumes'] for rp in results]))
        return self.filter_resources(volumes)
        

@actions.register('copy-instance-tags')
class CopyInstanceTags(BaseAction):
    """Copy instance tags to its attached volume.

    Mostly useful for volumes not set to delete on termination, which
    are otherwise candidates for garbage collection, copying the
    instance tags gives us more semantic information to determine if
    that's useful, as well letting us know the last time the volume
    was actually used.

    """
    def process(self, volumes):
        volumes = [v for v in volumes if v['Attachments']]
        with self.executor_factory(max_workers=10) as w:
            list(w.map(self.process_volume, volumes))

    def process_volume(self, volume):
        client = local_session(self.manager.session_factory).client('ec2')
        attachment = volume['Attachments'][0]
        instance_id = attachment['InstanceId']
        
        # Todo: We could bulk fetch these before processing individual
        # volumes, we might run into request size limits though.
        result = client.describe_instances(
            Filters=[
                {'Name': 'instance-id',
                 'Value': [instance_id]}])
        found = False
        for r in result.get('Reservations', []):
            for i in r['Instances']:
                if i['InstanceId'] == instance_id:
                    found = i
                    break        
        if not found:
            log.debug("Could not find instance %s for volume %s" % (
                instance_id, volume['VolumeId']))
            return

        copy_tags = []
        extant_tags = dict([
            (t['Key'], t['Value']) for t in volume.get('Tags', [])])
        
        for t in found['Tags']:
            if t['Key'] in extant_tags:
                continue
            if t['Key'].startswith('aws:'):
                continue
            copy_tags.append(t)
    
        copy_tags.append(
            {'Key': 'LastAttachTime',
             'Value': attachment['AttachTime'].isoformat()})
        copy_tags.append(
            {'Key': 'LastAttachInstance', 'Value': attachment['InstanceId']})

        # Don't add tags if we're already current
        if 'LastAttachInstance' in extant_tags \
           and extant_tags['LastAttachInstance'] == attachment['InstanceId']:
            return

        # Can't add more tags than the resource supports
        if len(copy_tags) > 10:
            log.warning("action:%s volume:%s instance:%s too many tags to copy" % (
                self.__class__.__name__.lower(),
                volume['VolumeId'],
                attachment['InstanceId']))
            return
        
        client.create_tags(
            Resources=[volume['VolumeId']],
            Tags=copy_tags,
            DryRun=self.manager.config.dryrun)


@actions.register('encrypt')        
class EncryptVolume(BaseAction):
    """Encrypt an extant volume, and attach it to an instance.

    Not suitable for autoscale groups.
    """
    def process(self, volumes):
        original_count = len(volumes)
        volumes = [v for v in volumes if not v['Encrypted']]
        log.debug("EncryptVolumes filtered from %d to %d unencrypted volumes" % (
            original_count, len(volumes)))
        key_id = self.data.get('key')
        if not key_id:
            self.log.warning("No key specificed for encrypt volume, skipping")
            return
        with self.executor_factory(max_workers=10) as w:
            list(w.map(self.process_volume, volumes))

    def process_volume(self, v):
        """Encrypt extant unencrypted ebs volume

        Multistep process

        - Create snapshot
        - Wait on snapshot creation
        - Copy Snapshot to create encrypted snapshot
        - Wait on snapshot creation
        - Create encrypted volume from snapshot
        - Wait on volume creation
        - Delete transient snapshots
        - Stop instance / modify block device mapping
        - Delete unencrypted volume
        """
        key_id = self.get_encryption_key()
        vol_id = self.create_encrypted_volume(v, key_id)

        if v['Attachments']:
            self.attach_encrypted_volume(v, vol_id)

        client = local_session(self.manager.session_factory).client('ec2')
        client.delete_volume(VolumeId=v['VolumeId'])
                    
        # Delete unencrypted volume

    def create_encrypted_volume(self, v, key_id):
        ec2 = local_session(self.manager.session_factory).client('ec2')
        results = ec2.create_snapshot(
            VolumeId=v['VolumeId'],
            Description="Transient snapshot for encryption",)
        transient_snapshots = [results['SnapshotId']]
        self.wait_on_resource(ec2, results['SnapshotId'])
        
        results = ec2.copy_snapshot(
            SourceSnapshotId=results['SnapshotId'],
            SourceRegion=v['AvailabilityZone'].rsplit('-', 1)[0],
            Description='Transient snapshot for encryption',
            Encrypted=True,
            KmsKeyId=key_id)
        transient_snapshots.append(results['SnapshotId'])
        self.wait_on_resource(ec2, results['SnapshotId'])

        # Todo provisioned iops passthrough on create replacement volume
        results = ec2.create_volume(
            Size=v['VolumeSize'],
            VolumeType=v['VolumeType'],
            SnapshotId=results['SnapshotId'],
            KmsKeyId=key_id)

        # Wait on encrypted volume creation
        self.wait_on_resource(ec2, results['VolumeId'])
        
        # Delete transient snapshots        
        for sid in transient_snapshots:
            ec2.delete_snapshot(SnapshotId=sid)
        return results['VolumeId']

    def attach_encrypted_volume(self, v, vol_id):
        ec2 = local_session(self.manager.session_factory).client('ec2')
        instance_id = v['Attachments'][0]['InstanceId']
        results = ec2.describe_instances(InstanceIds=[instance_id])
        found = None
        for r in results['Reservations']:
            for i in r['Instances']:
                if i['InstanceId'] == instance_id:
                    found = i
                    break
        if not found:
            log.warning("EncryptVolumes: Instance:%s not found" % i['InstanceId'])
            return
        ec2.stop_instances(InstanceIds=[instance_id])
        self.wait_on_resource(instance_id)
        ec2.detach_volume(VolumeId=v['VolumeId'])
        ec2.attach_volume(VolumeId=vol_id, Device=v['Attachments'][0]['Device'])
        ec2.start_instances(InstanceIds=[instance_id])
        
    def get_encryption_key(self):
        kms = local_session(self.manager.session_factory).client('kms')
        key_alias = self.data.get('key')
        result = kms.describe_key(KeyId=key_alias)
        key_id = result['KeyMetadata']['KeyId']
        return key_id
    
    def wait_on_resource(self, client, snapshot_id=None, volume_id=None, instance_id=None):
        # boto client waiters poll every 15 seconds up to a max 600s (5m)
        if snapshot_id:
            waiter = client.get_waiter('snapshot_completed')
            waiter.wait(SnapshotIds=[snapshot_id])
        elif volume_id:
            waiter = client.get_waiter('volume_available')
            waiter.wait(VolumeIds=[volume_id])
        elif instance_id:
            waiter = client.get_waiter('instance_stopped')
            waiter.wait(InstanceIds=[instance_id])
                        

@actions.register('delete')
class Delete(BaseAction):

    def process(self, volumes):
        with self.executor_factory(max_workers=10) as w:
            list(w.map(self.process_volume, volumes))
                
    def process_volume(self, volume):
        client = local_session(self.manager.session_factory).client('ec2')
        self._run_api(
            client.delete_volume,
            VolumeId=volume['VolumeId'],
            DryRun=self.manager.config.dryrun)
