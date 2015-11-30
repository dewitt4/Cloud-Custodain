import logging
import itertools

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

    def process(self, volumes):
        volumes = [v for v in volumes if v['Attachments']]
        with self.executor_factory(max_workers=10) as w:
            w.map(self.process_volume, volumes)

    def process_volume(self, volume):
        client = local_session(self.manager.session_factory).client('ec2')
        attachment = volume['Attachments'][0]
        instance_id = attachment['InstanceId']
        # Todo: We could bulk fetch these before processing individual
        # volumes, we might run into request size limits though.
        result = client.describe_instance(
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
        extant_tags = [t['Name'] for t in volume.get('Tags', [])]
        for t in found['Tags']:
            if t['Name'] in extant_tags:
                continue
            if t['Name'].startswith('aws:'):
                continue
            copy_tags.append(t)
        copy_tags.append(
            {'Name': 'LastAttachTime', 'Value': attachment['AttachTime']})
        copy_tags.append(
            {'Name': 'LastAttachInstance', 'Value': attachment['InstanceId']})

        client.create_tags(
            Resources=[volume['VolumeId']],
            Tags=copy_tags,
            DryRun=self.manager.config.dryrun)


@actions.register('delete')
class Delete(BaseAction):

    def process(self, volumes):
        with self.executor_factory(max_workers=10) as w:
            w.map(self.process_volume, volumes)
                
    def process_volume(self, volume):
        client = local_session(self.manager.session_factory).client('ec2')
        self._run_api(
            client.delete_volume,
            VolumeId=volume['VolumeId'],
            DryRun=self.manager.config.dryrun)
