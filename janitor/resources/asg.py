from collections import Counter
from concurrent.futures import as_completed

from datetime import datetime, timedelta
from dateutil.tz import tzutc

import logging
import itertools

from janitor.actions import ActionRegistry, BaseAction
from janitor.filters import FilterRegistry, MarkedForOp

from janitor.manager import ResourceManager, resources
from janitor.offhours import Time, OffHour, OnHour
from janitor.utils import local_session, query_instances

log = logging.getLogger('maid.asg')

filters = FilterRegistry('asg.filters')
actions = ActionRegistry('asg.actions')


filters.register('time', Time)
filters.register('offhour', OffHour)
filters.register('onhour', OnHour)
filters.register('marked-for-op', MarkedForOp)


@resources.register('asg')
class ASG(ResourceManager):

    def __init__(self, ctx, data):
        super(ASG, self).__init__(ctx, data)
        self.filters = filters.parse(
            self.data.get('filters', []), self)
        self.actions = actions.parse(
            self.data.get('actions', []), self)

    def resources(self):
        c = self.session_factory().client('autoscaling')
        query = self.resource_query()  # FIXME: This is always []. What's going on?
        if self._cache.load():
            asgs = self._cache.get({'resource': 'asg', 'q': query})
            if asgs is not None:
                self.log.debug("Using cached asgs: %d" % len(asgs))
                return self.filter_resources(asgs)
        self.log.info("Querying asg instances")
        p = c.get_paginator('describe_auto_scaling_groups')
        results = p.paginate()
        asgs = list(itertools.chain(
            *[rp['AutoScalingGroups'] for rp in results]))
        self._cache.save({'resource': 'asg', 'q': query}, asgs)
        return self.filter_resources(asgs)


@actions.register('tag')            
@actions.register('mark')
class Tag(BaseAction):

    def process(self, asgs):
        with self.executor_factory(max_workers=10) as w:
            list(w.map(self.process_asg, asgs))
        
    def process_asg(self, asg, msg=None):
        session = local_session(self.manager.session_factory)
        client = session.client('autoscaling')
        tag = self.data.get('tag', 'maid_status')
        propagate = self.data.get('propagate_launch', False)
        
        if msg is None:
            msg = self.data.get(
                'msg', 'AutoScaleGroup does not meet policy guidelines')
        new_t = {"Key": tag,
             "PropagateAtLaunch": propagate,
             "ResourceType": "auto-scaling-group",
             "ResourceId": asg["AutoScalingGroupName"],
             "Value": msg}

        client.create_or_update_tags(Tags=[new_t])
        update_tags(asg, new_t)
        
        
def update_tags(asg, new_t):
    tags = list(asg.get('Tags', []))
    found = False
    for idx, t in enumerate(asg.get('Tags', [])):
        if t['Key'] == new_t['Key']:
            tags[idx] = new_t
            found = True
            break
    if not found:
        tags.append(new_t)
    asg['Tags'] = tags
                
        
@actions.register('propagate-tags')        
class PropagateTags(Tag):
    """Propagate tags to an asg instances.

    In AWS changing an asg tag does not propagate to instances.

    This action exists to do that, and can also trim older tags
    not present on the asg anymore that are present on instances.
    """
    def validate(self):
        if not isinstance(self.data.get('tags', []), []):
            raise ValueError("No tags specified")

    def process(self, asgs):
        if not asgs:
            return
        if self.data.get('trim', False):
            self.instance_map = self.get_instance_map(asgs)
        with self.executor_factory(max_workers=10) as w:
            instance_count = sum(list(w.map(self.process_asg, asgs)))
            self.log.info("Applied tags to %d instances" % instance_count)

    def process_asg(self, asg):
        client = local_session(self.manager.session_factory).client('ec2')
        instance_ids = [i['InstanceId'] for i in asg['Instances']]
        tag_map = {t['Key']: t['Value'] for t in asg.get('Tags', [])
                   if t['PropagateAtLaunch']
                   and not t['Key'].startswith('aws:')}

        if self.data.get('tags'):
            tag_map = {k:v for k,v in tag_map.items() if k in self.data['tags']}
            
        tag_set = set(tag_map)
        if self.data.get('trim', False):
            instances = [self.instance_map[i] for i in instance_ids]
            self.prune_instance_tags(client, asg, tag_set, instances)
        if not self.manager.config.dryrun:
            client.create_tags(
                Resources=instance_ids,
                Tags=[{'Key': k, 'Value': v} for k, v in tag_map.items()])
        return len(instance_ids)
    
    def prune_instance_tags(self, client, asg, tag_set, instances):
        """Remove tags present on all asg instances which are not present 
        on the asg.
        """
        instance_tags = Counter()
        instance_count = len(instances)

        remove_tags = []
        extra_tags = []
        
        for i in instances:
            instance_tags.update([
                t['Key'] for t in i['Tags']
                if not t['Key'].startswith('aws:')])
        for k, v in instance_tags.items():
            # For now only remove tags present on all instances
            if not v >= instance_count:
                extra_tags.append(k)
                continue
            if k not in tag_set:
                remove_tags.append(k)

        if remove_tags:
            log.debug("Pruning asg:%s instances:%d of old tags: %s" % (
                asg['AutoScalingGroupName'], instance_count, remove_tags))
        if extra_tags:
            log.debug("Asg: %s has uneven tags population: %s" % (
                instance_tags))

        if not self.manager.config.dryrun:
            client.delete_tags(
                Resources=[i['InstanceId'] for i in instances],
                Tags=[{'Key': t} for t in remove_tags])
                    
    def get_instance_map(self, asgs):
        instance_ids = [
            i['InstanceId'] for i in
            list(itertools.chain(*[
                g['Instances']
                for g in asgs if g['Instances']]))]
        if not instance_ids:
            return {}
        instances = query_instances(
            local_session(self.manager.session_factory),
            InstanceIds=instance_ids)
        return {i['InstanceId']: i for i in instances}

    
@actions.register('rename-tag')
class RenameTag(Tag):
    """Rename a tag on an AutoScaleGroup.
    """

    def process(self, asgs):
        source = self.data.get('source')
        dest = self.data.get('dest')
        count = len(asgs)

        filtered = []
        for a in asgs:
            for t in a.get('Tags'):
                if t['Key'] == source:
                    filtered.append(a)
                    break
        asgs = filtered
        self.log.info("Filtered from %d asgs to %d" % (
            count, len(asgs)))
        self.log.info("Renaming %s to %s on %d asgs" % (
            source, dest, len(filtered)))

        with self.executor_factory(max_workers=10) as w:
            list(w.map(self.process_asg, asgs))

    def process_asg(self, asg):
        """Move source tag to destination tag.

        Check tag count on asg
        Create new tag tag
        Delete old tag
        Check tag count on instance
        Create new tag
        Delete old tag
        """
        source_tag = self.data.get('source')
        tag_map = {t['Key']: t for t in asg.get('Tags', [])}
        source = tag_map[source_tag]
        destination_tag = self.data.get('dest')
        propagate = self.data.get('propagate', True)        
        client = local_session(
            self.manager.session_factory).client('autoscaling')
        # technically safer to create first, but running into
        # max tags constraints, otherwise.
        #
        # delete_first = len([t for t in tag_map if not t.startswith('aws:')])
        client.delete_tags(Tags=[
            {'ResourceId': 'tags-auto-scaling-group',
             'ResourceType': 'auto-scaling-group',
             'Key': source_tag,
             'Value': source['Value']}])
        client.create_or_update_tags(Tags=[
            {'ResourceId': 'tags-auto-scaling-group',
             'ResourceType': 'auto-scaling-group',
             'PropagateAtLaunch': propagate,
             'Key': destination_tag,
             'Value': source['Value']}])
        self.propogate_instance_tag(source, destination_tag, asg)

    def propogate_instance_tag(self, source, destination_tag, asg):
        client = local_session(self.manager.session_factory).client('ec2')
        client.delete_tags(
            Resources=[i['InstanceId'] for i in asg['Instances']],
            Tags=[{"Key": source['Key']}])
        client.create_tags(
            Resources=[i['InstanceId'] for i in asg['Instances']],
            Tags=[{'Key': source['Key'], 'Value': source['Value']}])
            
            
@actions.register('mark-for-op')
class MarkForOp(Tag):

    def process(self, asgs):
        msg_tmpl = self.data.get(
            'msg',
            'AutoScaleGroup does not meet org tag policy: {op}@{stop_date}')
        
        op = self.data.get('op', 'suspend')
        tag = self.data.get('tag', 'maid_status')
        date = self.data.get('days', 4)
        
        n = datetime.now(tz=tzutc())
        stop_date = n + timedelta(days=date)
        msg = msg_tmpl.format(
            op=op, stop_date=stop_date.strftime('%Y/%m/%d'))

        self.log.info("Tagging %d asgs for %s on %s" % (
            len(asgs), op, stop_date.strftime('%Y/%m/%d')))

        futures = []
        with self.executor_factory(max_workers=10) as w:
            for a in asgs:
                futures.append(
                    w.submit(self.process_asg, a, msg))

        for f in as_completed(futures):
            if f.exception():
                log.exception("Exception processing asg:%s" % (
                    a['AutoScalingGroupName']))
                continue
                    

@actions.register('suspend')
class Suspend(BaseAction):

    LoadBalancerTagKey = 'AsgLoadBalancer'
    
    def process(self, asgs):
        original_count = len(asgs)
        asgs = [a for a in asgs if a['Instances']]
        self.log.debug("Filtered from %d to %d asgs with instances" % (
            original_count, len(asgs)))
        with self.executor_factory(max_workers=10) as w:
            list(w.map(self.process_asg, asgs))

    def process_asg(self, asg):
        """Multistep process to stop an asg aprori of setup

        - suspend processes
        - note load balancer in tag
        - detach load balancer
        - stop instances
        """
        session = local_session(self.manager.session_factory)
        asg_client = session.client('autoscaling')
        asg_client.suspend_processes(
            AutoScalingGroupName=asg['AutoScalingGroupName'])
        if self.record_asg_load_balancer(asg_client, asg):
            asg_client.detach_load_balancers(
                AutoScalingGroupName=asg['AutoScalingGroupName'],
                LoadBalancerNames=asg['LoadBalancerNames'])
        ec2_client = session.client('ec2')
        ec2_client.stop_instances(
            InstanceIds=[i['InstanceId'] for i in asg['Instances']])
        
    def record_asg_load_balancer(self, client, asg):
        # todo should be idempotent, or we should guard against
        # multiple invocations on the same asg, by merging values
        found = None
        for t in asg.get('Tags', []):
            if t['Key'] == self.LoadBalancerTagKey:
                found = t
                break
        if not found:
            return False
        tvalue = ",".join(asg['LoadBalancerNames'])
        if found and found['Value'] == tvalue:
            return
        elb_tag = {
            "Key": self.LoadBalancerTagKey,
            "Value": tvalue,
            "PropagateAtLaunch": False,
            "ResourceType": "auto-scaling-group",
            "ResourceId": asg['AutoScalingGroupName']
            }
        client.create_or_update_tags(Tags=[elb_tag])
        return True

            
@actions.register('resume')
class Resume(BaseAction):
    """
    Todo.. Attach Tag to the ELB so it can be differentiated from unused.
    """
    LoadBalancerTagKey = 'AsgLoadBalancer'
    
    def process(self, asgs):
        original_count = len(asgs)
        asgs = [a for a in asgs if a['SuspendedProcesses']]
        self.log.debug("Filtered from %d to %d suspended asgs" % (
            original_count, len(asgs)))
        with self.executor_factory(max_workers=10) as w:
            list(w.map(self.process_asg, asgs))
                
    def process_asg(self, asg):
        """Multi-step process to resume

        - Start any stopped ec2 instances
        - Reattach ELB
        - Resume ASG Processes

        """
        session = local_session(self.manager.session_factory)
        asg_client = session.client('autoscaling')
        ec2_client = session.client('ec2')

        ec2_client.start_instances(
            InstanceIds=[i['InstanceId'] for i in asg['Instances']])

        found = None
        for t in asg.get('Tags', []):
            if t['Key'] == self.LoadBalancerTagKey:
                found = t['Value']
                break
        if not found:
            log.debug("No Load Balancers to attach found on asg:%s" % (
                asg['AutoScalingGroupName']))
        else:
            balancers = found.split(',')
            asg_client.attach_load_balancers(
                AutoScalingGroupName=asg['AutoScalingGroupName'],
                LoadBalancerNames=balancers)

        asg_client.resume_processes(
            AutoScalingGroupName=asg['AutoScalingGroupName'])
            

@actions.register('delete')
class Delete(BaseAction):

    def process(self, asgs):
        with self.executor_factory(max_workers=10) as w:
            list(w.map(self.process_asg, asgs))

    def process_asg(self, asg):
        session = local_session(self.manager.session_factory)
        asg_client = session.client('autoscaling')
        asg_client.delete_auto_scaling_group(
                AutoScalingGroupName=asg['AutoScalingGroupName'])
    
        
