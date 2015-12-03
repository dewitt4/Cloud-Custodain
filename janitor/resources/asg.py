import logging
import itertools

from janitor.actions import ActionRegistry, BaseAction
from janitor.filters import FilterRegistry

from janitor.manager import ResourceManager, resources
from janitor.utils import local_session

log = logging.getLogger('maid.asg')


filters = FilterRegistry('asg.filters')
actions = ActionRegistry('asg.actions')


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
        query = self.resource_query()
        self.log.info("Querying asg instances")
        p = c.get_paginator('describe_auto_scaling_groups')
        results = p.paginate()
        elbs = list(itertools.chain(
            *[rp['AutoScalingGroups'] for rp in results]))
        return self.filter_resources(elbs)


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
        self.record_asg_load_balancer(asg_client, asg)

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
        tvalue = ",".join(asg['LoadBalancerNames'])
        if found and found['Value'] == tvalue:
            return
        elb_tag = {
            "Key": self.LoadBalancerTagKey,
            "Value": tvalue,
            "PropogateAtLaunch": False,
            "ResourceType": "auto-scaling-group",
            "ResourceId": asg['AutoScalingGroupName']
            }
        client.create_or_update_tags([elb_tag])


@actions.register('resume')
class Resume(BaseAction):

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
            log.warning("No Load Balancers to attach found on asg:%s" % asg['AutoScalingGroupName'])
            return
        balancers = found.split(',')
        asg_client.attach_load_balancers(
            AutoScalingGroupName=asg['AutoScalingGroupName'],
            LoadBalancerNames=balancers)

        asg_client.resume_processes(
            AutoScalingGroupName=asg['AutoScalingGroupName'])
            
