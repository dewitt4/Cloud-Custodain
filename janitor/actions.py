"""
Actions to take on ec2 instances
"""

from botocore.exceptions import ClientError

from dateutil.tz import tzutc
from datetime import datetime, timedelta

import logging

from janitor.registry import Registry


def parse(data, manager):
    results = []
    for d in data:
        a = factory(d, manager)
        results.append(a)
    return results
    

def factory(data, manager):
    if isinstance(data, dict):
        action_type = data.get('type')
        if action_type is None:
            raise ValueError("Invalid action type found in %s" % (data))
    else:
        action_type = data
        data = {}

    action_class = actions.get(action_type)
    if action_class is None:
        raise ValueError("Invalid action type %s, valid actions %s" % (
            action_type, actions.keys()))
    return action_class(data, manager)


actions = Registry('ec2.actions')
register_action = actions.register_class    
    
    
class BaseAction(object):

    log = logging.getLogger(__name__)
    
    def __init__(self, data=None, manager=None):
        self.data = data or {}
        self.manager = manager

    def process(self, instances):
        raise NotImplemented(
            "Base action class does not implement behavior")

    def _run_api(self, cmd, *args, **kw):
        try:
            return cmd(*args, **kw)
        except ClientError, e:
            if (e.response['Error']['Code'] == 'DryRunOperation'
                and e.status == 412
                and e.reason == 'Precondition Failed'):
                return self.log.info(
                    "Dry run operation %s succeeded" % (
                        self.__class__.__name__.lower()))
            raise
            
    
@register_action('mark')        
class Mark(BaseAction):

    def process(self, instances):
        msg = self.data.get(
            'msg', 'Instance does not meet ec2 policy guidelines')
        tag = self.data.get('tag', 'maid_status')
        self._run_api(
            self.manager.client.create_tags,
            Resources=[i['InstanceId'] for i in instances],
            Tags=[
                {"Key": tag,
                 "Value": msg}],
            DryRun=self.manager.config.dryrun)


@register_action('unmark')
class Unmark(BaseAction):

    def process(self, instances):
        tag = self.data.get('tag', 'maid_status')
        self._run_api(
            self.manager.client.create_tags,
            Resources=[i['InstanceId'] for i in instances],
            Tags=[
                {"Key": tag, "Value": None}],
            DryRun=self.manager.config.dryrun)


@register_action('start')        
class Start(BaseAction):

    def process(self, instances):
        self._run_api(
            self.manager.client.start_instances,
            InstanceIds=[i['InstanceId'] for i in instances],
            DryRun=self.manager.config.dryrun)


@register_action('stop')
class Stop(BaseAction):

    def process(self, instances):
        self.log.info("Stopping %d instances" % len(instances))        
        self._run_api(
            self.manager.client.stop_instances,
            InstanceIds=[i['InstanceId'] for i in instances],
            DryRun=self.manager.config.dryrun)

        
@register_action('terminate')        
class Terminate(BaseAction):

    def process(self, instances):
        self.log.info("Terminating %d instances" % len(instances))
        self._run_api(
            self.manager.client.terminate_instances,
            InstanceIds=[i['InstanceId'] for i in instances],
            DryRun=self.manager.config.dryrun)

        
@register_action('mark-for-op')
class MarkForOp(BaseAction):

    def process(self, instances):
        msg_tmpl = self.data.get(
            'msg',
            'Instance does not meet ec2 tag policy: {op}@{stop_date}')

        op = self.data.get('op', 'stop')
        tag = self.data.get('tag', 'maid_status')
        date = self.data.get('days', 4)
        
        n = datetime.now(tz=tzutc())
        stop_date = n + timedelta(days=date)
        msg = msg_tmpl.format(
            op=op, stop_date=stop_date.strftime('%Y/%m/%d'))

        self.log.info("Tagging %d instances for %s on %s" % (
            len(instances), op, stop_date.strftime('%Y/%m/%d')))
        
        self._run_api(
            self.manager.client.create_tags,
            Resources=[i['InstanceId'] for i in instances],
            Tags=[
                {"Key": tag,
                 "Value": msg}],
            DryRun=self.manager.config.dryrun)

        
@register_action('notify-owner')
class NotifyOwner(BaseAction):

    def process(self, instances):
        raise NotImplemented(
            "Waiting on access to appropriate s3 buckets to map instances to eids")


actions.load_plugins()
