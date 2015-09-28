"""
Actions to take on ec2 instances
"""
from boto.exception import EC2ResponseError

import logging

from janitor.registry import Registry


def parse(data):
    results = []
    for d in data:
        a = factory(d)
        results.append(a)
    return results
    

def factory(data):
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
    return action_class(data)


actions = Registry('ec2.actions')
register_action = actions.register_class    
    
    
class BaseAction(object):

    log = logging.getLogger(__name__)
    
    def __init__(self, data=None):
        self.data = data or {}

    def process(self, instances):
        raise NotImplemented(
            "Base action class does not implement behavior")

    def _run_api(self, cmd, *args, **kw):
        try:
            return cmd(*args, **kw)
        except EC2ResponseError, e:
            if (e.error_code == 'DryRunOperation'
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
        self._run_api(self.policy.connection.create_tags,
            [i.id for i in instances],
            {tag: msg}, dry_run=self.options.dryrun)


@register_action('unmark')
class Unmark(BaseAction):

    def process(self, instances):
        tag = self.data.get('tag', 'maid_status')
        self._run_api(self.policy.connection.create_tags,
            [i.id for i in instances],
            {tag: None}, dry_run=self.options.dryrun)


@register_action('start')        
class Start(BaseAction):

    def process(self, instances):
        self._run_api(
            self.policy.connection.start_instances,
            [i.id for i in instances],
            dry_run=self.options.dry_run)


@register_action('stop')
class Stop(BaseAction):

    def process(self, instances):
        self._run_api(self.policy.connection.stop_instances,
            [i.id for i in instances], dry_run=self.options.dryrun)


@register_action('terminate')        
class Terminate(BaseAction):

    def process(self, instances):
        self._run_api(self.policy.connection.terminate_instances,
            [i.id for i in instances], dry_run=self.options.dryrun)


@register_action('notify-owner')        
class NotifyOwner(BaseAction):

    def process(self, instances):
        raise NotImplemented(
            "Waiting on access to appropriate s3 buckets to map instances to eids")


actions.load_plugins()
