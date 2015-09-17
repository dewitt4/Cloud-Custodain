from boto.exception import EC2ResponseError
import logging


def action(action, options, policy):
    data = None

    if isinstance(action, dict):
        data = action
        action = data.get('type')
        if action is None:
            raise ValueError("Invalid action type found in %s" % (data))
        
    action_map = dict([(s.__name__.lower(), s) for s in BaseAction.__subclasses__()])
    key = action.replace('-', '').lower()
    action_class = action_map.get(key)
    if action_class is None:
        raise ValueError("Invalid action type %s, valid actions %s" % (action, action_map.keys()))
    return action_class(options, policy, data)
    
    
class BaseAction(object):

    log = logging.getLogger(__name__)
    
    def __init__(self, options, policy, data=None):
        self.options = options
        self.policy = policy
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
                return self.log.info("Dry run operation %s succeeded" % self.__class__.__name__.lower())
            raise
            

class Mark(BaseAction):

    def process(self, instances):
        msg = self.data.get(
            'msg', 'Instance does not meet ec2 policy guidelines')
        tag = self.data.get('tag', 'maid_status')
        self._run_api(self.policy.connection.create_tags,
            [i.id for i in instances],
            {tag: msg}, dry_run=self.options.dryrun)


class Unmark(BaseAction):

    def process(self, instances):
        tag = self.data.get('tag', 'maid_status')
        self._run_api(self.policy.connection.create_tags,
            [i.id for i in instances],
            {tag: None}, dry_run=self.options.dryrun)


class Start(BaseAction):

    def process(self, instances):
        self._run_api(
            self.policy.connection.start_instances,
            [i.id for i in instances],
            dry_run=self.options.dry_run)


class Stop(BaseAction):

    def process(self, instances):
        self._run_api(self.policy.connection.stop_instances,
            [i.id for i in instances], dry_run=self.options.dryrun)


class Terminate(BaseAction):

    def process(self, instances):
        self._run_api(self.policy.connection.terminate_instances,
            [i.id for i in instances], dry_run=self.options.dryrun)


class NotifyOwner(BaseAction):

    def process(self, instances):
        raise NotImplemented(
            "Waiting on access to appropriate s3 buckets to map instances to eids")
