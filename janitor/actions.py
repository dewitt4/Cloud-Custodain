"""
Actions to take on resources
"""

import logging
from botocore.exceptions import ClientError

from janitor.registry import Registry


class ActionRegistry(Registry):

    def parse(self, data, manager):
        results = []
        for d in data:
            results.append(self.factory(d, manager))
        return results

    def factory(self, data, manager):
        if isinstance(data, dict):
            action_type = data.get('type')
            if action_type is None:
                raise ValueError(
                    "Invalid action type found in %s" % (data))
        else:
            action_type = data
            data = {}

        action_class = self.get(action_type)
        if action_class is None:
            raise ValueError(
                "Invalid action type %s, valid actions %s" % (
                    action_type, self.keys()))
        return action_class(data, manager)

    
class BaseAction(object):

    permissions = ()
    
    log = logging.getLogger(__name__)

    def __init__(self, data=None, manager=None, log_dir=None):
        self.data = data or {}
        self.manager = manager
        self.log_dir = log_dir

    @property
    def name(self):
        return self.__class__.__name__
    
    def process(self, resources):
        raise NotImplemented(
            "Base action class does not implement behavior")

    def get_permissions(self):
        return self.permissions
    
    def _run_api(self, cmd, *args, **kw):
        try:
            return cmd(*args, **kw)
        except ClientError, e:
            if (e.response['Error']['Code'] == 'DryRunOperation'
                and e.response['HTTPStatusCode'] == 412
                and 'would have succeeded' in e.message):
                return self.log.info(
                    "Dry run operation %s succeeded" % (
                        self.__class__.__name__.lower()))
            raise
            
    
