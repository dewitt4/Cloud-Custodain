import logging
import os
import time

import boto3
import yaml

from janitor.ctx import ExecutionContext
from janitor.manager import resources
from janitor import output, utils

# Trigger Registrations
import janitor.resources


def load(options, path):
    if not os.path.exists(path):
        raise ValueError("Invalid path for config %r" % path)
    
    with open(path) as fh:
        data = yaml.load(fh, Loader=yaml.SafeLoader)
    return PolicyCollection(data, options)


class PolicyCollection(object):

    def __init__(self, data, options):
        self.data = data
        self.options = options
        
    def policies(self):
        return [Policy(p, self.options) for p in self.data.get('policies', [])]

    def __iter__(self):
        return iter(self.policies())
    

class Policy(object):

    log = logging.getLogger('maid.policy')

    def __init__(self, data, options):
        self.data = data
        self.options = options
        assert "name" in self.data
        self.ctx = ExecutionContext(
            self.name, self, self.options)
        self.resource_manager = self.get_resource_manager()

    @property
    def name(self):
        return self.data['name']

    @property
    def resource_type(self):
        return self.data['resource']

    def __call__(self, ctx):
        with self.ctx:
            resources = self.resource_manager.resources()
            self.log.info(
                "policy: %s resource:%s has count:%s resources" % (
                    self.name, self.resource_type, len(resources)))
            self._write_file('resources.json', utils.dumps(resources))
            
            for a in self.resource_manager.actions:
                s = time.time()
                results = a.process(resources)
                self.log.info(
                    "policy: %s action: %s execution_time: %0.2f" % (
                        self.name, a.name, time.time()-s))
                self._write_file("action-%s" % a.name, utils.dumps(results))
                
    def _write_file(self, rel_p, value):
        with open(
                os.path.join(self.ctx.log_dir, rel_p), 'w') as fh:
            fh.write(value)

    def session_factory(self):
        session =  boto3.Session(
            region_name=self.options.region,
            profile_name=self.options.profile)
        session._session.user_agent_name = "CloudMaid"
        session._session.user_agent_version = "0.5"
        return session
        
    def get_resource_manager(self):
        resource_type = self.data.get('resource')
        factory = resources.get(resource_type)
        if not factory:
            raise ValueError(
                "Invalid resource type: %s" % resource_type)
        return factory(self.ctx, self.data)
