import fnmatch
import json
import logging
import os
import time

import boto3
import yaml

from janitor.ctx import ExecutionContext
from janitor.manager import resources
from janitor import utils

# Trigger Registrations
import janitor.resources


def load(options, path, format='yaml'):
    if not os.path.exists(path):
        raise ValueError("Invalid path for config %r" % path)
    
    with open(path) as fh:
        if format == 'yaml':
            data = yaml.load(fh, Loader=yaml.SafeLoader)
        elif format == 'json':
            data = json.load(fh)
    return PolicyCollection(data, options)


class PolicyCollection(object):

    def __init__(self, data, options):
        self.data = data
        self.options = options
        
    def policies(self, filters=None):
        policies = [Policy(p, self.options) for p in self.data.get(
            'policies', [])]
        if not filters:
            return policies

        sort_order = [p.get('name') for p in self.data.get('policies', [])]
        policy_map = dict([(p.name, p) for p in policies])
        
        matched = fnmatch.filter(policy_map.keys(), filters)
        return [policy_map[n] for n in sort_order if n in matched]

    def __iter__(self):
        return iter(self.policies())
    

class Policy(object):

    log = logging.getLogger('maid.policy')

    def __init__(self, data, options):
        self.data = data
        self.options = options
        assert "name" in self.data
        self.ctx = ExecutionContext(self.session_factory, self, self.options)
        self.resource_manager = self.get_resource_manager()

    @property
    def name(self):
        return self.data['name']

    @property
    def resource_type(self):
        return self.data['resource']

    def process_event(self, event, lambda_ctx, resource):
        """Run policy on single lambda event."""
        results = self.resource_manager.filter_resources([resource])
        if not results:
            return
        for a in self.resource_manager.actions:
            a(results)

    def __call__(self):
        """Run policy."""
        with self.ctx:
            self.log.info("Running policy %s" % self.name)
            s = time.time()
            resources = self.resource_manager.resources()
            rt = time.time() - s
            self.log.info(
                "policy: %s resource:%s has count:%d time:%0.2f" % (
                    self.name, self.resource_type, len(resources), rt))
            self.ctx.metrics.put_metric(
                "ResourceCount", len(resources), "Count", Scope="Policy")
            self.ctx.metrics.put_metric(
                "ResourceTime", rt, "Seconds", Scope="Policy")
            self._write_file('resources.json', utils.dumps(resources))

            at = time.time()            
            for a in self.resource_manager.actions:
                s = time.time()
                results = a.process(resources)
                self.log.info(
                    "policy: %s action: %s execution_time: %0.2f" % (
                        self.name, a.name, time.time()-s))
                self._write_file("action-%s" % a.name, utils.dumps(results))
            self.ctx.metrics.put_metric(
                "ActionTime", time.time() - at, "Seconds", Scope="Policy")
            
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
