import fnmatch
import json
import logging
import os
import time

import jmespath
import yaml

from botocore.client import ClientError

from janitor.ctrail import CloudTrailResource
from janitor.ctx import ExecutionContext
from janitor.credentials import SessionFactory
from janitor.manager import resources
from janitor import utils

# This import causes our resources to be initialized
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
        # self.options is the CLI options specified in cli.setup_parser()
        policies = [Policy(p, self.options) for p in self.data.get(
            'policies', [])]
        if not filters:
            return policies

        return [p for p in policies if fnmatch.fnmatch(p.name, filters)]

    def __iter__(self):
        return iter(self.policies())
    

class Policy(object):

    log = logging.getLogger('maid.policy')

    def __init__(self, data, options, session_factory=None):
        self.data = data
        self.options = options
        assert "name" in self.data
        if session_factory is None:
            session_factory = SessionFactory(
                options.region,
                options.profile,
                options.assume_role)
        self.session_factory = session_factory
        self.ctx = ExecutionContext(self.session_factory, self, self.options)
        self.resource_manager = self.get_resource_manager()
            
    @property
    def name(self):
        return self.data['name']

    @property
    def resource_type(self):
        return self.data['resource']

    @property
    def is_lambda(self):
        if not 'mode' in self.data:
            return False
        return True
    
    def push(self, event, lambda_ctx):
        """Run policy in push mode against given event.
 
        Lambda automatically generates cloud watch logs, and metrics
        for us, albeit with some deficienies, metrics no longer count
        against valid resources matches, but against execution. 
        Fortunately we already have replacements.

        TODO: better customization around execution context outputs
        TODO: support centralized lambda exec across accounts.
        """
        mode = self.data.get('mode', {})
        mode_type = mode.get('type')
        
        if mode_type == 'periodic':
            return self.poll()
        elif mode_type == 'ec2-instance-state':
            resource_ids = filter(None, [event.get('detail', {}).get('instance-id')])
        elif mode_type == 'asg-instance-state':
            raise NotImplementedError("asg-instance-state event not supported")
        elif mode_type != 'cloudtrail':
            raise ValueError("Invalid push event mode %s" % self.data)
        else:
            info = CloudTrailResource.match(event)
            if info:
                resource_ids = info['ids'].search(event)
            else:
                id_query = mode.get('ids') or mode.get('resources')
                if not id_query:
                    raise ValueError("No id query configured")
                resource_ids = jmespath.search(id_query, event)

        if not isinstance(resource_ids, list):
            resource_ids = [resource_ids]
                
        self.log.info('found resource ids: %s' % resource_ids)
        if not resource_ids:
            self.log.warning("Could not find resource ids with %s" % (
                mode.get('resources')))
            return
        resources = self.resource_manager.get_resources(resource_ids)
        resources = self.resource_manager.filter_resources(resources, event)

        if not resources:
            self.log.info("policy: %s resources: %s no resources matched" % (
                self.name, self.resource_type))
            return
        
        for action in self.resource_manager.actions:
            action.process(resources)

    def provision(self):
        """Provision policy as a lambda function."""
        # Avoiding runtime lambda dep, premature optimization?
        from janitor.mu import PolicyLambda, LambdaManager

        with self.ctx:
            self.log.info(
                "Provisioning policy lambda %s", self.name)
            try:
                manager = LambdaManager(self.session_factory)
            except ClientError:
                # For cli usage by normal users, don't assume the role just use
                # it for the lambda
                manager = LambdaManager(
                    lambda assume=False: self.session_factory(assume))
            return manager.publish(
                PolicyLambda(self), 'current', role=self.options.assume_role)
            
    def poll(self):
        """Query resources and apply policy."""
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
            self._write_file(
                'resources.json', utils.dumps(resources, indent=2))

            at = time.time()            
            for a in self.resource_manager.actions:
                s = time.time()
                results = a.process(resources)
                self.log.info(
                    "policy: %s action: %s resources: %d execution_time: %0.2f" % (
                        self.name, a.name, len(resources), time.time()-s))
                self._write_file("action-%s" % a.name, utils.dumps(results))
            self.ctx.metrics.put_metric(
                "ActionTime", time.time() - at, "Seconds", Scope="Policy")
            return resources

    def __call__(self):
        """Run policy in default mode"""
        if self.is_lambda:
            return self.provision()
        else:
            return self.poll()

    run = __call__
    
    def _write_file(self, rel_p, value):
        with open(
                os.path.join(self.ctx.log_dir, rel_p), 'w') as fh:
            fh.write(value)

    def get_resource_manager(self):
        resource_type = self.data.get('resource')
        factory = resources.get(resource_type)
        if not factory:
            raise ValueError(
                "Invalid resource type: %s" % resource_type)
        return factory(self.ctx, self.data)

    
