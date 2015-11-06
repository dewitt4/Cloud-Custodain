import logging
import os
import time

import boto3
#import bson
import yaml

from janitor.manager import resources
from janitor import output

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
        assert "name" in self.data
        self.options = options
        factory = output.select(self.options.output_dir)
        self.output = factory(
            self.session_factory,
            factory.join(self.options.output_dir, self.name))
        self.resource_manager = self.get_resource_manager()

    @property
    def name(self):
        return self.data['name']

    @property
    def resource_type(self):
        return self.data['resource']

    def __call__(self):
        with self.output: 
            resources = self.resource_manager.resources()
            self.log.info(
                "policy: %s resource:%s has count:%s resources" % (
                    self.name, self.resource_type, len(resources)))
            #self._write_file('resources.bson', bson.dumps(resources))
            
            for a in self.resource_manager.actions:
                s = time.time()
                results = a.process(resources)
                self.log.info(
                    "policy: %s action: %s execution_time: %0.2f" % (
                        self.name, a.name, time.time()-s))
                #self._write_file("action-%s" % a.name, bson.dumps(results))
                
    def _write_file(self, rel_p, value):
        with open(
                os.path.join(self.output.root_dir, rel_p), 'w') as fh:
            fh.write(value)
                    
    def session_factory(self):
        return boto3.Session(
            region_name=self.options.region,
            profile_name=self.options.profile)

    def get_resource_manager(self):
        resource_type = self.data.get('resource')
        factory = resources.get(resource_type)
        if not factory:
            raise ValueError(
                "Invalid resource type: %s" % resource_type)
        return factory(self.session_factory,
                       self.data,
                       self.options,
                       self.output.root_dir)
