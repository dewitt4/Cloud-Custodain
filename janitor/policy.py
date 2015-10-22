import os

import boto3
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

    def __init__(self, data, options):
        self.data = data
        self.options = options
        self.resource_manager = self.get_resource_manager()

    def __call__(self):
        with output.S3Output(self.session_factory, self.options.s3_path):
            resources = self.resource_manager.resources()
            for a in self.resource_manager.actions():
                a(resources)

    def session_factory(self):
        return boto3.Session(
            region_name=self.options.region,
            profile_name=self.options.profile)

    def get_resource_manager(self):
        resource_type = self.data.get('resource')
        factory = resources.get(resource_type)
        return factory(self.session_factory,
                       self.data,
                       self.options)
