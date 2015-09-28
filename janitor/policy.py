import os

import boto3
import yaml

from janitor.manager import EC2


def load(options, path):
    if not os.path.exists(path):
        raise ValueError("Invalid path for config %r" % path)
    
    with open(path) as fh:
        data = yaml.load(fh, Loader=yaml.SafeLoader)
    return Policy(data, options)
    

class Policy(object):

    def __init__(self, data, options):
        self.data = data
        self.options = options

    def session_factory(self):
        return boto3.Session(region=self.options.region)

    def resource_manager(self, resource_type='ec2'):
        # TODO make lookup via res mgr registry
        return EC2(self.session_factory,
                   self.data.get(resource_type),
                   self.options)
