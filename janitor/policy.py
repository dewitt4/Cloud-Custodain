import os

import boto
import yaml

from janitor.inventory import Inventory
from janitor.filters import filter
from janitor.actions import action


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

    @property
    def connection(self):
        found = False
        for r in boto.regioninfo.get_regions('ec2'):
            if r.name == self.options.region:
                found = True
                break
        if not found:
            raise ValueError(
                "Invalid region specified %s" % self.options.region)

        return boto.connect_ec2(region=r)
    
    @property
    def inventory(self):
        return Inventory(self.connection, self.filters, self.options)

    @property
    def filters(self):
        f = []
        for fdat in self.data.get('ec2', {}).get('filters', []):
            f.append(filter(fdat))
        return f
    
    @property
    def actions(self):
        o = []
        for adat in self.data.get('ec2', {}).get('actions', []):
            o.append(action(adat, self.options, self))
        return o
    


