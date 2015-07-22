import unittest
import tempfile
import yaml

from janitor import policy

class BaseTest(unittest.TestCase):

    def load_policy(self, data):
        t = tempfile.NamedTemporaryFile()
        t.write(yaml.dump(data, Dumper=yaml.SafeDumper))
        t.flush()
        self.addCleanup(t.close)
        return policy.load({}, t.name)
    

class Instance(object):

    def __init__(self, data):
        self.data = data

    def __getattr__(self, k):
        try:
            return self.data[k]
        except KeyError:
            raise AttributeError(k)
        
Config = Instance
Reservation = Instance

class Client(object):

    def __init__(self, instances):
        self.instances = instances
        self.filters = None

    def get_all_instances(self, filters=None):
        self.filters = filters
        return [Reservation(
            {'instances': [i for i in self.instances]})]
        
        
