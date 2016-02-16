import json
import logging
import os
import unittest
import shutil
import tempfile
import yaml

import boto3
import placebo

from janitor import policy
from janitor.ctx import ExecutionContext

logging.getLogger('placebo').setLevel(logging.WARNING)
logging.getLogger('botocore').setLevel(logging.WARNING)


class BaseTest(unittest.TestCase):

    def get_context(self, config=None, session_factory=None, policy=None):
        if config is None:
            self.context_output_dir = self.mkdtemp()
            self.addCleanup(shutil.rmtree, self.context_output_dir)
            config = Config.empty(output_dir=self.context_output_dir)
        ctx = ExecutionContext(
            session_factory,
            policy or Bag({'name':'test-policy'}),
            config)
        return ctx
    
    def load_policy(self, data, config=None):
        t = tempfile.NamedTemporaryFile()
        t.write(yaml.dump(data, Dumper=yaml.SafeDumper))
        t.flush()
        self.addCleanup(t.close)
        if config:
            e = Config.empty(**config)
        else:
            e = Config.empty()
        return policy.load(e, t.name)

    def patch(self, obj, attr, new):
        old = getattr(obj, attr, None)
        setattr(obj, attr, new)
        self.addCleanup(setattr, obj, attr, old)
    
    def record_flight_data(self, test_case):
        test_dir = placebo_dir(test_case)
        if os.path.exists(test_dir):
            shutil.rmtree(test_dir)
        os.makedirs(test_dir)

        session = boto3.Session()
        pill = placebo.attach(session, test_dir)
        pill.record()
        # return session factory
        return lambda x=None: session
    
    def replay_flight_data(self, test_case):
        test_dir = placebo_dir(test_case)
        if not os.path.exists(test_dir):
            raise RuntimeError(
                "Invalid Test Dir for flight data %s" % test_dir)

        session = boto3.Session()
        pill = placebo.attach(session, test_dir)
        pill.playback()
        return lambda x=None: session
    
    
def placebo_dir(name):
    return os.path.join(
        os.path.dirname(__file__), 'data', 'placebo', name)


def event_data(name):
    with open(
            os.path.join(
                os.path.dirname(__file__), 'data', 'cwe', name)) as fh:
        return json.load(fh)
        

def load_data(file_name, state=None, **kw):
    data = json.loads(open(
        os.path.join(
            os.path.dirname(__file__), 'data',
            file_name)).read())
    if state:
        data.update(state)
    if kw:
        data.update(kw)
    return data


def instance(state=None, **kw):
    return load_data('instance.json', state, **kw)


class Bag(dict):
        
    def __getattr__(self, k):
        try:
            return self[k]
        except KeyError:
            raise AttributeError(k)

        
class Config(Bag):

    @classmethod
    def empty(cls, **kw):
        d = {}
        d.update({
            'region': "us-east-1",
            'cache': '',
            'profile': None,
            'assume_role': None,
            'log_group': None,
            'metrics_enabled': False,
            'output_dir': 's3://test-example/foo',
            'cache_period': 0,
            'dryrun': False})
        d.update(kw)
        return cls(d)

    
class Instance(Bag): pass


class Reservation(Bag): pass


class Client(object):

    def __init__(self, instances):
        self.instances = instances
        self.filters = None

    def get_all_instances(self, filters=None):
        self.filters = filters
        return [Reservation(
            {'instances': [i for i in self.instances]})]
        
        

