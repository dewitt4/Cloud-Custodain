"""
Cloud-Maid Lambda Entry Point

Mostly this serves to load up the policy and dispatch
an event.
"""

from cStringIO import StringIO

import logging
import json

from janitor.policy import load
    
logging.root.setLevel(logging.INFO)
logging.getLogger('botocore').setLevel(logging.WARNING)
log = logging.getLogger('maid.lambda')


# TODO move me / we should load config options directly from policy config   
class Config(dict):

    def __getattr__(self, k):
        try:
            return self[k]
        except KeyError:
            raise AttributeError(k)
        
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
            'output_dir': '/tmp/',
            'cache_period': 0,
            'dryrun': False})
        d.update(kw)
        return cls(d)

    
def format_event(evt):
    io = StringIO()
    json.dump(evt, io, indent=2)
    return io.getvalue()


def dispatch_event(event, context):
    log.info("Processing event\n %s", format_event(event))
    policies = load(Config.empty(), 'config.json', format='json')
    for p in policies:
        p.push(event, context)

