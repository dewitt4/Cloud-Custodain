"""Provide basic caching services to avoid extraneous
queries over multiple.


"""

import cPickle

import os
import logging
import time

log = logging.getLogger('maid.cache')


def factory(config):
    if not config:
        return NullCache(None)
    
    if not config.cache or not config.cache_period:
        log.info("Disabling cache")    
        return NullCache(config)
    
    return FileCacheManager(config)


class NullCache(object):

    def __init__(self, config):
        self.config = config

    def load(self):
        return False

    def get(self, key):
        pass
    
    def save(self, key, data):
        pass
    
    
class FileCacheManager(object):

    def __init__(self, config):
        self.config = config
        self.cache_period = config.cache_period
        self.cache_path = os.path.abspath(
            os.path.expanduser(
                os.path.expandvars(
                    config.cache)))
        self.data = {}

    def get(self, key):
        k = cPickle.dumps(key)
        return self.data.get(k)
        
    def load(self):
        if os.path.isfile(self.cache_path):
            if (time.time() - os.stat(self.cache_path).st_mtime >
                self.config.cache_period * 60):
                return False
            with open(self.cache_path) as fh:
                self.data = cPickle.load(fh)
            log.info("Using cache file %s" % self.cache_path)
            return True
        
    def save(self, key, data):
        with open(self.cache_path, 'w') as fh:
            cPickle.dump({
                cPickle.dumps(key): data}, fh, protocol=2)


