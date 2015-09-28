
import cPickle

import os
import logging
import time

log = logging.getLogger('janitor.cache')


def factory(config):
    if not config:
        return NullCache(None)
    
    if not config.cache or not config.cache_period:
        log.info("Disabling cache")    
        return NullCache(config)
    
    log.info("Using cache file %s" % config.cache)
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
        
    def load(self):
        if os.path.isfile(self._cache_path):

            if time.time() - os.stat(self._cache_path).st_mtime > self.config.cache_period * 60:
                return False            
            with open(self._cache_path) as fh:
                data = cPickle.load(fh)
                if (self._filter_params() != data.get('key')
                    or data['region'].name != self.client.region.name):
                    return False
                self._cache = data['cache']


    def save(self, key, data):
        with open(self._cache_path, 'w') as fh:
            cPickle.dump({
                'key': self._filter_params(),
                'region': self.client.region,
                'cache': self._cache},
                fh, protocol=2)

