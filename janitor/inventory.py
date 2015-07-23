
import cPickle
import itertools
import os
import time
import logging

from janitor.filters import QueryFilter, InstanceFilter


class Inventory(object):

    def __init__(self, client, filters, config):
        self.client = client
        self.filters = filters
        self.config = config
        self._cache = None
        self.log = logging.getLogger(__name__)
        
    def query(self):
        filters = self._filter_params()
        self.log.info("Querying ec2 instances with %s" % filters)
        results = self.client.get_all_instances(filters=self._filter_params())

        instances =  list(itertools.chain(
            *[r.instances for r in results]))
        self.log.debug("Found %d instances on %d reservations" % (
            len(instances), len(results)))        
        return instances

    def _filter_params(self):
        params = {}
        for f in self.filters:
            if not isinstance(f, QueryFilter):
                continue
            params.update(f.query())
        return params
    
    def _save_cache(self):
        if not self.config.cache or not self.config.cache_period:
            return
        with open(self._cache_path, 'w') as fh:
            cPickle.dump({
                'key': self._filter_params(),
                'region': self.client.region,
                'cache': self._cache},
                fh, protocol=2)

    @property
    def _cache_path(self):
        return os.path.abspath(
            os.path.expanduser(os.path.expandvars(self.config.cache)))
        
    def _load_cache(self):
        if not self.config.cache or not self.config.cache_period:
            return False
        if os.path.isfile(self._cache_path):
            if time.time() - os.stat(self._cache_path).st_mtime > self.config.cache_period * 60:
                return False            
            with open(self._cache_path) as fh:
                data = cPickle.load(fh)
                if (self._filter_params() != data.get('key')
                    or data['region'].name != self.client.region.name):
                    return False
                self.log.info("Using cache")
                self._cache = data['cache']
            return True
        return False

    def __iter__(self):
        if not self._cache:
            if not self._load_cache():
                self._cache = self.query()
                self._save_cache()

        for f in [f for f in self.filters if isinstance(f, InstanceFilter)]:
            self.log.info("Filtering instances with instance "
                     "filter:%s value:%s state:%s" % (
                         f.data['filter'], f.data.get('value', 'null'),
                         f.data.get('state', 'present')))
            
        instances = filter(self._instance_filters, self._cache)
        self.log.info("Matched instances %d" % len(instances))
        return iter(instances)

    def _instance_filters(self, i):
        
        found = [
            s.process(i) for s in self.filters if isinstance(s, InstanceFilter)]
        # No Filters
        if len(found) == 0:
            return True

        op = self.config.or_operator and all or any
        return op(found)
        
                    
