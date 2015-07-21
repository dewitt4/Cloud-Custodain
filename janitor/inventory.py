
import cPickle
import itertools
import os
import time

from janitor.filters import QueryFilter, InstanceFilter


class Inventory(object):

    def __init__(self, client, filters, config):
        self.client = client
        self.filters = filters
        self.config = config
        self._cache = None

    def query(self):
        results = self.client.get_all_instances(filters=self._filter_params())
        return list(itertools.chain(
            *[r.instances for r in results]))

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
            if time.time() - os.stat(self._cache_path).st_mtime > 60 * 5:
                return False            
            with open(self._cache_path) as fh:
                data = cPickle.load(fh)
                if (self._filter_params() != data.get('key')
                    or data['region'].name != self.client.region.name):
                    return False
                self._cache = data['cache']
            return True
        return False

    def __iter__(self):
        if not self._cache:
            if not self._load_cache():
                self._cache = self.query()
                self._save_cache()

        for i in filter(self._instance_filters, self._cache):
            yield i

    def _instance_filters(self, i):
        found = [
            s.process(i) for s in self.filters if isinstance(s, InstanceFilter)]
        return any(found)
        
                    
