import logging

from janitor import cache
from janitor.registry import Registry
from janitor.utils import dumps


resources = Registry('resources')


class ResourceManager(object):

    def __init__(self, ctx, data):
        self.ctx = ctx
        self.session_factory = ctx.session_factory
        self.config = ctx.options
        self.data = data
        self.log_dir = ctx.log_dir
        self._cache = cache.factory(self.ctx.options)
        self.log = logging.getLogger('maid.resources.%s' % (
            self.__class__.__name__.lower()))

    def format_json(self, resources, fh):
        return dumps(resources, fh, indent=2)

    # FIXME: Only overridden by ec2. Explain.
    def resource_query(self):
        return []
    
    def filter_resources(self, resources):
        # FIXME: resources shadows global variable
        original = len(resources)
        for f in self.filters:
            resources = f.process(resources)
        self.log.info("Filtered from %d to %d %s" % (
            original, len(resources), self.__class__.__name__.lower()))
        return resources
