import logging

from janitor import cache
from janitor.registry import PluginRegistry
from janitor.utils import dumps


resources = PluginRegistry('resources')


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

    def resource_query(self):
        """Return server side query filter for the given api."""
        return []

    def get_resources(self, resource_ids):
        pass
    
    def filter_resources(self, resources, event=None):
        original = len(resources)
        for f in self.filters:
            resources = f.process(resources, event)
        self.log.info("Filtered from %d to %d %s" % (
            original, len(resources), self.__class__.__name__.lower()))
        return resources
