import logging

from janitor import cache
from janitor.registry import Registry


resources = Registry('resources')


class ResourceManager(object):

    def __init__(self, ctx, data):
        self.ctx = ctx
        self.session_factory = ctx.session_factory
        self.config = ctx.options
        self.data = data
        self.log_dir = ctx.log_dir
        self._cache = cache.factory(self.ctx.options)
        self.log = logging.getLogger('janitor.resources.%s' % (
            self.__class__.__name__.lower()))


