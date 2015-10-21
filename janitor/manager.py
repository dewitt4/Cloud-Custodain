import logging

from janitor import cache


class ResourceManager(object):

    def __init__(self, session_factory, data, config):
        self.session_factory = session_factory
        self.config = config
        self.data = data
        self._cache = cache.factory(config)
        self.log = logging.getLogger('janitor.resources.%s' % (
            self.__class__.__name__.lower()))

