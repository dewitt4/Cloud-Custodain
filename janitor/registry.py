from pkg_resources import iter_entry_points


class Registry(object):

    def __init__(self, plugin_type):
        self.plugin_type = plugin_type
        self.data = {}

    def register_class(self, name, klass=None):
        if klass:
            self.data[name] = klass
            return

        def _register_class(klass):
            self.data[name] = klass
            return klass
        return _register_class

    register = register_class

    def unregister(self, name):
        if name in self.data:
            del self.data[name]
        
    def get(self, name):
        return self.data.get(name)

    def keys(self):
        return self.data.keys()
    
    def load_plugins(self):
        for ep in iter_entry_points(group="maid.%s" % self.plugin_type):
            f = ep.load()
            f()


