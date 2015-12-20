from pkg_resources import iter_entry_points


class Registry(object):

    def __init__(self, plugin_type):
        self.plugin_type = plugin_type
        # FIXME: rename data to something more descriptive - classLookup? classByName?
        self.data = {}

    # FIXME: rename to register
    def register_class(self, name, klass=None):
        # invoked as function
        if klass:
            self.data[name] = klass
            # FIXME: return klass to allow chaining?
            return

        # invoked as class decorator
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
    
    # FIXME: This is only used by the ExecutorRegistry; move it there
    def load_plugins(self):
        # In setup.py, define entry point
        # FIXME: Add example here
        for ep in iter_entry_points(group="maid.%s" % self.plugin_type):
            f = ep.load()
            f()


