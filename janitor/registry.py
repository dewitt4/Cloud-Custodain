from pkg_resources import iter_entry_points


class PluginRegistry(object):
    """A plugin registry

    Maid is intended to be innately pluggable both internally and
    externally, for resource types and their filters and actions.

    This plugin registry abstraction provides the core mechanism for
    that. Its a simple string to class map, with python package
    entry_point loading for external plugins.

    As an example of defining an external plugin using a python package
    
    ```python
    setup(
      name="maid_cmdb",
      description="Maid filters for interacting with internal CMDB"
      version='1.0',
      packages=find_packages(),
      entry_points={
         'console_scripts': [
            'maid.ec2.filters = maid_cmdb:filter_ec2']},
      )
    ```
    
    For loading the plugins we can simply invoke method:load_plugins like
    so::

      PluginRegistry('ec2.filters').load_plugins()

    """
    def __init__(self, plugin_type):
        self.plugin_type = plugin_type
        self._factories = {}

    def register(self, name, klass=None):
        # invoked as function
        if klass:
            self._factories[name] = klass
            return klass

        # invoked as class decorator
        def _register_class(klass):
            self._factories[name] = klass
            return klass
        return _register_class

    def unregister(self, name):
        if name in self._factories:
            del self._factories[name]
        
    def get(self, name):
        return self._factories.get(name)

    def keys(self):
        return self._factories.keys()
    
    def load_plugins(self):
        """ Load external plugins.

        Maid is intended to interact with internal and external systems
        that are not suitable for embedding into the maid code base.
        """
        for ep in iter_entry_points(group="maid.%s" % self.plugin_type):
            f = ep.load()
            f()


