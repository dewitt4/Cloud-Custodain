
from concurrent.futures import (
    ProcessPoolExecutor, ThreadPoolExecutor)

from janitor.registry import PluginRegistry

import threading


class ExecutorRegistry(PluginRegistry):

    def __init__(self, plugin_type):
        super(ExecutorRegistry, self).__init__(plugin_type)

        self.register('process', ProcessPoolExecutor)
        self.register('thread', ThreadPoolExecutor)
        self.register('main', MainThreadExecutor)


def executor(name, **kw):
    factory = executors.get(name)
    # post element refactoring
    #factory.validate(kw)
    if factory is None:
        raise ValueError("No Such Executor %s" % name)
    return factory(**kw)


class MainThreadExecutor(object):
    # For Dev/Unit Testing with concurrent.futures
    def __init__(self, *args, **kw):
        self.args = args
        self.kw = kw

    def map(self, func, iterable):
        for args in iterable:
            yield func(args)

    def submit(self, func, *args, **kw):
        return MainThreadFuture(func(*args, **kw))

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    
class MainThreadFuture(object):
    # For Dev/Unit Testing with concurrent.futures

    def __init__(self, value):
        self.value = value
        # Sigh concurrent.futures pokes at privates
        self._state = 'FINISHED'
        self._waiters = []
        self._condition = threading.Condition()
        
    def cancel(self):
        return False

    def cancelled(self):
        return False

    def exception(self):
        return None

    def done(self):
        return True

    def result(self, timeout=None):
        return self.value

    def add_done_callback(self, fn):
        return fn(self)


executors = ExecutorRegistry('executor')
executors.load_plugins()

    
