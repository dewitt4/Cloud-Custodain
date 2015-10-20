
from concurrent.futures import (
    ProcessPoolExecutor, ThreadPoolExecutor)


def executor(name, max_workers=1):

    name_worker = {
        'process': ProcessPoolExecutor,
        'thread': ThreadPoolExecutor,
        'main': MainThreadExecutor,
        }

    assert name in name_worker
    return name_worker[name](max_workers=max_workers)


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
