from datetime import datetime

import json
import threading
import time


def loads(body):
    return json.loads(body)


def dumps(data, fh=None, indent=0):
    if fh:
        return json.dump(data, fh, cls=DateTimeEncoder, indent=indent)
    else:
        return json.dumps(data, cls=DateTimeEncoder, indent=indent)


class DateTimeEncoder(json.JSONEncoder):

    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return json.JSONEncoder.default(self, obj)

    
def chunks(iterable, size=50):
    """Break an iterable into lists of size"""
    batch = []
    for n in iterable:
        batch.append(n)
        if len(batch) % size == 0:
            yield batch
            batch = []
    if batch:
        yield batch

        
CONN_CACHE = threading.local()


def local_session(factory):
    s = getattr(CONN_CACHE, 'session', None)
    t = getattr(CONN_CACHE, 'time', 0)
    n = time.time()
    if s is not None and t + 3600 > n:
        return s
    s = factory()
    CONN_CACHE.session = s
    CONN_CACHE.time = n
    return s


def annotation(i, k):
    return i.get(k, ())


def set_annotation(i, k, v):
    """ 
    >>> x = {}
    >>> set_annotation(x, 'marker', 'a')
    >>> annotation(x, 'marker')
    ['a']
    """
    if not isinstance(i, dict):
        raise ValueError("Can only annotate dictionaries")

    if not isinstance(v, list):
        v = [v]
        
    if k in i:
        ev = i.get(k)
        if isinstance(ev, list):
            ev.extend(v)
    else:
        i[k] = v

    
