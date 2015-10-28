import threading
import time


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
    
    if k in i:
        ev = i.get(k)
        if isinstance(ev, list):
            ev.extend(v)
        else:
            i[k] = [v]
    else:
        i[k] = [v]

    
