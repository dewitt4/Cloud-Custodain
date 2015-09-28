
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

    
