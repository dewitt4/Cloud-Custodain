"""
EC2 Instance Filtering Logic

"""
import jmespath
import operator

from janitor.registry import Registry
from janitor.utils import set_annotation


class FilterValidationError(Exception): pass


# Matching filters annotate their key onto objects
ANNOTATION_KEY = "MatchedFilters"


OPERATORS = {
    'eq': operator.eq,
    'gt': operator.gt,
    'ge': operator.ge,
    'le': operator.le,
    'lt': operator.lt}


def parse(data):
    results = []
    for d in data:
        f = factory(d)
        results.append(f)
    return results


def factory(data):
    """Factory func for filters."""

    # Make the syntax a little nicer for common cases.
    if len(data) == 1:
        if data.keys()[0] == 'or':
            return Or(data)
        return ValueFilter(data).validate()

    filter_type = data.get('type')
    if not filter_type:
        raise FilterValidationError(
            "EC2 Invalid Filter %s" % data)

    filter_class = _filters.get(filter_type)
    if filter_class is not None:
        return filter_class(data).validate()
    else:
        raise FilterValidationError(
            "EC2 Invalid filter type %s" % data)


_filters = Registry('ec2.filters')
register_filter = _filters.register_class


# Really should be an abstract base class
class Filter(object):

    def __init__(self, data):
        self.data = data

    def validate(self):
        return self

    @property
    def type(self):
        pass

    @property
    def name(self):
        pass

    def __call__(self, instance):
        raise NotImplementedError()
    

class Or(Filter):

    def __init__(self, data):
        super(Or, self).__init__(data)
        self.filters = parse(self.data.values()[0])

    def __call__(self, i):
        for f in self.filters:
            if f(i):
                return True
        return False

            
@register_filter('age')        
class InstanceAgeFilter(Filter):
    pass
            
    
@register_filter('value')
class ValueFilter(Filter):

    expr = None
    op = v = None

    def validate(self):
        if len(self.data) == 1:
            return self
        if not 'key' in self.data:
            raise FilterValidationError(
                "Missing 'key' in value filter %s" % self.data)
        if not 'value' in self.data:
            raise FilterValidationError(
                "Missing 'value' in value filter %s" % self.data)
        if 'op' in self.data:
            if not self.data['op'] in OPERATORS:
                raise FilterValidationError(
                    "Invalid operatorin value filter %s" %  self.data)

        return self

    def __call__(self, i):
        matched = self.match(i)
        if matched:
            set_annotation(i, ANNOTATION_KEY, self.k)
        return matched
        
    def match(self, i):

        if self.v is None and len(self.data) == 1:
            [(self.k, self.v)] = self.data.items()
        elif self.v is None: 
            self.k = self.data.get('key')
            self.op = self.data.get('op')
            self.v = self.data.get('value')

        if self.k.startswith('tag:'):
            tk = self.k.split(':', 1)[1]
            r = None
            for t in i.get("Tags", []):
                if t.get('Name') == tk:
                    r = t.get('Value')
                    break
        elif not '.' in self.k and not '[' in self.k and not '(' in self.k:
            r = i.get(self.k)
        elif self.expr:
            r = self.expr.search(i)
        else:
            self.expr = jmespath.compile(self.k)
            r = self.expr.search(i)
        if r is None and self.v is 'absent':
            return True
        elif self.v == 'null' and not r:
            return True
        elif self.op:
            op = OPERATORS[self.op]
            return op(r, self.v)
        elif r == self.v:
            return True
        return False
