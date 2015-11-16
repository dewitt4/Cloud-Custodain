"""
Resource Filtering Logic
"""


import jmespath
import operator

from janitor.executor import ThreadPoolExecutor
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


class FilterRegistry(Registry):

    def __init__(self, *args, **kw):
        super(FilterRegistry, self).__init__(*args, **kw)
        self.register_class('value', ValueFilter)
        self.register_class('or', Or)
        
    def parse(self, data, manager):
        results = []
        for d in data:
            results.append(self.factory(d, manager))
        return results

    def factory(self, data, manager=None):
        """Factory func for filters.

        data - policy config for filters
        manager - resource type manager (ec2, s3, etc)
        """

        # Make the syntax a little nicer for common cases.
        if len(data) == 1 and not 'type' in data:
            if data.keys()[0] == 'or':
                return Or(data, self, manager)
            return ValueFilter(data, manager).validate()

        filter_type = data.get('type')
        if not filter_type:
            raise FilterValidationError(
                "%s Invalid Filter %s" % (
                    self.plugin_type, data))
        filter_class = self.get(filter_type)
        if filter_class is not None:
            return filter_class(data, manager).validate()
        else:
            raise FilterValidationError(
                "%s Invalid filter type %s" % (
                    self.plugin_type, data))


# Really should be an abstract base class (abc) or
# zope.interface

class Filter(object):

    executor_factory = ThreadPoolExecutor
    
    def __init__(self, data, manager=None):
        self.data = data
        self.manager = manager

    def validate(self):
        """validate filter config, return validation error or self"""
        return self

    @property
    def name(self):
        """ Name of the filter"""
        raise NotImplementedError()
    
    def process(self, resources):
        """ Bulk process resources and return filtered set."""
        return filter(self, resources)
            
    def __call__(self, instance):
        """ Process an individual resource."""
        raise NotImplementedError()
    

class Or(Filter):

    def __init__(self, data, registry, manager):
        super(Or, self).__init__(data)
        self.registry = registry
        self.filters = registry.parse(self.data.values()[0], self.manager)

    def __call__(self, i):
        for f in self.filters:
            if f(i):
                return True
        return False
        

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

        # Value extract
        if self.k.startswith('tag:'):
            tk = self.k.split(':', 1)[1]
            r = None
            for t in i.get("Tags", []):
                if t.get('Key') == tk:
                    r = t.get('Value')
                    break
        elif not '.' in self.k and not '[' in self.k and not '(' in self.k:
            r = i.get(self.k)
        elif self.expr:
            r = self.expr.search(i)
        else:
            self.expr = jmespath.compile(self.k)
            r = self.expr.search(i)

        # Value match
        if r is None and self.v == 'absent':
            return True
        elif self.v == 'not-null' and r:
            return True
        elif self.op:
            op = OPERATORS[self.op]
            return op(r, self.v)
        elif r == self.v:
            return True
        return False
