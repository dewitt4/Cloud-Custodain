"""
EC2 Instance Filtering Logic

"""
from dateutil.parser import parse as parse_date
from dateutil.tz import tzutc

import jmespath

from datetime import datetime, timedelta
import logging
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
    if len(data) == 1 and not 'type' in data:
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


# Really should be an abstract base class (abc) or zope.interface
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

            
@register_filter('instance-age')        
class InstanceAgeFilter(Filter):

    threshold_date = None
    
    def __call__(self, i):
        if not self.threshold_date:
            days = self.data.get('days', 60)
            n = datetime.now(tz=tzutc())
            self.threshold_date = n - timedelta(days)            
        return self.threshold_date > i['LaunchTime']
                

@register_filter('marked-for-op')
class MarkedForOp(Filter):

    log = logging.getLogger("maid.ec2.filters.marked_for_op")

    current_date = None

    def __call__(self, i):
        tag = self.data.get('tag', 'maid_status')
        op = self.data.get('op', 'stop')
        
        v = None
        for n in i.get('Tags', ()):
            if n['Key'] == tag:
                v = n['Value']
                break

        if v is None:
            return False
        if not ':' in v or not '@' in v:
            return False

        msg, tgt = v.rsplit(':', 1)
        action, action_date_str = tgt.strip().split('@', 1)

        if action != op:
            return False
        
        try:
            action_date = parse_date(action_date_str)
        except:
            self.log.warning("%s could not parse tag:%s value:%s" % (
                i['InstanceId'], tag, v))

        if self.current_date is None:
            self.current_date = datetime.now()

        return self.current_date >= action_date
        
        

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
