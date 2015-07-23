"""
Filter logic is either matching for queries, or not matching for 'state': 'absent' instance queries.
"""

class FilterValidationError(Exception): pass

# Valid EC2 Query Filters
# http://docs.aws.amazon.com/AWSEC2/latest/CommandLineReference/ApiReference-cmd-DescribeInstances.html
EC2_VALID_FILTERS = {
    'architecture': ('i386', 'x86_64'),
    'availability-zone': str,
    'iam-instance-profile.arn': str,
    'image-id': str,
    'instance-id': str,
    'instance-lifecycle': ('spot',),
    'instance-state-name': (
        'pending',
        'terminated',
        'running',
        'shutting-down',
        'stopping',
        'stopped'),
    'instance.group-id': str,
    'instance.group-name': str,
    'tag-key': str,
    'tag-value': str,
    'tag:': str,
    'vpc-id': str}


# Map Query Filters to Instance Attributes for late bound queries
EC2_FILTER_INSTANCE_MAP = {
    'architecture': 'architecture',
    'availability-zone': 'placement',
    'iam-instance-profile.arn': 'instance_profile',
    'vpc-id': 'vpc_id',
    'instance-state-name': 'state',
    'architecture': 'architecture'
    }

    
def filter(data):
    """Factory func for filters."""
    filter_type = data.get('type', 'ec2')
    
    if filter_type == 'ec2':
        if data.get('state', '') == 'absent':
            return EC2InstanceFilter(data).validate()
        else:
            return EC2QueryFilter(data).validate()
    elif filter_type == 'janitor':
        return JanitorFilter(data).validate()
    else:
        raise FilterValidationError('invalid filter type: %s for %s' % (
            filter_type, data))
            
    
class Filter(object):

    template = ()

    def __init__(self, data):
        self.data = dict(self.template)
        self.data.update(data)
        
    def validate(self):
        if not 'filter' in self.data:
            raise FilterValidationError('missing filter in %s' % self.data)
        return self

    @property
    def type(self):
        return self.data['type']


class QueryFilter(Filter): pass
    
class InstanceFilter(Filter): pass


class EC2InstanceFilter(InstanceFilter):

    def process(self, i):
        assert self.data.get('state', '') == 'absent'
        f = self.data['filter']
        if f == 'tag-key':
            if self.data['value'] in i.tags:
                return True
        elif f == 'tag-value':
            if self.data.get('value') in i.tags.values():
                return True
        elif f.startswith('tag:'):
            _, k = f.split(":", 1)
            v = self.data.get('value')
            if not k in i.tags:
                return True
            elif v and not i.tags[k] == v:
                return True
            
        elif f in EC2_FILTER_INSTANCE_MAP:
            k = EC2_FILTER_INSTANCE_MAP[f]
            iv = getattr(i, k, None)
            v = self.data.get('value')
            if iv is None:
                return True
            elif iv and v:
                return iv != v
            else:
                return False
        return False
                

    
class EC2QueryFilter(QueryFilter):

    def validate(self):
        super(EC2QueryFilter, self).validate()
        if self.data.get('value') is None:
            raise ValueError(
                "EC2 Query Filters must have a value, use tag-key"
                " w/ tag name as value for tag present checks"
                " %s" % self.data)
        return self
    
    def query(self):
        return {self.data['filter']: self.data['value']}
