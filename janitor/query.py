"""
Queries for ec2 instances
"""

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


def parse(data):
    results = []
    for d in data:
        if not isinstance(d, dict):
            raise ValueError(
                "EC2 Query Filter Invalid structure %s" % d)
        results.append(EC2QueryFilter(d).validate())
    return results


class QueryFilter(object):

    def __init__(self, data):
        self.data = data
        self.key = None
        self.value = None
        
    def validate(self):
        if not len(self.data.keys()) == 1:
            raise ValueError(
                "EC2 Query Filter Invalid %s" % self.data)
        self.key = self.data.keys()[0]
        self.value = self.data.values()[0]
        

class EC2QueryFilter(QueryFilter):

    def validate(self):
        super(EC2QueryFilter, self).validate()
        if not self.key in EC2_VALID_FILTERS and not self.key.startswith('tag:'):
            raise ValueError(
                "EC2 Query Filter invalid filter name %s" % (self.data))
                
        if self.value is None:
            raise ValueError(
                "EC2 Query Filters must have a value, use tag-key"
                " w/ tag name as value for tag present checks"
                " %s" % self.data)
        return self
    
    def query(self):
        value = self.value
        if isinstance(self.value, basestring):
            value = [self.value]
            
        return {'Name': self.key, 'Values': value}


