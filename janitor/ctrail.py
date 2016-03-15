import jmespath


class CloudTrailResource(object):
    """A mapping of events to resource types."""
    
    mappings = {
        # event source, resource type as keys, mapping to api call and
        # jmespath expression
        'CreateBucket': {
            'ids': 'requestParameters.bucketName',
            'source': 'aws.s3'},
        
        'CreateVolume': {
            'ids': 'responseElements.volumeId',
            'source': 'ec2.amazonaws.com'},

        'CreateLoadBalancer': {
            'ids': 'requestParameters.loadBalancerName',
            'source': 'elasticloadbalancing.amazonaws.com',
            },
        
        'CreateLoadBalancerPolicy': {
            'ids': 'requestParameters.loadBalancerName',
            'source': 'elasticloadbalancing.amazonaws.com'},

        'CreateDBInstance': {
            'ids': 'requestParameters.dbInstanceIdentifier',
            'source': 'rds.amazonaws.com'},
        
        'RunInstances': {
            'ids': 'responseElements.instancesSet.items[].instanceId',
            'source': 'ec2.amazonaws.com'}}

    @classmethod
    def get(cls, event_name):
        return cls.mappings.get(event_name)
    
    @classmethod
    def match(cls, event):
        """Match a given cwe event as cloudtrail with an api call

        That has its information filled out.
        """
        if 'detail' not in event:
            return False
        if 'eventName' not in event['detail']:
            return False
        k = event['detail']['eventName']

        # We want callers to use a compiled expression, but want to avoid
        # initialization cost of doing it without cause. Not thread safe.
        if k in cls.mappings:
            v = dict(cls.mappings[k])
            if isinstance(v['ids'], basestring):
                v['ids'] = e = jmespath.compile('detail.%s' % v['ids'])
                cls.mappings[k]['ids'] = e
            return v

        return False
