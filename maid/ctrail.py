# Copyright 2016 Capital One Services, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
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
            'ids': 'requestParameters.dBInstanceIdentifier',
            'source': 'rds.amazonaws.com'},

        'SetLoadBalancerPoliciesOfListener': {
            'ids': 'requestParameters.loadBalancerName',
            'source': 'elasticloadbalancing.amazonaws.com'},
        
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
