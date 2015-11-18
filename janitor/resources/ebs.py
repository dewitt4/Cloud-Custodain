import logging
import itertools

from janitor import executor

from janitor.actions import ActionRegistry, BaseAction
from janitor.filters import FilterRegistry, Filter

from janitor.manager import ResourceManager, resources


log = logging.getLogger('maid.ebs')

filters = FilterRegistry('ebs.filters')
actions = ActionRegistry('ebs.actions')


@resources.register('ebs')
class EBS(ResourceManager):

    def __init__(self, ctx, data):
        super(EBS, self).__init__(ctx, data)
        self.filters = filters.parse(
            self.data.get('filters', []), self)
        self.actions = actions.parse(
            self.data.get('actions', []), self) 

    def resource_query(self):
        return []
    
    def resources(self):
        c = self.session_factory().client('ec2')
        query = self.resource_query()
        self.log.info("Querying ebs volumes")
        p = c.get_paginator('describe_volumes')
        results = p.paginate(Filters=query)
        volumes = list(itertools.chain(*[rp['Volumes'] for rp in results]))
        return self.filter_resources(volumes)
        
    def filter_resources(self, resources):
        original = len(resources)
        for f in self.filters:
            resources = f.process(resources)
        self.log.info("Filtered from %d to %d volumes" % (
            original, len(resources)))
        return resources
            
