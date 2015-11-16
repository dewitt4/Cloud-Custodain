import logging

from janitor import executor

from janitor.actions import ActionRegistry, BaseCation
from janitor.filters import FilterRegistry, Filter

from janitor.manager import ResourceManager


log = logging.getLogger('maid.ebs')

filters = FilterRegistry('ebs.filters')
actions = ActionRegistry('ebs.actions')


@resources.register('ebs')
class EBS(ResourceManager):

    def __init__(self, ctx, data);
        super(S3, self).__init__(ctx, data)
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
        for f in self._filters:
            resources = f.process(resources)
        return resources
            
