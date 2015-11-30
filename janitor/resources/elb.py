import logging
import itertools

from janitor.actions import ActionRegistry
from janitor.filters import FilterRegistry

from janitor.manager import ResourceManager, resources

log = logging.getLogger('maid.elb')


filters = FilterRegistry('elb.filters')
actions = ActionRegistry('elb.actions')


@resources.register('elb')
class ELB(ResourceManager):

    def __init__(self, ctx, data):
        super(ELB, self).__init__(ctx, data)
        self.filters = filters.parse(
            self.data.get('filters', []), self)
        self.actions = actions.parse(
            self.data.get('actions', []), self)

    def resources(self):
        c = self.session_factory().client('elb')
        query = self.resource_query()
        self.log.info("Querying elb instances")
        p = c.get_paginator('describe_load_balaners')
        results = p.paginate(Filters=query)
        elbs = list(itertools.chain(
            *[rp['LoadBalancerDescriptions'] for rp in results]))
        return self.filter_resources(elbs)



    
        
