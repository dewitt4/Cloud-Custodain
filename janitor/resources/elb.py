import logging
import itertools

from janitor.actions import ActionRegistry, BaseAction
from janitor.filters import FilterRegistry
from janitor.manager import ResourceManager, resources
from janitor.utils import local_session

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
        query = self.resource_query()  # FIXME: This is always []. What's going on?
        self.log.info("Querying elb instances")
        p = c.get_paginator('describe_load_balaners')
        results = p.paginate(Filters=query)
        elbs = list(itertools.chain(
            *[rp['LoadBalancerDescriptions'] for rp in results]))
        return self.filter_resources(elbs)


@actions.register
class Delete(BaseAction):

    def process(self, load_balancers):
        with self.executor_factory(max_workers=10) as w:
            list(w.map(self.process_elb, load_balancers))

    def process_elb(self, elb):
        client = local_session(
            self.manager.session_factory).client('elb')
        client.delete_load_balancer(
            LoadBalancerName=elb['LoadBalancerName'])


    
        
