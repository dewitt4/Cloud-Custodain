"""
Elastic Load Balancers
----------------------


Common Policies
###############

SSL Policy enforcement

Empty instance waste collection

Actions
#######

filters:
  - Instances: []
actions:
  - type: mark-for-op
    op: 'delete'
    days: 7

filters:
  - type: marked-for-op
    op: delete
actions:
  - delete


Filters
#######

In addition to value filters

.. code-block:: yaml

  filters:
    - type: ssl-policy:
      name: []
      whitelist: []
      blacklist:
      - "Protocol-SSLv2"


  filters:
    - type: healthcheck-protocol-mismatch:

"""
import logging
import itertools

from janitor.actions import ActionRegistry, BaseAction
from janitor.filters import Filter, FilterRegistry
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
        query = self.resource_query()  # FIXME: This is not used.
        # paginator for ELB only takes load balancer names and a few other params,
        # not a generic query
        self.log.info("Querying elb instances")
        p = c.get_paginator('describe_load_balancers')
        results = p.paginate()
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


@filters.register('healthcheck-protocol-mismatch')
class HealthCheckProtocolMismatch(Filter):

    def __call__(self, load_balancer):
        health_check_protocol = load_balancer['HealthCheck']['Target'].split(':')[0]
        listener_descriptions = load_balancer['ListenerDescriptions']
        if len(listener_descriptions) == 0:
            return True

        # check if any of the protocols in the ELB match the health check. There is only 1 health
        # check, so if there are multiple listeners, we only check if at least one of them matches
        protocols = [ listener['Listener']['InstanceProtocol'] for listener in listener_descriptions ]
        return health_check_protocol in protocols
