"""
Elastic Load Balancers
----------------------


TODO
####

- SSL Policy enforcement
- Empty instance waste collection

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
    # Matches when the backend listener and health check are
    # not on the same protocol
    - healthcheck-protocol-mismatch

"""
from concurrent.futures import as_completed
import logging
import itertools

from janitor.actions import ActionRegistry, BaseAction
from janitor.filters import Filter, FilterRegistry
from janitor.manager import ResourceManager, resources
from janitor.utils import local_session, chunks

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
        client = local_session(self.manager.session_factory).client('elb')
        client.delete_load_balancer(LoadBalancerName=elb['LoadBalancerName'])


@filters.register('ssl-policy')
class SSLPolicyFilter(Filter):
    """Filter ELBs on the properties of SSLNegotation policies.
    TODO: Only works on custom policies at the moment.
    filters:
      - type: ssl-policy
        blacklist:
        - "Protocol-SSLv2"
        - "Protocol-SSLv3"
    """
    
    def process(self, balancers):
        balancers = [b for b in balancers if self.is_ssl(b)]
        balancer_policy_map = {}
        policy_attr_map = {}
        
        for b in balancers:
            for ld in b['ListenerDescriptions']:
                if ld['Listener']['Protocol'] != 'HTTPS':
                    continue
                for p in ld['PolicyNames']:
                    # Skip precanned
                    if p.startswith('ELBSecurityPolicy'):
                        continue
                    elif p.startswith('ELBSample'):
                        continue
                    balancer_policy_map.setdefault(
                        b['LoadBalancerName'], []).apppend(p)

        with self.executor_factory(max_workers=3) as w:
            futures = []
            
            for elb_policy_set in chunks(balancer_policy_map.items(), 50):
                futures.append(
                    w.submit(self.process_elb_policy_set, elb_policy_set))

                for f in as_completed(futures):
                    if f.exception():
                        self.log.error(
                            "Exception processing elb policies \n %s" % (
                                f.exception()))
                        continue
                for elb_policies in f.result():
                    pass
        
    def process_elb_policy_set(self, elb_policy_set):
        results = []        
        client = local_session(self.manager.session_factory).client('elb')
        
        for (elb_name, policy_names) in elb_policy_set:
            policies = client.describe_load_balancer_policies(
                LoadBalancerName=elb_name,
                PolicyNames=policy_names)['PolicyDescriptions']
            lb_policies = []
            for p in policies:
                if p['PolicyTypeName'] != 'SSLNegotiationPolicyType':
                    lb_policies.append(
                        {'Name': p['PolicyName'],
                         'Type': p['PolicyTypeName'],
                         'Attrs': {a['AttributeName']: a['AttributeValue']
                                   for a in p['PolicyAttributeDescriptions']}})
            results.append((elb_name, lb_policies))
        return results
                
            
    @staticmethod
    def is_ssl(b):
        for ld in b['ListenerDescriptions']:
            if ld['Listener']['Protocol'] != 'HTTPS':
                continue
            return True
        return False        


@filters.register('healthcheck-protocol-mismatch')
class HealthCheckProtocolMismatch(Filter):
    """
    """
    def __call__(self, load_balancer):
        health_check_protocol = load_balancer['HealthCheck']['Target'].split(':')[0]
        listener_descriptions = load_balancer['ListenerDescriptions']
        
        if len(listener_descriptions) == 0:
            return True

        # check if any of the protocols in the ELB match the health
        # check. There is only 1 health check, so if there are
        # multiple listeners, we only check if at least one of them
        # matches
        protocols = [listener['Listener']['InstanceProtocol']
                     for listener in listener_descriptions]
        return health_check_protocol in protocols
