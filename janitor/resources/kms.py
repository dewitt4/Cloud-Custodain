import itertools
import logging

from janitor.actions import ActionRegistry
from janitor.filters import FilterRegistry, Filter

from janitor.manager import ResourceManager, resources
from janitor.utils import local_session

log = logging.getLogger('maid.kms')

filters = FilterRegistry('kms.filters')
actions = ActionRegistry('kms.actions')


@resources.register('kms')
class KMS(ResourceManager):

    def __init__(self, ctx, data):
        super(KMS, self).__init__(ctx, data)
        self.filters = filters.parse(
            self.data.get('filters', []), self)
        self.actions = actions.parse(
            self.data.get('actions', []), self) 

    def resources(self):
        c = self.session_factory().client('kms')
        query = self.resource_query()  # FIXME: Not used
        self.log.info("Querying kms keys")
        keys = c.list_aliases()['Aliases']
        original_count = len(keys)
        keys = [k for k in keys if 'TargetKeyId' in k]
        log.debug(
            "Filtered aliases without targets from %d to %d" % (
                original_count, len(keys)))
        return self.filter_resources(keys)


@filters.register('grant-count')
class GrantCount(Filter):

    def process(self, keys, event=None):
        with self.executor_factory(max_workers=10) as w:
            return filter(None, (w.map(self.process_key, keys)))

    def process_key(self, key):
        client = local_session(self.manager.session_factory).client('kms')
        p = client.get_paginator('list_grants')
        grant_count = 0
        for rp in p.paginate(KeyId=key['TargetKeyId']):
            grant_count += len(rp['Grants'])
        key['GrantCount'] = grant_count

        grant_threshold = self.data.get('min', 5)
        if grant_count < grant_threshold:
            return None
        
        self.manager.ctx.metrics.put_metric(
            "ExtantGrants", grant_count, "Count",
            Scope=key['AliasName'][6:])

        return key
