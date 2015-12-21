"""
RDS Resource Manager
====================

Example Policies
----------------

Find rds instances that are publicly available

.. code-block:: yaml

   policies:
      - name: rds-public
        resource: rds
        filters: 
         - PubliclyAccessible: true

Find rds instances that are not encrypted

.. code-block:: yaml

   policies: 
      - name: rds-non-encrypted
        resource: rds
        filters:
         - type: value
           key: StorageEncrypted
           value: true
           op: ne


Todo/Notes
----------
- Tag api for rds is highly inconsistent
  compared to every other aws api, it
  requires full arns. The api never exposes
  arn. We should use a policy attribute
  for arn, that can dereference from assume
  role, instance profile role, iam user (GetUser), 
  or for sts assume role users we need to
  require cli params for this resource type.

- aurora databases also generate clusters
  that are listed separately and return
  different metadata using the cluster api


"""
import logging
import itertools

from janitor.actions import ActionRegistry, BaseAction
from janitor.filters import FilterRegistry
from janitor.manager import ResourceManager, resources
from janitor.utils import local_session

log = logging.getLogger('maid.rds')


filters = FilterRegistry('rds.filters')
actions = ActionRegistry('rds.actions')


@resources.register('rds')
class RDS(ResourceManager):

    def __init__(self, ctx, data):
        super(RDS, self).__init__(ctx, data)
        self.filters = filters.parse(
            self.data.get('filters', []), self)
        self.actions = actions.parse(
            self.data.get('actions', []), self)

    def resources(self):
        c = self.session_factory().client('rds')
        query = self.resource_query()
        if self._cache.load():
            dbs = self._cache.get(
                {'resource': 'rds', 'q': query})
            if dbs is not None:
                self.log.debug("Using cached rds: %d" % (
                    len(dbs)))
                return self.filter_resources(dbs)
        self.log.info("Querying rds instances")
        p = c.get_paginator('describe_db_instances')
        results = p.paginate(Filters=query)
        dbs = list(itertools.chain(
            *[rp['DBInstances'] for rp in results]))
        self._cache.save({'resource': 'rds', 'q': query}, dbs)
        return self.filter_resources(dbs)



    
        
