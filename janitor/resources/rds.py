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

from botocore.exceptions import ClientError

from janitor.actions import ActionRegistry, BaseAction
from janitor.filters import FilterRegistry, Filter
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

    def get_resources(self, resource_ids):
        c = local_session(self.session_factory).client('rds')
        results = []
        for db_id in resource_ids:
            results.extend(
                c.describe_db_instances(
                    DBInstanceIdentifier=db_id)['DBInstances'])
        return results


@filters.register('default-vpc')
class DefaultVpc(Filter):
    """ Matches if an rds database is in the default vpc
    """

    vpcs = None
    default_vpc = None

    def __call__(self, rdb):
        vpc_id = rdb['DBSubnetGroup']['VpcId']
        if self.vpcs is None:
            self.vpcs = set((vpc_id,))
            query_vpc = vpc_id
        else:
            query_vpc = vpc_id not in self.vpcs and vpc_id or None

        if query_vpc:
            client = local_session(self.manager.session_factory).client('ec2')
            self.log.debug("querying vpc %s" % vpc_id)
            vpcs = [v['VpcId'] for v
                    in client.describe_vpcs(VpcIds=[vpc_id])['Vpcs']
                    if v['IsDefault']]
            self.vpcs.add(vpc_id)
            if not vpcs:
                return []
            self.default_vpc = vpcs.pop()
        return vpc_id == self.default_vpc and True or False

    
@actions.register('delete')
class Delete(BaseAction):

    def process(self, resources):
        self.skip = self.data.get('skip-snapshot', False)
        
        # Concurrency feels like over kill here.
        client = local_session(self.manager.session_factory).client('rds')
        
        for rdb in resources:
            params = dict(
                DBInstanceIdentifier=rdb['DBInstanceIdentifier'])
            if self.skip:
                params['SkipFinalSnapshot'] = True
            else:
                params[
                    'FinalDBSnapshotIdentifier'] = rdb['DBInstanceIdentifier']
            try:
                client.delete_db_instance(**params)
            except ClientError as e:
                if e.response['Error']['Code'] == "InvalidDBInstanceState":
                    continue
                raise

            self.log.info("Deleted rds: %s" % rdb['DBInstanceIdentifier'])
        
        
