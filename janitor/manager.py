import boto3

import csv
import itertools
import logging


from janitor import actions, cache, filters, query


class ResourceManager(object):

    def __init__(self, session_factory, data, config):
        self.session_factory = session_factory
        self.config = config
        self.data = data
        self._cache = None
        

class EC2(ResourceManager):

    def __init__(self, session_factory, data, config):
        super(EC2, self).__init__(session_factory, data, config)
        self.log = logging.getLogger('janitor.resources.ec2')        
        self._cache = cache.factory(config)
        self._queries = query.parse(self.data.get('query', []))
        self._filters = filters.parse(self.data.get('filters', []))
        self._actions = actions.parse(self.data.get('actions', []))

    @property
    def client(self):
        return self.session_factory().client('ec2')
        
    ### Begin Test Helpers
    @property
    def queries(self):
        return self._queries

    @property
    def filters(self):
        return self._filters

    @property
    def actions(self):
        return self._actions

    ### End Test Helpers

    def resources(self): 
        qf = self.resource_query()

        if self._cache.load():
            instances = self._cache.get(qf)
        if instances is not None:
            self.log.info(
                'Using cached instance query: %s instances' % len(instances))
            return instances

        self.log.info("Querying ec2 instances with %s" % qf)        
        p = self.client.get_paginator('describe_instances')
        results = p.paginate(Filters=qf)
        instances =  list(itertools.chain(*[r.instances for r in results]))
        self.log.debug("Found %d instances on %d reservations" % (
            len(instances), len(results)))

        self._cache.save(qf, instances)
        return instances
    
    def format_json(self, resources):
        return {'EC2': {
            [{'instance-id': i.id,
              'tags': i.tags,
              'ami': i.image_id,
              'key': i.key_name,
              'created': i.launch_time,
              'type': i.instance_type} for i in resources]}}

    def format_csv(self, resources, fh):
        writer = csv.writer(fh)
        writer.writerow(
            ('name',
             'launch_time',
             'instance_type',
             'image_id',
             'key_name',
             'asv',
             'cmdbenv'))
        for i in resources:
            writer.writerow((
                i.tags.get('Name', "NA"),
                i.launch_time,
                i.instance_type,
                i.image_id,
                i.key_name,
                i.tags.get("ASV", "NA"),
                i.tags.get("CMDBEnvironment", "NA")                
            ))
        
    
    def resource_query(self):
        qf = []
        qf_names = set()
        # allow same name to be specified multiple times and append the queries
        # under the same name
        for q in self._queries:
            qd = q.query()
            if qd['Name'] in qf_names:
                for qf in qf:
                    if qd['Name'] == qf['Name']:
                        qf['Values'].extend(qd['Values'])
            else:
                qf_names.add(qd['Name'])
                qf.append(qd)
        return qf

                                      
                                    
