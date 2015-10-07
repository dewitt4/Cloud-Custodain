import csv
import json
import itertools
import logging
import operator

from janitor import actions, cache, filters, query


class ResourceManager(object):

    def __init__(self, session_factory, data, config):
        self.session_factory = session_factory
        self.config = config
        self.data = data
        self._cache = cache.factory(config)
        self.log = logging.getLogger('janitor.resources.%s' % (
            self.__class__.__name__.lower()))

        
class EC2(ResourceManager):

    def __init__(self, session_factory, data, config):
        super(EC2, self).__init__(session_factory, data, config)
        if not isinstance(self.data, dict):
            raise ValueError(
                "Invalid format, expecting dictionary found %s" % (
                    type(self.data)))
                
        self._queries = query.parse(self.data.get('query', []))
        self._filters = filters.parse(self.data.get('filters', []))
        self._actions = actions.parse(self.data.get('actions', []), self)

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
 
    def filter_resources(self, resources):
        results = []
        for i in resources:
            matched = True
            for f in self._filters:
                if not f(i):
                    matched = False
                    break
            if matched:
                results.append(i)
        self.log.info("Filtered resources from %d to %d" % (
            len(resources), len(results)))
        return results
    
    def resources(self): 
        qf = self.resource_query()
        instances = None
        
        if self._cache.load():
            instances = self._cache.get(qf)
        if instances is not None:
            self.log.info(
                'Using cached instance query: %s instances' % len(instances))
            return self.filter_resources(instances)

        self.log.info("Querying ec2 instances with %s" % qf)
        session = self.session_factory()
        client = session.client('ec2')
        p = client.get_paginator('describe_instances')

        results = p.paginate(Filters=qf)
        reservations = list(itertools.chain(*[pp['Reservations'] for pp in results]))
        instances =  list(itertools.chain(
            *[r["Instances"] for r in reservations]))
        self.log.debug("Found %d instances on %d reservations" % (
            len(instances), len(reservations)))
        self._cache.save(qf, instances)

        # Filter instances
        return self.filter_resources(instances)
    
    def format_json(self, resources, fh):
        resources = sorted(
            resources, key=operator.itemgetter('LaunchTime'))
        json.dump({'ec2': [
            {'instance-id': i['InstanceId'],
             'tags': i.get('Tags'),
             'ami': i['ImageId'],
             'key': i.get('KeyName', ''),
             'created': i['LaunchTime'].isoformat(),
             'type': i['InstanceType']} for i in resources]},
        fh, indent=2)

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
                i.get('Tags', {}).get('Name', "NA"),
                i['LaunchTime'].isoformat(),
                i['InstanceType'],
                i['ImageId'],
                i.get('KeyName', 'NA'),
                i.get('Tags', {}).get("ASV", "NA"),
                i.get('Tags', {}).get("CMDBEnvironment", "NA")                
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

                                      
                                    
