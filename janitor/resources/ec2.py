from dateutil.parser import parse as parse_date
from dateutil.tz import tzutc

import csv
from datetime import datetime, timedelta
import json
import itertools
import logging
import operator


from janitor.actions import ActionRegistry, BaseAction
from janitor.filters import FilterRegistry, Filter

from janitor.manager import ResourceManager, resources


filters = FilterRegistry('ec2.filters')
actions = ActionRegistry('ec2.actions')


@resources.register('ec2')
class EC2(ResourceManager):

    def __init__(self, ctx, data):
        super(EC2, self).__init__(ctx, data)
        if not isinstance(self.data, dict):
            raise ValueError(
                "Invalid format, expecting dictionary found %s" % (
                    type(self.data)))
        self._queries = QueryFilter.parse(self.data.get('query', []))
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


@filters.register('instance-age')        
class InstanceAgeFilter(Filter):

    threshold_date = None
    
    def __call__(self, i):
        if not self.threshold_date:
            days = self.data.get('days', 60)
            n = datetime.now(tz=tzutc())
            self.threshold_date = n - timedelta(days)            
        return self.threshold_date > i['LaunchTime']
                

@filters.register('marked-for-op')
class MarkedForOp(Filter):

    log = logging.getLogger("maid.ec2.filters.marked_for_op")

    current_date = None

    def __call__(self, i):
        tag = self.data.get('tag', 'maid_status')
        op = self.data.get('op', 'stop')
        
        v = None
        for n in i.get('Tags', ()):
            if n['Key'] == tag:
                v = n['Value']
                break

        if v is None:
            return False
        if not ':' in v or not '@' in v:
            return False

        msg, tgt = v.rsplit(':', 1)
        action, action_date_str = tgt.strip().split('@', 1)

        if action != op:
            return False
        
        try:
            action_date = parse_date(action_date_str)
        except:
            self.log.warning("%s could not parse tag:%s value:%s" % (
                i['InstanceId'], tag, v))

        if self.current_date is None:
            self.current_date = datetime.now()

        return self.current_date >= action_date
        
    

@actions.register('mark')        
class Mark(BaseAction):

    def process(self, instances):
        if not len(instances):
            return
        msg = self.data.get(
            'msg', 'Instance does not meet ec2 policy guidelines')
        tag = self.data.get('tag', 'maid_status')
        self._run_api(
            self.manager.client.create_tags,
            Resources=[i['InstanceId'] for i in instances],
            Tags=[
                {"Key": tag,
                 "Value": msg}],
            DryRun=self.manager.config.dryrun)


@actions.register('unmark')
class Unmark(BaseAction):

    def process(self, instances):
        if not len(instances):
            return
        tag = self.data.get('tag', 'maid_status')
        self._run_api(
            self.manager.client.create_tags,
            Resources=[i['InstanceId'] for i in instances],
            Tags=[
                {"Key": tag, "Value": None}],
            DryRun=self.manager.config.dryrun)


@actions.register('start')        
class Start(BaseAction):

    def process(self, instances):
        if not len(instances):
            return
        self._run_api(
            self.manager.client.start_instances,
            InstanceIds=[i['InstanceId'] for i in instances],
            DryRun=self.manager.config.dryrun)


@actions.register('stop')
class Stop(BaseAction):

    def process(self, instances):
        self.log.info("Stopping %d instances" % len(instances))
        if not len(instances):
            return
        self._run_api(
            self.manager.client.stop_instances,
            InstanceIds=[i['InstanceId'] for i in instances],
            DryRun=self.manager.config.dryrun)

        
@actions.register('terminate')        
class Terminate(BaseAction):

    def process(self, instances):
        self.log.info("Terminating %d instances" % len(instances))
        if not len(instances):
            return
        self._run_api(
            self.manager.client.terminate_instances,
            InstanceIds=[i['InstanceId'] for i in instances],
            DryRun=self.manager.config.dryrun)

        
@actions.register('mark-for-op')
class MarkForOp(BaseAction):

    def process(self, instances):
        msg_tmpl = self.data.get(
            'msg',
            'Instance does not meet ec2 tag policy: {op}@{stop_date}')

        op = self.data.get('op', 'stop')
        tag = self.data.get('tag', 'maid_status')
        date = self.data.get('days', 4)
        
        n = datetime.now(tz=tzutc())
        stop_date = n + timedelta(days=date)
        msg = msg_tmpl.format(
            op=op, stop_date=stop_date.strftime('%Y/%m/%d'))

        self.log.info("Tagging %d instances for %s on %s" % (
            len(instances), op, stop_date.strftime('%Y/%m/%d')))

        if not len(instances):
            return
        
        self._run_api(
            self.manager.client.create_tags,
            Resources=[i['InstanceId'] for i in instances],
            Tags=[
                {"Key": tag,
                 "Value": msg}],
            DryRun=self.manager.config.dryrun)



# Valid EC2 Query Filters
# http://docs.aws.amazon.com/AWSEC2/latest/CommandLineReference/ApiReference-cmd-DescribeInstances.html
EC2_VALID_FILTERS = {
    'architecture': ('i386', 'x86_64'),
    'availability-zone': str,
    'iam-instance-profile.arn': str, 
    'image-id': str,
    'instance-id': str,
    'instance-lifecycle': ('spot',),
    'instance-state-name': (
        'pending',
        'terminated',
        'running',
        'shutting-down',
        'stopping',
        'stopped'),
    'instance.group-id': str,
    'instance.group-name': str,
    'tag-key': str,
    'tag-value': str,
    'tag:': str,
    'vpc-id': str}


class QueryFilter(object):

    @classmethod
    def parse(cls, data):
        results = []
        for d in data:
            if not isinstance(d, dict):
                raise ValueError(
                    "EC2 Query Filter Invalid structure %s" % d)
            results.append(cls(d).validate())
        return results

    def __init__(self, data):
        self.data = data
        self.key = None
        self.value = None
        
    def validate(self):
        if not len(self.data.keys()) == 1:
            raise ValueError(
                "EC2 Query Filter Invalid %s" % self.data)
        self.key = self.data.keys()[0]
        self.value = self.data.values()[0]

        if not self.key in EC2_VALID_FILTERS and not self.key.startswith('tag:'):
            raise ValueError(
                "EC2 Query Filter invalid filter name %s" % (self.data))
                
        if self.value is None:
            raise ValueError(
                "EC2 Query Filters must have a value, use tag-key"
                " w/ tag name as value for tag present checks"
                " %s" % self.data)
        return self
    
    def query(self):
        value = self.value
        if isinstance(self.value, basestring):
            value = [self.value]
            
        return {'Name': self.key, 'Values': value}


    
                                    
