from dateutil.parser import parse as parse_date
from dateutil.tz import tzutc

from datetime import datetime, timedelta
import itertools
import logging
import operator


from janitor.actions import ActionRegistry, BaseAction
from janitor.filters import FilterRegistry, Filter, AgeFilter, OPERATORS
from janitor.manager import ResourceManager, resources
from janitor.offhours import Time, OffHour, OnHour
from janitor import utils


filters = FilterRegistry('ec2.filters')
actions = ActionRegistry('ec2.actions')


filters.register('time', Time)


@resources.register('ec2')
class EC2(ResourceManager):

    def __init__(self, ctx, data):
        super(EC2, self).__init__(ctx, data)
        # FIXME: should we be doing this check in every ResourceManager?
        if not isinstance(self.data, dict):
            raise ValueError(
                "Invalid format, expecting dictionary found %s" % (
                    type(self.data)))
        self.queries = QueryFilter.parse(self.data.get('query', []))
        self.filters = filters.parse(self.data.get('filters', []), self)
        self.actions = actions.parse(self.data.get('actions', []), self)

    @property
    def client(self):
        # FIXME: Where is this used?
        return self.session_factory().client('ec2')
        
    def filter_resources(self, resources):
        original = len(resources)
        for f in self.filters:
            resources = f.process(resources)
        self.log.info("Filtered resources from %d to %d" % (
            original, len(resources)))
        return resources
    
    def resources(self):
        # FIXME: Explain why this is different from the other ResourceManagers
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
        utils.dumps(resources, fh, indent=2)

    def resource_query(self):
        qf = []
        qf_names = set()
        # allow same name to be specified multiple times and append the queries
        # under the same name
        for q in self.queries:
            qd = q.query()
            if qd['Name'] in qf_names:
                for qf in qf:
                    if qd['Name'] == qf['Name']:
                        qf['Values'].extend(qd['Values'])
            else:
                qf_names.add(qd['Name'])
                qf.append(qd)
        return qf



class StateTransitionFilter(object):
    """Filter instances by state.

    Try to simplify construction for policy authors by automatically
    filtering elements (filters or actions) to the instances states
    they are valid for.
    
    For more details see http://goo.gl/TZH9Q5

    """
    valid_origin_states = ()

    def filter_instance_state(self, instances):
        orig_length = len(instances)
        results = [i for i in instances
                   if i['State']['Name'] in self.valid_origin_states]
        self.log.info("%s %d of %d instances" % (
            self.__class__.__name__, len(results), orig_length))
        return results
        
    
@filters.register('offhour')
class InstanceOffHour(OffHour, StateTransitionFilter):

    valid_origin_states = ('running',)

    def process(self, resources):
        return super(InstanceOffHour, self).process(
            self.filter_instance_state(resources))

    
@filters.register('onhour')
class InstanceOnHour(OnHour, StateTransitionFilter):
    
    valid_origin_states = ('stopped',)

    def process(self, resources):
        return super(InstanceOnHour, self).process(
            self.filter_instance_state(resources))
    

@filters.register('tag-count')
class TagCountFilter(Filter):

    def __call__(self, i):
        count = self.data.get('count', 10)
        op_name = self.data.get('op', 'lt')
        op = OPERATORS.get(op_name)
        tag_count = len([
            t['Key'] for t in i.get('Tags', [])
            if not t['Key'].startswith('aws:')])
        return op(tag_count, count)

    
@filters.register('instance-age')        
class InstanceAgeFilter(AgeFilter):

    date_attribute = "LaunchTime"
    
                
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

    
@actions.register('tag')    
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

        
@actions.register('untag')
@actions.register('unmark')
class Unmark(BaseAction):

    def process(self, instances):
        if not len(instances):
            return
        tag = self.data.get('tag', 'maid_status')
        self._run_api(
            self.manager.client.delete_tags,
            Resources=[i['InstanceId'] for i in instances],
            Tags=[
                {"Key": tag}],
            DryRun=self.manager.config.dryrun)


    
@actions.register('start')        
class Start(BaseAction, StateTransitionFilter):

    valid_origin_states = ('stopped',)

    def process(self, instances):
        instances = self.filter_instance_state(instances)
        if not len(instances):
            return
        self._run_api(
            self.manager.client.start_instances,
            InstanceIds=[i['InstanceId'] for i in instances],
            DryRun=self.manager.config.dryrun)


@actions.register('stop')
class Stop(BaseAction, StateTransitionFilter):

    valid_origin_states = ('running', 'pending')
    
    def process(self, instances):
        instances = self.filter_instance_state(instances)
        if not len(instances):
            return
        self._run_api(
            self.manager.client.stop_instances,
            InstanceIds=[i['InstanceId'] for i in instances],
            DryRun=self.manager.config.dryrun)

        
@actions.register('terminate')        
class Terminate(BaseAction, StateTransitionFilter):
    """ Terminate a set of instances.
    
    While ec2 offers a bulk delete api, any given instance can be configured
    with api deletion termination protection, so we can't use the bulk call
    reliabily, we need to process the instances individually. Additionally
    If we're configured with 'force' then we'll turn off instance termination
    protection.
    """

    valid_origin_states = ('running', 'stopped', 'pending', 'stopping')
    
    def process(self, instances):
        instances = self.filter_instance_state(instances)
        if not len(instances):
            return
        if self.data.get('force'):
            self.log.info("Disabling termination protection on instances")
            self.disable_deletion_protection(instances)
        self._run_api(
            self.manager.client.terminate_instances,
            InstanceIds=[i['InstanceId'] for i in instances],
            DryRun=self.manager.config.dryrun)

    def disable_deletion_protection(self, instances):
        def process_instance(i):
            client = utils.local_session(
                self.manager.session_factory).client('ec2')
            self._run_api(
                client.modify_instance_attribute,
                InstanceId=i['InstanceId'],
                Attribute='disableApiTermination',
                Value='false',
                DryRun=self.manager.config.dryrun)

        with self.executor_factory(max_workers=10) as w:
            list(w.map(process_instance, instances))
            
        
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


    
                                    
