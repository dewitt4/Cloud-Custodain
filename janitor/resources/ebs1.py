import logging
import itertools

from janitor import executor
from janitor.actions import ActionRegistry, BaseAction
from janitor.filters import FilterRegistry, Filter
from janitor.manager import ResourceManager, resources

log = logging.getLogger('maid.ebs')

filters = FilterRegistry('ebs.filters')
actions = ActionRegistry('ebs.actions')

@resources.register('ebs')
class EBS(ResourceManager):
	def __init__(self, session_factory, data, config, log_dir):
        super(EC2, self).__init__(session_factory, data, config, log_dir)
        if not isinstance(self.data, dict):
            raise ValueError("Invalid format, expecting dictionary found %s" % (type(self.data)))
                
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
        self.log.info("Filtered resources from %d to %d" % (len(resources), len(results)))
        return results
    
    def resources(self): 
        qf = self.resource_query()
        instances = None
        
        if self._cache.load():
            instances = self._cache.get(qf)
        if instances is not None:
            self.log.info('Using cached instance query: %s instances' % len(instances))
            return self.filter_resources(instances)

        self.log.info("Querying ebs volumes with %s" % qf)
        session = self.session_factory()
        client = session.client('ec2')
        p = client.get_paginator('describe_volumes')

        results = p.paginate(Filters=qf)
        volumes = list(itertools.chain(*[pp['Reservations'] for pp in results]))
        self.log.debug("Found %d volumes" % (len(volumes)))
        self._cache.save(qf, volumes)

        # Filter instances
        return self.filter_resources(volumes)
    
    def format_json(self, resources, fh):
        resources = sorted(resources, key=operator.itemgetter('LaunchTime'))
        json.dump({'ebs': [
            {'volume-id': i['VolumeId'],
             'tags': i.get('Tags'),
             'encrypted': i['Encrypted'],
             'key': i.get('KmsKeyId', ''),
             'created': i['CreateTime'].isoformat(),
             'type': i['VolumeType']} for i in resources]},
        fh, indent=2)

    def format_csv(self, resources, fh):
        writer = csv.writer(fh)
        writer.writerow(
            ('AvailabilityZone',
  			 'Attachments',
			 'Encrypted',
			 'VolumeType',
			 'VolumeId',
			 'State',
			 'Iops',
			 'KmsKeyId',
			 'SnapshotId',
			 'CreateTime',
			 'Size'))
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

@filters.register('volume-encryption')
class VolumeEncryptFilter(Filter):
	threshold_boolean = None
	def __call__(self, i):
		if not self.threshold_boolean:
			threshold_boolean = False
		return threshold_boolean

@actions.register('mark')		
class Mark(BaseAction):
	def process(self, volumes):
		msg = self.data.get('msg', 'EBS volume does not meet encryption guidelines')
		tag = self.data.get('tag', 'maid_status')
		self.run_api(self.manager.client.create_tags, Resources=[i['VolumeId'] for i in volumes], Tags=[{'Key': tag, 'Value': msg}], DryRun=self.manager.config.dryrun)
		
@actions.register('unmark')
class Unmark(BaseAction):
    def process(self, volumes):
        tag = self.data.get('tag', 'maid_status')
        self._run_api(self.manager.client.create_tags, Resources=[i['VolumeId'] for i in volumes], Tags=[{"Key": tag, "Value": None}],DryRun=self.manager.config.dryrun)

@actions.register('start')
class Start(BaseAction):
    def process(self, instances):
        self._run_api(self.manager.client.start_instances, InstanceIds=[i['InstanceId'] for i in instances], DryRun=self.manager.config.dryrun)

@actions.register('stop')
class Stop(BaseAction):
    def process(self, instances):
        self.log.info("Stopping %d instances" % len(instances))        
        self._run_api(self.manager.client.stop_instances, InstanceIds=[i['InstanceId'] for i in instances], DryRun=self.manager.config.dryrun)

@actions.register('mark-for-encryption')
class MarkForEncryption(BaseAction):
	def process(self, volumes):
		msg_tmpl = self.data.get('msg', 'EBS volume does not meet encryption guidelines: {enc}@{stop_date}')
		enc = self.data.get('enc', 'stop')
		tag = self.data.get('tag', 'maid_status')
		date = self.data.get('days', 5)
		
		n = datetime.now(tz=tzutc())
		stop_date = n + timedelta(days=date)
		msg = msg_tmpl.format(enc=enc, stop_date=stop_date.strftime('%Y/%m/%d'))
		
		self.log.info("Tagging %d volumes for %s on %s" % (len(volumes), op, stop_date.strftime('%Y/%m/%d')))
        self._run_api(self.manager.client.create_tags,Resources=[i['VolumeId'] for i in volumes],Tags=[{"Key": tag,"Value": msg}],DryRun=self.manager.config.dryrun)
		
@actions.register('marked-for-encryption')
class MarkedForEncryption(Filter):
	log = logging.getLogger("maid.ec2.filters.marked_for_encryption")
	current_date = None
	def __call__(self, i):
		tag = self.data.get('tag', 'maid_status')
		enc = self.data.get('enc', 'stop')
		
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
		
		if action != enc:
			return False
			
		try:
			action_date = parse_date(action_date_str)
		except:
			self.log.warning("%s could not parse tag:%s value:%s" % (i['InstanceId'], tag, v))
			
		if self.current_date is None:
            self.current_date = datetime.now()

        return self.current_date >= action_date


# Valid EBS Snapshot Query Filters
# http://docs.aws.amazon.com/AWSEC2/latest/CommandLineReference/ApiReference-cmd-DescribeSnapshots.html
EBS_VALID_FILTERS = {
	'description' : str,
	'encrypted' : (True, False),
	'owner-alias' : str,
	'owner-id' : str,
	'progress' : str,
	'status' : ('pending', 'complete', 'error'),
	'snapshot-id' : str,
	'start-time' : str,
	'volume-id' : str,
	'volume-size' : str,
	'tag-key': str,
    'tag-value': str,
    'tag:': str
}	
