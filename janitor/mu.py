"""CloudMaid Lambda Integration
----------------------------

Lambda provides for powerful realtime and near realtime compliance
execution when integrated in with a number of different amazon
services as event sources.

AWS Cloud Config
----------------

One event source is using AWS Cloud Config, which provides versioned
json representation of objects into s3 with rules execution against
them.  Config Rules allow for lambda execution against these resource
states to determine compliance along with a nice dashboard targeted
towards visualizing compliance information over time. At the moment
config rules execute after the resource is already active, based on the
underlying resource poll and config snapshot delivery. 

Underlying the hood aws config and config rules, appear to be just
productizing a poll of some resources into json files in s3 with
lambda and versioned metrics reports. At the moment config rules
only support items managed under the ec2 api (ec2, ebs, network) which
means they have significant coverage gap when looking at the totality
of aws services since they only cover a single api. As a result atm,
they are best suited to orgs that are using a small subset of aws that
requires audit (ie. just ec2) and prefer a pre-configured dashboard on
that subset. Of course overtime the config service will evolve.

However for capabilities and reporting around compliance Netflix
security monkey would be a better choice atm imo. Maid distinguishes
in its configurable policy engine, as opposed to hard coded, ability
to run serverless, better integration with current best aws practices
and provides remediation and enforcement capabilities.

Open question on config rules, Its unclear if rules execute against
only on a delta to a resource or against each config snapshot..

For a wider range of coverage and functionality we turn to

Cloud Watch Events
------------------

Cloud watchs events is a general event bus for aws infrastructure, atm
it covers two major sources of information, real time instance status events
and cloud trail api calls over a poll period on cloud trail delivery.

Cloud trail provides a much richer data source over the entire range
of aws services exposed via the audit trail to enable defining
compliance policy effectively against any aws product.

Additionally for ec2 instances we can provide mandatory policy
compliance, that effectively means the non compliant resource never
became available.

Cloud Maid Integration
----------------------

Maid provides for policy level execution against any lambda subscribable
event stream.

We reconstitue current state for the given resource and execute
the policy against it, matching against the policy filters, and applying
the policy actions.

Mu is the letter after lambda, lambda is a keyword in python.

Configuration
-------------


proposed syntax

```
policies:
  - name: s3-bucket-policy
    mode: 
      type: cloudwatch
      events: 
       - CreateBucket
    filters:
      # Bucket policy not extant
      -
    actions:
      - encryption-policy
  - name: ec2-encrypted-instance-volumes
    mode:
      type: cloudwatch
      events:
      - CreateVolume
    actions:
      - encrypt-instance-volume
```

alternatively we could associate relevant events to some
actions, like encryption-keys with a list of events, and
encryption-policy with a list of events.
  
Event Sources
-------------

We need to distribute cloud-watch events api json atm for install


Todo
----

Maid additionally can use lambda execution for resource intensive policy
actions, using dynamodb for results aggregation, and a periodic result checker.
"""


import inspect
from cStringIO import StringIO
import fnmatch
import json
import logging
import os
import pprint
import tempfile
import sys
import zipfile

from botocore.exceptions import ClientError

import janitor

from janitor.policy import load

log = logging.getLogger('maid.lambda')


__notes__ = """
Architecture implementation notes

We need to load policies for lambda functions a bit differently so that
they can create the resources needed.


For full lifecycle management we need to be able to determine

 - all resources associated to a given policy
 - all resources created by maid
 - diff of current resources to goal state of resources
 - remove previous policy lambdas and their event sources
   - we need either the previous config file or we need
     to assume only one maid running lambdas in a given
     account.

 
Sample interactions

  $ cloud-maid resources -c config.yml

   lambda:
     - function: name
       sources:
        - source info
   

"""


def resource_handle(resource_type, event, lambda_context):
    """
    Generic resource handler dispatch
    """
    policies = load('config.json', format='json')
    resources = None
    
    log.info("Processing event \n %s", format_event(event))
    
    if not 'Records' in event:
        log.warning("Could not found resource records in event")
        return
    
    for p in policies:
        if p.resource_type != resource_type:
            continue
        # Actualize resources once for all policies
        if resources is None:
            resources = p.resource_manager.load(event['Records'])
        p.process_event(event, lambda_context, resources)

        
def format_event(evt):
    io = StringIO()
    pprint.pprint(evt, io)
    return io.getvalue()


# Explicit entry points by type (could go do dyn dispatch with evt inspect)
def s3_handle(event, context):
    """S3 Event Handler"""
    return resource_handle('s3', event, context)


def ec2_handle(event, context):
    """EC2 Instance Event Handler"""
    return resource_handle('ec2', event, context)


def cwe_handle(event, context):
#    raise NotImplementedError()
    return resource_handle()


class PythonPackageArchive(object):

    def __init__(self, src_path, virtualenv_dir, skip=None):
        self.src_path = src_path
        self.virtualenv_dir = virtualenv_dir
        self._temp_archive_file = None
        self._zip_file = None
        self._closed = False
        self.skip = skip

    @property
    def path(self):
        return self._temp_archive_file.name

    @property
    def size(self):
        if not self._closed:
            raise ValueError("Archive not closed, size not accurate")
        return os.stat(self._temp_archive_file.name).st_size

    def filter_files(self, files):
        if not self.skip:
            return files
        skip_files = set(fnmatch.filter(files, self.skip))
        return [f for f in files if not f in skip_files]
    
    def create(self):
        self._temp_archive_file = tempfile.NamedTemporaryFile()
        self._zip_file = zipfile.ZipFile(
            self._temp_archive_file, mode='w',
            compression=zipfile.ZIP_DEFLATED)

        prefix = os.path.dirname(self.src_path)
        # Package Source
        for root, dirs, files in os.walk(self.src_path):
            arc_prefix = os.path.relpath(root, os.path.dirname(self.src_path))
            files = self.filter_files(files)
            for f in files:
                self._zip_file.write(
                    os.path.join(root, f),
                    os.path.join(arc_prefix, f))
            
        # Library Source
        venv_lib_path = os.path.join(
            self.virtualenv_dir, 'lib', 'python2.7', 'site-packages')
                    
        for root, dirs, files in os.walk(venv_lib_path):
            arc_prefix = os.path.relpath(root, venv_lib_path)
            files = self.filter_files(files)
            for f in files:
                self._zip_file.write(
                    os.path.join(root, f),
                    os.path.join(arc_prefix, f))

    def add_contents(self, dest, contents):
        assert not self._closed, "Archive closed"
        self._zip_file.writestr(dest, contents)

    def close(self):
        self._closed = True
        self._zip_file.close()
        log.debug("Created maid lambda archive size: %0.2fmb",
                  (os.path.getsize(self._temp_archive_file.name) / (1024.0 * 1024.0)))
        return self

    def remove(self):
        if self._temp_archive_file:
            self._temp_archive_file = None
            
    def get_bytes(self):
        assert self._closed, "Archive not closed"
        return open(self._temp_archive_file.name, 'rb').read()
    
        
class LambdaManager(object):

    def __init__(self, session_factory):
        self.session_factory = session_factory
        self.client = self.session_factory().client('lambda')
        
    def publish(self, func, alias=None):
        log.debug('Publishing maid lambda function %s', func.name)
        with func as archive:
            result = self._create_or_update(func, archive)
            func.alias = self.publish_alias(result, alias)

        for e in func.get_events(self.session_factory):
            log.debug("Adding function: %s event source: %s",
                      func.alias, e)
            e.add(func)

    def _create_or_update(self, func, archive):
        if self.exists(func.name):
            log.debug("updating function %s", func.name)
            result = self.client.update_function_code(
                FunctionName=func.name,
                ZipFile=archive.get_bytes(),
                Publish=True  # why would this ever be false
            )
        else:
            result = self.client.create_function(
                FunctionName=func.name,
                Code={'ZipFile': archive.get_bytes()},
                Runtime=func.runtime,
                Role=func.role,
                Handler=func.handler,
                Description=func.description,
                Timeout=func.timeout,
                MemorySize=func.memory_size
            )
        return result
            
    def publish_alias(self, func_data, alias):
        if not alias:
            return func_data['FunctionArn']
        func_name = func_data['FunctionName']
        func_version = func_data['Version']
        log.debug("Publishing maid lambda alias %s", alias)

        exists = resource_exists(
            self.client.get_alias, FunctionName=func_name, Name=alias)

        if not exists:
            alias_result = self.client.create_alias(
                FunctionName=func_name,
                Name=alias,
                FunctionVersion=func_version)
        else:
            alias_result = self.client.update_alias(
                FunctionName=func_name,
                Name=alias,
                FunctionVersion=func_version)
        return alias_result['AliasArn']
                        
    def exists(self, func_name):
        return resource_exists(
            self.client.get_function, FunctionName=func_name)

    
def resource_exists(op, *args, **kw):
    try:
        op(*args, **kw)
    except ClientError, e:
        if e.response['Error']['Code'] == "ResourceNotFoundException":
            return False
        raise
    return True
        
    
    
class LambdaFunction(object):
    # name
    # runtime
    # events

    alias = None
    
    def process(self, resources):
        pass

    def generate_lambda(self):
        raise NotImplementedError("generate_lambda()")


class PythonFunction(LambdaFunction):

    runtime = "python2.7"


PolicyHandlerTemplate = """\
from janitor import mu

def handler(event, ctx):
    mu.%s_handler(event, ctx)
"""


def maid_archive(skip=None):
    return PythonPackageArchive(
        os.path.dirname(inspect.getabsfile(janitor)),
        os.path.abspath(os.path.join(
            os.path.dirname(sys.executable), '..')),
        skip=skip)
    

class PolicyLambda(PythonFunction):

    handler = "policy:handler"
    timeout = 60
    
    def __init__(self, policy):
        self.policy = policy
        self.archive = maid_archive('*pyc')

    @property
    def name(self):
        return "maid-%s" % self.policy.name

    @property
    def description(self):
        return self.policy.data.get(
            'description', 'cloud-maid lambda policy')

    @property
    def role(self):
        return self.policy.data['mode'].get(
            'role',
            'arn:aws:iam::873150696559:role/CapOne-CrossAccount-CustomRole-CloudMaid')
            
    @property
    def memory_size(self):
        return self.policy.data['mode'].get('memory', 512)

    def get_events(self, session_manager):
        events = []
        for e in self.policy.data['mode'].get('events', []):
            events.append(CloudWatchEventSource(e, self.session_factory))
        return events
            
    def __enter__(self):
        self.archive.create()
        self.archive.add_contents(
            'config.json', json.dumps({'policies': self.policy.data}))
        self.archive.add_contents(
            'handler.py', PolicyHandlerTemplate % (
                self.policy.data['mode']['type']))
        self.archive.close()
        return self.archive
    
    def __exit__(self, *args):
        self.archive.remove()
        return

    
class CloudWatchEventSource(object):
    """
    Modeled after kappa event source, such that it can be contributed
    post cloudwatch events ga or public beta.

    Event Pattern for Instance State

    { 
      "source": ["aws.ec2"],
      "detail-type": ["EC2 Instance State-change Notification"],
      "detail": { "state": ["pending"]}
    }

    Event Pattern for Cloud Trail API

    {
      "detail-type": ["AWS API Call via CloudTrail"],
      "detail": {
         "eventSource": ["s3.amazonaws.com"],
         "eventName": ["CreateBucket", "DeleteBucket"]
      }
    }
    """

    def __init__(self, data, session_factory):
        self.session_factory = session_factory
        self.client = self.session_factory.client('events')

    def _make_notification_id(self, function_name):
        return "maid-%s" % function_name

    def exists(self, function):
        try:
            self.client.describe_rule(
                Name=self._make_notification_id(function.name))
            return True
        except ClientError, e:
            if e['Error']['Code'] == "ResourceNotFoundException":
                return False
            raise

    def add(self, func):
        schedule = self.data.get('schedule')
        self.client.put_rule(
            Name=func.name,
            ScheduleExpression=schedule,
            EventPattern=json.dumps({}),
            State='ENABLED',
            RoleArn=self.func.role)

    def update(self, func):
        self.add(func)

    def remove(self, func):
        self.client.delete_rule(
            Name=func.name,
        )
    
