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
      - 
  
Event Sources
-------------

We need to distribute cloud-watch events api json atm.


Todo
----

Maid additionally can use lambda execution for resource intensive policy
actions, using dynamodb for results aggregation, and a periodic result checker.

"""
import inspect
from cStringIO import StringIO
import json
import logging
import os
import pprint
import tempfile
import sys
import shutil
import zipfile

from kappa.context import Context

import janitor

from janitor.action import BaseAction
from janitor import jobs
from janitor.policy import load


log = logging.getLogger('maid.lambda')


def resource_handle(resource_type, event, lambda_context):
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
    return resource_handle('s3', event, context)


def ec2_handle(event, context):
    return resource_handle('ec2', event, context)


def cwe_handle(event, context):
    raise NotImplementedError()
    return resource_handle()


class PythonPackageArchive(object):

    def __init__(self, src_path, virtualenv_dir):
        self.src_path = src_path
        self.virtualenv_dir = virtualenv_dir
        self._temp_archive_file = None
        self._zip_file = None

    @property
    def path(self):
        return self._temp_archive_file.name
    
    def create(self):
        self.temp_archive_file = tempfile.NamedTemporaryFile()
        self._zip_file = zipfile.ZipFile(
            self.temp_archive_file, mode='w',
            compression=zipfile.ZIP_DEFLATED)

        prefix = os.path.dirname(self.src_path)
        # Package Source
        for root, dirs, files in os.walk(self.src_path):
            arc_prefix = os.path.relpath(root, os.path.dirname(self.src_path))
            for f in files:
                self._zip_file.write(
                    os.path.join(root, f),
                    os.path.join(arc_prefix, f))

        # Library Source
        venv_lib_path = os.path.join(
            self.virtualenv_dir, 'lib', 'python2.7', 'site-packages')
                    
        for root, dirs, files in os.walk(venv_lib_path):
            arc_prefix = os.path.relpath(root, venv_lib_path)
            for f in files:
                self._zip_file.write(
                    os.path.join(root, f),
                    os.path.join(arc_prefix, f))

    def add_contents(self, dest, contents):
        self._zip_file.writestr(dest, contents)

    def close(self):
        self._zip_file.close()

    def get_bytes(self):
        return open(self._temp_archive_file, 'rb').read()
    
        
class LambdaManager(object):

    def __init__(self, session_factory):
        self.session_factory = session_factory
        self.client = self.session_factory().client('lambda')
        
    def publish(self, func, alias):
        with self.func as archive:
            self.client.create_function(
                FunctionName=func.name,
                Code={'ZipFile': archive.get_bytes()},
                Runtime=func.runtime,
                Role=func.role,
                Handler=func.handler,
                Description=func.description,
                Timeout=func.timeout,
                MemorySize=func.memory_size
            )

    def exists(self, func_name):
        try:
            result = self.client.get_function(
                FunctionName=func_name)
        except Exception:
            return False
        return result

    
class LambdaFunction:
    # name
    # runtime
    # events
    
    def process(self, resources):
        config = self.generate_lambda(resources)
        ctx = Context(**config)
        ctx.create()

    def generate_lambda(self):
        raise NotImplementedError("generate_lambda()")


class PythonFunction(LambdaFunction):

    runtime = "python2.7"


PolicyHandlerTemplate = """\
from janitor import mu

def handler(event, ctx):
    mu.%s_handler(event, ctx)
"""

class PolicyLambda(PythonFunction):

    handler = "policy:handler"
    timeout = 60
    
    def __init__(self, policy):
        self.policy = policy
        self.archive = PythonPackageArchive(
            os.path.dirname(inspect.getabsfile(janitor)),
            os.path.join(
                os.path.dirname(sys.executable), '..'))

    @property
    def name(self):
        return "maid-%s" % self.policy.name

    @property
    def description(self):
        return self.policy.data.get('description', 'cloud-maid lambda policy')
    
    @property
    def memory_size(self):
        return self.policy.data['mode'].get('memory', 512)

    def __enter__(self):

        self.archive.__enter__()
        self.archive.add_contents(
            'config.json', json.dumps({'policies': self.policy.data}))
        self.archive.add_contents(
            'handler.py', PolicyHandlerTemplate % (
                self.policy.data['mode']['type']))
            
    def __exit__(self, *args):
        self.archive.__exit__()
        return

    
class CloudWatchEventSource(object):
    """

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

    def __init__(self, session_factory, func):
        self.session_factory = session_factory
        self.client = self.session_factory('events')
        self.func = func

    def create(self):
        self.client.put_rule(
            Name=self.func.name,
            ScheduleExpression="",
            EventPattern=json.dumps({}),
            State='ENABLED',
            RoleArn=self.func.role)

    def update(self):
        pass

    def remove(self):
        pass
    
