"""
# Record Outputs

 Structured and Unstructured per action and resource

 - Python Execution Log
 - Policy Resource Records
 - Policy Action Records
 - CloudWatch Metrics

# S3 Bucket Location

 s3://cloud-maid-sts-digital-dev/

 policies
   - <policy-name>
     - <date>
         - <file.log.gz>
         - <file.json.gz>
         - maid

Actions have output / or even state 


Every policy gets a temp directory
   - maid-run.log.gz
   - 

"""

import datetime
import gzip
import logging
import shutil
import tempfile

import os

from boto3.s3.transfer import S3Transfer
from janitor.utils import local_session


log = logging.getLogger('maid.output')


class MetricsOutput(object):
    """Send metrics data to cloudwatch
    """

    permissions = ("cloudWatch:PutMetricData",)

    @staticmethod
    def select(metrics_enabled):
        if metrics_enabled:
            return MetricsOutput
        return NullMetricsOutput
    
    def __init__(self, ctx, namespace="CloudMaid"):
        self.ctx = ctx
        self.namespace = namespace
        self.buf = []

    def flush(self):
        if self.buf:
            self._put_metrics(self.namespace, self.buf)
            self.buf = []
    
    def put_metric(self, key, value, unit, buffer=False, **dimensions):
        d = {
            "MetricName": key,
            "Timestamp": datetime.datetime.now(),
            "Value": value,
            "Unit": unit}
        d["Dimensions"] = [
            {"Name": "Policy", "Value": self.ctx.policy.name},
            {"Name": "ResType", "Value": self.ctx.policy.resource_type}]
        for k, v in dimensions.items():
            d['Dimensions'].append({"Name": k, "Value": v})

        if buffer:
            self.buf.append(d)
            # Max metrics in a single request
            if len(self.buf) == 20:
                self.flush()
        else:
            self._put_metrics(self.namespace, [d])

    def _put_metrics(self, ns, metrics):
        watch = local_session(self.ctx.session_factory).client('cloudwatch')
        return watch.put_metric_data(Namespace=ns, MetricData=metrics)


class NullMetricsOutput(MetricsOutput):

    permissions = ()

    def __init__(self, ctx, namespace="CloudMaid"):
        super(NullMetricsOutput, self).__init__(ctx, namespace)
        self.data = []
    
    def _put_metrics(self, ns, metrics):
        self.data.append({'Namespace': ns, 'MetricData': metrics})
        for m in metrics:
            if m['MetricName'] not in ('ActionTime', 'ResourceTime'):
                log.debug(self.format_metric(m))

    def format_metric(self, m):
        l = "metric:%s %s:%s" % (m['MetricName'], m['Unit'], m['Value'])
        for d in m['Dimensions']:
            l += " %s:%s" % (d['Name'].lower(), d['Value'].lower())
        return l

    
class FSOutput(object):

    @staticmethod
    def select(path):
        if path.startswith('s3://'):
            return S3Output
        else:
            return DirectoryOutput
        
    def __init__(self, ctx):
        self.ctx = ctx
        self.root_dir = self.ctx.output_path or tempfile.mkdtemp()
        self.date_path = datetime.datetime.now().strftime('%Y-%m-%d-%H')
        self.handler = None        

    def __enter__(self):
        log.info("Storing output to %s" % self.root_dir)
        self.join_log()
        return self

    @staticmethod
    def join(*parts):
        return os.path.join(*parts)
    
    def __exit__(self, exc_type=None, exc_value=None, exc_traceback=None):
        self.leave_log()

    def join_log(self):
        self.handler = logging.FileHandler(
            os.path.join(self.root_dir, 'maid-run.log'))
        self.handler.setLevel(logging.DEBUG)
        self.handler.setFormatter(
            logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        mlog = logging.getLogger('maid')
        mlog.addHandler(self.handler)

    def leave_log(self):
        self.handler.flush()
        mlog = logging.getLogger('maid')
        mlog.removeHandler(self.handler)
        
    def compress(self):
        # Compress files individually so thats easy to walk them, without
        # downloading tar and extracting.
        for root, dirs, files in os.walk(self.root_dir):
            for f in files:
                fp = os.path.join(root, f)
                with gzip.open(fp + ".gz", "wb", compresslevel=7) as zfh:
                    with open(fp) as sfh:
                        shutil.copyfileobj(sfh, zfh, length=2**15)
                    os.remove(fp)

                    
class DirectoryOutput(FSOutput):

    permissions = ()

    def __init__(self, ctx):
        super(DirectoryOutput, self).__init__(ctx)
        if self.ctx.output_path is not None:
            if not os.path.exists(self.ctx.output_path):
                os.makedirs(self.ctx.output_path)

    
class S3Output(FSOutput):
    """
    Usage::

    with S3Output(session_factory, 's3://bucket/prefix'):
        log.info('xyz')  # -> log messages sent to maid-run.log.gz
    """

    permissions = ('S3:PutObject',)
    
    def __init__(self, ctx):
        super(S3Output, self).__init__(ctx)
        self.s3_path, self.bucket, self.key_prefix = self.parse_s3(
            self.ctx.output_path)
        self.root_dir = tempfile.mkdtemp()
        self.transfer = None

    @staticmethod
    def join(*parts):
        return "/".join([s.strip('/') for s in parts])
    
    @staticmethod
    def parse_s3(s3_path):
        if not s3_path.startswith('s3://'):
            raise ValueError("invalid s3 path")
        ridx = s3_path.find('/', 5)
        if ridx == -1:
            ridx = None
        bucket = s3_path[5:ridx]
        s3_path = s3_path.rstrip('/')
        if ridx is None:
            key_prefix = ""
        else:
            key_prefix = s3_path[s3_path.find('/', 5):]
        return s3_path, bucket, key_prefix
    
    def __exit__(self, exc_type=None, exc_value=None, exc_traceback=None):
        log.debug("Uploading policy logs")
        self.leave_log()
        self.compress()
        self.transfer = S3Transfer(self.ctx.session_factory().client('s3'))
        self.upload()
        shutil.rmtree(self.root_dir)
        log.debug("Policy Logs uploaded")

    def upload(self):
        for root, dirs, files in os.walk(self.root_dir):
            for f in files:
                key = "%s/%s%s" % (
                    self.key_prefix,
                    self.date_path,
                    "%s/%s" % (
                        root[len(self.root_dir):], f))
                key = key.strip('/')
                self.transfer.upload_file(
                    os.path.join(root, f), self.bucket, key,
                    extra_args={
                        'ServerSideEncryption': 'AES256'})
                    


