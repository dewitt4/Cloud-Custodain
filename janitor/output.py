"""
# Record Outputs

 Structured and Unstructured per action and resource

 - Python Execution Log
 - Policy Resource Records
 - Policy Action Records
 - CloudWatch Metrics ??

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
import time
import os

from boto3.s3.transfer import S3Transfer
from janitor.utils import local_session


log = logging.getLogger('maid.output.s3')


class S3OutputReader(object):

    def __init__(self, session_factory, s3_path):
        pass

    def read_last(self, policy_name, path):
        pass

    def read_last_log(self, policy_name):
        pass
    

class ExecutionContext(object):

    def __init__(self, session_factory, policy_name, s3_path):
        self.policy_name = policy_name
        self.s3_path = s3_path
        self.session_factory = session_factory
        self.metrics = MetricsOutput(self.session_factory, self.policy_name)
        self.output = S3Output(self.session_factory)
        self.start_time = None

    @property
    def log_dir(self):
        return self.output.root_dir    

    def __enter__(self):
        self.output.__enter__()
        self.start_time = time.time()
        return self

    def __exit__(self, exc_type=None, exc_value=None, exc_traceback=None):
        self.output.__exit__()
        self.metrics.put_metric('ExecutionTime', time.time()-self.start_time)



class MetricsOutput(object):
    """
    Usage:
      Metrics output
    """
    def __init__(self, session_factory, prefix, namespace="CloudMaid"):
        self.session_factory = session_factory
        self.namespace = namespace
        self.prefix = prefix

    def metric(self, key, value, units=None, value_type=None):
        watch = local_session(self.session_factory).client('cloudwatch')
        d = {
            "MetricName": "%s.%s" % (self.prefix, key),
            "Timestamp": datetime.datetime.now(),
            "Value": self,
            "Unit": units}
        if units:
            d['Unit'] = units
        if value_type:
            d["StatisticValues"] = {value_type: value}
        else:
            d["Dimensions"] = [{"Name": key, "Value": value}]
        return watch.put_metric(
            Namespace=self.namespace,
            MetricData=d)


def select(path):
    import pdb; pdb.set_trace()
    if path.startswith('s3://'):
        return S3Output
    else:
        return DirectoryOutput
    
    
class DirectoryOutput(object):

    permissions = ()

    def __init__(self, session_factory, path=None):
        self.session_factory = session_factory
        if path is not None:
            if not os.path.exists(path):
                os.makedirs(path)
        self.root_dir = path or tempfile.mkdtemp()
        self.date_path = datetime.datetime.now().strftime('%Y-%m-%d-%H')
        self.handler = None        
        
    def __enter__(self):
        log.info("Storing output to %s" % self.root_dir)
        self.join_log()
        return self

    @staticmethod
    def join(self, *parts):
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

    
class S3Output(DirectoryOutput):
    """
    Usage::

    with S3Output(session_factory, 's3://bucket/prefix'):
        log.info('xyz')  # -> log messages sent to maid-run.log.gz
    """

    permissions = ('S3:PutObject',)
    
    def __init__(self, session_factory, s3_path):
        super(S3Output, self).__init__(session_factory)
        self.s3_path, self.bucket, self.key_prefix = self.parse_s3(s3_path)
        self.transfer = None

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
    
    def __enter__(self):
        self.join_log()
        return self
    
    def __exit__(self, exc_type=None, exc_value=None, exc_traceback=None):
        log.debug("Uploading policy logs")
        self.leave_log()
        self.compress()
        self.transfer = S3Transfer(self.session_factory().client('s3'))
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
                    


