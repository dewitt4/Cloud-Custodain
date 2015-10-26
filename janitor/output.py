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
import os

from boto3.s3.transfer import S3Transfer

log = logging.getLogger('maid.output.s3')


class S3OutputReader(object):

    def __init__(self, session_factory, s3_path):
        pass

    def read_last(self, policy_name, path):
        pass

    def read_last_log(self, policy_name):
        pass
    

def s3_path_join(*parts):
    return "/".join([s.strip('/') for s in parts])


class S3Output(object):
    """
    Usage::

    with S3Output(session_factory, 's3://bucket/prefix'):
        log.info('xyz')  # -> log messages sent to maid-run.log.gz
    """

    permissions = ()
    
    def __init__(self, session_factory, s3_path):
        if not s3_path.startswith('s3://'):
            raise ValueError("invalid s3 path")
        ridx = s3_path.find('/', 5)
        if ridx == -1:
            ridx = None
        self.bucket = s3_path[5:ridx]
        self.s3_path = s3_path.rstrip('/')
        if ridx is None:
            self.key_prefix = ""
        else:
            self.key_prefix = s3_path[s3_path.find('/', 5):]
        
        self.session_factory = session_factory
        self.root_dir = tempfile.mkdtemp()
        self.date_path = datetime.datetime.now().strftime('%Y-%m-%d-%H')
        self.transfer = None
        self.handler = None
    
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
                    


