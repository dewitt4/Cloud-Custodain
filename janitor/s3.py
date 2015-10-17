"""
S3 Resource Manager

Scanning buckets is io and cpu bound.

List Buckets ->
  Per Bucket Process
    List Objects ->
      Per Key Thread (from pool)

"""
from concurrent.futures import (
    ProcessPoolExecutor,
    ThreadPoolExecutor,
    as_completed)
from botocore.exceptions import ClientError

import json
import itertools
import logging
import os
import time
import threading

from janitor.manager import ResourceManager
from janitor.rate import TokenBucket


log = logging.getLogger('maid.s3')


class S3(ResourceManager):

    def __init__(self, session_factory, data, config):
        super(S3, self).__init__(session_factory, data, config)
        self.rate_limit = {
            'key_process_rate': TokenBucket(2000),
            'list_objects': TokenBucket(12),
            'get_object': TokenBucket(50),
            'head_object': TokenBucket(50),
            'copy_object': TokenBucket(20),
        }

    def incr(self, m, v=1):
        return self.rate_limit[m].consume(v)

    def resources(self):
        c = self.session_factory().client('s3')

        log.debug('Retrieving buckets')
        response = c.list_buckets()
        buckets = response['Buckets']
        log.debug('Got %d buckets' % len(buckets))
        
        log.debug('Assembling bucket documents')
        with ThreadPoolExecutor(max_workers=15) as w:
            futures = [w.submit(
                assemble_bucket, self.session_factory, b) for b in buckets]
            for f in as_completed(futures):
                b = f.result()

        log.info("Processed")
        return buckets

    
def assemble_bucket(factory, b):
    """Assemble a document representing all the config state around a bucket.


    """
    # TODO make suffix addressing for bucket instead of host in us-east-1
    # running into a few issues with subdomain addressing and dots
    if '.' in b['Name']:
        log.warning("Skipping %s due to nested subdomain addressing" % b['Name'])
        return b

    s = factory()
    c = s.client('s3')

    methods = [
#        ('get_bucket_location', 'Location'),
        ('get_bucket_tagging', 'Tags'),
        ('get_bucket_acl', 'Acl'),
#        ('get_bucket_cors', 'Cors'),
        ('get_bucket_policy',  'Policy'),
#        ('get_bucket_versioning', 'Versioning'),
#        ('get_bucket_replication', 'Replication'),
#        ('get_bucket_lifecycle', 'Lifecycle'),
#        ('get_bucket_notification_configuration', 'Notification')
    ]
         
    for m, k in methods:
        try:
            method = getattr(c, m)
            v = method(Bucket=b['Name'])
            v.pop('ResponseMetadata')
        except ClientError, e:
            code =  e.response['Error']['Code']
            if code.startswith("NoSuch") or "NotFound" in code:
                v = None
            elif code == 'PermanentRedirect':
                log.error(e.response)
#                s = factory()
#                c = s.client(
#                    's3', region_name="us-east-1",
#                    endpoint_url="https://%s" % e.response['Error']['Endpoint'])
#                methods.append((m, k))
                continue
            else:
                log.error(e.response)
                v = None
        b[k] = v
    log.debug('Processed %s' % b['Name'])
    return b

## Filters


## Actions

class EncryptedPolicy(object):

    def __init__(self, data=None, manager=None):
        self.data = data or {}
        self.manager = manager
        
    def process(self, buckets):
        results = []
        with ThreadPoolExecutor(max_workers=3) as w:
            futures = [w.submit(
                self.process_bucket, b) for b in buckets]
            for f in as_completed(futures):
                results.append(f.result())
        return results

    def process_bucket(self, b):
        log.info("Attaching Encryption Policy bucket:%s" % b['Name'])
        p = b['Policy']
        if p is not None:
            statements = p['Statements']

        found = False
        for s in statements:
            if s['Sid'] == 'EncryptionPolicy':
                found = True
                log.info("Found extant Encryption Policy")
                return

        session = self.manager.session_factory()
        s3 = session.client('s3')
        
        statements.append(
            {'Sid': 'EncryptionPolicy',
             'Effect': 'Allow',
             'Action': 's3:PutObject',
             "Resource":"arn:aws:s3:::%s/*" % b['Name'],
             "Condition":{
                 "StringNotEquals":{
                     "s3:x-amz-server-side-encryption":"AES256"
                 }
             }})
        log.debug('policy \n %s\n\n' % json.dumps(statements))
#        s3.put_bucket_policy(
#            Bucket=b['Name'],
#            Policy=json.dumps(p))

        
class BucketLog(object):

    def __init__(self, log_dir, name):
        self.log_dir = log_dir
        self.name = name
        self.fh = None
        self.count = 0

    def __enter__(self):
        self.fh = open(os.path.join(self.log_dir, "%s.json" % self.name), 'w')
        self.fh.write("[\n")
        return self
    
    def __exit__(self, exc_type=None, exc_value=None, exc_frame=None):
        self.fh.write("\n]")
        self.fh.close()
        if not self.count:
            os.remove(self.fh.name)
        self.fh = None
        return False
        
    def log(self, keys):
        self.count += len(keys)
        for v in map(json.dumps, keys):
            self.fh.write(v)



class ScanBucket(object):

    def __init__(self, data=None, manager=None, log_dir=None):
        self.data = data or {}
        self.manager = manager
        self.log_dir = log_dir
    
    def process(self, buckets):
        results = []
#        with MainThreadExecutor(max_workers=3) as w:        
        with ThreadPoolExecutor(max_workers=3) as w:
            results.extend(
                f for f in w.map(self.process_bucket, buckets))
#            futures = [w.submit(
#                self.process_bucket, b) for b in buckets]
#            for f in as_completed(futures):
#                results.append(f.result())

        return results

    def process_bucket(self, b):
        log.info(
            "Scanning bucket:%s visitor:%s" % (
                b['Name'], self.__class__.__name__))
        s = self.manager.session_factory()
        s3 = s.client('s3')
        p = s3.get_paginator('list_objects').paginate(Bucket=b['Name'])
        with BucketLog(self.log_dir, b['Name']) as key_log:
#            with MainThreadExecutor(max_workers=10) as w:
            with ThreadPoolExecutor(max_workers=10) as w:
                return self._process_bucket(b, p, key_log, w)
                
    def _process_bucket(self, b, p, key_log, w):
        count = 0
        results = []
        for key_set in p:
            count += len(key_set['Contents'])
            log.info("Scan Progress bucket:%s %d%s" % (
                b['Name'], count,
                key_set['IsTruncated'] and '...' or ' Complete'
            ))
            for batch in chunks(key_set):
                now = time.time()
                slow = self.manager.incr('key_process_rate', len(batch))
                if slow:
                    log.info(
                        "Rate Limit BackOff:object_rate Bucket:%s delay:%s" % (
                            b['Name'], slow))
                    time.sleep(slow)
                futures = w.map(self.process_key,
                                zip(key_set['Contents'], itertools.repeat(b['Name'])))
                key_log.log([f for f in futures if f])
        result = {'Bucket': b['Name'], 'Contents': key_log.count}
        return result

    def process_key(self, params):
        return None


class MainThreadExecutor(object):

    def __init__(self, *args, **kw):
        self.args = args
        self.kw = kw

    def map(self, func, iterable):
        for args in iterable:
            yield func(args)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    
class EncryptExtantKeys(ScanBucket):

    def process_key(self, params):
        key, bucket = params
        k = key['Key']
        s3 = local_session(self.manager.session_factory).client('s3')
        data = s3.head_object(Bucket=b, Key=k)

        if 'ServerSideEncryption' in data:
            return None

        # Aborted attempt to put back acls            
        # acl = s3.get_object_acl(Bucket=b, Key=k)
        # log.debug("Remediating object %s" % k)

        s3.copy_object(
            Bucket=b, Key=k,
            CopySource="/%s/%s" % (b, k),
            MetadataDirective='COPY',
            ServerSideEncryption="AES256")

        # Aborted attempt to put back acls            
        # acl = s3.get_object_acl(Bucket=b, Key=k)
        # log.debug("Remediating object %s" % k)
        return k

    

def chunks(iterable, size=50):
    iterable = iter(iterable)
    while True:
        yield [next(iterable) for n in range(size)]

        
CONN_CACHE = threading.local()


def local_session(factory):
    s = getattr(CONN_CACHE, 'session', None)
    t = getattr(CONN_CACHE, 'time', 0)
    n = time.time()
    if s is not None and t + 3600 > n:
        return s
    s = factory()
    CONN_CACHE.session = s
    CONN_CACHE.time = n
    return s

    
def main():
    import boto3
    import time
    import logging

    
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s: %(name)s:%(levelname)s %(message)s")
    logging.getLogger('botocore').setLevel(level=logging.ERROR)
    
    s = S3(lambda x=None: boto3.Session(), None, None)
    t = time.time()

    #log.debug("Starting resource collection")
    #buckets = s.resources()
    #log.debug("Fetched %d in %s" % (len(buckets), time.time()-t))
    #bucket_map = dict([(b['Name'], b) for b in buckets])

    scanner = EncryptExtantKeys({}, s, 'logs')
    results = scanner.process([{"Name": 'dms2-qa-st-waf'}])

    import pprint
    pprint.pprint(results)
    
if __name__ == '__main__':
    try:
        main()
    except:
        raise
        import pdb, traceback, sys
        traceback.print_exc()
        pdb.post_mortem(sys.exc_info()[-1])
