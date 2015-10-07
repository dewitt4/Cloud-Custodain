from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError

import itertools
import logging
import time
import threading

from janitor.manager import ResourceManager
from janitor.rate import TokenBucket


log = logging.getLogger('maid.s3')


class S3(ResourceManager):

    def __init__(self, session_factory, data, config):
        super(S3, self).__init__(session_factory, data, config)
        self.rate_limit = {
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
    

class ScanBucket(object):

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
        log.info(
            "Scanning bucket:%s object check" % b['Name'])
        s = self.manager.session_factory()
        s3 = s.client('s3')
        m = 'list_objects'
        p = s3.get_paginator(m).paginate(Bucket=b['Name'])

        results = []
        with ThreadPoolExecutor(max_workers=10) as w:
            count = 0
            for key_set in p:
                count += len(key_set['Contents'])
                now = time.time()

                slow = self.manager.incr(m, 1)
                log.info("Scan Progress bucket:%s %d%s" % (
                    b['Name'], count, key_set['IsTruncated'] and '...' or ''
                ))
                futures = w.map(self.process_key,
                                zip(key_set['Contents'], itertools.repeat(b['Name'])))
                results.extend([f for f in futures if f])
                if slow:
                    elapsed = time.time() - now
                    slow -= elapsed
                    if slow > 0:
                        log.info(
                            "Rate Limit BackOff:list_objects Bucket:%s delay:%s" % (
                                b['Name'], slow))
                    time.sleep(slow)
        return {'Bucket': b['Name'], 'Contents': results}

    def process_key(self, item):
        obj, b = item
        s = local_session(self.manager.session_factory)
        s3 = s.client('s3')
        k = obj['Key']
        slow = self.manager.incr('head_object')
        
        if slow:
            log.debug("Rate Limit Backoff:head_object Bucket:%s delay:%s" % (
                b, slow))
            time.sleep(slow)
        data = s3.head_object(Bucket=b, Key=k)

        if 'ServerSideEncryption' in data:
            return None

        slow = self.manager.incr('copy_object')
        if slow:
            log.debug("Rate Limit Backoff:copy_object Bucket:%s delay:%s" % (
                b, slow))
            time.sleep(slow)

# Aborted attempt to put back acls            
#        acl = s3.get_object_acl(Bucket=b, Key=k)
        log.debug("Remediating object %s" % k)

        s3.copy_object(
            Bucket=b, Key=k,
            CopySource="/%s/%s" % (b, k),
            MetadataDirective='COPY',
            ServerSideEncryption="AES256")

# Aborted attempt to put back acls
#        if len(acl['Grants']) > 1:
#            grants = acl['Grants']
#            for g in grants:
#                g['Grantee']['Type'] = 'CanonicalUser'
#            s3.put_object_acl(
#                Bucket=b, Key=k,
#                AccessControlPolicy={
#                    'Grants': grants,
#                    })
        return obj


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

    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger('botocore').setLevel(level=logging.ERROR)
    
    s = S3(lambda x=None: boto3.Session(), None, None)
    t = time.time()

    #log.debug("Starting resource collection")
    #buckets = s.resources()
    #log.debug("Fetched %d in %s" % (len(buckets), time.time()-t))
    #bucket_map = dict([(b['Name'], b) for b in buckets])

    scanner = ScanBucket({}, s)
    results = scanner.process(s.resources())

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
