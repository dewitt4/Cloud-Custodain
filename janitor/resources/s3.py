"""
S3 Resource Manager

Actions:

 encrypt-prefix  

   Useful for aws log storage, basically encrypt the prefix key
   like 'AWSLogs' and that will inherit any keys with that prefix.

 encrypt-keys

   Scan all keys in a bucket and optionally encrypt them in place.

 global-grants

   Check bucket acls for global grants
  
 encryption-policy

   Attach an encryption required policy to a bucket, this will break
   applications that are not using encryption, including aws log
   delivery.

# Todo ? / Not Implemented
Filters
  path-exists
  
Query
  name

"""

from botocore.client import Config
from botocore.exceptions import ClientError

import json
import itertools
import logging
import os
import time

from janitor import executor
from janitor.actions import ActionRegistry, BaseAction
from janitor.filters import (
    FilterRegistry, Filter, FilterValidationError)

from janitor.manager import ResourceManager, resources
from janitor.rate import TokenBucket
from janitor.utils import chunks, local_session


log = logging.getLogger('maid.s3')

filters = FilterRegistry('s3.filters')
actions = ActionRegistry('s3.actions')


@resources.register('s3')
class S3(ResourceManager):

    executor_factory = executor.ThreadPoolExecutor

    def __init__(self, session_factory, data, config, log_dir):
        super(S3, self).__init__(
            session_factory, data, config, log_dir)
        self.log_dir = log_dir
        self.rate_limit = {
            'key_process_rate': TokenBucket(2000),
        }
        self.filters = filters.parse(
            self.data.get('filters', []))
        self.actions = actions.parse(
            self.data.get('actions', []), self)
        
    def incr(self, m, v=1):
        return self.rate_limit[m].consume(v)

    def format_json(self, resources):
        return [r['Name'] for r in resources]
        
    def resources(self, matches=('preview-config-rules',)):
        c = self.session_factory().client('s3')
        log.debug('Retrieving buckets')
        response = c.list_buckets()
        buckets = response['Buckets']
        log.debug('Got %d buckets' % len(buckets))

        if matches:
            buckets = filter(lambda x: x['Name'] in matches, buckets)
            log.debug("Filtered to %d buckets" % len(buckets))

        log.debug('Assembling bucket documents')
        with self.executor_factory(max_workers=10) as w:
            results = w.map(assemble_bucket, zip(itertools.repeat(self.session_factory), buckets))
            results = filter(None, results)

        for f in self.filters:
            results = filter(f, results)

        log.debug("Filtered to %d buckets" % len(results))
        return results

    
def assemble_bucket(item):
    """Assemble a document representing all the config state around a bucket.
    """
    factory, b = item

    s = factory()
    c = s.client('s3')

    methods = [
        ('get_bucket_location', 'Location'),
        ('get_bucket_tagging', 'Tags'),
        ('get_bucket_policy',  'Policy'),        
        ('get_bucket_acl', 'Acl'),
        ('get_bucket_replication', 'Replication'),        
#        ('get_bucket_cors', 'Cors'),        
#        ('get_bucket_versioning', 'Versioning'),
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
                #log.warning(e.response)
                s = factory()
                c = bucket_client(s, b)
                # Requeue with the correct region given location constraint
                methods.append((m, k))
                continue
            else:
                log.error("Bucket:%s unable to invoke method:%s error:%s " % (
                    b['Name'], m, e.response['Error']['Message']))
                #buf = StringIO.StringIO()
                #pprint.pprint(b, buf)                
                #if e.response['Error']['Code'] != 'AccessDenied':
                #    log.error("Error: %s" % buf.getvalue())

                #v = None
                return None
        b[k] = v
    return b


def bucket_client(s, b):
    location = b.get('Location')
    if location is None:
        region = 'us-east-1'
    else:
        region = location['LocationConstraint'] or 'us-east-1'
    return s.client(
        's3', region_name=region,
        # Need v4 for aws:kms crypto
        config=Config(signature_version='s3v4'))


class BucketActionBase(BaseAction):

    executor_factory = executor.MainThreadExecutor

    def get_permissions(self):
        return self.permissions


@actions.register('encrypted-prefix')
class EncryptedPrefix(BucketActionBase):

    permissions = ("s3:GetObject", "s3:PutObject")
    
    def process(self, buckets):
        prefix = self.data.get('prefix')
        with self.executor_factory(max_workers=5) as w:
            results = w.map(self.process_bucket, buckets)
            results = filter(None, list(results))
            return results

    def process_bucket(self, b):
        s3 = bucket_client(self.manager.session_factory(), b)
        k = self.data.get('prefix', 'AWSLogs')

        create = True
        try:
            data = s3.head_object(Bucket=b['Name'], Key=k)
            create = False
            if 'ServerSideEncryption' in data:
                return None
        except ClientError, e:
            if e.response['Error']['Code'] != '404':
                raise

        crypto_method = self.data.get('crypto', 'AES256')
        if create:
            content = "Path Prefix Object For Sub Path Encryption"
            s3.put_object(
                Bucket=b['Name'],
                Key=k,
                ACL="bucket-owner-full-control",
                Body=content,
                ServerSideEncryption=crypto_method)
            return {'Bucket': b['Name'], 'Prefix': k, 'State': 'Created'}

        # Note on copy we lose individual key acl grants        
        s3.copy_object(
            Bucket=b['Name'], Key=k,
            CopySource="/%s/%s" % (b, k),
            MetadataDirective='COPY',
            ServerSideEncryption=crypto_method)
        return {'Bucket': b['Name'], 'Prefix': k, 'State': 'Updated'}
        
            
@actions.register('global-grants')        
class NoGlobalGrants(BucketActionBase):

    permissions = ("s3:GetBucketACL", "s3:SetBucketACL")
    
    GLOBAL_ALL = "http://acs.amazonaws.com/groups/global/AllUsers"
    AUTH_ALL = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
    
    def process(self, buckets):
        with self.executor_factory(max_workers=5) as w:
            results = w.map(self.process_bucket, buckets)
            results = filter(None, list(results))
            return results

    def process_bucket(self, b):
        acl = b.get('Acl', {'Grants': []})

        results = []
        for grant in acl['Grants']:
            if not 'URI' in grant.get("Grantee", {}):
                continue
            if grant['Grantee']['URI'] in [self.AUTH_ALL, self.GLOBAL_ALL]:
                results.append(grant['Permission'])

        c = bucket_client(self.manager.session_factory(), b)
        remediate = True

        # Handle valid case of website
        if results == ['READ']:
            website = c.get_bucket_website(Bucket=b['Name'])
            website.pop('ResponseMetadata')
            if website:
                remediate = False
        elif not results:
            return None
        
        if results and remediate:
            # TODO / For now reporting is okay
            pass
        return {'Bucket': b['Name'], 'GlobalPermissions': results, 'Website': not remediate}


@actions.register('encryption-policy')    
class EncryptionRequiredPolicy(BucketActionBase):

    permissions = ("s3:GetBucketPolicy", "s3:PutBucketPolicy")
                           
    def __init__(self, data=None, manager=None):
        self.data = data or {}
        self.manager = manager
        
    def process(self, buckets):
        with self.executor_factory(max_workers=3) as w:
            results = w.map(self.process_bucket, buckets)
            results = filter(None, list(results))
            return results

    def process_bucket(self, b):
        p = b['Policy']
        if p is None:
            log.info("No policy found, creating new")
            p = {'Version': "2012-10-17", "Statements": []}
        else:
            p = json.loads(p['Policy'])
            
        statements = p.get('Statement', [])
        found = False
        for s in list(statements):
            if s['Sid'] == 'RequireEncryptedPutObject':
                log.debug(
                    "Bucket:%s Found extant Encryption Policy" % b['Name'])
                return
            # Migration from manual in digital-dev
            #if s['Sid'] == 'DenyUnEncryptedObjectUploads':
            #    found = True
            #    statements.remove(s)
        
        session = self.manager.session_factory()
        s3 = bucket_client(session, b)

        statements.append(
            {'Sid': 'RequireEncryptedPutObject',
             'Effect': 'Deny',
             'Principal': '*',
             'Action': 's3:PutObject',
             "Resource":"arn:aws:s3:::%s/*" % b['Name'],
             "Condition":{
                 # AWS Managed Keys or KMS keys, note policy language
                 # does not support customer supplied keys.
                 "StringNotEquals":{
                     "s3:x-amz-server-side-encryption": ["AES256", "aws:kms"]}}
             })
        p['Statement'] = statements
        log.info('Bucket:%s attached encryption policy' % b['Name'])

        s3.put_bucket_policy(
            Bucket=b['Name'],
            Policy=json.dumps(p))
        return {'Name': b['Name'], 'State': 'PolicyAttached'}

        
class BucketScanLog(object):
    """Offload remediated key ids to a disk file in batches
    
    A bucket keyspace is effectively infinite, we need to store partial
    results out of memory, this class provides for a json log on disk
    with partial write support.
    """
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
        
    def add(self, keys):
        self.count += len(keys)
        for v in map(json.dumps, keys):
            self.fh.write(v)
            self.fh.write(",")            


class ScanBucket(BucketActionBase):

    permissions = ("s3:ListBucket",)
    
    def process(self, buckets):
        results = []
        with self.executor_factory(max_workers=3) as w:
            results.extend(
                f for f in w.map(self, buckets) if f)
        return results

    def process_bucket(self, b):
        log.info(
            "Scanning bucket:%s visitor:%s" % (
                b['Name'], self.__class__.__name__))
        s = self.manager.session_factory()
        s3 = bucket_client(s, b)

        # The bulk of _process_bucket function executes inline in
        # calling thread/worker context, neither paginator nor
        # bucketscan log should be used across worker boundary.
        p = s3.get_paginator('list_objects').paginate(Bucket=b['Name'])
        with self.executor_factory(max_workers=10) as w:
            try:
                with BucketScanLog(self.manager.log_dir, b['Name']) as key_log:
                    return self._process_bucket(b, p, key_log, w)
            except ClientError, e:
                log.exception("Error processing bucket:%s paginator:%s" % (
                    b['Name'], p)
                )
                return None

    __call__ = process_bucket
    
    def _process_bucket(self, b, p, key_log, w):
        count = 0
        results = []
        for key_set in p:
            count += len(key_set.get('Contents', []))
            # Empty bucket check
            if not 'Contents' in key_set:
                return {'Bucket': b['Name'],
                        'Remediated': key_log.count,
                        'Count': count}
            for batch in chunks(key_set['Contents']):
                now = time.time()
                slow = self.manager.incr('key_process_rate', len(batch))
                if slow:
                    log.info(
                        "Rate Limit BackOff:object_rate Bucket:%s delay:%s" % (
                            b['Name'], slow))
                    time.sleep(slow)
                futures = w.map(
                    self.process_key,
                    zip(key_set['Contents'], itertools.repeat(b)))
                key_log.add([f for f in futures if f])
        result = {'Bucket': b['Name'], 'Remediated': key_log.count, 'Count': count}

        # Log completion at info level, progress at debug level
        ellipis = key_set['IsTruncated'] and '...' or ' Complete'
        log_method = ellipis == ' Complete' and 'info' or 'debug'
        getattr(log, log_method)(
            "Scan Progress bucket:%s keys:%d remediated:%d %s" % (
                b['Name'], count, key_log.count, ellipis))
        return result

    def process_key(self, params):
        return None


@actions.register('encrypt-keys')    
class EncryptExtantKeys(ScanBucket):

    permissions = ("s3:PutObject", "s3:GetObject",) + ScanBucket.permissions
    customer_keys = None
    
    def process_key(self, params):
        key, bucket = params
        k = key['Key']
        b = bucket['Name']
        s3 = bucket_client(
            local_session(self.manager.session_factory), bucket)

        data = s3.head_object(Bucket=b, Key=k)

        if 'ServerSideEncryption' in data:
            return None

        if self.data.get('report-only'):
            return k

        crypto_method = self.data.get('crypto', 'AES256')
        # Not on copy we lose individual key acl grants        
        s3.copy_object(
            Bucket=b, Key=k,
            CopySource="/%s/%s" % (b, k),
            MetadataDirective='COPY',
            ServerSideEncryption=crypto_method)
        return k
