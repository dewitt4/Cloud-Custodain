"""S3 Resource Manager

The generic Values filters (jmespath) expression and Or filter are
available with S3 Buckets, we include several additonal bucket data
(Tags, Replication, Acl, Policy) as keys within a bucket
representation.

Actions:

 encrypt-keys

   Scan all keys in a bucket and optionally encrypt them in place.

 global-grants

   Check bucket acls for global grants
  
 encryption-policy

   Attach an encryption required policy to a bucket, this will break
   applications that are not using encryption, including aws log
   delivery.

"""

from botocore.client import Config
from botocore.exceptions import ClientError
from concurrent.futures import as_completed

import gc
import json
import itertools
import logging
import os
import time

from janitor import executor
from janitor.actions import ActionRegistry, BaseAction
from janitor.filters import (
    FilterRegistry, Filter)

from janitor.manager import ResourceManager, resources
from janitor.rate import TokenBucket
from janitor.utils import chunks, local_session, dumps, set_annotation


log = logging.getLogger('maid.s3')

filters = FilterRegistry('s3.filters')
actions = ActionRegistry('s3.actions')


@resources.register('s3')
class S3(ResourceManager):

    executor_factory = executor.ThreadPoolExecutor

    def __init__(self, ctx, data):
        super(S3, self).__init__(ctx, data)
        self.log_dir = ctx.log_dir
        self.rate_limit = {
            'key_process_rate': TokenBucket(2000),
        }
        self.filters = filters.parse(
            self.data.get('filters', []), self)
        self.actions = actions.parse(
            self.data.get('actions', []), self)
        
    def incr(self, m, v=1):
        return self.rate_limit[m].consume(v)
        
    def resources(self, matches=()):
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
            results = f.process(results)

        log.debug("Filtered to %d buckets" % len(results))
        return results

    
def assemble_bucket(item):
    """Assemble a document representing all the config state around a bucket.
    """
    factory, b = item

    s = factory()
    c = s.client('s3')

    methods = [
        ('get_bucket_location', 'Location', None, None),
        ('get_bucket_tagging', 'Tags', [], 'TagSet'),
        ('get_bucket_policy',  'Policy', None, None),   
        ('get_bucket_acl', 'Acl', None, None),
        ('get_bucket_replication', 'Replication', None, None),
#        ('get_bucket_cors', 'Cors'),        
#        ('get_bucket_versioning', 'Versioning'),
#        ('get_bucket_lifecycle', 'Lifecycle'),
#        ('get_bucket_notification_configuration', 'Notification')
    ]

    b_location = c_location = location = "us-east-1"
    
    for m, k, default, select in methods:
        try:
            method = getattr(c, m)
            v = method(Bucket=b['Name'])
            v.pop('ResponseMetadata')
            if select is not None:
                v = v[select]
        except ClientError, e:
            code =  e.response['Error']['Code']
            if code.startswith("NoSuch") or "NotFound" in code:
                v = default
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
                return None
        # As soon as we learn location (which generally works)
        if k == 'Location':
            b_location = v.get('LocationConstraint')
            if v and v != c_location:
                c = s.client('s3', region_name=b_location)
            elif c_location != location:
                c = s.client('s3', region_name=location)
        b[k] = v
    return b


def bucket_client(s, b, kms=False):
    location = b.get('Location')
    if location is None:
        region = 'us-east-1'
    else:
        region = location['LocationConstraint'] or 'us-east-1'
    if kms:
        config = Config(signature_version='s3v4')
    else:
        config = None
    return s.client(
        's3', region_name=region,
        # Need v4 for aws:kms crypto
        config=config)


@filters.register('global-grants')        
class NoGlobalGrants(Filter):

    GLOBAL_ALL = "http://acs.amazonaws.com/groups/global/AllUsers"
    AUTH_ALL = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
    
    def process(self, buckets):
        with self.executor_factory(max_workers=5) as w:
            results = w.map(self.process_bucket, buckets)
            results = filter(None, list(results))
            return results

    def process_bucket(self, b):
        acl = b.get('Acl', {'Grants': []})
        if not acl or not acl['Grants']:
            return
        results = []
        for grant in acl['Grants']:
            if not 'URI' in grant.get("Grantee", {}):
                continue
            if grant['Grantee']['URI'] in [self.AUTH_ALL, self.GLOBAL_ALL]:
                results.append(grant['Permission'])

        c = bucket_client(self.manager.session_factory(), b)

        if results:
            set_annotation(b, 'GlobalPermissions', results)
            return b


class BucketActionBase(BaseAction):

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
                 # does not support custom kms (todo add issue)
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

    json output format:
     - [list_of_serialized_keys],
     - [] # Empty list of keys at end when we close the buffer
    
    """
    def __init__(self, log_dir, name):
        self.log_dir = log_dir
        self.name = name
        self.fh = None
        self.count = 0

    @property
    def path(self):
        return os.path.join(self.log_dir, "%s.json" % self.name)
    
    def __enter__(self):
        self.fh = open(self.path, 'w')
        self.fh.write("[\n")
        return self
    
    def __exit__(self, exc_type=None, exc_value=None, exc_frame=None):
        # we need an empty marker list at end to avoid trailing commas
        self.fh.write("[]")
        # and close the surrounding list
        self.fh.write("\n]")
        self.fh.close()
        if not self.count:
            os.remove(self.fh.name)
        self.fh = None
        return False
        
    def add(self, keys):
        self.count += len(keys)
        self.fh.write(json.dumps(keys))
        self.fh.write(",\n")


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
        with BucketScanLog(self.manager.log_dir, b['Name']) as key_log:
            with self.executor_factory(max_workers=10) as w:
                try:
                    return self._process_bucket(b, p, key_log, w)
                except ClientError, e:
                    log.exception(
                        "Error processing bucket:%s paginator:%s" % (
                            b['Name'], p))
                return None

    __call__ = process_bucket
    
    def _process_bucket(self, b, p, key_log, w):
        count = 0
        loop_count = 0
        
        for key_set in p:
            # Empty bucket check
            if not 'Contents' in key_set:
                return {'Bucket': b['Name'],
                        'Remediated': key_log.count,
                        'Count': count}
            futures = []
            for batch in chunks(key_set['Contents'], size=100):
                futures.append(w.submit(self.process_chunk, batch, b))

            for f in as_completed(futures):
                if f.exception():
                    log.exception("Exception Processing bucket:%s key batch %s" % (
                        b['Name'], f.exception()))
                    continue
                r = f.result()
                if r:
                    key_log.add(r)

            count += len(key_set.get('Contents', []))

            # On pypy we need more explicit memory collection to avoid pressure
            # and excess open files/sockets. every thousand objects
            loop_count += 1
            if loop_count % 1000 == 0:
                gc.collect()

            # Log completion at info level, progress at debug level
            if key_set['IsTruncated']:
                log.debug('Scan progress bucket:%s keys:%d remediated:%d ...',
                         b['Name'], count, key_log.count)
            else:
                log.info('Scan Complete bucket:%s keys:%d remediated:%d',
                         b['Name'], count, key_log.count)

        return {'Bucket': b['Name'], 'Remediated': key_log.count, 'Count': count}

    def process_chunk(self, batch, bucket):
        return None
    

@actions.register('encrypt-keys')    
class EncryptExtantKeys(ScanBucket):

    permissions = ("s3:PutObject", "s3:GetObject",) + ScanBucket.permissions
    customer_keys = None

    def process(self, buckets):
        t = time.time()
        results = super(EncryptExtantKeys, self).process(buckets)
        run_time = time.time() - t
        remediated_count = object_count = 0
        for r in results:
            object_count += r['Count']
            remediated_count += r['Remediated']
            self.manager.ctx.metrics.put_metric(
                "Unencrypted", r['Remediated'], "Count", Scope=r['Bucket'],
                buffer=True)

        self.manager.ctx.metrics.put_metric(
            "Unencrypted", remediated_count, "Count", Scope="Account",
            buffer=True
        )
        self.manager.ctx.metrics.put_metric(
            "Total Keys", object_count, "Count", Scope="Account",
            buffer=True
        )
        self.manager.ctx.metrics.flush()
                
        log.info(
            "EncryptExtant Complete keys:%d remediated:%d rate:%0.2f/s time:%0.2fs",
            object_count,
            remediated_count,
            float(object_count) / run_time,
            run_time)

        return results

    def process_chunk(self, batch, bucket):
        crypto_method = self.data.get('crypto', 'AES256')
        b = bucket['Name']
        s3 = bucket_client(
            local_session(self.manager.session_factory), bucket,
            kms = (crypto_method == 'aws:kms'))
        results = []
        for key in batch:
            k = key['Key']
            data = s3.head_object(Bucket=b, Key=k)
            if 'ServerSideEncryption' in data:
                continue
            if self.data.get('report-only'):
                results.append(k)
                continue
            crypto_method = self.data.get('crypto', 'AES256')
            # Note on copy we lose individual object acl grants
            params = {'Bucket': b,
                      'Key': k,
                      'CopySource': "/%s/%s" % (b, k),
                      'MetadataDirective': 'COPY',
                      'StorageClass': key['StorageClass'],
                      'ServerSideEncryption': crypto_method}
            s3.copy_object(**params)
            results.append(k)
        return results
