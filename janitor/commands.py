from cStringIO import StringIO
from datetime import timedelta, datetime

import gzip
import logging
import json
import sys

from janitor.utils import dumps

log = logging.getLogger('maid.commands')

def identify(options, policy_collection):
    fh = sys.stdout
    for policy in policy_collection.policies(options.policies):
        manager = policy.resource_manager
        resources = manager.resources()
        manager.format_json(resources, fh)        

        
def run(options, policy_collection):
    for policy in policy_collection.policies(options.policies):
        try:
            policy()
        except Exception, e:
            # Output does an exception log
            log.warning("Error while executing policy %s, continuing" % (
                policy.name))
        
def blame(options, policy_collection):
    if not options.output_dir.startswith('s3://'):
        raise ValueError("Blame only supports s3 output")

    log = logging.getLogger('maid.blame')
    
    from janitor.output import S3Output
    
    names = [
        p.name for p in
        policy_collection.policies(options.policies) if p.resource_type == 'ec2']
    session = p.session_factory()
    s3 = session.client('s3')

    d = datetime.now()
    delta = timedelta(days=options.days)
    begin_date = d - delta

    ip_addrs, instance_ids = set(), set()
    if options.ip:
        ip_addrs = set(options.ip)
    if options.instance_id:
        instance_ids = set(options.instance_id)

    log.info("Checking records of policies: %s" % " ".join(names))
    results = []
    
    for n in names:
        output_path = S3Output.join(options.output_dir, n)
        _, bucket, key_prefix = S3Output.parse_s3(output_path)

        marker = key_prefix.strip('/') + "/" + begin_date.strftime('%Y-%m-%d-00') + "/resources.json.gz"
        log.info("Record Prefix %s Marker %s", key_prefix.strip('/'), marker)

        p = s3.get_paginator('list_objects').paginate(
            Bucket=bucket,
            Prefix=key_prefix.strip('/') + "/",
            Marker=marker)
        
        for key_set in p:
            if not 'Contents' in key_set:
                continue
            log.info("Key Set - %d" % len(key_set['Contents']))
            
            for k in key_set['Contents']:
                if k['Key'].endswith('resources.json.gz'):
                    print k['Key']
                    res = s3.get_object(Bucket=bucket, Key=k['Key'])
                    blob = StringIO(res['Body'].read())
                    records = json.load(gzip.GzipFile(fileobj=blob))
                    for r in records:
                        if not 'PrivateIpAddress' in r:
                            log.debug('No Ip address for %s' % r['InstanceId'])
                        if r.get('PrivateIpAddress', ' ') in ip_addrs:
                            results.append((k['Key'], r))
                        elif r['InstanceId'] in instance_ids:
                            results.append((k['Key'], r))

    print(dumps(results, indent=2))
                                        



            
        
            

    
    
    
    

        
