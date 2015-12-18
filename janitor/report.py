"""
Reporting tools against cloud-maid's json output
records
"""

from cStringIO import StringIO
import csv
import gzip
import json
import itertools
import logging

from dateutil.parser import parse as date_parse

from janitor.executor import ThreadPoolExecutor
from janitor.output import parse_s3, s3_join
from janitor.utils import local_session

log = logging.getLogger('maid.reports')


def report(
        session_factory,
        policy,
        start_date,
        output_fh,
        s3_record_path,
        filters=None):
    """Format a policy's extant records into a report."""
    formatter = RECORD_TYPE_FORMATTERS.get(policy.resource_type)

    if formatter is None:
        raise ValueError(
            "No formatter for resource type %s, valid: %s" % (
                policy.resource_type, ", ".join(RECORD_TYPE_FORMATTERS)))

    records = record_set(session_factory, s3_record_path, start_date)

    original_record_count = len(records)    
    if filters:
        for f in filters:
            records = f(records)
            
    log.debug("Filtered records from %d to %d" % (
        original_record_count, len(records)))
    
    formatter(output_fh, records)


def ec2_csv(output_fh, records):
    headers = ['instance-id', 'name',
               'instance-type', 'launch', 'vpc-id',
               'asv', 'env', 'owner']
    writer = csv.writer(output_fh, headers)
    writer.writerow(headers)
    
    for r in records:
        tag_map = {t['Key']: t['Value'] for t in r['Tags']}
        writer.writerow([
            r['InstanceId'],
            tag_map.get('Name', ''),
            r['InstanceType'],
            r['LaunchTime'],
            r['VpcId'],
            tag_map.get("ASV", ""),
            tag_map.get("CMDBEnvironment", ""),
            tag_map.get("OwnerContact", "")])

        
def asg_csv(output_fh, records):
    headers = ['name', 'instance-count',
               'asv', 'env', 'owner']
    writer = csv.writer(output_fh, headers)
    writer.writerow(headers)
    
    for r in records:
        tag_map = {t['Key']: t['Value'] for t in r['Tags']}
        writer.writerow([
            r['AutoScalingGroupName'],
            str(len(r['Instances'])),
            tag_map.get("ASV", ""),
            tag_map.get("CMDBEnvironment", ""),
            tag_map.get("OwnerContact", "")])


RECORD_TYPE_FORMATTERS = {
    'ec2': ec2_csv,
    'asg': asg_csv
    }


def record_set(session_factory, s3_url, start_date):
    """Retrieve all s3 records for the given policy output url

    From the given start date.
    """

    s3 = local_session(session_factory).client('s3')
    _, bucket, key_prefix = parse_s3(s3_url)
    marker = key_prefix.strip("/") + "/" + start_date.strftime(
        '%Y-%m-%d-00') + "/resources.json.gz"

    log.debug("Marker %s" % marker)

    records = []
    key_count = 0
    
    p = s3.get_paginator('list_objects').paginate(
        Bucket=bucket,
        Prefix=key_prefix.strip('/') + '/',
        Marker=marker)
    with(ThreadPoolExecutor(max_workers=20)) as w:
        for key_set in p:
            if not 'Contents' in key_set:
                continue
            keys = [k for k in key_set['Contents']
                    if k['Key'].endswith('resources.json.gz')]
            key_count += len(keys)
            map(records.extend,
                w.map(get_records,
                      zip(keys, itertools.repeat(session_factory))))
    log.info("Fetched %d records across %d files" % (
        len(records), key_count))
    return records


def get_records(ctx):
    session_factory, bucket, key = ctx
    # we're doing a lot of this in memory, worst case
    # though we're talking about a 10k objects, else
    # we should spool to temp files
    s3 = local_session(session_factory).client('s3')
    result = s3.get_object(Bucket=bucket, Key=key)
    blob = StringIO(result['Body'].read())
    records = json.loads(gzip.GzipFile(fileobj=blob))
    return records

        

    

    



    
