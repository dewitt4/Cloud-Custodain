"""
Reporting tools against cloud-maid's json output records.

For each policy execution maid stores structured output
in json format of the records a policy has filtered to
in an s3 bucket.

These represent the records matching the policy filters
that the policy will apply actions to.

The reporting mechanism here simply fetches those records
over a given time interval and constructs a resource type
specific report on them.

TODO

The type specific formatting needs easy customization, 
a config file for the report or maid, or named formats
with format spec on the cli are all under consideration.
"""

from concurrent.futures import as_completed

from cStringIO import StringIO
import csv
import gzip
import json
import itertools
import logging

from dateutil.parser import parse as date_parse

from janitor.executor import ThreadPoolExecutor, MainThreadExecutor
from janitor.output import parse_s3, s3_join
from janitor.utils import local_session

log = logging.getLogger('maid.reports')


def report(policy, start_date, output_fh, filters=None):
    """Format a policy's extant records into a report."""
    formatter = RECORD_TYPE_FORMATTERS.get(policy.resource_type)

    if formatter is None:
        raise ValueError(
            "No formatter for resource type %s, valid: %s" % (
                policy.resource_type, ", ".join(RECORD_TYPE_FORMATTERS)))

    records = record_set(
        policy.session_factory,
        policy.ctx.output.bucket,
        policy.ctx.output.key_prefix,
        start_date)
    
    original_record_count = len(records)    
    if filters:
        for f in filters:
            records = f(records)
            
    log.debug("Filtered records from %d to %d" % (
        original_record_count, len(records)))
    
    formatter(output_fh, records)


def ec2_csv(output_fh, records):
    headers = ['instance-id', 'name',
               'instance-type', 'launch', 'vpc-id', 'ip-addr',
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
            r['PrivateIpAddress'],
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


def record_set(session_factory, bucket, key_prefix, start_date):
    """Retrieve all s3 records for the given policy output url

    From the given start date.
    """

    s3 = local_session(session_factory).client('s3')
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
            futures = []
            for k in keys:
                futures.append(
                    w.submit(get_records, bucket, k, session_factory))

            for f in as_completed(futures):
                records.extend(f.result())

    log.info("Fetched %d records across %d files" % (
        len(records), key_count))
    return records


def get_records(bucket, key, session_factory):
    # we're doing a lot of this in memory, worst case
    # though we're talking about a 10k objects, else
    # we should spool to temp files
    _, date_str, _ = key['Key'].rsplit("/", 2)
    maid_date = date_parse(date_str)
    s3 = local_session(session_factory).client('s3')
    result = s3.get_object(Bucket=bucket, Key=key['Key'])
    blob = StringIO(result['Body'].read())
    records = json.load(gzip.GzipFile(fileobj=blob))
    for r in records:
        r['MaidDate'] = maid_date
    return records

        

    

    



    
