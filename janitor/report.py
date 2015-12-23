"""
Reporting Tools
---------------

Provides reporting tools against cloud-maid's json output records.

For each policy execution maid stores structured output
in json format of the records a policy has filtered to
in an s3 bucket.

These represent the records matching the policy filters
that the policy will apply actions to.

The reporting mechanism here simply fetches those records
over a given time interval and constructs a resource type
specific report on them.


CLI Usage
=========

```
 $ cloud-maid report -s s3://cloud-maid-xyz/policies \
   -p ec2-tag-compliance-terminate -v > terminated.csv
   


TODO

The type specific formatting needs easy customization, 
a config file for the report or maid, or named formats
with format spec on the cli are all viable.
"""

from concurrent.futures import as_completed

from cStringIO import StringIO
import csv
import gzip
import json
import logging
import operator

from dateutil.parser import parse as date_parse

from janitor.executor import ThreadPoolExecutor
from janitor.utils import local_session, dumps

log = logging.getLogger('maid.reports')


def report(policy, start_date, output_fh, raw_output_fh=None, filters=None):
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

    records = unique(records, formatter.id_field, filters=formatter.filters)
    rows = map(lambda record: fmt_csv(record, formatter.extractor), records)

    writer = csv.writer(output_fh, formatter.headers)
    writer.writerow(formatter.headers)
    for row in rows:
        writer.writerow(row)

    if raw_output_fh is not None:
        dumps(records, raw_output_fh, indent=2)


def unique(records, id_field, reverse=True, filters=None):
    # filter the records down to those that pass all the filters
    filters = filters or []
    filtered = filter(lambda record: reduce(lambda found, filter: found and filter(record), filters, True), records)
    filtered.sort(key=lambda r: r['MaidDate'], reverse=reverse)
    # unique record list by id_field
    uniq, _ = reduce(
        lambda (recs, keys), rec:
            (recs, keys) if rec[id_field] in keys  # if duplicate key, keep old accumulator
            else (recs + [rec], keys | {rec[id_field]}),  # add to records and keys
        filtered,
        ([], set()))  # (unique records, set of keys)
    log.debug("Uniqued from %d to %d" % (len(records), len(uniq)))
    return uniq


def fmt_csv(record, fn):
    tag_map = {t['Key']: t['Value'] for t in record['Tags']}
    return fn(record, tag_map)


class Formatter:
    def __init__(self, id_field, headers, extractor, filters=[]):
        self.id_field = id_field
        self.headers = headers
        self.extractor = extractor
        self.filters = filters


def ec2_csv(record, tag_map):
    return [
        record['MaidDate'].strftime("%Y-%m-%d"),
        record['InstanceId'],
        tag_map.get('Name', ''),
        record['InstanceType'],
        record['LaunchTime'],
        record.get('VpcId', ''),
        record.get('PrivateIpAddress', ''),
        tag_map.get("ASV", ""),
        tag_map.get("CMDBEnvironment", ""),
        tag_map.get("OwnerContact", ""),
    ]


def asg_csv(r, tag_map):
    return [
        r['AutoScalingGroupName'],
        str(len(r['Instances'])),
        tag_map.get("ASV", ""),
        tag_map.get("CMDBEnvironment", ""),
        tag_map.get("OwnerContact", "")
    ]


RECORD_TYPE_FORMATTERS = {
    'ec2': Formatter(
        'InstanceId',
        ['action-date', 'instance-id', 'name', 'instance-type', 'launch', 'vpc-id', 'ip-addr', 'asv', 'env', 'owner'],
        ec2_csv,
        [lambda x: x['State']['Name'] != 'terminated']),
    'asg': Formatter(
        'AutoScalingGroupName',
        ['name', 'instance-count', 'asv', 'env', 'owner'],
        asg_csv)
    }


def record_set(session_factory, bucket, key_prefix, start_date):
    """Retrieve all s3 records for the given policy output url

    From the given start date.
    """

    s3 = local_session(session_factory).client('s3')
    marker = key_prefix.strip("/") + "/" + start_date.strftime(
        '%Y-%m-%d-00') + "/resources.json.gz"

    records = []
    key_count = 0
    
    p = s3.get_paginator('list_objects').paginate(
        Bucket=bucket,
        Prefix=key_prefix.strip('/') + '/',
        Marker=marker)
    with ThreadPoolExecutor(max_workers=20) as w:
        for key_set in p:
            if not 'Contents' in key_set:
                continue
            keys = [k for k in key_set['Contents']
                    if k['Key'].endswith('resources.json.gz')]
            key_count += len(keys)
            futures = map(lambda k: w.submit(get_records, bucket, k, session_factory), keys)

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
    log.debug("bucket: %s key: %s records: %d",
              bucket, key['Key'], len(records))
    for r in records:
        r['MaidDate'] = maid_date
    return records
