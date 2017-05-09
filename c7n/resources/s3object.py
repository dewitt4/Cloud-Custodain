# Copyright 2016 Capital One Services, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from c7n.actions import Action
from c7n.manager import resources
from c7n.query import QueryResourceManager, DescribeSource
from c7n.utils import local_session, type_schema, get_retry
from c7n.resources.s3 import S3, bucket_client

import itertools
import threading

@resources.register('s3object')
class S3Object(QueryResourceManager):

    class resource_type(object):
        service = 's3'
        parent_enum_spec = (S3, '[].Name', 'Bucket', False)
        enum_spec = ('list_objects_v2', 'Contents', None)
        name = id = 'Key'
        date = None
        dimension = None

    def full_resources(self):
        buckets = self.get_resource_manager('s3').resources()

        results = []

        with self.executor_factory(max_workers=10) as w:
            bucket_items = list(w.map(self.list_objects_in_bucket, buckets))
            results.append(results)
        return list(itertools.chain(*bucket_items))

    def expand_item(self, params):
        client, bucket, item = params
        item['Bucket'] = bucket
        result = client.head_object(Bucket=bucket['Name'], Key=item['Key'])
        return dict(item, **result)

    def list_objects_in_bucket(self, bucket):
        client = bucket_client(local_session(self.session_factory), bucket)
        print(bucket['Name'], bucket['Location'])
        with self.executor_factory(max_workers=10) as w:
            items = client.get_paginator('list_objects_v2')
            print("Fetching items in %s" % (bucket['Name'],))
            response = items.paginate(Bucket=bucket['Name']).build_full_result()
            print("Converting / normalising tiems.")
            if 'Contents' in response:
                subset = response['Contents']
                input = map(lambda x: [client, bucket, x], subset)
                results = list(w.map(self.expand_item,  input))
                return list(itertools.chain(*results))
            else:
                return []




    def resources(self, query=None):
        return self.full_resources()


    # def augment(self, summaries):
    #   print(summaries)
    #   with self.executor_factory(
    #           max_workers=min((10, len(summaries) + 1))) as w:
    #       results = w.map(self.assemble_object, summaries)
    #       results = filter(None, results)
    #       return results     

    # def assemble_object(self, summary):

    #     client = local_session(self.session_factory).client('s3')

    #     summary['Object'] = client.head_object(Bucket=summary['c7n:parent_id'], Key=summary['Key'])

    #     return summary
        

