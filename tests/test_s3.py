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
import json
import mock
import shutil
import tempfile


from unittest import TestCase

from c7n.resources.s3 import (
#    EncryptedPrefix,
#    NoGlobalGrants,
#    EncryptionRequiredPolicy,
#    EncryptExtantKeys,
    BucketScanLog,
    restore_complete
)

from c7n.resources import s3 as s3_resource


class RestoreCompletionTest(TestCase):

    def test_restore_complete(self):

        self.assertTrue(
            restore_complete(
                ('ongoing-request="false", '
                 'expiry-date="Fri, 23 Dec 2012 00:00:00 GMT"')))

        self.assertFalse(restore_complete('ongoing-request="true"'))
    

class BucketScanLogTests(TestCase):

    def setUp(self):
        self.log_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.log_dir)
        self.log = BucketScanLog(self.log_dir, 'test')
        
    def test_scan_log(self):
        with self.log:
            self.log.add(range(10)[:5])
            self.log.add(range(10)[5:])

        with open(self.log.path) as fh:
            data = json.load(fh)
            self.assertEqual(
                data,
                [range(10)[:5], range(10)[5:], []])


class BucketAction(TestCase):

    def setUp(self):
        self.client = mock.Mock()
        self.client_factory = mock.patch(
            'maid.resources.s3.bucket_client',
            return_value=self.client)
        self.client_factory.start()
        
    def tearDown(self):
        self.client_factory.stop()

    def bucket(self, data):
        self.assertEqual(
            s3_resource.bucket_client(None, None),
            self.client)

        
#class EncryptedPrefixTest(BucketAction):
#    pass


#class GlobalGrantsTest(BucketAction):
#    pass


#class EncryptExtantKeyTest(BucketAction):
#    pass
