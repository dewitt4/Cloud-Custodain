import json
import mock
import shutil
import tempfile


from unittest import TestCase

from janitor.resources.s3 import (
    EncryptedPrefix,
    NoGlobalGrants,
    EncryptionRequiredPolicy,
    EncryptExtantKeys,
    BucketScanLog)

from janitor.resources import s3 as s3_resource
    

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
            'janitor.resources.s3.bucket_client',
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
