import mock

from unittest import TestCase

from janitor.resources.s3 import (
    EncryptedPrefix,
    NoGlobalGrants,
    EncryptionRequiredPolicy,
    EncryptExtantKeys,
    BucketScanLog)

from janitor.resources import s3 as s3_resource
    



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
