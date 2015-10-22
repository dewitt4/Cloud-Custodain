

from unittest import TestCase

from janitor.resources.s3 import assemble_bucket, S3

from mock import Mock


class S3ManagerTest(TestCase):

    def xtest_no_resources(self):
        factory = Mock()
        factory().client('s3').list_buckets().return_value = {'Buckets': []}
        s3 = S3(factory, {}, {})
        self.assertEqual(s3.resources(), [])

    def xtest_assembler_bucket(self):
        pass


