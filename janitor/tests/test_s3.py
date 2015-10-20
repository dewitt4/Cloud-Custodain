

from unittest import TestCase

from janitor.s3 import assemble_bucket, S3

from mock import Mock


class S3ManagerTest(TestCase):

    def test_no_resources(self):
        factory = Mock()
        factory().client('s3').list_buckets().return_value = {'Buckets': []}
        s3 = S3(factory, {}, {})
        self.assertEqual(s3.resources(), [])

    def test_assembler_bucket(self):
        pass


