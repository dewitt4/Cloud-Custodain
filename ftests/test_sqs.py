
import boto3
import logging
import os
import random
import string
import unittest

from janitor.sqsexec import SQSExecutor

TEST_SQS_PREFIX = os.environ.get("TEST_SQS_PREFIX", "cloud-maid-ftest")


def session_factory():
    return boto3.Session()


class SQSExecFunctional(unittest.TestCase):

    def setUp(self):
        logging.getLogger('botocore').setLevel(logging.WARNING)
        self.session = session_factory()
        self.client = self.session.client('sqs')
        self.map_queue = self.client.create_queue(
            QueueName = "%s-map-%s" % (
                TEST_SQS_PREFIX, "".join(random.sample(string.letters, 3))))[
                    'QueueUrl']
        self.addCleanup(self.client.delete_queue, QueueUrl=self.map_queue)
        self.reduce_queue = self.client.create_queue(
            QueueName = "%s-map-%s" % (
                TEST_SQS_PREFIX, "".join(random.sample(string.letters, 3))))[
                    'QueueUrl']
        self.addCleanup(self.client.delete_queue, QueueUrl=self.reduce_queue)        

    def xtest_executor(self):
        with SQSExecutor(session_factory, self.map_queue, self.reduce_queue) as w:
            results = w.map(sum, [1,2,3,4])
            print list(results)
        
