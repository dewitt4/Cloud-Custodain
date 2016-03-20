
import boto3
import json
import logging
import os
import random
import string
import unittest

from concurrent.futures import as_completed

from maid.sqsexec import SQSExecutor, MessageIterator
from maid import utils

TEST_SQS_PREFIX = os.environ.get("TEST_SQS_PREFIX", "cloud-maid-ftest")


def session_factory():
    return boto3.Session()


def int_processor(*args):
    if not args:
        return 1
    return args[0] * 2


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

    def test_executor_submit(self):
        with SQSExecutor(session_factory, self.map_queue, self.reduce_queue) as w:
            # Submit work
            futures = []
            for i in range(10):
                futures.append(w.submit(int_processor, i))

            # Manually process and send results
            messages = MessageIterator(self.client, self.map_queue, limit=10)
            for m in messages:
                d = utils.loads(m['Body'])
                self.assertEqual(
                    m['MessageAttributes']['op']['StringValue'],
                    'test_sqs:int_processor')
                self.client.send_message(
                    QueueUrl=self.reduce_queue,
                    MessageBody=utils.dumps([
                        d['args'], int_processor(*d['args'])]),
                    MessageAttributes=m['MessageAttributes'])
            w.gather()
            results = [json.loads(r.result()['Body'])
                       for r in list(as_completed(futures))]
            self.assertEqual(
                list(sorted(results))[-1],
                [[9], 18])
            
                

            
                
                
            

        
