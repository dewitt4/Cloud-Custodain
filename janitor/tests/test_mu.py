import json
import unittest
import StringIO
import zipfile

from janitor.mu import maid_archive, LambdaManager, PolicyLambda
from janitor.policy import Policy
from janitor.tests.common import BaseTest, Config


class PolicyLambdaProvision(BaseTest):

    def assert_items(self, result, expected):
        for k, v in expected.items():
            self.assertEqual(v, result[k])
            
    def test_cwe_trail(self):
        session_factory = self.replay_flight_data('test_cwe_trail')
        p = Policy({
            'resource': 's3',
            'name': 's3-bucket-policy',
            'mode': {
                'type': 'cloudtrail',
                'events': ["CreateBucket"],
                # Would be nice if we could obviate sources
                'sources': ['s3.amazonaws.com']
            },
            'filters': [
                {'type': 'missing-policy-statement',
                 'statement_ids': ['RequireEncryptedPutObject']}],
            'actions': ['no-op']
        }, Config.empty())
        pl = PolicyLambda(p)
        mgr = LambdaManager(session_factory)
        result = mgr.publish(pl, 'Dev')

        self.assert_items(
            result,
            {'Description': 'cloud-maid lambda policy',
             'FunctionName': 'maid-s3-bucket-policy',
             'Handler': 'maid_policy.run',
             'MemorySize': 512,
             'Runtime': 'python2.7',
             'Timeout': 60})
                             
    def test_cwe_instance(self):
        session_factory = self.replay_flight_data('test_cwe_instance')
        p = Policy({
            'resource': 's3',
            'name': 'ec2-encrypted-vol',
            'mode': {
                'type': 'ec2-instance-state',
                'events': ['pending']}
        }, Config.empty())
        pl = PolicyLambda(p)
        mgr = LambdaManager(session_factory)
        result = mgr.publish(pl, 'Dev')
        self.assert_items(
            result,
            {'Description': 'cloud-maid lambda policy',
             'FunctionName': 'maid-ec2-encrypted-vol',
             'Handler': 'maid_policy.run',
             'MemorySize': 512,
             'Runtime': 'python2.7',
             'Timeout': 60})

        events = session_factory().client('events')
        result = events.list_rules(NamePrefix="maid-ec2-encrypted-vol")
        self.assert_items(
            result['Rules'][0],
            {"State": "ENABLED", 
             "Name": "maid-ec2-encrypted-vol"})

        self.assertEqual(
            json.loads(result['Rules'][0]['EventPattern']),
            {"source": ["aws.ec2"],
             "detail": {
                 "state": ["pending"]},
             "detail-type": ["EC2 Instance State-change Notifications"]})
            
    def test_cwe_schedule(self):
        session_factory = self.replay_flight_data('test_cwe_schedule')
        p = Policy({
            'resource': 'ec2',
            'name': 'periodic-ec2-checker',
            'mode': {
                'type': 'periodic',
                'schedule': 'rate(1 day)'
                }
        }, Config.empty())

        pl = PolicyLambda(p)
        mgr = LambdaManager(session_factory)
        result = mgr.publish(pl, 'Dev')
        self.assert_items(
            result,
            {'FunctionName': 'maid-periodic-ec2-checker',
             'Handler': 'maid_policy.run',
             'MemorySize': 512,
             'Runtime': 'python2.7',
             'Timeout': 60})        

        events = session_factory().client('events')
        result = events.list_rules(NamePrefix="maid-periodic-ec2-checker")
        self.assert_items(
            result['Rules'][0],
            {
                "State": "ENABLED", 
                "ScheduleExpression": "rate(1 day)", 
                "Name": "maid-periodic-ec2-checker"})
        

class PythonArchiveTest(unittest.TestCase):

    def test_archive_bytes(self):
        self.archive = maid_archive()
        self.archive.create()
        self.addCleanup(self.archive.remove)
        self.archive.close()
        io = StringIO.StringIO(self.archive.get_bytes())
        reader = zipfile.ZipFile(io, mode='r')
        fileset = [n.filename for n in reader.filelist]
        self.assertTrue('janitor/__init__.py' in fileset)
        
    def test_archive_skip(self):
        self.archive = maid_archive("*.pyc")
        self.archive.create()
        self.addCleanup(self.archive.remove)        
        self.archive.close()
        with open(self.archive.path) as fh:
            reader = zipfile.ZipFile(fh, mode='r')
            fileset = [n.filename for n in reader.filelist]
            for i in ['janitor/__init__.pyc',
                      'janitor/resources/s3.pyc',
                      'boto3/__init__.pyc']:
                self.assertFalse(i in fileset)
        

        
