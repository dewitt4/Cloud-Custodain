import pprint
import logging

from .common import BaseTest
from janitor.resources.ebs import EncryptInstanceVolumes
from janitor.executor import MainThreadExecutor


class EncryptExtantVolumesTest(BaseTest):

    def test_encrypt_volumes(self):
        # More a functional/coverage test then a unit test.
        self.patch(
            EncryptInstanceVolumes, 'executor_factory', MainThreadExecutor)
        output = self.capture_logging(level=logging.DEBUG)
        session_factory = self.replay_flight_data('test_encrypt_volumes')
        
        policy = self.load_policy({
            'name': 'ebs-remediate-attached',
            'resource': 'ebs',
            'filters': [
                {'Encrypted': False},                
                {'VolumeId': 'vol-5fc3ca80'}],
            'actions': [
                {'type': 'encrypt-instance-volumes',
                 'key': 'alias/cof/ebs/encrypted'}]},
            session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(
            resources[0]['Encrypted'], False)
