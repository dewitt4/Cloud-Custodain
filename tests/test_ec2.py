import unittest

from janitor.resources import ec2
from janitor.resources.ec2 import actions, QueryFilter

from .common import BaseTest


class TestVolumeFilter(BaseTest):

    def test_ec2_attached_ebs_filter(self):
        session_factory = self.replay_flight_data(
            'test_ec2_attached_ebs_filter')
        policy = self.load_policy({
            'name': 'ec2-unencrypted-vol',
            'resource': 'ec2',
            'filters': [
                {'State.Name': 'running'},
                {'type': 'ebs',
                 'key': 'Encrypted',
                 'value': False}]},
            session_factory=session_factory)
        resources = policy.run()
        self.assertEqual(len(resources), 5)

        
class TestEC2QueryFilter(unittest.TestCase):

    def test_parse(self):
        self.assertEqual(QueryFilter.parse([]), [])
        x = QueryFilter.parse(
            [{'instance-state-name': 'running'}])
        self.assertEqual(
            x[0].query(),
            {'Name': 'instance-state-name', 'Values': ['running']})
        
        self.assertTrue(
            isinstance(
                QueryFilter.parse(
                    [{'tag:ASV': 'REALTIMEMSG'}])[0],
                QueryFilter))

        self.assertRaises(
            ValueError,
            QueryFilter.parse,
            [{'tag:ASV': None}])
        

class TestActions(unittest.TestCase):

    def test_action_construction(self):

        self.assertIsInstance(
            actions.factory('mark', None),
            ec2.Mark)

        self.assertIsInstance(
            actions.factory('stop', None),
            ec2.Stop)

        self.assertIsInstance(
            actions.factory('terminate', None),
            ec2.Terminate)        

        

