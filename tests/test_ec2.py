import unittest

from janitor.resources import ec2
from janitor.resources.ec2 import actions, QueryFilter


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

        

