import unittest

from janitor import query

class TestEC2QueryFilter(unittest.TestCase):

    def test_parse(self):
        self.assertEqual(query.parse([]), [])
        x = query.parse(
            [{'instance-state-name': 'running'}])
        self.assertEqual(
            x[0].query(),
            {'Name': 'instance-state-name', 'Values': ['running']})
        
        self.assertTrue(
            isinstance(
                query.parse(
                    [{'tag:ASV': 'REALTIMEMSG'}])[0],
                query.EC2QueryFilter))

        self.assertRaises(
            ValueError,
            query.parse,
            [{'tag:ASV': None}])
        
                
