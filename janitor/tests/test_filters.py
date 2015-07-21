
import unittest
import cPickle

from janitor import filters

from .common import Instance

class TestFilter(unittest.TestCase):

    def test_filter_construction(self):
        self.assertTrue(
            isinstance(
                filters.filter({'type': 'ec2', 'state': 'absent', 'filter': 'tag:ASV'}),
                filters.EC2InstanceFilter))

        self.assertTrue(
            isinstance(
                filters.filter({'type': 'ec2', 'filter': 'tag:ASV',  'value': 'REALTIMEMSG'}),
                filters.EC2QueryFilter))

    def test_filter_validation(self):
        self.assertRaises(filters.FilterValidationError,
                          filters.filter,
                          {'type': 'ax'})
        self.assertRaises(filters.FilterValidationError,
                          filters.filter,
                          {'type': 'ec2'})

            

class TestInstanceFilter(unittest.TestCase):

    def test_absent_tag(self):
        self.assertFalse(filters.filter(
            {'type': 'ec2', 'state': 'absent', 'filter': 'tag:ASV'}).process(
                Instance({
                    'tags': {'ASV': 'abcd'}})))

        self.assertTrue(filters.filter(
            {'type': 'ec2', 'state': 'absent', 'filter': 'tag:ASV'}).process(
                Instance({
                    'tags': {'CMDB': 'abcd'}})))

        self.assertFalse(filters.filter(
            {'type': 'ec2', 'state': 'absent',
             'filter': 'iam-instance-profile.arn'}).process(
                Instance({'instance_profile': 'asf'})))

        self.assertTrue(filters.filter(
            {'type': 'ec2', 'state': 'absent',
             'filter': 'iam-instance-profile.arn', 'value': 'asf2'}).process(
                Instance({'instance_profile': 'asf'})))        

        self.assertTrue(filters.filter(
            {'type': 'ec2', 'state': 'absent',
             'filter': 'iam-instance-profile.arn'}).process(
                Instance({})))        


if __name__ == '__main__':
    unittest.main()
        
