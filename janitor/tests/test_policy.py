import unittest

import yaml

from janitor import policy, manager
from janitor.resources.ec2 import EC2

from janitor.tests.common import BaseTest, Config


class TestPolicy(BaseTest):

    def test_file_not_found(self):
        self.assertRaises(
            ValueError, policy.load, Config.empty(), "/asdf12")

    def test_get_resource_manager(self):
        collection = self.load_policy(
            {'policies': [
                {'name': 'query-instances',
                 'resource': 'ec2',
                 'filters': [
                     {'tag-key': 'CMDBEnvironment'}
                 ]}]})
        p = collection.policies()[0]
        self.assertTrue(
            isinstance(p.get_resource_manager(), EC2))

        
