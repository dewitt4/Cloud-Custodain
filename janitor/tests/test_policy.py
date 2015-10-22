import unittest

import boto
import yaml

from janitor import policy, manager
from janitor.resources.ec2 import EC2

from janitor.tests.common import BaseTest, Config


class TestPolicy(BaseTest):

    def test_file_not_found(self):
        self.assertRaises(
            ValueError, policy.load, Config.empty(), "/asdf12")

    def test_get_resource_manager(self):
        p = self.load_policy(
            {'ec2':
             {'filters': [
                 {'tag-key': 'CMDBEnvironment'}
             ]}})

        self.assertTrue(
            isinstance(p.resource_manager('ec2'), EC2))

        
