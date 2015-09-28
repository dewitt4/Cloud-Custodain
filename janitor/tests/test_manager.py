import unittest

import boto
import yaml

from janitor import actions
from janitor.manager import EC2

from janitor.tests.common import BaseTest


class TestECManager(BaseTest):

    def get_manager(self, data, config=None):
        return EC2(None, data, config)

    def test_manager(self):
        ec2_mgr = self.get_manager(
            {'query': [
                {'tag-key': 'CMDBEnvironment'}],
             'filters': [
                 {'tag:ASV': 'absent'}]})
        self.assertEqual(len(ec2_mgr.filters), 1)
        self.assertEqual(len(ec2_mgr.queries), 1)
        self.assertEqual(
            ec2_mgr.resource_query(),
            [{'Values': ['CMDBEnvironment'], 'Name': 'tag-key'}])
                         
    def test_actions(self):
        # a simple action by string
        ec2 = self.get_manager({'actions': ['mark']})
        self.assertEqual(len(ec2.actions), 1)
        self.assertTrue(isinstance(ec2.actions[0], actions.Mark))

        # a configured action with dict
        ec2 = self.get_manager({
            'actions': [
                {'type': 'mark',
                 'msg': 'Missing proper tags'}]})
        self.assertEqual(len(ec2.actions), 1)
        self.assertTrue(isinstance(ec2.actions[0], actions.Mark))
        self.assertEqual(ec2.actions[0].data,
                         {'msg': 'Missing proper tags', 'type': 'mark'})
        

