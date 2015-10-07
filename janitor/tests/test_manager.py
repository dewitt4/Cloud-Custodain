import unittest

import boto
import yaml

from janitor import actions
from janitor.manager import EC2

from janitor.tests.common import BaseTest, Config, instance


class TestECManager(BaseTest):

    def get_manager(self, data, config=None, session_factory=None):
        return EC2(session_factory, data, config)

    def test_manager_invalid_data_type(self):
        self.assertRaises(
            ValueError,
            self.get_manager,
            [])
        
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

    def test_filters(self):
        ec2 = self.get_manager({
            'filters': [
                {'tag:CMDBEnvironment': 'absent'}]})
        
        self.assertEqual(
            len(ec2.filter_resources([
                instance(Tags=[{"Key": "ASV", "Value": "xyz"}])])),
            1)

        self.assertEqual(
            len(ec2.filter_resources([
                instance(Tags=[{"Key": "CMDBEnvironment", "Value": "xyz"}])])),
            0)        
    
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
        

