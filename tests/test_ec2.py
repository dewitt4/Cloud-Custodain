# Copyright 2016 Capital One Services, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import unittest

from janitor.resources import ec2
from janitor.resources.ec2 import actions, QueryFilter
from janitor import tags

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
            tags.Tag)

        self.assertIsInstance(
            actions.factory('stop', None),
            ec2.Stop)

        self.assertIsInstance(
            actions.factory('terminate', None),
            ec2.Terminate)        

        

