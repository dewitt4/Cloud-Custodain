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
import shutil
import tempfile

from c7n import policy, manager
from c7n.resources.ec2 import EC2

from .common import BaseTest, Config


class DummyResource(manager.ResourceManager):

    def resources(self):
        return [
            {'abc': 123},
            {'def': 456}]

    @property
    def actions(self):

        class _a(object):
            def name(self):
                return self.f.__name__
            def __init__(self, f):
                self.f = f
            def process(self, resources):
                return self.f(resources)
            
        def p1(resources):
            return [
                {'abc': 456},
                {'def': 321}]

        def p2(resources):
            return resources

        return [_a(p1), _a(p2)]
    
        
class TestPolicy(BaseTest):

    def test_policy_name_filtering(self):

        collection = self.load_policy_set(
            {'policies': [
                {'name': 's3-remediate',
                 'resource': 's3'},
                {'name': 's3-global-grants',
                 'resource': 's3'},
                {'name': 'ec2-tag-compliance-stop',
                 'resource': 'ec2'},
                {'name': 'ec2-tag-compliance-kill',
                 'resource': 'ec2'},
                {'name': 'ec2-tag-compliance-remove',
                 'resource': 'ec2'}]},
            )
        self.assertEqual(
            [p.name for p in collection.policies('s3*')],
            ['s3-remediate', 's3-global-grants'])

        self.assertEqual(
            [p.name for p in collection.policies('ec2*')],
            ['ec2-tag-compliance-stop',
             'ec2-tag-compliance-kill',
             'ec2-tag-compliance-remove'])
                
    def test_file_not_found(self):
        self.assertRaises(
            ValueError, policy.load, Config.empty(), "/asdf12")

    def test_get_resource_manager(self):
        collection = self.load_policy_set(
            {'policies': [
                {'name': 'query-instances',
                 'resource': 'ec2',
                 'filters': [
                     {'tag-key': 'CMDBEnvironment'}
                 ]}]})
        p = collection.policies()[0]
        self.assertTrue(
            isinstance(p.get_resource_manager(), EC2))

    def xtest_policy_run(self):
        manager.resources.register('dummy', DummyResource)
        self.addCleanup(manager.resources.unregister, 'dummy')
        self.output_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.output_dir)

        collection = self.load_policy_set(
            {'policies': [
                {'name': 'process-instances',
                 'resource': 'dummy'}]},
            {'output_dir': self.output_dir})
        p = collection.policies()[0]
        p()
        self.assertEqual(len(p.ctx.metrics.data), 3)

        
