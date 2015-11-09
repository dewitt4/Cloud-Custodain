import shutil
import tempfile

from janitor import policy, manager
from janitor.resources.ec2 import EC2

from janitor.tests.common import BaseTest, Config



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

    def test_policy_run(self):
        manager.resources.register('dummy', DummyResource)
        self.addCleanup(manager.resources.unregister, 'dummy')
        self.output_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.output_dir)

        collection = self.load_policy(
            {'policies': [
                {'name': 'process-instances',
                 'resource': 'dummy'}]},
            {'output_dir': self.output_dir})
        p = collection.policies()[0]
        p()
        self.assertEqual(len(p.ctx.metrics.data), 1)

        
