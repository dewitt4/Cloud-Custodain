from janitor.ctx import ExecutionContext
from janitor.resources.ec2 import EC2, Mark
from janitor.tests.common import BaseTest, instance, Bag, Config


class TestEC2Manager(BaseTest):

    def get_manager(self, data, config=None, session_factory=None):
        ctx = ExecutionContext(
            session_factory,
            Bag({'name':'test-policy'}),
            config or Config.empty())
        return EC2(ctx, data)

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
        self.assertTrue(isinstance(ec2.actions[0], Mark))

        # a configured action with dict
        ec2 = self.get_manager({
            'actions': [
                {'type': 'mark',
                 'msg': 'Missing proper tags'}]})
        self.assertEqual(len(ec2.actions), 1)
        self.assertTrue(isinstance(ec2.actions[0], Mark))
        self.assertEqual(ec2.actions[0].data,
                         {'msg': 'Missing proper tags', 'type': 'mark'})
        

