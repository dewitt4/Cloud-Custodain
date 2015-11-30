
import mock

from janitor.resources.elb import ELB

from janitor.tests.common import BaseTest


class ResourceManagerTest(BaseTest):

    def setUp(self):
        self.client = mock.Mock()
        self.session_factory = mock.Mock()
        self.session_factory.client.return_value = self.client
        self.session_factory.start()

    def tearDown(self):
        self.session_factory.stop()
        
    def xtest_resources(self):
        mgr = ELB(self.get_context(session_factory=self.session_factory), {})
        self.assertEqual(mgr.resources(), [])


    
