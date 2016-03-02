from .common import BaseTest
from janitor.filters import FilterValidationError
from nose.tools import raises

class HealthCheckProtocolMismatchTest(BaseTest):
    
    def test_healthcheck_protocol_mismatch(self):
        session_factory = self.replay_flight_data(
            'test_healthcheck_protocol_mismatch')
        policy = self.load_policy({
            'name': 'healthcheck-protocol-mismatch',
            'resource': 'elb',
            'filters': [
                {'type': 'healthcheck-protocol-mismatch'}
            ]},
            session_factory=session_factory)
        
        resources = policy.run()
        self.assertEqual(len(resources), 3)

        # make sure we matched the right load balcners
        elb_names = set([elb['LoadBalancerName'] for elb in resources])
        self.assertEqual(
            elb_names, set(
                ['test-elb-no-listeners',
                 'test-elb-protocol-matches',
                 'test-elb-multiple-listeners']))


class SSLPolicyTest(BaseTest):

    def test_ssl_ciphers(self):
        session_factory = self.replay_flight_data(
            'test_ssl_ciphers')
        policy = self.load_policy({
            'name': 'test-ssl-ciphers',
            'resource': 'elb',
            'filters': [
                {'type': 'ssl-policy',
                 'blacklist': ['Protocol-SSLv2']}
            ]},
            session_factory=session_factory)

        resources = policy.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]['LoadBalancerName'],'test-elb-invalid-policy')


    @raises(FilterValidationError)
    def test_filter_validation_no_blacklist(self):
        policy = self.load_policy({
            'name': 'test-ssl-ciphers',
            'resource': 'elb',
            'filters': [
                {'type': 'ssl-policy' }
            ]},
            session_factory=None)
        self.fail("validtion error should have been thrown")

    @raises(FilterValidationError)
    def test_filter_validation_blacklist_not_iterable(self):
        policy = self.load_policy({
            'name': 'test-ssl-ciphers',
            'resource': 'elb',
            'filters': [
                {'type': 'ssl-policy', 'blacklist': 'single-value'}
            ]},
            session_factory=None)
        self.fail("validtion error should have been thrown")