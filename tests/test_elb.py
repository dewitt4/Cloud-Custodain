from .common import BaseTest


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
