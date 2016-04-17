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
from .common import BaseTest
from c7n.filters import FilterValidationError
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
        self.assertEqual(
            resources[0]['LoadBalancerName'],
            'test-elb-invalid-policy')

    @raises(FilterValidationError)
    def test_filter_validation_no_blacklist(self):
        self.load_policy({
            'name': 'test-ssl-ciphers',
            'resource': 'elb',
            'filters': [
                {'type': 'ssl-policy'}
            ]},
            session_factory=None)
        self.fail("validtion error should have been thrown")

    @raises(FilterValidationError)
    def test_filter_validation_blacklist_not_iterable(self):
        self.load_policy({
            'name': 'test-ssl-ciphers',
            'resource': 'elb',
            'filters': [
                {'type': 'ssl-policy', 'blacklist': 'single-value'}
            ]},
            session_factory=None)
        self.fail("validtion error should have been thrown")
