

from common import BaseTest


class NotifyTest(BaseTest):

    def test_notify(self):
        session_factory = self.replay_flight_data(
            "test_notify_action", zdata=True)
        policy = self.load_policy({
            'name': 'instance-check',
            'resource': 'ec2',
            'filters': [
                {'tag:foi': 'testing'}],
            'actions': [
                {'type': 'notify',
                 'transport' : {
                     'type': 'sqs',
                     'queue': 'https://sqs.us-east-1.amazonaws.com/619193117841/maid-delivery',
                     }
                 }
                ]
        }, session_factory=session_factory)

        resources = policy.poll()
        self.assertJmes("[].MatchedFilters", resources, [['tag:foi']])
