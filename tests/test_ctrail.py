import jmespath
from unittest import TestCase

from .common import event_data

from janitor.ctrail import CloudTrailResource


class CloudTrailResourceTest(TestCase):

    def test_non_cloud_trail_event(self):
        for event in ['event-instance-state.json', 'event-scheduled.json']:
            self.assertFalse(CloudTrailResource.match(event_data(event)))

    def test_cloud_trail_resource(self):
        self.assertEqual(
            CloudTrailResource.match(
                event_data('event-cloud-trail-s3.json')),
            {'source': 'aws.s3',
             'ids': jmespath.compile('detail.requestParameters.bucketName')})
    
