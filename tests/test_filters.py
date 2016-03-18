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
from dateutil import tz

from datetime import datetime, timedelta
import unittest

from janitor import filters as base_filters
from janitor.resources.ec2 import filters
from janitor.utils import annotation
from .common import instance, event_data


class BaseFilterTest(unittest.TestCase):

    def assertFilter(self, f, i, v):
        """
        f: filter data/spec
        i: instance
        v: expected value (true/false)
        """
        try:
            self.assertEqual(filters.factory(f)(i), v)
        except AssertionError:
            print f, i['LaunchTime'], i['Tags'], v
            raise


class TestFilter(unittest.TestCase):

    def test_filter_construction(self):
        self.assertTrue(
            isinstance(
                filters.factory({'tag:ASV': 'absent'}),
                base_filters.ValueFilter))

    def test_filter_validation(self):
        self.assertRaises(
            base_filters.FilterValidationError,
            filters.factory, {'type': 'ax', 'xyz': 1})


class TestOrFilter(unittest.TestCase):

    def test_or(self):
        f = filters.factory({
            'or': [
                {'Architecture': 'x86_64'},
                {'Architecture': 'armv8'}]})
        self.assertEqual(
            f(instance(Architecture='x86_64')),
            True)
        self.assertEqual(
            f(instance(Architecture='amd64')),
            False)


class TestAndFilter(unittest.TestCase):

    def test_and(self):
        f = filters.factory({
            'and': [
                {'Architecture': 'x86_64'},
                {'Color': 'green'}]})
        self.assertEqual(
            f(instance(
                Architecture='x86_64',
                Color='green')),
            True)
        self.assertEqual(
            f(instance(
                Architecture='x86_64',
                Color='blue')),
            False)


class TestInstanceAge(BaseFilterTest):

    def test_filter_instance_age(self):
        now = datetime.now(tz=tz.tzutc())
        three_months = now - timedelta(90)
        two_months = now - timedelta(60)
        one_month = now - timedelta(30)

        def i(d):
            return instance(LaunchTime=d)

        for ii, v in [
                (i(now), False),
                (i(three_months), True),
                (i(two_months), True),
                (i(one_month), False)
        ]:
            self.assertFilter({'type': 'instance-uptime'}, ii, v)


class TestMarkedForAction(BaseFilterTest):

    def test_marked_for_op_with_skew(self):
        now = datetime.now()
        yesterday = datetime.now() - timedelta(7)
        next_week = now + timedelta(7)

        def i(d, action='stop'):
            return instance(Tags=[
                {"Key": "maid_status",
                 "Value": "not compliant: %s@%s" % (
                    action, d.strftime("%Y/%m/%d"))}])

        for inst, skew, expected in [
                (i(next_week), 7, True),
                (i(next_week), 3, False),
                (i(now), 0, True),
                (i(now), 5, True),
                (i(yesterday), 5, True),
                (i(now+timedelta(1)), 1, True),
                (i(now+timedelta(2)), 1, False),
                (i(now+timedelta(3)), 1, False)
        ]:
            self.assertFilter(
                {'type': 'marked-for-op', 'skew': skew}, inst, expected)

    def test_filter_action_date(self):
        now = datetime.now()
        yesterday = now - timedelta(1)
        tomorrow = now + timedelta(1)

        def i(d, action='stop'):
            return instance(Tags=[
                {"Key": "maid_status",
                 "Value": "not compliant: %s@%s" % (
                    action, d.strftime("%Y/%m/%d"))}])


        for ii, v in [
                (i(yesterday), True),
                (i(now), True),
                (i(tomorrow), False),
                (i(yesterday, 'terminate'), False)
        ]:
            self.assertFilter({'type': 'marked-for-op'}, ii, v)


class EventFilterTest(BaseFilterTest):

    def test_event_filter(self):
        event = event_data('event-instance-state.json')
        f = {'type': 'event',
             'key': 'detail.state',
             'value': 'pending'}
        self.assertTrue(filters.factory(f).process(
            [instance()], event))

        
class TestInstanceValue(BaseFilterTest):

    def test_filter_tag_count(self):
        tags = []
        for i in range(10):
            tags.append({'Key': str(i), 'Value': str(i)})
        i = instance(Tags=tags)
        self.assertFilter(
            {'type': 'tag-count'}, i, False)
        tags.pop(0)
        i = instance(Tags=tags)
        self.assertFilter(
            {'type': 'tag-count'}, i, True)

    def test_filter_tag(self):
        i = instance(Tags=[
            {'Key': 'ASV', 'Value': 'abcd'}])
        self.assertFilter(
            {'tag:ASV': 'def'}, i, False)
        self.assertEqual(
            annotation(i, base_filters.ANNOTATION_KEY), ())

        i = instance(Tags=[
            {'Key': 'CMDB', 'Value': 'abcd'}])
        self.assertFilter(
            {'tag:ASV': 'absent'}, i, True)
        self.assertEqual(
            annotation(i, base_filters.ANNOTATION_KEY), ['tag:ASV'])

    def test_jmespath(self):
        self.assertFilter(
            {'Placement.AvailabilityZone': 'us-east-1b'},
            instance(),
            True)

        self.assertFilter(
            {'Placement.AvailabilityZone': 'us-east-1c'},
            instance(),
            False)

    def test_complex_validator(self):
        self.assertRaises(
            base_filters.FilterValidationError,
            filters.factory,
            {"key": "xyz",
             "type": "value"})
        self.assertRaises(
            base_filters.FilterValidationError,
            filters.factory,
            {"value": "xyz",
             "type": "value"})
        self.assertRaises(
            base_filters.FilterValidationError,
            filters.factory,
            {"key": "xyz",
             "value": "xyz",
             "op": "oo",
             "type": "value"})

    def test_complex_value_filter(self):
        self.assertFilter(
            {"key": "length(BlockDeviceMappings[?Ebs.DeleteOnTermination == `false`].Ebs.DeleteOnTermination)",
             "value": 0,
             "type": "value",
             "op": "gt"},
            instance(),
            True)

    def test_not_null_filter(self):
        self.assertFilter(
            {"key": "tag:aws:cloudformation:stack-name",
             "value": "not-null",
             "type": "value"},
            instance(),
            True)

if __name__ == '__main__':
    unittest.main()
