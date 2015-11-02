
from dateutil import tz

from datetime import datetime, timedelta
import unittest

from janitor import filters as base_filters
from janitor.resources.ec2 import filters
from janitor.utils import annotation
from .common import instance


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
            self.assertFilter({'type': 'instance-age'}, ii, v)


class TestMarkedForAction(BaseFilterTest):

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
        
        
class TestInstanceValue(BaseFilterTest):

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

    def xtest_not_null_filter(self):
        self.assertFilter(
            {"key": "aws:cloudformation:stack-name:",
             "value": "not-null",
             "type": "value"},
            instance(),
            True)

if __name__ == '__main__':
    unittest.main()
        
