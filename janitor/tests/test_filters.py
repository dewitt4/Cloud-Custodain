
import unittest
import cPickle

from janitor import filters
from janitor.utils import annotation
from .common import Instance, instance




class TestFilter(unittest.TestCase):

    def test_filter_construction(self):
        self.assertTrue(
            isinstance(
                filters.factory({'tag:ASV': 'absent'}),
                filters.ValueFilter))

    def test_filter_validation(self):
        self.assertRaises(
            filters.FilterValidationError,
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

        
class TestInstanceValueFilter(unittest.TestCase):

    def _filter(self, f, i, v):
        self.assertEqual(filters.factory(f)(i), v)

        
    def test_filter_tag(self):
        i = instance(Tags=[
            {'Key': 'ASV', 'Value': 'abcd'}])
        self._filter(
            {'tag:ASV': 'def'}, i, False)
        self.assertEqual(
            annotation(i, filters.ANNOTATION_KEY), ())

        i = instance(Tags=[
            {'Key': 'CMDB', 'Value': 'abcd'}])
        self._filter(
            {'tag:ASV': 'absent'}, i, True)
        self.assertEqual(
            annotation(i, filters.ANNOTATION_KEY), ['tag:ASV'])

    def test_jmespath(self):
        self._filter(
            {'Placement.AvailabilityZone': 'us-east-1b'},
            instance(),
            True)

        self._filter(
            {'Placement.AvailabilityZone': 'us-east-1c'},
            instance(),
            False)

    def test_complex_validator(self):
        self.assertRaises(
            filters.FilterValidationError,
            filters.factory,
            {"key": "xyz",
             "type": "value"})
        self.assertRaises(
            filters.FilterValidationError,
            filters.factory,
            {"value": "xyz",
             "type": "value"})        
        self.assertRaises(
            filters.FilterValidationError,
            filters.factory,
            {"key": "xyz",
             "value": "xyz",
             "op": "oo",
             "type": "value"})        

                
    def test_complex_value_filter(self):
        self._filter(
            {"key": "length(BlockDeviceMappings[?Ebs.DeleteOnTermination == `false`].Ebs.DeleteOnTermination)",
             "value": 0,
             "type": "value",
             "op": "gt"},
            instance(),
            True)

    


if __name__ == '__main__':
    unittest.main()
        
