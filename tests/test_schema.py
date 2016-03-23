import json

from jsonschema.exceptions import best_match

from maid.schema import Validator, validate, generate, specific_error
from common import BaseTest


class SchemaTest(BaseTest):

    validator = None

    def findError(self, data, validator):
        e = best_match(validator.iter_errors(data))
        ex = specific_error(list(validator.iter_errors(data))[0])
        return e, ex
        
    def setUp(self):
        if not self.validator:
            self.validator = Validator(generate())

    def test_schema(self):
        try:
            schema = generate()
            Validator.check_schema(schema)
        except Exception:
            raise
            self.fail("Invalid schema")

    def test_basic_skelton(self):
        self.assertEqual(validate({'policies': []}), [])

    def test_invalid_resource_type(self):
        data = {
            'policies': [
                {'name': 'instance-policy',
                 'resource': 'ec3',
                 'filters': []}]}
        errors = list(self.validator.iter_errors(data))
        self.assertEqual(len(errors), 1)

    def test_value_filter_short_form_invalid(self):
        for rtype in ["elb", "rds", "ec2"]:
            data = {
                'policies': [
                    {'name': 'instance-policy',
                     'resource': 'elb',
                     'filters': [
                         {"tag:Role": "webserver"}]}
                ]}
            schema = generate([rtype])
            # Disable standard value short form
            schema['definitions']['filters']['valuekv'] = {'type': 'number'}
            validator = Validator(schema)
            errors = list(validator.iter_errors(data))
            self.assertEqual(len(errors), 1)

    def test_value_filter_short_form(self):
        data = {
            'policies': [
                {'name': 'instance-policy',
                 'resource': 'elb',
                 'filters': [
                     {"tag:Role": "webserver"}]}
                ]}

        errors = list(self.validator.iter_errors(data))
        self.assertEqual(errors, [])

    def test_offhours_stop(self):
        data = {
            'policies': [
                {'name': 'ec2-offhours-stop',
                 'resource': 'ec2',
                 'filters': [
                     {'tag:aws:autoscaling:groupName': 'absent'},
                     {'type': 'offhour',
                      'tag': 'maid_downtime',
                      'default_tz': 'et',
                      'hour': 19}]
                 }]
            }
        schema = generate(['ec2'])
        validator = Validator(schema)
        errors = list(validator.iter_errors(data))
        self.assertEqual(len(errors), 0)

    def test_instance_age(self):
        data = {
            'policies': [
                {'name': 'ancient-instances',
                 'resource': 'ec2',
                 'query': [{'instance-state-name': 'running'}],
                 'filters': [{'days': 60, 'type': 'instance-age'}]
             }]}
        schema = generate(['ec2'])
        validator = Validator(schema)
        errors = list(validator.iter_errors(data))
        self.assertEqual(len(errors), 0)

    def test_mark_for_op(self):
        data = {
            'policies': [{
                'name': 'ebs-mark-delete',
                'resource': 'ebs',
                'filters': [],
                'actions': [{
                    'type': 'mark-for-op',
                    'op': 'delete',
                    'days': 30}]}]
            }
        schema = generate(['ebs'])
        validator = Validator(schema)

        errors = list(validator.iter_errors(data))
        self.assertEqual(len(errors), 0)

