import unittest

from dateutil.parser import parse as date_parse

from janitor.report import RECORD_TYPE_FORMATTERS
from janitor.tests.common import load_data

class TestEC2Report(unittest.TestCase):
    def setUp(self):
        data = load_data('report.json')
        self.records = data['ec2']['records']
        self.headers = data['ec2']['headers']
        self.rows = data['ec2']['rows']
        for rec in self.records.values():
            rec['MaidDate'] = date_parse(rec['MaidDate'])

    def test_csv(self):
        formatter = RECORD_TYPE_FORMATTERS.get("ec2")
        tests = [
            ([self.records['full']],
             [self.rows['full']]),
            ([self.records['minimal']],
             [self.rows['minimal']]),
            ([self.records['full'], self.records['minimal']],
             [self.rows['full'], self.rows['minimal']]),
            ([self.records['full'], self.records['duplicate'], self.records['minimal']],
             [self.rows['full'], self.rows['minimal']]),
            ([self.records['full'], self.records['terminated'], self.records['minimal']],
             [self.rows['full'], self.rows['minimal']])]
        for recs, rows in tests:
            self.assertEqual(formatter.to_csv(recs), rows)


class TestASGReport(unittest.TestCase):
    def setUp(self):
        data = load_data('report.json')
        self.records = data['asg']['records']
        self.headers = data['asg']['headers']
        self.rows = data['asg']['rows']
        for rec in self.records.values():
            rec['MaidDate'] = date_parse(rec['MaidDate'])

    def test_csv(self):
        formatter = RECORD_TYPE_FORMATTERS.get("asg")
        tests = [
            ([self.records['full']],
             [self.rows['full']]),
            ([self.records['minimal']],
             [self.rows['minimal']]),
            ([self.records['full'], self.records['minimal']],
             [self.rows['full'], self.rows['minimal']]),
            ([self.records['full'], self.records['duplicate'], self.records['minimal']],
             [self.rows['full'], self.rows['minimal']])]
        for recs, rows in tests:
            self.assertEqual(formatter.to_csv(recs), rows)
