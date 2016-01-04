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

    def test_full(self):
        formatter = RECORD_TYPE_FORMATTERS.get("ec2")
        records = [self.records['full']]
        rows = formatter.to_csv(records)
        self.assertEqual(rows, [self.rows['full']])

    def test_minimal(self):
        formatter = RECORD_TYPE_FORMATTERS.get("ec2")
        records = [self.records['minimal']]
        rows = formatter.to_csv(records)
        self.assertEqual(rows, [self.rows['minimal']])

    def test_both(self):
        formatter = RECORD_TYPE_FORMATTERS.get("ec2")
        records = [self.records['full'], self.records['minimal']]
        rows = formatter.to_csv(records)
        self.assertEqual(rows, [self.rows['full'], self.rows['minimal']])

    def test_duplicate(self):
        formatter = RECORD_TYPE_FORMATTERS.get("ec2")
        records = [self.records['full'], self.records['duplicate'], self.records['minimal']]
        rows = formatter.to_csv(records)
        self.assertEqual(rows, [self.rows['full'], self.rows['minimal']])

    def test_terminated(self):
        formatter = RECORD_TYPE_FORMATTERS.get("ec2")
        records = [self.records['full'], self.records['terminated'], self.records['minimal']]
        rows = formatter.to_csv(records)
        self.assertEqual(rows, [self.rows['full'], self.rows['minimal']])


class TestASGReport(unittest.TestCase):
    def setUp(self):
        data = load_data('report.json')
        self.records = data['asg']['records']
        self.headers = data['asg']['headers']
        self.rows = data['asg']['rows']
        for rec in self.records.values():
            rec['MaidDate'] = date_parse(rec['MaidDate'])

    def test_full(self):
        formatter = RECORD_TYPE_FORMATTERS.get("asg")
        records = [self.records['full']]
        rows = formatter.to_csv(records)
        self.assertEqual(rows, [self.rows['full']])

    def test_minimal(self):
        formatter = RECORD_TYPE_FORMATTERS.get("asg")
        records = [self.records['minimal']]
        rows = formatter.to_csv(records)
        self.assertEqual(rows, [self.rows['minimal']])

    def test_both(self):
        formatter = RECORD_TYPE_FORMATTERS.get("asg")
        records = [self.records['full'], self.records['minimal']]
        rows = formatter.to_csv(records)
        self.assertEqual(rows, [self.rows['full'], self.rows['minimal']])

    def test_duplicate(self):
        formatter = RECORD_TYPE_FORMATTERS.get("asg")
        records = [self.records['full'], self.records['duplicate'], self.records['minimal']]
        rows = formatter.to_csv(records)
        self.assertEqual(rows, [self.rows['full'], self.rows['minimal']])
