import unittest

from dateutil.parser import parse as date_parse

from janitor.report import RECORD_TYPE_FORMATTERS
from .common import load_data


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
            (['full'], ['full']),
            (['minimal'], ['minimal']),
            (['full', 'minimal'], ['full', 'minimal']),
            (['full', 'duplicate', 'minimal'], ['full', 'minimal']),
            (['full', 'terminated', 'minimal'], ['full', 'minimal'])]
        for rec_ids, row_ids in tests:
            recs = map(lambda x: self.records[x], rec_ids)
            rows = map(lambda x: self.rows[x], row_ids)
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
            (['full'], ['full']),
            (['minimal'], ['minimal']),
            (['full', 'minimal'], ['full', 'minimal']),
            (['full', 'duplicate', 'minimal'], ['full', 'minimal'])]
        for rec_ids, row_ids in tests:
            recs = map(lambda x: self.records[x], rec_ids)
            rows = map(lambda x: self.rows[x], row_ids)
            self.assertEqual(formatter.to_csv(recs), rows)
