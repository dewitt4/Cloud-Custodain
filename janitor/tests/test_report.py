import unittest
import datetime

from janitor import report
from janitor.report import RECORD_TYPE_FORMATTERS, fmt_csv

class TestReport(unittest.TestCase):
    full_record = {"MaidDate": datetime.datetime(2015, 12, 23),
                   "State": {"Name": "running"},
                   "InstanceId": "InstanceId-1",
                   "InstanceType": "InstanceType-1",
                   "LaunchTime": "LaunchTime-1",
                   "VpcId": "VpcId-1",
                   "PrivateIpAddress": "PrivateIpAddress-1",
                   "IgnoredField": "IgnoredValue",
                   "Tags": [
                       {"Key": "Name", "Value": "Name-1"},
                       {"Key": "ASV", "Value": "ASV-1"},
                       {"Key": "CMDBEnvironment", "Value": "CMDBEnvironment-1"},
                       {"Key": "OwnerContact", "Value": "OwnerContact-1"},
                   ]
                   }
    minimal_record = {"MaidDate": datetime.datetime(2015, 12, 22),
                      "State": {"Name": "running"},
                      "InstanceId": "InstanceId-2",
                      "InstanceType": "InstanceType-2",
                      "LaunchTime": "LaunchTime-2",
                      "Tags": [],
                      "IgnoredField": "IgnoredValue",
                      }
    # same InstanceId as minimal, but older
    duplicate_record = {"MaidDate": datetime.datetime(2015, 12, 20),
                        "State": {"Name": "running"},
                        "InstanceId": "InstanceId-2",
                        "InstanceType": "InstanceType-2",
                        "LaunchTime": "LaunchTime-2",
                        "Tags": [],
                        "IgnoredField": "IgnoredValue",
                        }
    terminated_record = {"MaidDate": datetime.datetime(2015, 12, 21),
                         "State": {"Name": "terminated"},
                         "InstanceId": "InstanceId-3",
                         "InstanceType": "InstanceType-3",
                         "LaunchTime": "LaunchTime-3",
                         "Tags": [],
                         "IgnoredField": "IgnoredValue",
                         }
    header_rows = [
        'MaidDate',
        'InstanceId',
        'Name',
        'InstanceType',
        'LaunchTime',
        'VpcId',
        'PrivateIpAddress',
        'ASV',
        'CMDBEnvironment',
        'OwnerContact'
    ]

    full_rows = [
        '2015-12-23',
        'InstanceId-1',
        'Name-1',
        'InstanceType-1',
        'LaunchTime-1',
        'VpcId-1',
        'PrivateIpAddress-1',
        'ASV-1',
        'CMDBEnvironment-1',
        'OwnerContact-1'
    ]

    minimal_rows = [
        '2015-12-22',
        'InstanceId-2',
        '',
        'InstanceType-2',
        'LaunchTime-2',
        '',
        '',
        '',
        '',
        ''
    ]


    def test_full(self):
        formatter = RECORD_TYPE_FORMATTERS.get("ec2")
        records = [TestReport.full_record]
        records = report.unique(records, formatter.id_field, filters=formatter.filters)
        rows = map(lambda record: fmt_csv(record, formatter.extractor), records)

        self.assertEqual(rows, [TestReport.full_rows])


    def test_minimal(self):
        formatter = RECORD_TYPE_FORMATTERS.get("ec2")
        records = [TestReport.minimal_record]
        records = report.unique(records, formatter.id_field, filters=formatter.filters)
        rows = map(lambda record: fmt_csv(record, formatter.extractor), records)

        self.assertEqual(rows, [TestReport.minimal_rows])


    def test_both(self):
        formatter = RECORD_TYPE_FORMATTERS.get("ec2")
        records = [TestReport.full_record, TestReport.minimal_record]
        records = report.unique(records, formatter.id_field, filters=formatter.filters)
        rows = map(lambda record: fmt_csv(record, formatter.extractor), records)

        self.assertEqual(rows, [TestReport.full_rows, TestReport.minimal_rows])


    def test_duplicate(self):
        formatter = RECORD_TYPE_FORMATTERS.get("ec2")
        records = [TestReport.full_record, TestReport.duplicate_record, TestReport.minimal_record]
        records = report.unique(records, formatter.id_field, filters=formatter.filters)
        rows = map(lambda record: fmt_csv(record, formatter.extractor), records)

        self.assertEqual(rows, [TestReport.full_rows, TestReport.minimal_rows])


    def test_terminated(self):
        formatter = RECORD_TYPE_FORMATTERS.get("ec2")
        records = [TestReport.full_record, TestReport.terminated_record, TestReport.minimal_record]
        records = report.unique(records, formatter.id_field, filters=formatter.filters)
        rows = map(lambda record: fmt_csv(record, formatter.extractor), records)

        self.assertEqual(rows, [TestReport.full_rows, TestReport.minimal_rows])