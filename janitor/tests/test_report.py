import unittest
import datetime

from janitor import report
from janitor.report import RECORD_TYPE_FORMATTERS

class TestEC2Report(unittest.TestCase):
    def setUp(self):
        self.full_record = {"MaidDate": datetime.datetime(2015, 12, 23),
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
                                {"Key": "OwnerContact", "Value": "OwnerContact-1"}]}
        self.minimal_record = {"MaidDate": datetime.datetime(2015, 12, 22),
                               "State": {"Name": "running"},
                               "InstanceId": "InstanceId-2",
                               "InstanceType": "InstanceType-2",
                               "LaunchTime": "LaunchTime-2",
                               "Tags": [],
                               "IgnoredField": "IgnoredValue"}
        # same InstanceId as minimal, but older
        self.duplicate_record = {"MaidDate": datetime.datetime(2015, 12, 20),
                                 "State": {"Name": "running"},
                                 "InstanceId": "InstanceId-2",
                                 "InstanceType": "InstanceType-2",
                                 "LaunchTime": "LaunchTime-2",
                                 "Tags": [],
                                 "IgnoredField": "IgnoredValue"}
        self.terminated_record = {"MaidDate": datetime.datetime(2015, 12, 21),
                                  "State": {"Name": "terminated"},
                                  "InstanceId": "InstanceId-3",
                                  "InstanceType": "InstanceType-3",
                                  "LaunchTime": "LaunchTime-3",
                                  "Tags": [],
                                  "IgnoredField": "IgnoredValue"}
        self.header_rows = [
            'MaidDate',
            'InstanceId',
            'Name',
            'InstanceType',
            'LaunchTime',
            'VpcId',
            'PrivateIpAddress',
            'ASV',
            'CMDBEnvironment',
            'OwnerContact']

        self.full_rows = [
            '2015-12-23',
            'InstanceId-1',
            'Name-1',
            'InstanceType-1',
            'LaunchTime-1',
            'VpcId-1',
            'PrivateIpAddress-1',
            'ASV-1',
            'CMDBEnvironment-1',
            'OwnerContact-1']

        self.minimal_rows = [
            '2015-12-22',
            'InstanceId-2',
            '',
            'InstanceType-2',
            'LaunchTime-2',
            '',
            '',
            '',
            '',
            '']


    def test_full(self):
        formatter = RECORD_TYPE_FORMATTERS.get("ec2")
        records = [self.full_record]
        rows = formatter.to_csv(records)
        self.assertEqual(rows, [self.full_rows])


    def test_minimal(self):
        formatter = RECORD_TYPE_FORMATTERS.get("ec2")
        records = [self.minimal_record]
        rows = formatter.to_csv(records)
        self.assertEqual(rows, [self.minimal_rows])


    def test_both(self):
        formatter = RECORD_TYPE_FORMATTERS.get("ec2")
        records = [self.full_record, self.minimal_record]
        rows = formatter.to_csv(records)
        self.assertEqual(rows, [self.full_rows, self.minimal_rows])


    def test_duplicate(self):
        formatter = RECORD_TYPE_FORMATTERS.get("ec2")
        records = [self.full_record, self.duplicate_record, self.minimal_record]
        rows = formatter.to_csv(records)
        self.assertEqual(rows, [self.full_rows, self.minimal_rows])


    def test_terminated(self):
        formatter = RECORD_TYPE_FORMATTERS.get("ec2")
        records = [self.full_record, self.terminated_record, self.minimal_record]
        rows = formatter.to_csv(records)
        self.assertEqual(rows, [self.full_rows, self.minimal_rows])


class TestASGReport(unittest.TestCase):
    def setUp(self):
        self.full_record = {"MaidDate": datetime.datetime(2015, 12, 23),
                            "AutoScalingGroupName": "AutoScalingGroupName-1",
                            "Instances": ["Instance-1", "Instance-2", "Instance-3"], 
                            "LaunchTime": "LaunchTime-1",
                            "VpcId": "VpcId-1",
                            "PrivateIpAddress": "PrivateIpAddress-1",
                            "IgnoredField": "IgnoredValue",
                            "Tags": [
                                {"Key": "Name", "Value": "Name-1"},
                                {"Key": "ASV", "Value": "ASV-1"},
                                {"Key": "CMDBEnvironment", "Value": "CMDBEnvironment-1"},
                                {"Key": "OwnerContact", "Value": "OwnerContact-1"}]}
        self.minimal_record = {"MaidDate": datetime.datetime(2015, 12, 22),
                               "AutoScalingGroupName": "AutoScalingGroupName-2",
                            "Instances": [], 
                               "LaunchTime": "LaunchTime-2",
                               "Tags": [],
                               "IgnoredField": "IgnoredValue"}
        # same AutoScalingGroupName as minimal, but older
        self.duplicate_record = {"MaidDate": datetime.datetime(2015, 12, 20),
                                 "AutoScalingGroupName": "AutoScalingGroupName-2",
                            "Instances": [], 
                                 "LaunchTime": "LaunchTime-2",
                                 "Tags": [],
                                 "IgnoredField": "IgnoredValue"}
        self.header_rows = [
            'AutoScalingGroupName',
            'Instances',
            'ASV',
            'CMDBEnvironment',
            'OwnerContact']

        self.full_rows = [
            'AutoScalingGroupName-1',
            '3',
            'ASV-1',
            'CMDBEnvironment-1',
            'OwnerContact-1']

        self.minimal_rows = [
            'AutoScalingGroupName-2',
            '0',
            '',
            '',
            '']


    def test_full(self):
        formatter = RECORD_TYPE_FORMATTERS.get("asg")
        records = [self.full_record]
        rows = formatter.to_csv(records)
        self.assertEqual(rows, [self.full_rows])


    def test_minimal(self):
        formatter = RECORD_TYPE_FORMATTERS.get("asg")
        records = [self.minimal_record]
        rows = formatter.to_csv(records)
        self.assertEqual(rows, [self.minimal_rows])


    def test_both(self):
        formatter = RECORD_TYPE_FORMATTERS.get("asg")
        records = [self.full_record, self.minimal_record]
        rows = formatter.to_csv(records)
        self.assertEqual(rows, [self.full_rows, self.minimal_rows])


    def test_duplicate(self):
        formatter = RECORD_TYPE_FORMATTERS.get("asg")
        records = [self.full_record, self.duplicate_record, self.minimal_record]
        rows = formatter.to_csv(records)
        self.assertEqual(rows, [self.full_rows, self.minimal_rows])