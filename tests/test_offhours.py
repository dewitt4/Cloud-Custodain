import datetime
from dateutil import zoneinfo

from mock import mock

from .common import BaseTest, instance

from janitor.offhours import OffHour, OnHour


class OffHoursFilterTest(BaseTest):

    def test_current_time_test(self):
        t = datetime.datetime(
            year=2015, month=12, day=1, hour=19, minute=5,
            tzinfo=zoneinfo.gettz('America/New_York'))
        with mock.patch('datetime.datetime') as dt:
            dt.now.side_effect = lambda tz=None: t        
            i = instance(Tags=[
                {'Key': 'maid_offhours', 'Value': 'tz=est'}])
            f = OffHour({})
            p = f.get_tag_parts(i)
            self.assertEqual(p, ['tz=est'])
            tz = f.get_local_tz(p)
            self.assertEqual(str(tz), "tzfile('America/New_York')")
            self.assertEqual(
                datetime.datetime.now(tz), t)
            self.assertEqual(t.hour, 19)

    def test_offhours_real_world_values(self):
        t = datetime.datetime(year=2015, month=12, day=1, hour=19, minute=5,
                              tzinfo=zoneinfo.gettz('America/New_York'))
        with mock.patch('datetime.datetime') as dt:
            dt.now.side_effect = lambda tz=None: t
            for i in [
                    instance(Tags=[
                        {'Key': 'maid_offhours', 'Value': ''}]),
                    instance(Tags=[
                        {'Key': 'maid_offhours', 'Value': '"Offhours tz=ET"'}]),
                    instance(Tags=[
                        {'Key': 'maid_offhours', 'Value': 'Offhours tz=PT'}])]:
                self.assertEqual(OffHour({})(i), True)
        
    def test_offhours(self):
        t = datetime.datetime(year=2015, month=12, day=1, hour=19, minute=5,
                              tzinfo=zoneinfo.gettz('America/New_York'))
        with mock.patch('datetime.datetime') as dt:
            dt.now.side_effect = lambda tz=None: t
            i = instance(Tags=[
                {'Key': 'maid_offhours', 'Value': 'tz=est'}])
            self.assertEqual(OffHour({})(i), True)
        
    def test_onhour(self):
        t = datetime.datetime(year=2015, month=12, day=1, hour=7, minute=5,
                              tzinfo=zoneinfo.gettz('America/New_York'))
        with mock.patch('datetime.datetime') as dt:
            dt.now.side_effect = lambda tz: t    
            i = instance(Tags=[
                {'Key': 'maid_offhours', 'Value': 'tz=est'}])
            self.assertEqual(OnHour({})(i), True)
            self.assertEqual(OnHour({'onhour': 8})(i), False)
        
    def test_cant_parse_tz(self):
        i = instance(Tags=[
            {'Key': 'maid_offhours', 'Value': 'tz=evt'}])
        self.assertEqual(OffHour({})(i), False)


        
        
