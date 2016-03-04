"""
Offhours support
================

Turn resources off based on a schedule. There are two usage modes that
can be configured, opt-in with resources that wish to participate specifying
a tag value with their configuration for offhours. Additionally opt-out
where the schedule is set to apply to all resources that match the policy
filters, resources can specify a tag value then to allow opt-out behavior.

Schedules
=========

The default off hours and on hours are specified per the policy configuration
along with the opt-in/opt-out behavior. Resources can specify the timezone
that they wish to have this scheduled utilized with.


Tag Based Configuration
=======================

Note the tag name is configurable per policy configuration, examples below use
default tag name, ie. maid_downtime.

- maid_offhours: 

An empty tag value implies night and weekend offhours using the default
time zone configured in the policy (tz=est if unspecified).

- maid_offhours: tz=pt

Note all timezone aliases are referenced to a locality to ensure taking into
account local daylight savings time (if any).

- maid_offhours: tz=Americas/Los_Angeles

A geography can be specified but must be in the time zone database. 

Per http://www.iana.org/time-zones

- maid_offhours: off

If offhours is configured to run in opt-out mode, this tag can be specified
to disable offhours on a given instance.


Policy examples
===============

Turn ec2 instances on and off

.. code-block:: yaml

   policies:
     - name: offhours-stop
       resource: ec2
       filters:
          - offhours
       actions:
         - stop
   
     - name: offhours-start
       resource: ec2
       filters:
         - onhours
       actions:
         - start

Here's doing the same with auto scale groups

.. code-block:: yaml

    policies:
      - name: asg-offhours-stop
        resource: ec2
        filters:
           - offhours
        actions:
           - suspend
      - name: asg-onhours-start
        resource: ec2
        filters:
           - onhours
        actions:
           - resume
     

Options
=======

- tag: the tag name to use when configuring
- default_tz: the default timezone to use when interpreting offhours
- offhour: the time to turn instances off, specified in 0-24
- onhour: the time to turn instances on, specified in 0-24

.. code-block:: yaml

   policies:
     - name: offhours-stop
       resource: ec2
       filters:
         - type: offhours
           tag: downtime
           onhour: 8
           offhour: 20

TODO:
 
Also support one time use instances for quickly trying something out,
but wanting to turn terminate it after a length of time (like one
week, one month, etc).

Terminate after time period

- maid_offhours: terminate 1w

- maid_offhours: terminate 3d

- maid_offhours: terminate 3h

"""
from janitor.filters import Filter

import datetime

from dateutil import zoneinfo


TZ_ALIASES = {
    'pdt': 'America/Los_Angeles',
    'pt': 'America/Los_Angeles',
    'pst': 'America/Los_Angeles',
    'est': 'America/New_York',
    'edt': 'America/New_York',
    'et': 'America/New_York',
    'cst': 'America/Chicago',
    'cdt': 'America/Chicago',
    'ct': 'America/Chicago',
    'mt': 'America/Denver',
    'gmt': 'Europe/London',
    'gt': 'Europe/London'
}

TIME_ALIASES = {
    'w': 'week',
    'd': 'day',
    'm': 'month',
    'y': 'year'
}

DEFAULT_OFFHOUR = 19
DEFAULT_ONHOUR = 7
DEFAULT_TZ = 'et'


class Time(Filter):

    # Allow up to this many hours after sentinel time
    # to continue to match
    skew = 0

    def __init__(self, data, manager=None):
        super(Time, self).__init__(data, manager)
        self.skew = self.data.get('skew', self.skew)
        self.weekends = self.data.get('weekends', False)
        self.opt_out = self.data.get('opt-out', False)
        
    def __call__(self, i):
        parts, tag_map = self.get_tag_parts(i)
        if parts is False:
            if self.opt_out:
                parts = []
            else:
                return False
        if 'off' in parts:
            return False
        return self.process_current_time(i, parts)

    def process_terminate(self, i, parts):
        parts.pop('terminate')
        for p in parts:
            for t in TIME_ALIASES:
                pass
        return False

    def process_current_time(self, tag_map, parts):
        tz = self.get_local_tz(parts)
        if not tz:
            return False
        now = datetime.datetime.now(tz).replace(
            minute=0, second=0, microsecond=0)

        if not self.weekends and now.weekday() in (5, 6):
            return False

        sentinel = self.get_sentinel_time(tz)

        self.log.info("offhours compare %s to %s" % (
            now, sentinel))
        if sentinel == now:
            return True
        if not self.skew:
            return False
        hour = sentinel.hour
        for i in range(1, self.skew + 1):
            sentinel = sentinel.replace(hour=hour+i)
            if sentinel == now:
                return True
        return False

    def get_tag_parts(self, i):
        # Look for downtime tag, Normalize tag key and tag value
        tag_key = self.data.get('tag', 'maid_offhours').lower()
        tag_map = {t['Key'].lower(): t['Value'] for t in i.get('Tags', [])}
        if tag_key not in tag_map:
            return False, tag_map
        value = tag_map[tag_key].lower()
        # Sigh.. some folks seem to be interpreting the docs quote marks as
        # literal for values.
        value = value.strip("'").strip('"')
        self.log.debug('offhours instance %s %s' % (
            tag_map.get('name', ''), value))
        parts = filter(None, value.split())
        return parts, tag_map

    def get_sentinel_time(self, tz):
        t = datetime.datetime.now(tz)
        return t.replace(
            hour=self.data.get('hour', 0),
            minute=self.data.get('minute', 0),
            second=0,
            microsecond=0
            )
        

    def get_local_tz(self, parts):
        tz_spec = None
        for p in parts:
            if p.startswith('tz='):
                tz_spec = p
                break
        if tz_spec is None:
            tz_spec = (
                self.data.get('default_tz') or
                self.data.get('default-tz', DEFAULT_TZ))
        else:
            _, tz_spec = tz_spec.split('=')

        if tz_spec in TZ_ALIASES:
            tz_spec = TZ_ALIASES[tz_spec]
        tz = zoneinfo.gettz(tz_spec)
        if tz is None:
            self.log.warning(
                "filter:offhours unknown tz %s for %s" % (
                    tz_spec, parts))
                    
            return None
        return tz
    

class OffHour(Time):

    def get_sentinel_time(self, tz):
        t = super(OffHour, self).get_sentinel_time(tz)
        return t.replace(hour=self.data.get('offhour', DEFAULT_OFFHOUR))

                         
class OnHour(Time):

    def get_sentinel_time(self, tz):
        t = super(OnHour, self).get_sentinel_time(tz)
        return t.replace(hour=self.data.get('onhour', DEFAULT_ONHOUR))

    
    

