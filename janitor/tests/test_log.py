import boto3
import placebo
import time
import unittest
import logging

from janitor.log import CloudWatchLogHandler
from janitor.tests.common import placebo_dir


class LogTest(unittest.TestCase):

    def test_existing_stream(self):
        
        def session_factory():
            s = boto3.Session()
            pill = placebo.attach(s, placebo_dir('test_log_existing_stream'))
            pill.playback()
            return s
        
        handler = CloudWatchLogHandler(session_factory=session_factory)
        log = logging.getLogger("maid")
        log.addHandler(handler)
        log.setLevel(logging.DEBUG)

        for i in range(100, 115):
            log.info('hello world %s' % i)

        log.removeHandler(handler)
        handler.flush()
        handler.close()

    def test_time_flush(self):

        def session_factory():
            s = boto3.Session()
            pill = placebo.attach(s, placebo_dir('test_log_time_flush'))
            pill.playback()
            return s
        
        log = logging.getLogger("test-maid")
        handler = CloudWatchLogHandler("test-maid-4", "alpha", session_factory=session_factory)
        handler.batch_interval = 1
        log.addHandler(handler)
        log.setLevel(logging.DEBUG)

        for i in range(100, 105):
            log.info('hello world %s' % i)

        time.sleep(1.1)
        log.info('bye world')
        self.assertFalse(handler.buf)
        

if __name__ == '__main__':
    unittest.main()
