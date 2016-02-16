import time
import unittest
import logging

from janitor.log import CloudWatchLogHandler
from .common import BaseTest


class LogTest(BaseTest):

    def test_existing_stream(self):
        session_factory = self.replay_flight_data('test_log_existing_stream')
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
        session_factory = self.replay_flight_data('test_log_time_flush')
        log = logging.getLogger("test-maid")
        handler = CloudWatchLogHandler(
            "test-maid-4", "alpha", session_factory=session_factory)
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
