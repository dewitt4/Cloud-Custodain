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
        self.addCleanup(log.removeHandler, handler)
        log.setLevel(logging.DEBUG)

        for i in range(100, 115):
            log.info('hello world %s' % i)

        handler.flush()
        handler.close()

    def test_time_flush(self):
        session_factory = self.replay_flight_data('test_log_time_flush')
        log = logging.getLogger("test-maid")
        handler = CloudWatchLogHandler(
            "test-maid-4", "alpha", session_factory=session_factory)
        handler.batch_interval = 1
        log.addHandler(handler)
        self.addCleanup(log.removeHandler, handler)
        log.setLevel(logging.DEBUG)

        for i in range(100, 105):
            log.info('hello world %s' % i)

        time.sleep(1.1)
        log.info('bye world')
        self.assertFalse(handler.buf)

    def test_transport_buffer_flush(self):
        session_factory = self.replay_flight_data(
            'test_transport_buffer_flush')
        log = logging.getLogger("test-maid")
        handler = CloudWatchLogHandler(
            "test-maid-4", "alpha", session_factory=session_factory)
        handler.batch_size = 5
        log.addHandler(handler)
        self.addCleanup(log.removeHandler, handler)
        log.setLevel(logging.DEBUG)

        for i in range(10):
            log.info("knock, knock %d" % i)

        handler.flush()
        self.assertFalse(handler.transport.buffers)
        

if __name__ == '__main__':
    unittest.main()
