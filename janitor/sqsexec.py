"""

concurrent.futures implementation over sqs



"""

import random
import threading

from janitor import utils


class SQSExecutor(object):

    def __init__(self, session_factory, map_queue, reduce_queue):
        self.session_factory = session_factory
        self.map_queue = map_queue
        self.reduce_queue = reduce_queue
        self.sqs = utils.local_session(self.session_factory).client('sqs')
        self.op_sequence = int(random.random() * 1000000)
        self.futures = {}
        self.threads = set()
        self._shutdown_lock = threading.Lock()
        self._shutdown = False
        
    def submit(self, func, *args, **kwargs):
        with self._shutdown_lock:
            if self._shutdown:
               raise RuntimeError("cannot schedule new futures after shutdown")

            self.op_sequence += 1
            self.sqs.send_message(
                QueueUrl=self.map_queue,
                MessageBody=utils.dumps(args),
                MessageAttributes={
                    'sequence_id': {
                        'StringValue': str(self.op_sequence),
                        'DataType': 'Number'},
                    'ser': {
                        'StringValue': 'json',
                        'DataType': 'String'}}
            )
            self.futures[self.op_sequence] = f = SQSFuture(
                self.op_sequence)
            return f
        
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False



class SQSWorker(object):

    stopped = None
    
    def run(self):
        while True:
            self.loop_iteration()
            
    def loop_iteration(self):
        response = self.client.receive_message(
            QueueUrl=self.queue_url,
            WaitTimeSeconds=120)

        for m in response.get('Messages', []):
            msg = utils.loads(m['Body'])
            if msg['op'] == 'Stop':
                raise KeyboardInterrupt("Stop message received")
            op_name = msg['op']
            
            return op_name


class SQSFuture(object):

    marker = object()
               
    def __init__(self, sequence_id):
        self.sequence_id = sequence_id
        self.value = self.marker
               
    def cancel(self):
        return False

    def cancelled(self):
        return False

    def exception(self):
        return None

    def done(self):
        return self.value != self.marker

    def result(self, timeout=None):
        return self.value
    
    def add_done_callback(self, fn):
        return fn(self)
