# Token Bucket Rate Limiting
# License: MIT
# Author: Esteban Castro Borsani @ 2013/9/16
# http://code.activestate.com/recipes/578659-python-3-token-bucket-rate-limit/
# token_bucket.py


from time import time
from threading import Lock


class TokenBucket:
    """
    An implementation of the token bucket algorithm.
    """
    def __init__(self, rate=0):
        self.tokens = rate
        self.rate = rate
        self.last = time()
        self.lock = Lock()
        
    def set_rate(self, rate):
        with self.lock:
            self.rate = rate
            self.tokens = self.rate

    def consume(self, tokens):
        with self.lock:
            if not self.rate:
                return 0
        
            now = time()
            lapse = now - self.last

            self.last = now
            self.tokens += lapse * self.rate
            
            if self.tokens > self.rate:
                self.tokens = self.rate

            self.tokens -= tokens

            if self.tokens >= 0:
                return 0
            else:
                return -self.tokens / self.rate
