import os
import sys
from functools import partial

backend = None
environment = os.getenv('APP_ENV') or 'production'


class Backend(object):
  
  def report_exception(self, *args, **kwargs):
    pass

  def report(self, *args, **kwargs):
    print(args, kwargs)
    # pass

class RollbarBackend(object):
  
  def report_exception(self, *args, **kwargs):
    rollbar.report_exc_info(sys.exc_info(), *args, **kwargs)

  def report(self, *args, **kwargs):
    rollbar.report_message(*args, **kwargs)

if os.getenv('ROLLBAR_APP_TOKEN'):
  import rollbar
  rollbar.init(os.getenv('ROLLBAR_APP_TOKEN'), environment, allow_logging_basic_config=False)
  backend = RollbarBackend()
else:
  backend = Backend()

def report_exception(*args, **kwargs):
  backend.report_exception(*args, **kwargs)

def report(*args, **kwargs):
  backend.report(*args, **kwargs)