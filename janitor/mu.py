"""Lambda Integration

Mu is the letter after lambda, lambda is a keyword in python.


"""
import inspect
import os
import tempfile
import shutil

from kappa.context import Context

from janitor.action import BaseAction
from janitor import jobs


class LambdaAction(BaseAction):

    def process(self, resources):
        config = self.generate_lambda(resources)
        ctx = Context(**config)
        ctx.create()

    def generate_lambda(self):
        return

    
class KappaAction(LambdaAction):

    def generate_lambda(self):
        kappa_dir = os.path.abspath(self.data.get('kappa_dir'))
        if not os.path.isdir(kappa_dir):
            raise AssertionError(
                "Could not find kappa/lambda dir %s" % kappa_dir)
        return Context(os.path.join(kappa_dir))
    
        
class S3Crypter(LambdaAction):

    files = ('s3crypter.py',)

    def process(self, resources):
        config_file, debug = self.generate_lambda(resources)
        ctx = Context(config_file, debug)
        ctx.create()
    
    def generate_lambda(self, resources):
        mud = tempfile.mkdtemp()
        os.path.create(mud)
        self.copy_job_files(mud)
        fh = self.generate_job_config()
        return fh, True
    
    def copy_job_files(self, mud):
        job_dir = os.path.dirname(inspect.getabspath(jobs))
        shutil.copy2(
            os.path.join(job_dir, 's3crypter.py'),
            os.path.join(mud, 'lambda_handler.py'))

    def generate_job_config(self):
        pass
