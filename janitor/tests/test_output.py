
import logging
import mock
import unittest
import shutil
import os

from janitor.output import S3Output


class S3OutputTest(unittest.TestCase):
    
    def test_join_leave_log(self):
        output = S3Output(None, 's3://cloud-maid/policies/xyz')
        self.addCleanup(shutil.rmtree, output.root_dir)

        output.join_log()
        logging.getLogger('maid.s3').info('hello world')
        output.leave_log()
        logging.getLogger('maid.s3').info('byebye')
        
        with open(output.handler.stream.name) as fh:
            content = fh.read().strip()
            self.assertTrue(content.endswith('hello world'))

    def test_compress(self):
        output = S3Output(None, 's3://cloud-maid/policies/xyz')
        self.addCleanup(shutil.rmtree, output.root_dir)

        with open(os.path.join(output.root_dir, 'foo.txt'), 'w') as fh:
            fh.write('abc')

        os.mkdir(os.path.join(output.root_dir, 'bucket'))
        with open(os.path.join(output.root_dir, 'bucket', 'here.log'), 'w') as fh:
            fh.write('abc')

        output.compress()
        for root, dirs, files in os.walk(output.root_dir):
            for f in files:
                self.assertTrue(f.endswith('.gz'))

    def test_upload(self):
        output = S3Output(None, 's3://cloud-maid/policies/xyz')
        self.addCleanup(shutil.rmtree, output.root_dir)

        with open(os.path.join(output.root_dir, 'foo.txt'), 'w') as fh:
            fh.write('abc')
            
        output.transfer = mock.MagicMock()
        output.transfer.upload_file = m = mock.MagicMock()

        output.upload()
        
        m.assert_called_with(
            fh.name, 'cloud-maid',
            '/policies/xyz/%s/foo.txt' % output.date_path ,
            extra_args={
                'ServerSideEncryption': 'AES256'})
    
                
            
        

        
        
