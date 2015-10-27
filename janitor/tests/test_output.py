
import gzip
import logging
import mock
import unittest
import shutil
import os

from janitor.output import MetricsOutput, S3Output, s3_path_join


class S3OutputTest(unittest.TestCase):

    def test_path_join(self):

        self.assertEqual(
            s3_path_join('s3://xyz/', '/bar/'),
            's3://xyz/bar')

        self.assertEqual(
            s3_path_join('s3://xyz/', '/bar/', 'foo'),
            's3://xyz/bar/foo')

        self.assertEqual(
            s3_path_join('s3://xyz/xyz/', '/bar/'),
            's3://xyz/xyz/bar')
        
    
    def test_join_leave_log(self):
        output = S3Output(None, 's3://cloud-maid/policies/xyz')
        self.addCleanup(shutil.rmtree, output.root_dir)


        output.join_log()
        l = logging.getLogger('maid.s3')

        # recent versions of nose mess with the logging manager
        v = l.manager.disable
        l.manager.disable = 0

        l.info('hello world')
        output.leave_log()
        logging.getLogger('maid.s3').info('byebye')

        # Reset logging.manager back to nose configured value
        l.manager.disable = v
        
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

                with gzip.open(os.path.join(root, f)) as fh:
                    self.assertEqual(fh.read(), 'abc')
                    
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
            'policies/xyz/%s/foo.txt' % output.date_path ,
            extra_args={
                'ServerSideEncryption': 'AES256'})

    def test_sans_prefix(self):
        output = S3Output(None, 's3://cloud-maid')
        self.addCleanup(shutil.rmtree, output.root_dir)

        with open(os.path.join(output.root_dir, 'foo.txt'), 'w') as fh:
            fh.write('abc')
            
        output.transfer = mock.MagicMock()
        output.transfer.upload_file = m = mock.MagicMock()

        output.upload()
        
        m.assert_called_with(
            fh.name, 'cloud-maid',
            '%s/foo.txt' % output.date_path ,
            extra_args={
                'ServerSideEncryption': 'AES256'})
        
                
            
        

        
        
