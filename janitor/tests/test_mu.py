import unittest
import zipfile

from janitor.mu import maid_archive


class PythonArchiveTest(unittest.TestCase):

    def test_archive(self):
        self.archive = maid_archive()
        self.archive.create()
        self.archive.close()
        
        with open(self.archive.path) as fh:
            reader = zipfile.ZipFile(fh, mode='r')
            fileset = [n.filename for n in reader.filelist]
            for i in ['janitor/__init__.py',
                      'janitor/resources/s3.py',
                      'boto3/__init__.py']:
                self.assertTrue(i in fileset)

    def test_archive_skip(self):
        self.archive = maid_archive("*.pyc")
        self.archive.create()
        self.archive.close()
        
        with open(self.archive.path) as fh:
            reader = zipfile.ZipFile(fh, mode='r')
            fileset = [n.filename for n in reader.filelist]
            for i in ['janitor/__init__.pyc',
                      'janitor/resources/s3.pyc',
                      'boto3/__init__.pyc']:
                self.assertFalse(i in fileset)
        

        
