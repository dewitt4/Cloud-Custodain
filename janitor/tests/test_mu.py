import unittest
import StringIO
import zipfile

from janitor.mu import maid_archive


class PythonArchiveTest(unittest.TestCase):

    def test_archive_bytes(self):
        self.archive = maid_archive()
        self.archive.create()
        self.addCleanup(self.archive.remove)
        self.archive.close()
        io = StringIO.StringIO(self.archive.get_bytes())
        reader = zipfile.ZipFile(io, mode='r')
        fileset = [n.filename for n in reader.filelist]
        self.assertTrue('janitor/__init__.py' in fileset)
        
    def test_archive_skip(self):
        self.archive = maid_archive("*.pyc")
        self.archive.create()
        self.addCleanup(self.archive.remove)        
        self.archive.close()
        
        with open(self.archive.path) as fh:
            reader = zipfile.ZipFile(fh, mode='r')
            fileset = [n.filename for n in reader.filelist]
            for i in ['janitor/__init__.pyc',
                      'janitor/resources/s3.pyc',
                      'boto3/__init__.pyc']:
                self.assertFalse(i in fileset)
        

        
