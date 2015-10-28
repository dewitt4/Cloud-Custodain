
import unittest

from janitor.utils import chunks

class UtilTest(unittest.TestCase):


    def test_chunks(self):
        self.assertEqual(
            list(chunks(range(100), size=50)),
            [range(50), range(50, 100, 1)])
        self.assertEqual(
            list(chunks(range(1), size=50)),
            [range(1)])
        self.assertEqual(
            list(chunks(range(60), size=50)),
            [range(50), range(50, 60, 1)])
        
