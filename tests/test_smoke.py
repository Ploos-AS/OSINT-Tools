import os
import tempfile
import unittest
from osint_tools import __version__

class SmokeTest(unittest.TestCase):
    def test_version(self):
        self.assertEqual(__version__, "0.1.0")

    def test_data_dir_can_be_created(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "data")
            os.makedirs(p)
            self.assertTrue(os.path.isdir(p))

if __name__ == "__main__":
    unittest.main()
