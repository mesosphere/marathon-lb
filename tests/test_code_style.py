import unittest
import pep8
import os


class TestCodeFormat(unittest.TestCase):
    def get_py_files(self):
        pyfiles = []
        for root, dirs, files in os.walk(os.getcwd()):
            for file in files:
                if file.endswith(".py"):
                    pyfiles.append(os.path.join(root, file))
        return pyfiles

    def test_pep8_conformance(self):
        """Test that we conform to PEP8."""
        pep8style = pep8.StyleGuide()
        result = pep8style.check_files(self.get_py_files())
        self.assertEqual(result.total_errors, 0,
                         "Found code style errors (and warnings).")
