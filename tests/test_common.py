import unittest
import common
from mock import Mock


class TestCommon(unittest.TestCase):
    
    def test_setup_logging_log_level(self):
        logger = Mock()
        logger.FOO = 'BAR'
        common.setup_logging(logger, '/var/run/syslog', 
                             '%(name)s: %(message)s', 'FOO')

        logger.setLevel.assert_called_with('BAR')
