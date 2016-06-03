import unittest
import common
from mock import Mock


class TestCommon(unittest.TestCase):

    def test_setup_logging_log_level(self):
        logger = Mock()
        logger.INFO = 'BAR'
        common.setup_logging(logger, '/var/run/syslog',
                             '%(name)s: %(message)s', 'info')

        logger.setLevel.assert_called_with('BAR')

    def test_setup_logging_invalid_log_level(self):
        logger = Mock()
        with self.assertRaises(Exception) as context:
            common.setup_logging(logger, '/var/run/syslog',
                                 '%(name)s: %(message)s', 'banana')

        assert str(context.exception) == 'Invalid log level: BANANA'
