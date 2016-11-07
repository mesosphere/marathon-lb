import unittest

from mock import Mock

import common


class TestCommon(unittest.TestCase):

    def test_setup_logging_log_level(self):
        logger = Mock()
        common.setup_logging(logger, '/dev/null',
                             '%(name)s: %(message)s', 'info')

        logger.setLevel.assert_called_with(20)

    def test_setup_logging_invalid_log_level(self):
        logger = Mock()
        with self.assertRaises(Exception) as context:
            common.setup_logging(logger, '/dev/null',
                                 '%(name)s: %(message)s', 'banana')

        assert str(context.exception) == 'Invalid log level: BANANA'
