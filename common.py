#!/usr/bin/env python3

from logging.handlers import SysLogHandler

import sys
import logging


def setup_logging(logger, syslog_socket, log_format):
    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter(log_format)

    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(formatter)
    logger.addHandler(consoleHandler)

    if syslog_socket != '/dev/null':
        syslogHandler = SysLogHandler(syslog_socket)
        syslogHandler.setFormatter(formatter)
        logger.addHandler(syslogHandler)


def set_marathon_auth_args(parser):
    parser.add_argument("--marathon-auth-credential-file",
                        help="Path to file containing a user/pass for "
                        "the Marathon HTTP API in the format of 'user:pass'."
                        )

    return parser


def get_marathon_auth_params(args):
    if args.marathon_auth_credential_file is None:
        return None

    line = None
    with open(args.marathon_auth_credential_file, 'r') as f:
        line = f.readline().rstrip('\r\n')

    if line is not None:
        splat = line.split(':')
        return (splat[0], splat[1])

    return None


def set_logging_args(parser):
    default_log_socket = "/dev/log"
    if sys.platform == "darwin":
        default_log_socket = "/var/run/syslog"

    parser.add_argument("--syslog-socket",
                        help="Socket to write syslog messages to. "
                        "Use '/dev/null' to disable logging to syslog",
                        default=default_log_socket
                        )
    parser.add_argument("--log-format",
                        help="Set log message format",
                        default="%(name)s: %(message)s"
                        )
    return parser
