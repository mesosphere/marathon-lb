#!/usr/bin/env python3

import json
import logging
import os
import sys
import time
from logging.handlers import SysLogHandler

import jwt
import requests
from requests.auth import AuthBase


def setup_logging(logger, syslog_socket, log_format, log_level='DEBUG'):
    log_level = log_level.upper()

    if log_level not in ['CRITICAL', 'ERROR', 'WARNING',
                         'INFO', 'DEBUG', 'NOTSET']:
        raise Exception('Invalid log level: {}'.format(log_level.upper()))

    logger.setLevel(getattr(logging, log_level))

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
    parser.add_argument("--auth-credentials",
                        help="user/pass for the Marathon HTTP API in the "
                             "format of 'user:pass'.")
    parser.add_argument("--dcos-auth-credentials",
                        default=os.getenv('DCOS_SERVICE_ACCOUNT_CREDENTIAL'),
                        help="DC/OS service account credentials")

    return parser


class DCOSAuth(AuthBase):
    def __init__(self, credentials, ca_cert):
        creds = json.loads(credentials)
        self.uid = creds['uid']
        self.private_key = creds['private_key']
        self.login_endpoint = creds['login_endpoint']
        self.verify = False
        if ca_cert:
            self.verify = ca_cert

    def __call__(self, auth_request):
        payload = {
            'uid': self.uid,
            'exp': int(time.time()) + 3600,
        }
        token = jwt.encode(payload, self.private_key, 'RS256')

        data = {
            'uid': self.uid,
            'token': token.decode('ascii'),
        }
        r = requests.post(self.login_endpoint, json=data, verify=self.verify)
        r.raise_for_status()

        auth_header = 'token=' + r.cookies['dcos-acs-auth-cookie']
        auth_request.headers['Authorization'] = auth_header
        return auth_request


def get_marathon_auth_params(args):
    marathon_auth = None
    if args.marathon_auth_credential_file:
        with open(args.marathon_auth_credential_file, 'r') as f:
            line = f.readline().rstrip('\r\n')

        if line:
            marathon_auth = tuple(line.split(':'))
    elif args.auth_credentials:
        marathon_auth = \
            tuple(args.auth_credentials.split(':'))
    elif args.dcos_auth_credentials:
        return DCOSAuth(args.dcos_auth_credentials, args.marathon_ca_cert)

    if marathon_auth and len(marathon_auth) != 2:
        print(
            "Please provide marathon credentials in user:pass format"
        )
        sys.exit(1)

    return marathon_auth


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
    parser.add_argument("--log-level",
                        help="Set log level",
                        default="DEBUG"
                        )
    return parser
