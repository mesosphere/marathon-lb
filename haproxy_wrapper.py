#!/usr/bin/env python3
import os
import sys
import time
import errno
import logging

logger = logging.getLogger('haproxy_wrapper')
logger.setLevel(getattr(logging, 'DEBUG'))
formatter = logging.Formatter("%(asctime)-15s %(name)s: %(message)s")
consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(formatter)
logger.addHandler(consoleHandler)


def create_haproxy_pipe():
    logger.debug("create_haproxy_pipe called")
    pipefd = os.pipe()
    os.set_inheritable(pipefd[0], True)
    os.set_inheritable(pipefd[1], True)
    logger.debug("create_haproxy_pipe done")
    return pipefd


def close_and_swallow(fd):
    logger.debug("close_and_swallow called")
    try:
        os.close(fd)
        logger.debug("close_and_swallow successful")
    except OSError as e:
        # swallow
        logger.debug("close_and_swallow swallow OSError: %s", e)
        pass


def wait_on_haproxy_pipe(pipefd):
    logger.debug("wait_on_haproxy_pipe called")
    try:
        ret = os.read(pipefd[0], 1)
        if len(ret) == 0:
            close_and_swallow(pipefd[0])
            close_and_swallow(pipefd[1])
            logger.debug("wait_on_haproxy_pipe done (False)")
            return False
    except OSError as e:
        logger.debug("wait_on_haproxy_pipe OSError: %s", e)
        if e.args[0] != errno.EINTR:
            close_and_swallow(pipefd[0])
            close_and_swallow(pipefd[1])
            logger.debug("wait_on_haproxy_pipe done (False)")
            return False
    logger.debug("wait_on_haproxy_pipe done (True)")
    return True


pipefd = create_haproxy_pipe()

pid = os.fork()

if not pid:
    os.environ["HAPROXY_WRAPPER_FD"] = str(pipefd[1])
    # Close the read side
    os.close(pipefd[0])
    os.execv(sys.argv[1], sys.argv[1:])

# Close the write side
os.close(pipefd[1])
while wait_on_haproxy_pipe(pipefd):
    time.sleep(0.005)
sys.exit(0)
