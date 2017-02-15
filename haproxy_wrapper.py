#!/usr/bin/env python3
import os
import sys
import time
import errno


def create_haproxy_pipe():
    pipefd = os.pipe()
    os.set_inheritable(pipefd[0], True)
    os.set_inheritable(pipefd[1], True)
    return pipefd


def close_and_swallow(fd):
    try:
        os.close(fd)
    except OSError:
        # swallow
        pass


def wait_on_haproxy_pipe(pipefd):
    try:
        ret = os.read(pipefd[0], 1)
        if len(ret) == 0:
            close_and_swallow(pipefd[0])
            close_and_swallow(pipefd[1])
            return False
    except OSError as e:
        if e.args[0] != errno.EINTR:
            close_and_swallow(pipefd[0])
            close_and_swallow(pipefd[1])
            return False
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
