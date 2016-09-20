#!/usr/bin/env python3

import hashlib
import logging
import socket

from lrucache import LRUCache

logger = logging.getLogger('utils')

# The maximum number of clashes to allow when assigning a port.
MAX_CLASHES = 50


class ServicePortAssigner(object):
    """
    Helper class to assign service ports.

    Ordinarily Marathon should assign the service ports, but Marathon issue
    https://github.com/mesosphere/marathon/issues/3636 means that service
    ports are not returned for applications using IP-per-task.  We work around
    that here by assigning deterministic ports from a configurable range when
    required.

    Note that auto-assigning ports is only useful when using vhost: the ports
    that we assign here are not exposed to the client.

    The LB command line options --min-serv-port-ip-per-task and
    --max-serv-port-ip-per-task specify the allowed range of ports to
    auto-assign from.  The range of ports used for auto-assignment should be
    selected to ensure no clashes with the exposed LB ports and the
    Marathon-assigned services ports.

    The service port assigner provides a mechanism to auto assign service ports
    using the application name to generate service port (while preventing
    clashes when the port is already claimed by another app).  The assigner
    provides a deterministic set of ports for a given ordered set of port
    requests.
    """
    def __init__(self):
        self.min_port = None
        self.max_port = None
        self.max_ports = None
        self.can_assign = False
        self.next_port = None
        self.ports_by_app = {}

    def _assign_new_service_port(self, app, task_port):
        assert self.can_assign

        if self.max_ports <= len(self.ports_by_app):
            logger.warning("Service ports are exhausted")
            return None

        # We don't want to be searching forever, so limit the number of times
        # we clash to the number of remaining ports.
        ports = self.ports_by_app.values()
        port = None
        for i in range(MAX_CLASHES):
            hash_str = "%s-%s-%s" % (app['id'], task_port, i)
            hash_val = hashlib.sha1(hash_str.encode("utf-8")).hexdigest()
            hash_int = int(hash_val[:8], 16)
            trial_port = self.min_port + (hash_int % self.max_ports)
            if trial_port not in ports:
                port = trial_port
                break
        if port is None:
            for port in range(self.min_port, self.max_port + 1):
                if port not in ports:
                    break

        # We must have assigned a unique port by now since we know there were
        # some available.
        assert port and port not in ports, port

        logger.debug("Assigned new port: %d", port)
        return port

    def _get_service_port(self, app, task_port):
        key = (app['id'], task_port)
        port = (self.ports_by_app.get(key) or
                self._assign_new_service_port(app, task_port))
        self.ports_by_app[key] = port
        return port

    def set_ports(self, min_port, max_port):
        """
        Set the range of ports that we can use for auto-assignment of
        service ports - just for IP-per-task apps.
        :param min_port: The minimum port value
        :param max_port: The maximum port value
        """
        assert not self.ports_by_app
        assert max_port >= min_port
        self.min_port = min_port
        self.max_port = max_port
        self.max_ports = max_port - min_port + 1
        self.can_assign = self.min_port and self.max_port

    def reset(self):
        """
        Reset the assigner so that ports are newly assigned.
        """
        self.ports_by_app = {}

    def get_service_ports(self, app):
        """
        Return a list of service ports for this app.
        :param app: The application.
        :return: The list of ports.    Note that if auto-assigning and ports
        become exhausted, a port may be returned as None.
        """
        ports = app.get('ports', [])
        if 'portDefinitions' in app:
            ports = filter(lambda p: p is not None,
                           map(lambda p: p.get('port', None),
                               app.get('portDefinitions', []))
                           )
        ports = list(ports)  # wtf python?
        if not ports and is_ip_per_task(app) and self.can_assign \
                and len(app['tasks']) > 0:
            logger.warning("Auto assigning service port for "
                           "IP-per-container task")
            task = app['tasks'][0]
            _, task_ports = get_task_ip_and_ports(app, task)
            if task_ports is not None:
                ports = [self._get_service_port(app, task_port)
                         for task_port in task_ports]
        logger.debug("Service ports: %r", ports)
        return ports


def resolve_ip(host):
    cached_ip = ip_cache.get(host, None)
    if cached_ip:
        return cached_ip
    else:
        try:
            logger.debug("trying to resolve ip address for host %s", host)
            ip = socket.gethostbyname(host)
            ip_cache.set(host, ip)
            return ip
        except socket.gaierror:
            return None
ip_cache = LRUCache()


def set_ip_cache(new_ip_cache):
    ip_cache = new_ip_cache


def is_ip_per_task(app):
    """
    Return whether the application is using IP-per-task.
    :param app:  The application to check.
    :return:  True if using IP per task, False otherwise.
    """
    return app.get('ipAddress') is not None


def get_task_ip_and_ports(app, task):
    """
    Return the IP address and list of ports used to access a task.  For a
    task using IP-per-task, this is the IP address of the task, and the ports
    exposed by the task services.  Otherwise, this is the IP address of the
    host and the ports exposed by the host.
    :param app: The application owning the task.
    :param task: The task.
    :return: Tuple of (ip address, [ports]).  Returns (None, None) if no IP
    address could be resolved or found for the task.
    """
    # If the app ipAddress field is present and not None then this app is using
    # IP per task.  The ipAddress may be an empty dictionary though, in which
    # case there are no discovery ports.  At the moment, Mesos only supports a
    # single IP address, so just take the first IP in the list.
    if is_ip_per_task(app):
        logger.debug("Using IP per container")
        task_ip_addresses = task.get('ipAddresses')
        if not task_ip_addresses:
            logger.warning("Task %s does not yet have an ip address allocated",
                           task['id'])
            return None, None
        task_ip = task_ip_addresses[0]['ipAddress']

        discovery = app['ipAddress'].get('discovery', {})
        task_ports = [int(port['number'])
                      for port in discovery.get('ports', [])]
    else:
        logger.debug("Using host port mapping")
        task_ports = task.get('ports', [])
        task_ip = resolve_ip(task['host'])
        if not task_ip:
            logger.warning("Could not resolve ip for host %s, ignoring",
                           task['host'])
            return None, None

    logger.debug("Returning: %r, %r", task_ip, task_ports)
    return task_ip, task_ports
