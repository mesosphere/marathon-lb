#!/usr/bin/env python3

import hashlib
from io import BytesIO
import logging
import socket

import pycurl

from common import DCOSAuth
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
        mode = get_app_networking_mode(app)
        if mode == "container" or mode == "container/bridge":
            # Here we must use portMappings
            portMappings = get_app_port_mappings(app)
            if len(portMappings) > 0:
                ports = filter(lambda p: p is not None,
                               map(lambda p: p.get('servicePort', None),
                                   portMappings))
                ports = list(ports)
                if ports:
                    return list(ports)

        ports = app.get('ports', [])
        if 'portDefinitions' in app:
            ports = filter(lambda p: p is not None,
                           map(lambda p: p.get('port', None),
                               app.get('portDefinitions', []))
                           )
        ports = list(ports)  # wtf python?
        # This supports legacy ip-per-container for Marathon 1.4.x and prior
        if not ports and mode == "container" and self.can_assign \
                and len(app['tasks']) > 0:
            task = app['tasks'][0]
            task_ports = get_app_task_ports(app, task, mode)
            if len(task_ports) > 0:
                ports = [self._get_service_port(app, task_port)
                         for task_port in task_ports]
        logger.debug("Service ports: %r", ports)
        return ports


class CurlHttpEventStream(object):
    def __init__(self, url, auth, verify):
        self.url = url
        self.received_buffer = BytesIO()

        headers = ['Cache-Control: no-cache', 'Accept: text/event-stream']

        self.curl = pycurl.Curl()
        self.curl.setopt(pycurl.URL, url)
        self.curl.setopt(pycurl.ENCODING, 'gzip')
        self.curl.setopt(pycurl.CONNECTTIMEOUT, 10)
        self.curl.setopt(pycurl.WRITEDATA, self.received_buffer)

        # The below settings are to prevent the connection from hanging if the
        # connection breaks silently. Since marathon-lb only listens, silent
        # connection failure results in marathon-lb waiting infinitely.
        #
        # Minimum bytes/second below which it is considered "low speed". So
        # "low speed" here refers to 0 bytes/second.
        self.curl.setopt(pycurl.LOW_SPEED_LIMIT, 1)
        # How long (in seconds) it's allowed to go below the speed limit
        # before it times out
        self.curl.setopt(pycurl.LOW_SPEED_TIME, 300)

        if auth and type(auth) is DCOSAuth:
            auth.refresh_auth_header()
            headers.append('Authorization: %s' % auth.auth_header)
        elif auth:
            self.curl.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_BASIC)
            self.curl.setopt(pycurl.USERPWD, '%s:%s' % auth)
        if verify:
            self.curl.setopt(pycurl.CAINFO, verify)
        else:
            self.curl.setopt(pycurl.SSL_VERIFYHOST, 0)
            self.curl.setopt(pycurl.SSL_VERIFYPEER, 0)

        self.curl.setopt(pycurl.HTTPHEADER, headers)

        self.curlmulti = pycurl.CurlMulti()
        self.curlmulti.add_handle(self.curl)

        self.status_code = 0

    SELECT_TIMEOUT = 10

    def _any_data_received(self):
        return self.received_buffer.tell() != 0

    def _get_received_data(self):
        result = self.received_buffer.getvalue()
        self.received_buffer.truncate(0)
        self.received_buffer.seek(0)
        return result

    def _check_status_code(self):
        if self.status_code == 0:
            self.status_code = self.curl.getinfo(pycurl.HTTP_CODE)
        if self.status_code != 0 and self.status_code != 200:
            raise Exception(str(self.status_code) + ' ' + self.url)

    def _perform_on_curl(self):
        while True:
            ret, num_handles = self.curlmulti.perform()
            if ret != pycurl.E_CALL_MULTI_PERFORM:
                break
        return num_handles

    def _iter_chunks(self):
        while True:
            remaining = self._perform_on_curl()
            if self._any_data_received():
                self._check_status_code()
                yield self._get_received_data()
            if remaining == 0:
                break
            self.curlmulti.select(self.SELECT_TIMEOUT)

        self._check_status_code()
        self._check_curl_errors()

    def _check_curl_errors(self):
        for f in self.curlmulti.info_read()[2]:
            raise pycurl.error(*f[1:])

    def iter_lines(self):
        chunks = self._iter_chunks()
        return self._split_lines_from_chunks(chunks)

    @staticmethod
    def _split_lines_from_chunks(chunks):
        # same behaviour as requests' Response.iter_lines(...)

        pending = None
        for chunk in chunks:

            if pending is not None:
                chunk = pending + chunk
            lines = chunk.splitlines()

            if lines and lines[-1] and chunk and lines[-1][-1] == chunk[-1]:
                pending = lines.pop()
            else:
                pending = None

            for line in lines:
                yield line

        if pending is not None:
            yield pending


def resolve_ip(host):
    """
    :return: string, an empty string indicates that no ip was found.
    """
    cached_ip = ip_cache.get().get(host, "")
    if cached_ip != "":
        return cached_ip
    else:
        try:
            logger.debug("trying to resolve ip address for host %s", host)
            ip = socket.gethostbyname(host)
            ip_cache.get().set(host, ip)
            return ip
        except socket.gaierror:
            return ""


class LRUCacheSingleton(object):
    def __init__(self):
        self.lru_cache = None

    def get(self):
        if self.lru_cache is None:
            self.lru_cache = LRUCache()
        return self.lru_cache

    def set(self, lru_cache):
        self.lru_cache = lru_cache


ip_cache = LRUCacheSingleton()


def get_app_networking_mode(app):
    mode = 'host'

    if app.get('ipAddress'):
        mode = 'container'

    _mode = app.get('container', {})\
               .get('docker', {})\
               .get('network', '')
    if _mode == 'USER':
        mode = 'container'
    elif _mode == 'BRIDGE':
        mode = 'container/bridge'

    networks = app.get('networks', [])
    for n in networks:
        # Modes cannot be mixed, so assigning the last mode is fine
        mode = n.get('mode', 'container')

    return mode


def get_task_ip(task, mode):
    """
    :return: string, an empty string indicates that no ip was found.
    """
    if mode == 'container':
        task_ip_addresses = task.get('ipAddresses', [])
        if len(task_ip_addresses) == 0:
            logger.warning("Task %s does not yet have an ip address allocated",
                           task['id'])
            return ""
        task_ip = task_ip_addresses[0].get('ipAddress', "")
        if task_ip == "":
            logger.warning("Task %s does not yet have an ip address allocated",
                           task['id'])
            return ""
        return task_ip
    else:
        host = task.get('host', "")
        if host == "":
            logger.warning("Could not find task host, ignoring")
            return ""
        task_ip = resolve_ip(host)
        if task_ip == "":
            logger.warning("Could not resolve ip for host %s, ignoring",
                           host)
            return ""
        return task_ip


def get_app_port_mappings(app):
    """
    :return: list
    """
    portMappings = app.get('container', {})\
                      .get('docker', {})\
                      .get('portMappings', [])
    if len(portMappings) > 0:
        return portMappings

    return app.get('container', {})\
              .get('portMappings', [])


def get_task_ports(task):
    """
    :return: list
    """
    return task.get('ports', [])


def get_port_definition_ports(app):
    """
    :return: list
    """
    port_definitions = app.get('portDefinitions', [])
    return [p['port'] for p in port_definitions if 'port' in p]


def get_ip_address_discovery_ports(app):
    """
    :return: list
    """
    ip_address = app.get('ipAddress', {})
    if len(ip_address) == 0:
        return []
    discovery = app.get('ipAddress', {}).get('discovery', {})
    return [int(p['number'])
            for p in discovery.get('ports', [])
            if 'number' in p]


def get_port_mapping_ports(app):
    """
    :return: list
    """
    port_mappings = get_app_port_mappings(app)
    return [p['containerPort'] for p in port_mappings if 'containerPort' in p]


def get_app_task_ports(app, task, mode):
    """
    :return: list
    """
    if mode == 'host':
        task_ports = get_task_ports(task)
        if len(task_ports) > 0:
            return task_ports
        return get_port_definition_ports(app)
    elif mode == 'container/bridge':
        task_ports = get_task_ports(task)
        if len(task_ports) > 0:
            return task_ports
        # Will only work for Marathon < 1.5
        task_ports = get_port_definition_ports(app)
        if len(task_ports) > 0:
            return task_ports
        return get_port_mapping_ports(app)
    else:
        task_ports = get_ip_address_discovery_ports(app)
        if len(task_ports) > 0:
            return task_ports
        return get_port_mapping_ports(app)


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

    mode = get_app_networking_mode(app)
    task_ip = get_task_ip(task, mode)
    task_ports = get_app_task_ports(app, task, mode)
    # The overloading of empty string, and empty list as False is intentional.
    if not (task_ip and task_ports):
        return None, None
    logger.debug("Returning: %r, %r", task_ip, task_ports)
    return task_ip, task_ports
