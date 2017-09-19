#!/usr/bin/env python3

"""# marathon-lb
### Overview
The marathon-lb is a service discovery and load balancing tool
for Marathon based on HAProxy. It reads the Marathon task information
and dynamically generates HAProxy configuration details.

To gather the task information, marathon-lb needs to know where
to find Marathon. The service configuration details are stored in labels.

Every service port in Marathon can be configured independently.

### Configuration
Service configuration lives in Marathon via labels.
Marathon-lb just needs to know where to find Marathon.

### Command Line Usage
"""
import argparse
import hashlib
import json
import logging
import os
import os.path
import random
import re
import shlex
import signal
import stat
import subprocess
import sys
import threading
import time
import traceback
import datetime
from itertools import cycle
from operator import attrgetter
from shutil import move
from tempfile import mkstemp

import dateutil.parser
import requests

from common import (get_marathon_auth_params, set_logging_args,
                    set_marathon_auth_args, setup_logging, cleanup_json)
from config import ConfigTemplater, label_keys
from lrucache import LRUCache
from utils import (CurlHttpEventStream, get_task_ip_and_ports, ip_cache,
                   ServicePortAssigner)


logger = logging.getLogger('marathon_lb')
SERVICE_PORT_ASSIGNER = ServicePortAssigner()


class MarathonBackend(object):

    def __init__(self, host, ip, port, draining):
        self.host = host
        """
        The host that is running this task.
        """

        self.ip = ip
        """
        The IP address used to access the task.  For tasks using IP-per-task,
        this is the actual IP address of the task; otherwise, it is the IP
        address resolved from the hostname.
        """

        self.port = port
        """
        The port used to access a particular service on a task.  For tasks
        using IP-per-task, this is the actual port exposed by the task;
        otherwise, it is the port exposed on the host.
        """

        self.draining = draining
        """
        Whether we should be draining access to this task in the LB.
        """

    def __hash__(self):
        return hash((self.host, self.port))

    def __repr__(self):
        return "MarathonBackend(%r, %r, %r)" % (self.host, self.ip, self.port)


class MarathonService(object):

    def __init__(self, appId, servicePort, healthCheck, strictMode):
        self.appId = appId
        self.servicePort = servicePort
        self.backends = set()
        self.hostname = None
        self.proxypath = None
        self.revproxypath = None
        self.redirpath = None
        self.haproxy_groups = frozenset()
        self.path = None
        self.authRealm = None
        self.authUser = None
        self.authPasswd = None
        self.sticky = False
        self.enabled = not strictMode
        self.redirectHttpToHttps = False
        self.useHsts = False
        self.sslCert = None
        self.bindOptions = None
        self.bindAddr = '*'
        self.groups = frozenset()
        self.mode = None
        self.balance = 'roundrobin'
        self.healthCheck = healthCheck
        self.labels = {}
        self.backend_weight = 0
        self.network_allowed = None
        self.healthcheck_port_index = None
        if healthCheck:
            if healthCheck['protocol'] == 'HTTP':
                self.mode = 'http'

    def add_backend(self, host, ip, port, draining):
        self.backends.add(MarathonBackend(host, ip, port, draining))

    def __hash__(self):
        return hash(self.servicePort)

    def __eq__(self, other):
        return self.servicePort == other.servicePort

    def __repr__(self):
        return "MarathonService(%r, %r)" % (self.appId, self.servicePort)


class MarathonApp(object):

    def __init__(self, marathon, appId, app):
        self.app = app
        self.groups = frozenset()
        self.appId = appId

        # port -> MarathonService
        self.services = dict()

    def __hash__(self):
        return hash(self.appId)

    def __eq__(self, other):
        return self.appId == other.appId


class Marathon(object):
    def __init__(self, hosts, health_check, strict_mode, auth, ca_cert=None):
        # TODO(cmaloney): Support getting master list from zookeeper
        self.__hosts = hosts
        self.__health_check = health_check
        self.__strict_mode = strict_mode
        self.__auth = auth
        self.__cycle_hosts = cycle(self.__hosts)
        self.__verify = False
        if ca_cert:
            self.__verify = ca_cert

    def api_req_raw(self, method, path, auth, body=None, **kwargs):
        for host in self.__hosts:
            path_str = os.path.join(host, 'v2')

            for path_elem in path:
                path_str = path_str + "/" + path_elem

            response = requests.request(
                method,
                path_str,
                auth=auth,
                headers={
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                timeout=(3.05, 46),
                **kwargs
            )

            logger.debug("%s %s", method, response.url)
            if response.status_code == 200:
                break

        response.raise_for_status()

        resp_json = cleanup_json(response.json())
        if 'message' in resp_json:
            response.reason = "%s (%s)" % (
                response.reason,
                resp_json['message'])

        return response

    def api_req(self, method, path, **kwargs):
        data = self.api_req_raw(method, path, self.__auth,
                                verify=self.__verify, **kwargs).json()
        return cleanup_json(data)

    def create(self, app_json):
        return self.api_req('POST', ['apps'], app_json)

    def get_app(self, appid):
        logger.info('fetching app %s', appid)
        return self.api_req('GET', ['apps', appid])["app"]

    # Lists all running apps.
    def list(self):
        logger.info('fetching apps')
        return self.api_req('GET', ['apps'],
                            params={'embed': 'apps.tasks'})["apps"]

    def health_check(self):
        return self.__health_check

    def strict_mode(self):
        return self.__strict_mode

    def tasks(self):
        logger.info('fetching tasks')
        return self.api_req('GET', ['tasks'])["tasks"]

    def get_event_stream(self):
        url = self.host + "/v2/events"
        logger.info(
            "SSE Active, trying fetch events from {0}".format(url))

        resp = CurlHttpEventStream(url, self.__auth, self.__verify)

        class Event(object):
            def __init__(self, data):
                self.data = data

        for line in resp.iter_lines():
            if line.strip() != '':
                for real_event_data in re.split(r'\r\n',
                                                line.decode('utf-8')):
                    if real_event_data[:6] == "data: ":
                        event = Event(data=real_event_data[6:])
                        yield event

    @property
    def host(self):
        return next(self.__cycle_hosts)


def has_group(groups, app_groups):
    # All groups / wildcard match
    if '*' in groups:
        return True

    # empty group only
    if len(groups) == 0 and len(app_groups) == 0:
        raise Exception("No groups specified")

    # Contains matching groups
    if (len(frozenset(app_groups) & groups)):
        return True

    return False


def get_backend_port(apps, app, idx):
    """
    Return the port of the idx-th backend of the app which index in apps
    is defined by app.healthcheck_port_index.

    Example case:
        We define an app mapping two ports: 9000 and 9001, that we
        scaled to 3 instances.
        The port 9000 is used for the app itself, and the port 9001
        is used for the app healthchecks. Hence, we have 2 apps
        at the marathon level, each with 3 backends (one for each
        container).

        If app.healthcheck_port_index is set to 1 (via the
        HAPROXY_0_BACKEND_HEALTHCHECK_PORT_INDEX label), then
        get_backend_port(apps, app, 3) will return the port of the 3rd
        backend of the second app.

    See https://github.com/mesosphere/marathon-lb/issues/198 for the
    actual use case.

    Note: if app.healthcheck_port_index has a out of bounds value,
    then the app idx-th backend is returned instead.

    """
    def get_backends(app):
        key_func = attrgetter('host', 'port')
        return sorted(list(app.backends), key=key_func)

    apps = [_app for _app in apps if _app.appId == app.appId]

    # If no healthcheck port index is defined, or if its value is nonsense
    # simply return the app port
    if app.healthcheck_port_index is None \
            or abs(app.healthcheck_port_index) > len(apps):
        return get_backends(app)[idx].port

    # If a healthcheck port index is defined, fetch the app corresponding
    # to the argument app healthcheck port index,
    # and return its idx-th backend port
    apps = sorted(apps, key=attrgetter('appId', 'servicePort'))
    backends = get_backends(apps[app.healthcheck_port_index])
    return backends[idx].port


def _get_health_check_options(template, health_check, health_check_port):
    return template.format(
        healthCheck=health_check,
        healthCheckPortIndex=health_check.get('portIndex'),
        healthCheckPort=health_check_port,
        healthCheckProtocol=health_check['protocol'],
        healthCheckPath=health_check.get('path', '/'),
        healthCheckTimeoutSeconds=health_check['timeoutSeconds'],
        healthCheckIntervalSeconds=health_check['intervalSeconds'],
        healthCheckGracePeriodSeconds=health_check['gracePeriodSeconds'],
        healthCheckMaxConsecutiveFailures=health_check[
            'maxConsecutiveFailures'],
        healthCheckFalls=health_check['maxConsecutiveFailures'] + 1,
        healthCheckPortOptions=' port ' + str(
            health_check_port) if health_check_port else ''
    )


def config(apps, groups, bind_http_https, ssl_certs, templater,
           haproxy_map=False, domain_map_array=[], app_map_array=[],
           config_file="/etc/haproxy/haproxy.cfg"):
    logger.info("generating config")
    config = templater.haproxy_head
    groups = frozenset(groups)
    duplicate_map = {}
    # do not repeat use backend multiple times since map file is same.
    _ssl_certs = ssl_certs or "/etc/ssl/cert.pem"
    _ssl_certs = _ssl_certs.split(",")

    if bind_http_https:
        http_frontends = templater.haproxy_http_frontend_head
        https_frontends = templater.haproxy_https_frontend_head.format(
            sslCerts=" ".join(map(lambda cert: "crt " + cert, _ssl_certs))
        )

    userlists = str()
    frontends = str()
    backends = str()
    http_appid_frontends = templater.haproxy_http_frontend_appid_head
    apps_with_http_appid_backend = []
    http_frontend_list = []
    https_frontend_list = []
    haproxy_dir = os.path.dirname(config_file)
    logger.debug("HAProxy dir is %s", haproxy_dir)

    for app in sorted(apps, key=attrgetter('appId', 'servicePort')):
        # App only applies if we have it's group
        # Check if there is a haproxy group associated with service group
        # if not fallback to original HAPROXY group.
        # This is added for backward compatability with HAPROXY_GROUP
        if app.haproxy_groups:
            if not has_group(groups, app.haproxy_groups):
                continue
        else:
            if not has_group(groups, app.groups):
                continue
        # Skip if it's not actually enabled
        if not app.enabled:
            continue

        logger.debug("configuring app %s", app.appId)
        if len(app.backends) < 1:
            logger.error("skipping app %s as it is not valid to generate" +
                         " backend without any server entries!", app.appId)
            continue

        backend = app.appId[1:].replace('/', '_') + '_' + str(app.servicePort)

        logger.debug("frontend at %s:%d with backend %s",
                     app.bindAddr, app.servicePort, backend)

        # If app has HAPROXY_{n}_MODE set, use that setting.
        # Otherwise use 'http' if HAPROXY_{N}_VHOST is set, and 'tcp' if not.
        if app.mode is None:
            if app.hostname:
                app.mode = 'http'
            else:
                app.mode = 'tcp'

        if app.authUser:
            userlist_head = templater.haproxy_userlist_head(app)
            userlists += userlist_head.format(
                backend=backend,
                user=app.authUser,
                passwd=app.authPasswd
            )

        frontend_head = templater.haproxy_frontend_head(app)
        frontends += frontend_head.format(
            bindAddr=app.bindAddr,
            backend=backend,
            servicePort=app.servicePort,
            mode=app.mode,
            sslCert=' ssl crt ' + app.sslCert if app.sslCert else '',
            bindOptions=' ' + app.bindOptions if app.bindOptions else ''
        )

        backend_head = templater.haproxy_backend_head(app)
        backends += backend_head.format(
            backend=backend,
            balance=app.balance,
            mode=app.mode
        )

        # if a hostname is set we add the app to the vhost section
        # of our haproxy config
        # TODO(lloesche): Check if the hostname is already defined by another
        # service
        if bind_http_https and app.hostname:
            backend_weight, p_fe, s_fe = \
                generateHttpVhostAcl(templater,
                                     app,
                                     backend,
                                     haproxy_map,
                                     domain_map_array,
                                     haproxy_dir,
                                     duplicate_map)
            http_frontend_list.append((backend_weight, p_fe))
            https_frontend_list.append((backend_weight, s_fe))

        # if app mode is http, we add the app to the second http frontend
        # selecting apps by http header X-Marathon-App-Id
        if app.mode == 'http' and \
                app.appId not in apps_with_http_appid_backend:
            logger.debug("adding virtual host for app with id %s", app.appId)
            # remember appids to prevent multiple entries for the same app
            apps_with_http_appid_backend += [app.appId]
            cleanedUpAppId = re.sub(r'[^a-zA-Z0-9\-]', '_', app.appId)

            if haproxy_map:
                if 'map_http_frontend_appid_acl' not in duplicate_map:
                    http_appid_frontend_acl = templater \
                        .haproxy_map_http_frontend_appid_acl(app)
                    http_appid_frontends += http_appid_frontend_acl.format(
                        haproxy_dir=haproxy_dir
                    )
                    duplicate_map['map_http_frontend_appid_acl'] = 1
                map_element = {}
                map_element[app.appId] = backend
                if map_element not in app_map_array:
                    app_map_array.append(map_element)
            else:
                http_appid_frontend_acl = templater \
                    .haproxy_http_frontend_appid_acl(app)
                http_appid_frontends += http_appid_frontend_acl.format(
                    cleanedUpAppId=cleanedUpAppId,
                    hostname=app.hostname,
                    appId=app.appId,
                    backend=backend
                )

        if app.mode == 'http':
            if app.useHsts:
                backends += templater.haproxy_backend_hsts_options(app)
            backends += templater.haproxy_backend_http_options(app)
            backend_http_backend_proxypass = templater \
                .haproxy_http_backend_proxypass_glue(app)
            if app.proxypath:
                backends += backend_http_backend_proxypass.format(
                    hostname=app.hostname,
                    proxypath=app.proxypath
                )
            backend_http_backend_revproxy = templater \
                .haproxy_http_backend_revproxy_glue(app)
            if app.revproxypath:
                backends += backend_http_backend_revproxy.format(
                    hostname=app.hostname,
                    rootpath=app.revproxypath
                )
            backend_http_backend_redir = templater \
                .haproxy_http_backend_redir(app)
            if app.redirpath:
                backends += backend_http_backend_redir.format(
                    hostname=app.hostname,
                    redirpath=app.redirpath
                )

        # Set network allowed ACLs
        if app.mode == 'http' and app.network_allowed:
            for network in app.network_allowed.split():
                backends += templater.\
                    haproxy_http_backend_network_allowed_acl(app).\
                    format(network_allowed=network)
            backends += templater.haproxy_http_backend_acl_allow_deny
        elif app.mode == 'tcp' and app.network_allowed:
            for network in app.network_allowed.split():
                backends += templater.\
                    haproxy_tcp_backend_network_allowed_acl(app).\
                    format(network_allowed=network)
            backends += templater.haproxy_tcp_backend_acl_allow_deny

        if app.sticky:
            logger.debug("turning on sticky sessions")
            backends += templater.haproxy_backend_sticky_options(app)

        frontend_backend_glue = templater.haproxy_frontend_backend_glue(app)
        frontends += frontend_backend_glue.format(backend=backend)

        do_backend_healthcheck_options_once = True
        key_func = attrgetter('host', 'port')
        for backend_service_idx, backendServer\
                in enumerate(sorted(app.backends, key=key_func)):
            if do_backend_healthcheck_options_once:
                if app.healthCheck:
                    template_backend_health_check = None
                    if app.mode == 'tcp' \
                            or app.healthCheck['protocol'] == 'TCP':
                        template_backend_health_check = templater \
                            .haproxy_backend_tcp_healthcheck_options(app)
                    elif app.mode == 'http':
                        template_backend_health_check = templater \
                            .haproxy_backend_http_healthcheck_options(app)
                    if template_backend_health_check:
                        health_check_port = get_backend_port(
                            apps,
                            app,
                            backend_service_idx)
                        backends += _get_health_check_options(
                            template_backend_health_check,
                            app.healthCheck,
                            health_check_port)
                do_backend_healthcheck_options_once = False

            logger.debug(
                "backend server %s:%d on %s",
                backendServer.ip,
                backendServer.port,
                backendServer.host)

            # Create a unique, friendly name for the backend server.  We concat
            # the host, task IP and task port together.  If the host and task
            # IP are actually the same then omit one for clarity.
            if backendServer.host != backendServer.ip:
                serverName = re.sub(
                    r'[^a-zA-Z0-9\-]', '_',
                    (backendServer.host + '_' +
                     backendServer.ip + '_' +
                     str(backendServer.port)))
            else:
                serverName = re.sub(
                    r'[^a-zA-Z0-9\-]', '_',
                    (backendServer.ip + '_' +
                     str(backendServer.port)))
            shortHashedServerName = hashlib.sha1(serverName.encode()) \
                .hexdigest()[:10]

            server_health_check_options = None
            if app.healthCheck:
                template_server_healthcheck_options = None
                if app.mode == 'tcp' or app.healthCheck['protocol'] == 'TCP':
                    template_server_healthcheck_options = templater \
                        .haproxy_backend_server_tcp_healthcheck_options(app)
                elif app.mode == 'http':
                    template_server_healthcheck_options = templater \
                        .haproxy_backend_server_http_healthcheck_options(app)
                if template_server_healthcheck_options:
                    if app.healthcheck_port_index is not None:
                        health_check_port = \
                            get_backend_port(apps, app, backend_service_idx)
                    else:
                        health_check_port = app.healthCheck.get('port')
                    server_health_check_options = _get_health_check_options(
                        template_server_healthcheck_options,
                        app.healthCheck,
                        health_check_port)
            backend_server_options = templater \
                .haproxy_backend_server_options(app)
            backends += backend_server_options.format(
                host=backendServer.host,
                host_ipv4=backendServer.ip,
                port=backendServer.port,
                serverName=serverName,
                cookieOptions=' check cookie ' +
                shortHashedServerName if app.sticky else '',
                healthCheckOptions=server_health_check_options
                if server_health_check_options else '',
                otherOptions=' disabled' if backendServer.draining else ''
            )

    http_frontend_list.sort(key=lambda x: x[0], reverse=True)
    https_frontend_list.sort(key=lambda x: x[0], reverse=True)

    for backend in http_frontend_list:
        http_frontends += backend[1]
    for backend in https_frontend_list:
        https_frontends += backend[1]

    config += userlists
    if bind_http_https:
        config += http_frontends
    config += http_appid_frontends
    if bind_http_https:
        config += https_frontends
    config += frontends
    config += backends

    return config


def get_haproxy_pids():
    try:
        return set(map(lambda i: int(i), subprocess.check_output(
            "pidof haproxy",
            stderr=subprocess.STDOUT,
            shell=True).split()))
    except subprocess.CalledProcessError:
        return set()


def reloadConfig():
    reloadCommand = []
    if args.command:
        reloadCommand = shlex.split(args.command)
    else:
        logger.debug("No reload command provided, trying to find out how to" +
                     " reload the configuration")
        if os.path.isfile('/etc/init/haproxy.conf'):
            logger.debug("we seem to be running on an Upstart based system")
            reloadCommand = ['reload', 'haproxy']
        elif (os.path.isfile('/usr/lib/systemd/system/haproxy.service') or
              os.path.isfile('/lib/systemd/system/haproxy.service') or
              os.path.isfile('/etc/systemd/system/haproxy.service')):
            logger.debug("we seem to be running on systemd based system")
            reloadCommand = ['systemctl', 'reload', 'haproxy']
        elif os.path.isfile('/etc/init.d/haproxy'):
            logger.debug("we seem to be running on a sysvinit based system")
            reloadCommand = ['/etc/init.d/haproxy', 'reload']
        else:
            # if no haproxy exists (maybe running in a container)
            logger.debug("no haproxy detected. won't reload.")
            reloadCommand = None

    if reloadCommand:
        logger.info("reloading using %s", " ".join(reloadCommand))
        try:
            start_time = time.time()
            old_pids = get_haproxy_pids()
            subprocess.check_call(reloadCommand, close_fds=True)
            # Wait until the reload actually occurs and there's a new PID
            while len(get_haproxy_pids() - old_pids) < 1:
                logger.debug("Waiting for new haproxy pid...")
                time.sleep(0.1)
            logger.debug("reload finished, took %s seconds",
                         time.time() - start_time)
        except OSError as ex:
            logger.error("unable to reload config using command %s",
                         " ".join(reloadCommand))
            logger.error("OSError: %s", ex)
        except subprocess.CalledProcessError as ex:
            logger.error("unable to reload config using command %s",
                         " ".join(reloadCommand))
            logger.error("reload returned non-zero: %s", ex)


def generateHttpVhostAcl(
        templater, app, backend, haproxy_map, map_array,
        haproxy_dir, duplicate_map):
    # If the hostname contains the delimiter ',', then the marathon app is
    # requesting multiple hostname matches for the same backend, and we need
    # to use alternate templates from the default one-acl/one-use_backend.
    staging_http_frontends = ""
    staging_https_frontends = ""

    if "," in app.hostname:
        logger.debug(
            "vhost label specifies multiple hosts: %s", app.hostname)
        vhosts = app.hostname.split(',')
        acl_name = re.sub(r'[^a-zA-Z0-9\-]', '_', vhosts[0]) + \
            '_' + app.appId[1:].replace('/', '_')

        if app.path:
            if app.authRealm:
                # Set the path ACL if it exists
                logger.debug("adding path acl, path=%s", app.path)
                http_frontend_acl = \
                    templater.\
                    haproxy_http_frontend_acl_only_with_path_and_auth(app)
                staging_http_frontends += http_frontend_acl.format(
                    path=app.path,
                    cleanedUpHostname=acl_name,
                    hostname=vhosts[0],
                    realm=app.authRealm,
                    backend=backend
                )
                https_frontend_acl = \
                    templater.\
                    haproxy_https_frontend_acl_only_with_path(app)
                staging_https_frontends += https_frontend_acl.format(
                    path=app.path,
                    cleanedUpHostname=acl_name,
                    hostname=vhosts[0],
                    realm=app.authRealm,
                    backend=backend
                )
            else:
                # Set the path ACL if it exists
                logger.debug("adding path acl, path=%s", app.path)
                http_frontend_acl = \
                    templater.haproxy_http_frontend_acl_only_with_path(app)
                staging_http_frontends += http_frontend_acl.format(
                    path=app.path,
                    backend=backend
                )
                https_frontend_acl = \
                    templater.haproxy_https_frontend_acl_only_with_path(app)
                staging_https_frontends += https_frontend_acl.format(
                    path=app.path,
                    backend=backend
                )

        for vhost_hostname in vhosts:
            logger.debug("processing vhost %s", vhost_hostname)
            if haproxy_map and not app.path and not app.authRealm and \
                    not app.redirectHttpToHttps:
                if 'map_http_frontend_acl' not in duplicate_map:
                    app.backend_weight = -1
                    http_frontend_acl = templater.\
                        haproxy_map_http_frontend_acl_only(app)
                    staging_http_frontends += http_frontend_acl.format(
                        haproxy_dir=haproxy_dir
                    )
                    duplicate_map['map_http_frontend_acl'] = 1
                map_element = {}
                map_element[vhost_hostname] = backend
                if map_element not in map_array:
                    map_array.append(map_element)
            else:
                http_frontend_acl = templater.\
                    haproxy_http_frontend_acl_only(app)
                staging_http_frontends += http_frontend_acl.format(
                    cleanedUpHostname=acl_name,
                    hostname=vhost_hostname
                )

            # Tack on the SSL ACL as well
            if app.path:
                if app.authRealm:
                    https_frontend_acl = templater.\
                        haproxy_https_frontend_acl_with_auth_and_path(app)
                    staging_https_frontends += https_frontend_acl.format(
                        cleanedUpHostname=acl_name,
                        hostname=vhost_hostname,
                        appId=app.appId,
                        realm=app.authRealm,
                        backend=backend
                    )
                else:
                    https_frontend_acl = \
                        templater.haproxy_https_frontend_acl_with_path(app)
                    staging_https_frontends += https_frontend_acl.format(
                        cleanedUpHostname=acl_name,
                        hostname=vhost_hostname,
                        appId=app.appId,
                        backend=backend
                    )
            else:
                if app.authRealm:
                    https_frontend_acl = \
                        templater.haproxy_https_frontend_acl_with_auth(app)
                    staging_https_frontends += https_frontend_acl.format(
                        cleanedUpHostname=acl_name,
                        hostname=vhost_hostname,
                        appId=app.appId,
                        realm=app.authRealm,
                        backend=backend
                    )
                else:
                    if haproxy_map:
                        if 'map_https_frontend_acl' not in duplicate_map:
                            https_frontend_acl = templater.\
                                haproxy_map_https_frontend_acl(app)
                            staging_https_frontends += https_frontend_acl.\
                                format(
                                    hostname=vhost_hostname,
                                    haproxy_dir=haproxy_dir
                                )
                            duplicate_map['map_https_frontend_acl'] = 1
                        map_element = {}
                        map_element[vhost_hostname] = backend
                        if map_element not in map_array:
                            map_array.append(map_element)

                    else:
                        https_frontend_acl = templater.\
                            haproxy_https_frontend_acl(app)
                        staging_https_frontends += https_frontend_acl.format(
                            cleanedUpHostname=acl_name,
                            hostname=vhost_hostname,
                            appId=app.appId,
                            backend=backend
                        )

        # We've added the http acl lines, now route them to the same backend
        if app.redirectHttpToHttps:
            logger.debug("writing rule to redirect http to https traffic")
            if app.path:
                haproxy_backend_redirect_http_to_https = \
                    templater.\
                    haproxy_backend_redirect_http_to_https_with_path(app)
                frontend = haproxy_backend_redirect_http_to_https.format(
                    bindAddr=app.bindAddr,
                    cleanedUpHostname=acl_name,
                    backend=backend
                )
                staging_http_frontends += frontend
            else:
                haproxy_backend_redirect_http_to_https = \
                    templater.haproxy_backend_redirect_http_to_https(app)
                frontend = haproxy_backend_redirect_http_to_https.format(
                    bindAddr=app.bindAddr,
                    cleanedUpHostname=acl_name
                )
                staging_http_frontends += frontend
        elif app.path:
            if app.authRealm:
                http_frontend_route = \
                    templater.\
                    haproxy_http_frontend_routing_only_with_path_and_auth(app)
                staging_http_frontends += http_frontend_route.format(
                    cleanedUpHostname=acl_name,
                    realm=app.authRealm,
                    backend=backend
                )
            else:
                http_frontend_route = \
                    templater.haproxy_http_frontend_routing_only_with_path(app)
                staging_http_frontends += http_frontend_route.format(
                    cleanedUpHostname=acl_name,
                    backend=backend
                )
        else:
            if app.authRealm:
                http_frontend_route = \
                    templater.\
                    haproxy_http_frontend_routing_only_with_auth(app)
                staging_http_frontends += http_frontend_route.format(
                    cleanedUpHostname=acl_name,
                    realm=app.authRealm,
                    backend=backend
                )
            else:
                if not haproxy_map:
                    http_frontend_route = \
                        templater.haproxy_http_frontend_routing_only(app)
                    staging_http_frontends += http_frontend_route.format(
                        cleanedUpHostname=acl_name,
                        backend=backend
                    )

    else:
        # A single hostname in the VHOST label
        logger.debug(
            "adding virtual host for app with hostname %s", app.hostname)
        acl_name = re.sub(r'[^a-zA-Z0-9\-]', '_', app.hostname) + \
            '_' + app.appId[1:].replace('/', '_')

        if app.path:
            if app.redirectHttpToHttps:
                http_frontend_acl = \
                    templater.haproxy_http_frontend_acl_only(app)
                staging_http_frontends += http_frontend_acl.format(
                    cleanedUpHostname=acl_name,
                    hostname=app.hostname
                )
                http_frontend_acl = \
                    templater.haproxy_http_frontend_acl_only_with_path(app)
                staging_http_frontends += http_frontend_acl.format(
                    cleanedUpHostname=acl_name,
                    hostname=app.hostname,
                    path=app.path,
                    backend=backend
                )
                haproxy_backend_redirect_http_to_https = \
                    templater.\
                    haproxy_backend_redirect_http_to_https_with_path(app)
                frontend = haproxy_backend_redirect_http_to_https.format(
                    bindAddr=app.bindAddr,
                    cleanedUpHostname=acl_name,
                    backend=backend
                )
                staging_http_frontends += frontend
            else:
                if app.authRealm:
                    http_frontend_acl = \
                        templater.\
                        haproxy_http_frontend_acl_with_auth_and_path(app)
                    staging_http_frontends += http_frontend_acl.format(
                        cleanedUpHostname=acl_name,
                        hostname=app.hostname,
                        path=app.path,
                        appId=app.appId,
                        realm=app.authRealm,
                        backend=backend
                    )
                else:
                    http_frontend_acl = \
                        templater.haproxy_http_frontend_acl_with_path(app)
                    staging_http_frontends += http_frontend_acl.format(
                        cleanedUpHostname=acl_name,
                        hostname=app.hostname,
                        path=app.path,
                        appId=app.appId,
                        backend=backend
                    )
            https_frontend_acl = \
                templater.haproxy_https_frontend_acl_only_with_path(app)
            staging_https_frontends += https_frontend_acl.format(
                path=app.path,
                backend=backend
            )
            if app.authRealm:
                https_frontend_acl = \
                    templater.\
                    haproxy_https_frontend_acl_with_auth_and_path(app)
                staging_https_frontends += https_frontend_acl.format(
                    cleanedUpHostname=acl_name,
                    hostname=app.hostname,
                    path=app.path,
                    appId=app.appId,
                    realm=app.authRealm,
                    backend=backend
                )
            else:
                https_frontend_acl = \
                    templater.haproxy_https_frontend_acl_with_path(app)
                staging_https_frontends += https_frontend_acl.format(
                    cleanedUpHostname=acl_name,
                    hostname=app.hostname,
                    appId=app.appId,
                    backend=backend
                )
        else:
            if app.redirectHttpToHttps:
                http_frontend_acl = \
                    templater.haproxy_http_frontend_acl_only(app)
                staging_http_frontends += http_frontend_acl.format(
                    cleanedUpHostname=acl_name,
                    hostname=app.hostname
                )
                haproxy_backend_redirect_http_to_https = \
                    templater.\
                    haproxy_backend_redirect_http_to_https(app)
                frontend = haproxy_backend_redirect_http_to_https.format(
                    bindAddr=app.bindAddr,
                    cleanedUpHostname=acl_name
                )
                staging_http_frontends += frontend
            else:
                if app.authRealm:
                    http_frontend_acl = \
                        templater.haproxy_http_frontend_acl_with_auth(app)
                    staging_http_frontends += http_frontend_acl.format(
                        cleanedUpHostname=acl_name,
                        hostname=app.hostname,
                        appId=app.appId,
                        realm=app.authRealm,
                        backend=backend
                    )
                else:
                    if haproxy_map:
                        if 'map_http_frontend_acl' not in duplicate_map:
                            app.backend_weight = -1
                            http_frontend_acl = \
                                templater.haproxy_map_http_frontend_acl(app)
                            staging_http_frontends += http_frontend_acl.format(
                                haproxy_dir=haproxy_dir
                            )
                            duplicate_map['map_http_frontend_acl'] = 1
                        map_element = {}
                        map_element[app.hostname] = backend
                        if map_element not in map_array:
                            map_array.append(map_element)
                    else:
                        http_frontend_acl = \
                            templater.haproxy_http_frontend_acl(app)
                        staging_http_frontends += http_frontend_acl.format(
                            cleanedUpHostname=acl_name,
                            hostname=app.hostname,
                            appId=app.appId,
                            backend=backend
                        )
            if app.authRealm:
                https_frontend_acl = \
                    templater.haproxy_https_frontend_acl_with_auth(app)
                staging_https_frontends += https_frontend_acl.format(
                    cleanedUpHostname=acl_name,
                    hostname=app.hostname,
                    appId=app.appId,
                    realm=app.authRealm,
                    backend=backend
                )
            else:
                if haproxy_map:
                    if 'map_https_frontend_acl' not in duplicate_map:
                        app.backend_weight = -1
                        https_frontend_acl = templater.\
                            haproxy_map_https_frontend_acl(app)
                        staging_https_frontends += https_frontend_acl.format(
                            hostname=app.hostname,
                            haproxy_dir=haproxy_dir
                        )
                        duplicate_map['map_https_frontend_acl'] = 1
                    map_element = {}
                    map_element[app.hostname] = backend
                    if map_element not in map_array:
                        map_array.append(map_element)
                else:
                    https_frontend_acl = templater.\
                        haproxy_https_frontend_acl(app)
                    staging_https_frontends += https_frontend_acl.format(
                        cleanedUpHostname=acl_name,
                        hostname=app.hostname,
                        appId=app.appId,
                        backend=backend
                    )
    return (app.backend_weight,
            staging_http_frontends,
            staging_https_frontends)


def writeConfigAndValidate(
        config, config_file, domain_map_string, domain_map_file,
        app_map_string, app_map_file, haproxy_map):
    # Test run, print to stdout and exit
    if args.dry:
        print(config)
        sys.exit()

    temp_config = config

    # First write the new maps to temporary files
    if haproxy_map:
        domain_temp_map_file = writeReplacementTempFile(domain_map_string,
                                                        domain_map_file)
        app_temp_map_file = writeReplacementTempFile(app_map_string,
                                                     app_map_file)

        # Change the file paths in the config to (temporarily) point to the
        # temporary map files so those can also be checked when the config is
        # validated
        temp_config = config.replace(
            domain_map_file, domain_temp_map_file
        ).replace(app_map_file, app_temp_map_file)

    # Write the new config to a temporary file
    haproxyTempConfigFile = writeReplacementTempFile(temp_config, config_file)

    if validateConfig(haproxyTempConfigFile):
        # Move into place
        if haproxy_map:
            moveTempFile(domain_temp_map_file, domain_map_file)
            moveTempFile(app_temp_map_file, app_map_file)

            # Edit the config file again to point to the actual map paths
            with open(haproxyTempConfigFile, 'w') as tempConfig:
                tempConfig.write(config)
        else:
            truncateMapFileIfExists(domain_map_file)
            truncateMapFileIfExists(app_map_file)

        moveTempFile(haproxyTempConfigFile, config_file)
        return True
    else:
        return False


def writeReplacementTempFile(content, file_to_replace):
    # Create a temporary file containing the given content that will be used to
    # replace the given file after validation. Returns the path to the
    # temporary file.
    fd, tempFile = mkstemp()
    logger.debug(
        "writing temp file %s that will replace %s", tempFile, file_to_replace)
    with os.fdopen(fd, 'w') as tempConfig:
        tempConfig.write(content)

    # Ensure the new file is created with the same permissions the old file had
    # or use defaults if the file doesn't exist yet
    perms = 0o644
    if os.path.isfile(file_to_replace):
        perms = stat.S_IMODE(os.lstat(file_to_replace).st_mode)
    os.chmod(tempFile, perms)

    return tempFile


def validateConfig(haproxy_config_file):
    # If skip validation flag is provided, don't check.
    if args.skip_validation:
        logger.debug("skipping validation.")
        return True

    # Check that config is valid
    cmd = ['haproxy', '-f', haproxy_config_file, '-c']
    logger.debug("checking config with command: " + str(cmd))
    returncode = subprocess.call(args=cmd)
    if returncode == 0:
        return True
    else:
        logger.error("haproxy returned non-zero when checking config")
        return False


def moveTempFile(temp_file, dest_file):
    # Replace the old file with the new from its temporary location
    logger.debug("moving temp file %s to %s", temp_file, dest_file)
    move(temp_file, dest_file)


def truncateMapFileIfExists(map_file):
    if os.path.isfile(map_file):
        logger.debug("Truncating map file as haproxy-map flag "
                     "is disabled %s", map_file)
        fd = os.open(map_file, os.O_RDWR)
        os.ftruncate(fd, 0)
        os.close(fd)


def compareWriteAndReloadConfig(config, config_file, domain_map_array,
                                app_map_array, haproxy_map):
    # See if the last config on disk matches this, and if so don't reload
    # haproxy
    domain_map_file = os.path.join(os.path.dirname(config_file),
                                   "domain2backend.map")
    app_map_file = os.path.join(os.path.dirname(config_file),
                                "app2backend.map")

    domain_map_string = str()
    app_map_string = str()
    runningConfig = str()
    try:
        logger.debug("reading running config from %s", config_file)
        with open(config_file, "r") as f:
            runningConfig = f.read()
    except IOError:
        logger.warning("couldn't open config file for reading")

    if haproxy_map:
        domain_map_string = generateMapString(domain_map_array)
        app_map_string = generateMapString(app_map_array)

        if (runningConfig != config or
                compareMapFile(domain_map_file, domain_map_string) or
                compareMapFile(app_map_file, app_map_string)):
            logger.info(
                "running config/map is different from generated"
                " config - reloading")
            if writeConfigAndValidate(
                    config, config_file, domain_map_string, domain_map_file,
                    app_map_string, app_map_file, haproxy_map):
                reloadConfig()
            else:
                logger.warning("skipping reload: config/map not valid")
        else:
            logger.debug("skipping reload: config/map unchanged")
    else:
        truncateMapFileIfExists(domain_map_file)
        truncateMapFileIfExists(app_map_file)
        if runningConfig != config:
            logger.info(
                "running config is different from generated config"
                " - reloading")
            if writeConfigAndValidate(
                    config, config_file, domain_map_string, domain_map_file,
                    app_map_string, app_map_file, haproxy_map):
                reloadConfig()
            else:
                logger.warning("skipping reload: config not valid")
        else:
            logger.debug("skipping reload: config unchanged")


def generateMapString(map_array):
    # Generate the string representation of the map file from a map array
    map_string = str()
    for element in map_array:
        for key, value in list(element.items()):
            map_string = map_string + str(key) + " " + str(value) + "\n"
    return map_string


def compareMapFile(map_file, map_string):
    # Read the map file (creating an empty file if it does not exist) and
    # compare its contents to the given map string. Returns true if the map
    # string is different to the contents of the file.
    if not os.path.isfile(map_file):
        open(map_file, 'a').close()

    runningmap = str()
    try:
        logger.debug("reading map config from %s", map_file)
        with open(map_file, "r") as f:
            runningmap = f.read()
    except IOError:
        logger.warning("couldn't open map file for reading")

    return runningmap != map_string


def get_health_check(app, portIndex):
    if 'healthChecks' not in app:
        return None
    for check in app['healthChecks']:
        if check.get('port'):
            return check
        if check.get('portIndex') == portIndex:
            return check
    return None


healthCheckResultCache = LRUCache()


def get_apps(marathon):
    apps = marathon.list()
    logger.debug("got apps %s", [app["id"] for app in apps])

    marathon_apps = []
    # This process requires 2 passes: the first is to gather apps belonging
    # to a deployment group.
    processed_apps = []
    deployment_groups = {}
    for app in apps:
        deployment_group = None
        if 'HAPROXY_DEPLOYMENT_GROUP' in app['labels']:
            deployment_group = app['labels']['HAPROXY_DEPLOYMENT_GROUP']
            # mutate the app id to match deployment group
            if deployment_group[0] != '/':
                deployment_group = '/' + deployment_group
            app['id'] = deployment_group
        else:
            processed_apps.append(app)
            continue
        if deployment_group in deployment_groups:
            # merge the groups, with the oldest taking precedence
            prev = deployment_groups[deployment_group]
            cur = app

            # If for some reason neither label is set correctly, then it's a
            # crapshoot. Most likely, whichever one is unset was not deployed
            # with ZDD, so we should prefer the one with a date set.
            cur_date = datetime.datetime.min
            prev_date = datetime.datetime.min
            if 'HAPROXY_DEPLOYMENT_STARTED_AT' in prev['labels']:
                prev_date = dateutil.parser.parse(
                    prev['labels']['HAPROXY_DEPLOYMENT_STARTED_AT'])

            if 'HAPROXY_DEPLOYMENT_STARTED_AT' in cur['labels']:
                cur_date = dateutil.parser.parse(
                    cur['labels']['HAPROXY_DEPLOYMENT_STARTED_AT'])

            old = new = None
            if prev_date < cur_date:
                old = prev
                new = cur
            else:
                new = prev
                old = cur

            if 'HAPROXY_DEPLOYMENT_NEW_INSTANCES' in new['labels']:
                if int(new['labels']['HAPROXY_DEPLOYMENT_NEW_INSTANCES'] != 0):
                    new_scale_time = dateutil.parser.parse(
                        new['versionInfo']['lastScalingAt'])
                    old_scale_time = dateutil.parser.parse(
                        old['versionInfo']['lastScalingAt'])
                    if old_scale_time > new_scale_time:
                        temp = old
                        old = new
                        new = temp

            target_instances = \
                int(new['labels']['HAPROXY_DEPLOYMENT_TARGET_INSTANCES'])

            # Mark N tasks from old app as draining, where N is the
            # number of instances in the new app.  Sort the old tasks so that
            # order is deterministic (i.e. so that we always drain the same
            # tasks).
            old_tasks = sorted(old['tasks'], key=lambda task: task['id'])

            healthy_new_instances = 0
            if len(app['healthChecks']) > 0:
                for task in new['tasks']:
                    if 'healthCheckResults' not in task:
                        continue
                    alive = True
                    for result in task['healthCheckResults']:
                        if not result['alive']:
                            alive = False
                    if alive:
                        healthy_new_instances += 1
            else:
                healthy_new_instances = new['instances']

            maximum_drainable = \
                max(0, (healthy_new_instances + old['instances']) -
                    target_instances)

            for i in range(0, min(len(old_tasks),
                                  healthy_new_instances,
                                  maximum_drainable)):
                old_tasks[i]['draining'] = True

            # merge tasks from new app into old app
            merged = old
            old_tasks.extend(new['tasks'])
            merged['tasks'] = old_tasks

            deployment_groups[deployment_group] = merged
        else:
            deployment_groups[deployment_group] = app

    processed_apps.extend(deployment_groups.values())

    # Reset the service port assigner.  This forces the port assigner to
    # re-assign ports for IP-per-task applications.  The upshot is that
    # the service port for a particular app may change dynamically, but
    # the service port will be deterministic and identical across all
    # instances of the marathon-lb.
    SERVICE_PORT_ASSIGNER.reset()

    for app in processed_apps:
        appId = app['id']
        if appId[1:] == os.environ.get("FRAMEWORK_NAME"):
            continue

        marathon_app = MarathonApp(marathon, appId, app)

        if 'HAPROXY_GROUP' in marathon_app.app['labels']:
            marathon_app.groups = \
                marathon_app.app['labels']['HAPROXY_GROUP'].split(',')
        marathon_apps.append(marathon_app)

        service_ports = SERVICE_PORT_ASSIGNER.get_service_ports(app)
        for i, servicePort in enumerate(service_ports):
            if servicePort is None:
                logger.warning("Skipping undefined service port")
                continue

            service = MarathonService(appId, servicePort,
                                      get_health_check(app, i),
                                      marathon.strict_mode())

            for key_unformatted in label_keys:
                key = key_unformatted.format(i)
                if key in marathon_app.app['labels']:
                    func = label_keys[key_unformatted]
                    func(service,
                         key_unformatted,
                         marathon_app.app['labels'][key])

            # https://github.com/mesosphere/marathon-lb/issues/198
            # Marathon app manifest which defines healthChecks is
            # defined for a specific given service port identified
            # by either a port or portIndex.
            # (Marathon itself will prefer port before portIndex
            # https://mesosphere.github.io/marathon/docs/health-checks.html)
            #
            # We want to be able to instruct HAProxy
            # to use health check defined for service port B
            # in marathon to indicate service port A is healthy
            # or not for service port A in HAProxy.
            #
            # This is done by specifying a label:
            #  HAPROXY_{n}_BACKEND_HEALTHCHECK_PORT_INDEX
            #
            # TODO(norangshol) Refactor and supply MarathonService
            # TODO(norangshol) with its labels and do this in its constructor?
            if service.healthCheck is None \
                    and service.healthcheck_port_index is not None:
                service.healthCheck = \
                    get_health_check(app, service.healthcheck_port_index)
                if service.healthCheck:
                    healthProto = service.healthCheck['protocol']
                    if healthProto in ['HTTP', 'HTTPS', 'MESOS_HTTP',
                                       'MESOS_HTTPS']:
                        service.mode = 'http'

            marathon_app.services[servicePort] = service

        for task in app['tasks']:
            # Marathon 0.7.6 bug workaround
            if not task['host']:
                logger.warning("Ignoring Marathon task without host " +
                               task['id'])
                continue

            if marathon.health_check() and 'healthChecks' in app and \
               len(app['healthChecks']) > 0:
                alive = True
                if 'healthCheckResults' not in task:
                    # use previously cached result, if it exists
                    if not healthCheckResultCache.get(task['id'], False):
                        continue
                else:
                    for result in task['healthCheckResults']:
                        if not result['alive']:
                            alive = False
                    healthCheckResultCache.set(task['id'], alive)
                    if not alive:
                        continue

            task_ip, task_ports = get_task_ip_and_ports(app, task)
            if task_ip is None:
                logger.warning("Task has no resolvable IP address - skip")
                continue

            draining = task.get('draining', False)

            # if different versions of app have different number of ports,
            # try to match as many ports as possible
            for task_port, service_port in zip(task_ports, service_ports):
                service = marathon_app.services.get(service_port, None)
                if service:
                    service.groups = marathon_app.groups
                    service.add_backend(task['host'],
                                        task_ip,
                                        task_port,
                                        draining)

    # Convert into a list for easier consumption
    apps_list = []
    for marathon_app in marathon_apps:
        for service in list(marathon_app.services.values()):
            if service.backends:
                apps_list.append(service)

    return apps_list


def regenerate_config(apps, config_file, groups, bind_http_https,
                      ssl_certs, templater, haproxy_map):
    domain_map_array = []
    app_map_array = []

    generated_config = config(apps, groups, bind_http_https, ssl_certs,
                              templater, haproxy_map, domain_map_array,
                              app_map_array, config_file)

    compareWriteAndReloadConfig(generated_config, config_file,
                                domain_map_array, app_map_array, haproxy_map)


class MarathonEventProcessor(object):

    def __init__(self, marathon, config_file, groups,
                 bind_http_https, ssl_certs, haproxy_map):
        self.__marathon = marathon
        # appId -> MarathonApp
        self.__apps = dict()
        self.__config_file = config_file
        self.__groups = groups
        self.__templater = ConfigTemplater()
        self.__bind_http_https = bind_http_https
        self.__ssl_certs = ssl_certs

        self.__condition = threading.Condition()
        self.__pending_reset = False
        self.__pending_reload = False
        self.__haproxy_map = haproxy_map

        # Fetch the base data
        self.reset_from_tasks()

    def start(self):
        self.__stop = False
        self.__thread = threading.Thread(target=self.try_reset)
        self.__thread.start()

    def try_reset(self):
        with self.__condition:
            logger.info('starting event processor thread')
            while True:
                self.__condition.acquire()

                if self.__stop:
                    logger.info('stopping event processor thread')
                    self.__condition.release()
                    return

                if not self.__pending_reset and not self.__pending_reload:
                    if not self.__condition.wait(300):
                        logger.info('condition wait expired')

                pending_reset = self.__pending_reset
                pending_reload = self.__pending_reload
                self.__pending_reset = False
                self.__pending_reload = False

                self.__condition.release()

                # Reset takes precedence over reload
                if pending_reset:
                    self.do_reset()
                elif pending_reload:
                    self.do_reload()
                else:
                    # Timed out waiting on the condition variable, just do a
                    # full reset for good measure (as was done before).
                    self.do_reset()

    def do_reset(self):
        try:
            start_time = time.time()

            self.__apps = get_apps(self.__marathon)
            regenerate_config(self.__apps,
                              self.__config_file,
                              self.__groups,
                              self.__bind_http_https,
                              self.__ssl_certs,
                              self.__templater,
                              self.__haproxy_map)

            logger.debug("updating tasks finished, took %s seconds",
                         time.time() - start_time)
        except requests.exceptions.ConnectionError as e:
            logger.error("Connection error({0}): {1}".format(
                e.errno, e.strerror))
        except:
            logger.exception("Unexpected error!")

    def do_reload(self):
        try:
            # Validate the existing config before reloading
            logger.debug("attempting to reload existing config...")
            if validateConfig(self.__config_file):
                reloadConfig()
        except:
            logger.exception("Unexpected error!")

    def stop(self):
        self.__condition.acquire()
        self.__stop = True
        self.__condition.notify()
        self.__condition.release()

    def reset_from_tasks(self):
        self.__condition.acquire()
        self.__pending_reset = True
        self.__condition.notify()
        self.__condition.release()

    def reload_existing_config(self):
        self.__condition.acquire()
        self.__pending_reload = True
        self.__condition.notify()
        self.__condition.release()

    def handle_event(self, event):
        if event['eventType'] == 'status_update_event' or \
                event['eventType'] == 'health_status_changed_event' or \
                event['eventType'] == 'api_post_event':
            self.reset_from_tasks()

    def handle_signal(self, sig, stack):
        if sig == signal.SIGHUP:
            logger.debug('received signal SIGHUP - reloading config')
            self.reset_from_tasks()
        elif sig == signal.SIGUSR1:
            logger.debug('received signal SIGUSR1 - reloading existing config')
            self.reload_existing_config()
        else:
            logger.warning('received unknown signal %d' % (sig,))


def get_arg_parser():
    parser = argparse.ArgumentParser(
        description="Marathon HAProxy Load Balancer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--longhelp",
                        help="Print out configuration details",
                        action="store_true"
                        )
    parser.add_argument("--marathon", "-m",
                        nargs="+",
                        help="[required] Marathon endpoint, eg. " +
                             "-m http://marathon1:8080 http://marathon2:8080",
                        default=["http://master.mesos:8080"]
                        )
    parser.add_argument("--haproxy-config",
                        help="Location of haproxy configuration",
                        default="/etc/haproxy/haproxy.cfg"
                        )
    parser.add_argument("--group",
                        help="[required] Only generate config for apps which"
                        " list the specified names. Use '*' to match all"
                        " groups, including those without a group specified.",
                        action="append",
                        default=list())
    parser.add_argument("--command", "-c",
                        help="If set, run this command to reload haproxy.",
                        default=None)
    parser.add_argument("--strict-mode",
                        help="If set, backends are only advertised if"
                        " HAPROXY_{n}_ENABLED=true. Strict mode will be"
                        " enabled by default in a future release.",
                        action="store_true")
    parser.add_argument("--sse", "-s",
                        help="Use Server Sent Events",
                        action="store_true")
    parser.add_argument("--health-check", "-H",
                        help="If set, respect Marathon's health check "
                        "statuses before adding the app instance into "
                        "the backend pool.",
                        action="store_true")
    parser.add_argument("--lru-cache-capacity",
                        help="LRU cache size (in number "
                        "of items). This should be at least as large as the "
                        "number of tasks exposed via marathon-lb.",
                        type=int, default=1000
                        )
    parser.add_argument("--haproxy-map",
                        help="Use HAProxy maps for domain name to backend"
                        "mapping.", action="store_true")
    parser.add_argument("--dont-bind-http-https",
                        help="Don't bind to HTTP and HTTPS frontends.",
                        action="store_true")
    parser.add_argument("--ssl-certs",
                        help="List of SSL certificates separated by comma"
                             "for frontend marathon_https_in"
                             "Ex: /etc/ssl/site1.co.pem,/etc/ssl/site2.co.pem",
                        default="/etc/ssl/cert.pem")
    parser.add_argument("--skip-validation",
                        help="Skip haproxy config file validation",
                        action="store_true")
    parser.add_argument("--dry", "-d",
                        help="Only print configuration to console",
                        action="store_true")
    parser.add_argument("--min-serv-port-ip-per-task",
                        help="Minimum port number to use when auto-assigning "
                             "service ports for IP-per-task applications",
                        type=int, default=10050)
    parser.add_argument("--max-serv-port-ip-per-task",
                        help="Maximum port number to use when auto-assigning "
                             "service ports for IP-per-task applications",
                        type=int, default=10100)
    parser = set_logging_args(parser)
    parser = set_marathon_auth_args(parser)
    return parser


def process_sse_events(marathon, processor):
    try:
        processor.start()
        events = marathon.get_event_stream()
        for event in events:
            try:
                # logger.info("received event: {0}".format(event))
                # marathon might also send empty messages as keepalive...
                if (event.data.strip() != ''):
                    # marathon sometimes sends more than one json per event
                    # e.g. {}\r\n{}\r\n\r\n
                    for real_event_data in re.split(r'\r\n', event.data):
                        data = load_json(real_event_data)
                        logger.info(
                            "received event of type {0}"
                            .format(data['eventType']))
                        processor.handle_event(data)
                else:
                    logger.info("skipping empty message")
            except:
                print(event.data)
                print("Unexpected error:", sys.exc_info()[0])
                traceback.print_stack()
                raise
    finally:
        processor.stop()


def load_json(data_str):
    return cleanup_json(json.loads(data_str))


if __name__ == '__main__':
    # Process arguments
    arg_parser = get_arg_parser()
    args = arg_parser.parse_args()

    # Print the long help text if flag is set
    if args.longhelp:
        print(__doc__)
        print('```')
        arg_parser.print_help()
        print('```')
        print(ConfigTemplater().get_descriptions())
        sys.exit()
    # otherwise make sure that a Marathon URL was specified
    else:
        if args.marathon is None:
            arg_parser.error('argument --marathon/-m is required')
        if bool(args.min_serv_port_ip_per_task) != \
           bool(args.max_serv_port_ip_per_task):
            arg_parser.error(
                'either specify both --min-serv-port-ip-per-task '
                'and --max-serv-port-ip-per-task or neither (set both to zero '
                'to disable auto assignment)')
        if args.min_serv_port_ip_per_task > args.max_serv_port_ip_per_task:
            arg_parser.error(
                'cannot set --min-serv-port-ip-per-task to a higher value '
                'than --max-serv-port-ip-per-task')
        if len(args.group) == 0:
            arg_parser.error('argument --group is required: please' +
                             'specify at least one group name')

    # Configure the service port assigner if min/max ports have been specified.
    if args.min_serv_port_ip_per_task and args.max_serv_port_ip_per_task:
        SERVICE_PORT_ASSIGNER.set_ports(args.min_serv_port_ip_per_task,
                                        args.max_serv_port_ip_per_task)

    # Set request retries
    s = requests.Session()
    a = requests.adapters.HTTPAdapter(max_retries=3)
    s.mount('http://', a)

    # Setup logging
    setup_logging(logger, args.syslog_socket, args.log_format, args.log_level)

    # initialize health check LRU cache
    if args.health_check:
        healthCheckResultCache = LRUCache(args.lru_cache_capacity)
    ip_cache.set(LRUCache(args.lru_cache_capacity))

    # Marathon API connector
    marathon = Marathon(args.marathon,
                        args.health_check,
                        args.strict_mode,
                        get_marathon_auth_params(args),
                        args.marathon_ca_cert)

    # If we're going to be handling events, set up the event processor and
    # hook it up to the process signals.
    if args.sse:
        processor = MarathonEventProcessor(marathon,
                                           args.haproxy_config,
                                           args.group,
                                           not args.dont_bind_http_https,
                                           args.ssl_certs,
                                           args.haproxy_map)
        signal.signal(signal.SIGHUP, processor.handle_signal)
        signal.signal(signal.SIGUSR1, processor.handle_signal)
        backoff = 3
        while True:
            stream_started = time.time()
            try:
                process_sse_events(marathon, processor)
            except:
                logger.exception("Caught exception")
                backoff = backoff * 1.5
                if backoff > 300:
                    backoff = 300
                logger.error("Reconnecting in {}s...".format(backoff))
            # Reset the backoff if it's been more than 10 minutes
            if time.time() - stream_started > 600:
                backoff = 3
            time.sleep(random.random() * backoff)
    else:
        # Generate base config
        regenerate_config(get_apps(marathon),
                          args.haproxy_config,
                          args.group,
                          not args.dont_bind_http_https,
                          args.ssl_certs,
                          ConfigTemplater(),
                          args.haproxy_map)
