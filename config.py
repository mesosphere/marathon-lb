#!/usr/bin/env python3

import logging
import os

logger = logging.getLogger('marathon_lb')


class ConfigTemplate:
    def __init__(self, name, value, overridable, description):
        self.name = name
        self.full_name = 'HAPROXY_' + name
        self.value = value
        self.default_value = value
        self.overridable = overridable
        self.description = description


class ConfigTemplater(object):
    def add_template(self, template):
        self.t[template.name] = template

    def global_default_options(self):
        default = 'redispatch,http-server-close,dontlognull'
        options = os.getenv('HAPROXY_GLOBAL_DEFAULT_OPTIONS', default)
        template = '  option            {opt}\n'
        lines = sorted(set(template.format(opt=opt.strip())
                           for opt in options.split(',')))
        return ''.join(lines)

    def load(self):
        self.add_template(
            ConfigTemplate(name='HEAD',
                           value='''\
global
  daemon
  log /dev/log local0
  log /dev/log local1 notice
  spread-checks 5
  max-spread-checks 15000
  maxconn 50000
  tune.ssl.default-dh-param 2048
  ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:\
ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:\
ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:\
DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:\
ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES128-SHA256:\
DHE-RSA-AES256-SHA256:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:\
AES256-SHA256:!aNULL:!MD5:!DSS
  ssl-default-bind-options no-sslv3 no-tlsv10 no-tls-tickets
  ssl-default-server-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:\
ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:\
ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:\
DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:\
ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES128-SHA256:\
DHE-RSA-AES256-SHA256:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:\
AES256-SHA256:!aNULL:!MD5:!DSS
  ssl-default-server-options no-sslv3 no-tlsv10 no-tls-tickets
  stats socket /var/run/haproxy/socket
  server-state-file global
  server-state-base /var/state/haproxy/
  lua-load /marathon-lb/getpids.lua
  lua-load /marathon-lb/getconfig.lua
  lua-load /marathon-lb/getmaps.lua
  lua-load /marathon-lb/signalmlb.lua
defaults
  load-server-state-from-file global
  log               global
  retries                   3
  backlog               10000
  maxconn               10000
  timeout connect          3s
  timeout client          30s
  timeout server          30s
  timeout tunnel        3600s
  timeout http-keep-alive  1s
  timeout http-request    15s
  timeout queue           30s
  timeout tarpit          60s
''' + self.global_default_options() + '''\
listen stats
  bind 0.0.0.0:9090
  balance
  mode http
  stats enable
  monitor-uri /_haproxy_health_check
  acl getpid path /_haproxy_getpids
  http-request use-service lua.getpids if getpid
  acl getvhostmap path /_haproxy_getvhostmap
  http-request use-service lua.getvhostmap if getvhostmap
  acl getappmap path /_haproxy_getappmap
  http-request use-service lua.getappmap if getappmap
  acl getconfig path /_haproxy_getconfig
  http-request use-service lua.getconfig if getconfig

  acl signalmlbhup path /_mlb_signal/hup
  http-request use-service lua.signalmlbhup if signalmlbhup
  acl signalmlbusr1 path /_mlb_signal/usr1
  http-request use-service lua.signalmlbusr1 if signalmlbusr1
''',
                           overridable=False,
                           description='''\
The head of the HAProxy config. This contains global settings
and defaults.
'''))

        self.add_template(
            ConfigTemplate(name='USERLIST_HEAD',
                           value='''
userlist user_{backend}
  user {user} password {passwd}
''',
                           overridable=True,
                           description='''\
The userlist for basic HTTP auth.
'''))

        self.add_template(
            ConfigTemplate(name='HTTP_FRONTEND_HEAD',
                           value='''
frontend marathon_http_in
  bind *:80
  mode http
''',
                           overridable=False,
                           description='''\
An HTTP frontend that binds to port *:80 by default and gathers
all virtual hosts as defined by the `HAPROXY_{n}_VHOST` label.
'''))

        self.add_template(
            ConfigTemplate(name='HTTP_FRONTEND_APPID_HEAD',
                           value='''
frontend marathon_http_appid_in
  bind *:9091
  mode http
''',
                           overridable=False,
                           description='''\
An HTTP frontend that binds to port *:9091 by default and gathers
all apps in HTTP mode.
To use this frontend to forward to your app, configure the app with
`HAPROXY_0_MODE=http` then you can access it via a call to the :9091
with the header "X-Marathon-App-Id" set to the Marathon AppId.
Note multiple HTTP ports being exposed by the same marathon app are not
supported. Only the first HTTP port is available via this frontend.
'''))

        # TODO(lloesche): make certificate path dynamic and allow multi-certs
        self.add_template(
            ConfigTemplate(name='HTTPS_FRONTEND_HEAD',
                           value='''
frontend marathon_https_in
  bind *:443 ssl {sslCerts}
  mode http
''',
                           overridable=False,
                           description='''\
An HTTPS frontend for encrypted connections that binds to port *:443 by
default and gathers all virtual hosts as defined by the
`HAPROXY_{n}_VHOST` label. You must modify this file to
include your certificate.
'''))

        self.add_template(
            ConfigTemplate(name='FRONTEND_HEAD',
                           value='''
frontend {backend}
  bind {bindAddr}:{servicePort}{sslCert}{bindOptions}
  mode {mode}
''',
                           overridable=True,
                           description='''\
Defines the address and port to bind to for this frontend.
'''))

        self.add_template(
            ConfigTemplate(name='BACKEND_HEAD',
                           value='''
backend {backend}
  balance {balance}
  mode {mode}
''',
                           overridable=True,
                           description='''\
Defines the type of load balancing, roundrobin by default,
and connection mode, TCP or HTTP.
'''))

        self.add_template(
            ConfigTemplate(name='BACKEND_REDIRECT_HTTP_TO_HTTPS',
                           value='''\
  redirect scheme https code 301 if !{{ ssl_fc }} host_{cleanedUpHostname}
''',
                           overridable=True,
                           description='''\
This template is used with backends where the
`HAPROXY_{n}_REDIRECT_TO_HTTPS` label is set to true
'''))

        self.add_template(
            ConfigTemplate(name='BACKEND_REDIRECT_HTTP_TO_HTTPS_WITH_PATH',
                           value='''\
  redirect scheme https code 301 if !{{ ssl_fc }} host_{cleanedUpHostname}\
 path_{backend}
''',
                           overridable=True,
                           description='''\
Same as `HAPROXY_BACKEND_REDIRECT_HTTP_TO_HTTPS`,
but includes a path.
'''))

        self.add_template(
            ConfigTemplate(name='BACKEND_HSTS_OPTIONS',
                           value='''\
  rspadd  Strict-Transport-Security:\ max-age=15768000
''',
                           overridable=True,
                           description='''\
This template is used for the backend where the
`HAPROXY_{n}_USE_HSTS` label is set to true.
'''))

        self.add_template(
            ConfigTemplate(name='HTTP_FRONTEND_ACL',
                           value='''\
  acl host_{cleanedUpHostname} hdr(host) -i {hostname}
  use_backend {backend} if host_{cleanedUpHostname}
''',
                           overridable=True,
                           description='''\
The ACL that glues a backend to the corresponding virtual host
of the `HAPROXY_HTTP_FRONTEND_HEAD`
'''))

        self.add_template(
            ConfigTemplate(name='MAP_HTTP_FRONTEND_ACL',
                           value='''\
  use_backend %[req.hdr(host),lower,regsub(:.*$,,),\
map({haproxy_dir}/domain2backend.map)]
''',
                           overridable=True,
                           description='''\
The ACL that glues a backend to the corresponding virtual host
of the `HAPROXY_HTTP_FRONTEND_HEAD` using haproxy maps.
'''))

        self.add_template(
            ConfigTemplate(name='HTTP_FRONTEND_ACL_WITH_AUTH',
                           value='''\
  acl host_{cleanedUpHostname} hdr(host) -i {hostname}
  acl auth_{cleanedUpHostname} http_auth(user_{backend})
  http-request auth realm "{realm}" if host_{cleanedUpHostname}\
 !auth_{cleanedUpHostname}
  use_backend {backend} if host_{cleanedUpHostname}
''',
                           overridable=True,
                           description='''\
The ACL that glues a backend to the corresponding virtual host
of the `HAPROXY_HTTP_FRONTEND_HEAD` thru HTTP basic auth.
'''))

        self.add_template(
            ConfigTemplate(name='HTTP_FRONTEND_ACL_ONLY',
                           value='''\
  acl host_{cleanedUpHostname} hdr(host) -i {hostname}
''',
                           overridable=True,
                           description='''\
Define the ACL matching a particular hostname, but unlike
`HAPROXY_HTTP_FRONTEND_ACL`, only do the ACL portion. Does not glue
the ACL to the backend. This is useful only in the case of multiple
vhosts routing to the same backend.
'''))

        self.add_template(
            ConfigTemplate(name='MAP_HTTP_FRONTEND_ACL_ONLY',
                           value='''\
  use_backend %[req.hdr(host),lower,regsub(:.*$,,),\
map({haproxy_dir}/domain2backend.map)]
''',
                           overridable=True,
                           description='''\
Define the ACL matching a particular hostname, This is useful only in the case
 of multiple vhosts routing to the same backend in haproxy map.
'''))

        self.add_template(
            ConfigTemplate(name='HTTP_FRONTEND_ROUTING_ONLY',
                           value='''\
  use_backend {backend} if host_{cleanedUpHostname}
''',
                           overridable=True,
                           description='''\
This is the counterpart to `HAPROXY_HTTP_FRONTEND_ACL_ONLY` which
glues the acl name to the appropriate backend.
'''))

        self.add_template(
            ConfigTemplate(name='HTTP_FRONTEND_ROUTING_ONLY_WITH_AUTH',
                           value='''\
  acl auth_{cleanedUpHostname} http_auth(user_{backend})
  http-request auth realm "{realm}" if host_{cleanedUpHostname} \
!auth_{cleanedUpHostname}
  use_backend {backend} if host_{cleanedUpHostname}
''',
                           overridable=True,
                           description='''\
This is the counterpart to `HAPROXY_HTTP_FRONTEND_ACL_ONLY` which
glues the acl name to the appropriate backend, and add http basic auth.
'''))

        self.add_template(
            ConfigTemplate(name='HTTP_FRONTEND_ACL_WITH_PATH',
                           value='''\
  acl host_{cleanedUpHostname} hdr(host) -i {hostname}
  acl path_{backend} path_beg {path}
  use_backend {backend} if host_{cleanedUpHostname} path_{backend}
''',
                           overridable=True,
                           description='''\
The ACL that glues a backend to the corresponding virtual host with path
of the `HAPROXY_HTTP_FRONTEND_HEAD`.
'''))

        self.add_template(
            ConfigTemplate(name='HTTP_FRONTEND_ACL_WITH_AUTH_AND_PATH',
                           value='''\
  acl host_{cleanedUpHostname} hdr(host) -i {hostname}
  acl auth_{cleanedUpHostname} http_auth(user_{backend})
  acl path_{backend} path_beg {path}
  http-request auth realm "{realm}" if host_{cleanedUpHostname} \
path_{backend} !auth_{cleanedUpHostname}
  use_backend {backend} if host_{cleanedUpHostname} path_{backend}
''',
                           overridable=True,
                           description='''\
The ACL that glues a backend to the corresponding virtual host with path
of the `HAPROXY_HTTP_FRONTEND_HEAD` thru HTTP basic auth.
'''))

        self.add_template(
            ConfigTemplate(name='HTTP_FRONTEND_ACL_ONLY_WITH_PATH',
                           value='''\
  acl path_{backend} path_beg {path}
''',
                           overridable=True,
                           description='''\
Define the ACL matching a particular hostname with path, but unlike
`HAPROXY_HTTP_FRONTEND_ACL_WITH_PATH`, only do the ACL portion. Does not glue
the ACL to the backend. This is useful only in the case of multiple
vhosts routing to the same backend
'''))

        self.add_template(
            ConfigTemplate(name='HTTP_FRONTEND_ACL_ONLY_WITH_PATH_AND_AUTH',
                           value='''\
  acl path_{backend} path_beg {path}
  acl auth_{cleanedUpHostname} http_auth(user_{backend})
''',
                           overridable=True,
                           description='''\
Define the ACL matching a particular hostname with path and auth, but unlike
`HAPROXY_HTTP_FRONTEND_ACL_WITH_PATH`, only do the ACL portion. Does not glue
the ACL to the backend. This is useful only in the case of multiple
vhosts routing to the same backend
'''))

        self.add_template(
            ConfigTemplate(name='HTTPS_FRONTEND_ACL_ONLY_WITH_PATH',
                           value='''\
  acl path_{backend} path_beg {path}
''',
                           overridable=True,
                           description='''\
Same as HTTP_FRONTEND_ACL_ONLY_WITH_PATH, but for HTTPS.
'''))

        self.add_template(
            ConfigTemplate(name='HTTP_FRONTEND_ROUTING_ONLY_WITH_PATH',
                           value='''\
  use_backend {backend} if host_{cleanedUpHostname} path_{backend}
''',
                           overridable=True,
                           description='''\
This is the counterpart to `HAPROXY_HTTP_FRONTEND_ACL_ONLY_WITH_PATH` which
glues the acl names to the appropriate backend
'''))

        self.add_template(
            ConfigTemplate(name='\
HTTP_FRONTEND_ROUTING_ONLY_WITH_PATH_AND_AUTH',
                           value='''\
  http-request auth realm "{realm}" if host_{cleanedUpHostname} \
path_{backend} !auth_{cleanedUpHostname}
  use_backend {backend} if host_{cleanedUpHostname} path_{backend}
''',
                           overridable=True,
                           description='''\
This is the counterpart to `HAPROXY_HTTP_FRONTEND_ACL_ONLY_WITH_PATH` which
glues the acl names to the appropriate backend
'''))

        # XXX Missing function set label in app, as well as not appending
        # a label. Since neither exist, not adding this for now.
        self.add_template(
            ConfigTemplate(name='\
HTTPS_FRONTEND_ROUTING_ONLY_WITH_PATH_AND_AUTH',
                           value='''\
  http-request auth realm "{realm}" if host_{cleanedUpHostname} \
path_{backend} !auth_{cleanedUpHostname}
  use_backend {backend} if host_{cleanedUpHostname} path_{backend}
''',
                           overridable=True,
                           description='''\
This is the counterpart to `HAPROXY_HTTP_FRONTEND_ACL_ONLY_WITH_PATH` which
glues the acl names to the appropriate backend
'''))
        self.add_template(
            ConfigTemplate(name='HTTP_FRONTEND_APPID_ACL',
                           value='''\
  acl app_{cleanedUpAppId} hdr(x-marathon-app-id) -i {appId}
  use_backend {backend} if app_{cleanedUpAppId}
''',
                           overridable=True,
                           description='''\
The ACL that glues a backend to the corresponding app
of the `HAPROXY_HTTP_FRONTEND_APPID_HEAD`.
'''))

        self.add_template(
            ConfigTemplate(name='MAP_HTTP_FRONTEND_APPID_ACL',
                           value='''\
  use_backend %[req.hdr(x-marathon-app-id),lower,\
map({haproxy_dir}/app2backend.map)]
''',
                           overridable=True,
                           description='''\
The ACL that glues a backend to the corresponding app
of the `HAPROXY_HTTP_FRONTEND_APPID_HEAD` using haproxy maps.
'''))

        self.add_template(
            ConfigTemplate(name='HTTPS_FRONTEND_ACL',
                           value='''\
  use_backend {backend} if {{ ssl_fc_sni {hostname} }}
''',
                           overridable=True,
                           description='''\
The ACL that performs the SNI based hostname matching
for the `HAPROXY_HTTPS_FRONTEND_HEAD` template.
'''))

        self.add_template(
            ConfigTemplate(name='MAP_HTTPS_FRONTEND_ACL',
                           value='''\
  use_backend %[ssl_fc_sni,lower,map({haproxy_dir}/domain2backend.map)]
''',
                           overridable=True,
                           description='''\
The ACL that performs the SNI based hostname matching
for the `HAPROXY_HTTPS_FRONTEND_HEAD` template using haproxy maps
'''))

        self.add_template(
            ConfigTemplate(name='HTTPS_FRONTEND_ACL_WITH_AUTH',
                           value='''\
  acl auth_{cleanedUpHostname} http_auth(user_{backend})
  http-request auth realm "{realm}" if {{ ssl_fc_sni {hostname} }} \
!auth_{cleanedUpHostname}
  use_backend {backend} if {{ ssl_fc_sni {hostname} }}
''',
                           overridable=True,
                           description='''\
The ACL that glues a backend to the corresponding virtual host
of the `HAPROXY_HTTPS_FRONTEND_HEAD` thru HTTP basic auth.
'''))

        # XXX Missing function set label in app, as well as not appending
        # a label. Since neither exist, not adding this for now.
        self.add_template(
            ConfigTemplate(name='HTTPS_FRONTEND_AUTH_ACL_ONLY',
                           value='''\
  acl auth_{cleanedUpHostname} http_auth(user_{backend})
''',
                           overridable=True,
                           description='''\
The http auth ACL to the corresponding virtual host.
'''))

        # XXX Missing function set label in app, as well as not appending
        # a label. Since neither exist, not adding this for now.
        self.add_template(
            ConfigTemplate(name='HTTPS_FRONTEND_AUTH_REQUEST_ONLY',
                           value='''\
  http-request auth realm "{realm}" if {{ ssl_fc_sni {hostname} }} \
!auth_{cleanedUpHostname}
''',
                           overridable=True,
                           description='''\
The http auth request to the corresponding virtual host.
'''))

        self.add_template(
            ConfigTemplate(name='HTTPS_FRONTEND_ACL_WITH_PATH',
                           value='''\
  use_backend {backend} if {{ ssl_fc_sni {hostname} }} path_{backend}
''',
                           overridable=True,
                           description='''\
The ACL that performs the SNI based hostname matching with path
for the `HAPROXY_HTTPS_FRONTEND_HEAD` template.
'''))

        self.add_template(
            ConfigTemplate(name='HTTPS_FRONTEND_ACL_WITH_AUTH_AND_PATH',
                           value='''\
  acl auth_{cleanedUpHostname} http_auth(user_{backend})
  http-request auth realm "{realm}" if {{ ssl_fc_sni {hostname} }} \
path_{backend} !auth_{cleanedUpHostname}
  use_backend {backend} if {{ ssl_fc_sni {hostname} }} path_{backend}
''',
                           overridable=True,
                           description='''\
The ACL that glues a backend to the corresponding virtual host with path
of the `HAPROXY_HTTPS_FRONTEND_HEAD` thru HTTP basic auth.
'''))

        self.add_template(
            ConfigTemplate(name='BACKEND_HTTP_OPTIONS',
                           value='''\
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
''',
                           overridable=True,
                           description='''\
Sets HTTP headers, for example X-Forwarded-For and X-Forwarded-Proto.
'''))

        self.add_template(
            ConfigTemplate(name='HTTP_BACKEND_PROXYPASS_GLUE',
                           value='''\
  http-request set-header Host {hostname}
  reqirep  "^([^ :]*)\ {proxypath}/?(.*)" "\\1\ /\\2"
''',
                           overridable=True,
                           description='''\
Backend glue for `HAPROXY_{n}_HTTP_BACKEND_PROXYPASS_PATH`.
'''))

        self.add_template(
            ConfigTemplate(name='HTTP_BACKEND_REVPROXY_GLUE',
                           value='''\
  acl hdr_location res.hdr(Location) -m found
  rspirep "^Location: (https?://{hostname}(:[0-9]+)?)?(/.*)" "Location: \
  {rootpath} if hdr_location"
''',
                           overridable=True,
                           description='''\
Backend glue for `HAPROXY_{n}_HTTP_BACKEND_REVPROXY_PATH`.
'''))

        self.add_template(
            ConfigTemplate(name='HTTP_BACKEND_REDIR',
                           value='''\
  acl is_root path -i /
  acl is_domain hdr(host) -i {hostname}
  redirect code 301 location {redirpath} if is_domain is_root
''',
                           overridable=True,
                           description='''\
Set the path to redirect the root of the domain to
Ex: HAPROXY_0_HTTP_BACKEND_REDIR = '/my/content'
'''))

        self.add_template(
            ConfigTemplate(name='BACKEND_HTTP_HEALTHCHECK_OPTIONS',
                           value='''\
  option  httpchk GET {healthCheckPath}
  timeout check {healthCheckTimeoutSeconds}s
''',
                           overridable=True,
                           description='''\
Sets HTTP health check options, for example timeout check and httpchk GET.
Parameters of the first health check for this service are exposed as:
  * healthCheckPortIndex
  * healthCheckPort
  * healthCheckProtocol
  * healthCheckPath
  * healthCheckTimeoutSeconds
  * healthCheckIntervalSeconds
  * healthCheckGracePeriodSeconds
  * healthCheckMaxConsecutiveFailures
  * healthCheckFalls is set to healthCheckMaxConsecutiveFailures + 1
  * healthCheckPortOptions is set to ` port {healthCheckPort}`

Defaults to empty string.

Example:
```
  option  httpchk GET {healthCheckPath}
  timeout check {healthCheckTimeoutSeconds}s
```
  '''))

        self.add_template(
            ConfigTemplate(name='BACKEND_TCP_HEALTHCHECK_OPTIONS',
                           value='',
                           overridable=True,
                           description='''\
Sets TCP health check options, for example timeout check.
Parameters of the first health check for this service are exposed as:
  * healthCheckPortIndex
  * healthCheckPort
  * healthCheckProtocol
  * healthCheckTimeoutSeconds
  * healthCheckIntervalSeconds
  * healthCheckGracePeriodSeconds
  * healthCheckMaxConsecutiveFailures
  * healthCheckFalls is set to healthCheckMaxConsecutiveFailures + 1
  * healthCheckPortOptions is set to ` port {healthCheckPort}`

Defaults to empty string.

Example:
```
  timeout check {healthCheckTimeoutSeconds}s
```
  '''))

        self.add_template(
            ConfigTemplate(name='BACKEND_STICKY_OPTIONS',
                           value='''\
  cookie mesosphere_server_id insert indirect nocache
''',
                           overridable=True,
                           description='''\
Sets a cookie for services where `HAPROXY_{n}_STICKY` is true.
    '''))

        self.add_template(
            ConfigTemplate(name='BACKEND_SERVER_OPTIONS',
                           value='''\
  server {serverName} {host_ipv4}:{port}{cookieOptions}\
{healthCheckOptions}{otherOptions}
''',
                           overridable=True,
                           description='''\
The options for each server added to a backend.
    '''))

        self.add_template(
            ConfigTemplate(name='BACKEND_SERVER_HTTP_HEALTHCHECK_OPTIONS',
                           value='''\
  check inter {healthCheckIntervalSeconds}s fall {healthCheckFalls}\
{healthCheckPortOptions}
''',
                           overridable=True,
                           description='''\
Sets HTTP health check options for a single server, e.g. check inter.
Parameters of the first health check for this service are exposed as:
  * healthCheckPortIndex
  * healthCheckPort
  * healthCheckProtocol
  * healthCheckPath
  * healthCheckTimeoutSeconds
  * healthCheckIntervalSeconds
  * healthCheckGracePeriodSeconds
  * healthCheckMaxConsecutiveFailures
  * healthCheckFalls is set to healthCheckMaxConsecutiveFailures + 1
  * healthCheckPortOptions is set to ` port {healthCheckPort}`

Defaults to empty string.

Example:
```
  check inter {healthCheckIntervalSeconds}s fall {healthCheckFalls}
```
  '''))

        self.add_template(
            ConfigTemplate(name='BACKEND_SERVER_TCP_HEALTHCHECK_OPTIONS',
                           value='''\
  check inter {healthCheckIntervalSeconds}s fall {healthCheckFalls}\
{healthCheckPortOptions}
''',
                           overridable=True,
                           description='''\
Sets TCP health check options for a single server, e.g. check inter.
Parameters of the first health check for this service are exposed as:
  * healthCheckPortIndex
  * healthCheckPort
  * healthCheckProtocol
  * healthCheckTimeoutSeconds
  * healthCheckIntervalSeconds
  * healthCheckGracePeriodSeconds
  * healthCheckMaxConsecutiveFailures
  * healthCheckFalls is set to healthCheckMaxConsecutiveFailures + 1
  * healthCheckPortOptions is set to ` port {healthCheckPort}`

Defaults to empty string.

Example:
```
  check inter {healthCheckIntervalSeconds}s fall {healthCheckFalls}
```
  '''))

        self.add_template(
            ConfigTemplate(name='FRONTEND_BACKEND_GLUE',
                           value='''\
  use_backend {backend}
''',
                           overridable=True,
                           description='''\
This option glues the backend to the frontend.
    '''))

        self.add_template(
            ConfigTemplate(name='HTTP_BACKEND_NETWORK_ALLOWED_ACL',
                           value='''\
  acl network_allowed src {network_allowed}
''',
                           overridable=True,
                           description='''\
This option set the IPs (or IP ranges) having access to the HTTP backend.
'''))

        self.add_template(
            ConfigTemplate(name='HTTP_BACKEND_ACL_ALLOW_DENY',
                           value='''\
  http-request allow if network_allowed
  http-request deny
''',
                           overridable=False,
                           description='''\
This option denies all IPs (or IP ranges) not explicitly allowed to access\
 the HTTP backend.
Use with `HAPROXY_HTTP_BACKEND_NETWORK_ALLOWED_ACL`.
'''))

        self.add_template(
            ConfigTemplate(name='TCP_BACKEND_NETWORK_ALLOWED_ACL',
                           value='''\
  acl network_allowed src {network_allowed}
''',
                           overridable=True,
                           description='''\
This option set the IPs (or IP ranges) having access to the TCP backend.
'''))

        self.add_template(
            ConfigTemplate(name='TCP_BACKEND_ACL_ALLOW_DENY',
                           value='''\
  tcp-request content accept if network_allowed
  tcp-request content reject
''',
                           overridable=False,
                           description='''\
This option denies all IPs (or IP ranges) not explicitly allowed to access\
 the TCP backend.
Use with HAPROXY_TCP_BACKEND_ACL_ALLOW_DENY.
'''))

    def __init__(self, directory='templates'):
        self.__template_directory = directory
        self.t = dict()
        self.load()
        self.__load_templates()

    def __load_templates(self):
        '''Look in environment variables for templates.  If not set in env,
        load template files if they exist. Othwerwise it sets defaults'''

        for template in self.t:
            name = self.t[template].full_name
            if os.environ.get(name):
                logger.info('overriding %s from environment variable', name)
                env_template_val = os.environ.get(name)

                # Handle escaped endlines
                self.t[template].value = env_template_val.replace("\\n", "\n")
            else:
                try:
                    filename = os.path.join(self.__template_directory, name)
                    with open(filename) as f:
                        logger.info('overriding %s from %s', name, filename)
                        self.t[template].value = f.read()
                except IOError:
                    logger.debug("setting default value for %s", name)

    def get_descriptions(self):
        descriptions = '''\
## Templates

The following is a list of the available HAProxy templates.
Some templates are global-only (such as `HAPROXY_HEAD`), but most may
be overridden on a per service port basis using the
`HAPROXY_{n}_...` syntax.

'''
        desc_template = '''\
## `{full_name}`
  *{overridable}*

Specified as {specifiedAs}.

{description}

**Default template for `{full_name}`:**
```
{default}```
'''
        for tname in sorted(self.t.keys()):
            t = self.t[tname]
            spec = "`HAPROXY_" + t.name + "` template"
            if t.overridable:
                spec += " or with label `HAPROXY_{n}_" + t.name + "`"
            descriptions += desc_template.format(
                full_name=t.full_name,
                specifiedAs=spec,
                overridable="Overridable per app" if t.overridable
                else "Global",
                description=t.description,
                default=t.default_value
            )

        descriptions += '''\
## Other Labels
These labels may be used to configure other app settings.

'''
        desc_template = '''\
## `{full_name}`
  *{perServicePort}*

Specified as {specifiedAs}.

{description}

'''
        for label in labels:
            if label.name not in self.t:
                if label.name == 'GROUP':
                    # this one is a special snowflake
                    spec = "`HAPROXY_{n}_" + label.name + "`" + " or " + \
                        "`HAPROXY_" + label.name + "`"
                elif label.perServicePort:
                    spec = "`HAPROXY_{n}_" + label.name + "`"
                else:
                    spec = "`HAPROXY_" + label.name + "`"
                descriptions += desc_template.format(
                    full_name=label.full_name.replace('_{0}_', '_{n}_'),
                    specifiedAs=spec,
                    perServicePort="per service port" if label.perServicePort
                    else "per app",
                    description=label.description
                )
        return descriptions

    @property
    def haproxy_head(self):
        return self.t['HEAD'].value

    @property
    def haproxy_http_frontend_head(self):
        return self.t['HTTP_FRONTEND_HEAD'].value

    @property
    def haproxy_http_frontend_appid_head(self):
        return self.t['HTTP_FRONTEND_APPID_HEAD'].value

    @property
    def haproxy_http_backend_acl_allow_deny(self):
        return self.t['HTTP_BACKEND_ACL_ALLOW_DENY'].value

    @property
    def haproxy_tcp_backend_acl_allow_deny(self):
        return self.t['TCP_BACKEND_ACL_ALLOW_DENY'].value

    @property
    def haproxy_https_frontend_head(self):
        return self.t['HTTPS_FRONTEND_HEAD'].value

    def haproxy_userlist_head(self, app):
        if 'HAPROXY_{0}_USERLIST_HEAD' in app.labels:
            return app.labels['HAPROXY_{0}_USERLIST_HEAD']
        return self.t['USERLIST_HEAD'].value

    def haproxy_http_frontend_acl_with_auth(self, app):
        if 'HAPROXY_{0}_HTTP_FRONTEND_ACL_WITH_AUTH' in app.labels:
            return app.labels['HAPROXY_{0}_HTTP_FRONTEND_ACL_WITH_AUTH']
        return self.t['HTTP_FRONTEND_ACL_WITH_AUTH'].value

    def haproxy_https_frontend_acl_with_auth(self, app):
        if 'HAPROXY_{0}_HTTPS_FRONTEND_ACL_WITH_AUTH' in app.labels:
            return app.labels['HAPROXY_{0}_HTTPS_FRONTEND_ACL_WITH_AUTH']
        return self.t['HTTPS_FRONTEND_ACL_WITH_AUTH'].value

    def haproxy_http_frontend_acl_with_auth_and_path(self, app):
        if 'HAPROXY_{0}_HTTP_FRONTEND_ACL_WITH_AUTH_AND_PATH' in app.labels:
            return \
                app.labels['HAPROXY_{0}_HTTP_FRONTEND_ACL_WITH_AUTH_AND_PATH']
        return self.t['HTTP_FRONTEND_ACL_WITH_AUTH_AND_PATH'].value

    def haproxy_https_frontend_acl_with_auth_and_path(self, app):
        if 'HAPROXY_{0}_HTTPS_FRONTEND_ACL_WITH_AUTH_AND_PATH' in app.labels:
            return \
                app.labels['HAPROXY_{0}_HTTPS_FRONTEND_ACL_WITH_AUTH_AND_PATH']
        return self.t['HTTPS_FRONTEND_ACL_WITH_AUTH_AND_PATH'].value

    def haproxy_frontend_head(self, app):
        if 'HAPROXY_{0}_FRONTEND_HEAD' in app.labels:
            return app.labels['HAPROXY_{0}_FRONTEND_HEAD']
        return self.t['FRONTEND_HEAD'].value

    def haproxy_backend_redirect_http_to_https(self, app):
        if 'HAPROXY_{0}_BACKEND_REDIRECT_HTTP_TO_HTTPS' in app.labels:
            return app.labels['HAPROXY_{0}_BACKEND_REDIRECT_HTTP_TO_HTTPS']
        return self.t['BACKEND_REDIRECT_HTTP_TO_HTTPS'].value

    def haproxy_backend_redirect_http_to_https_with_path(self, app):
        if 'HAPROXY_{0}_BACKEND_REDIRECT_HTTP_TO_HTTPS_WITH_PATH' in\
          app.labels:
            return app.\
                labels['HAPROXY_{0}_BACKEND_REDIRECT_HTTP_TO_HTTPS_WITH_PATH']
        return self.t['BACKEND_REDIRECT_HTTP_TO_HTTPS_WITH_PATH'].value

    def haproxy_backend_hsts_options(self, app):
        if 'HAPROXY_{0}_BACKEND_HSTS_OPTIONS' in app.labels:
            return app.labels['HAPROXY_{0}_BACKEND_HSTS_OPTIONS']
        return self.t['BACKEND_HSTS_OPTIONS'].value

    def haproxy_backend_head(self, app):
        if 'HAPROXY_{0}_BACKEND_HEAD' in app.labels:
            return app.labels['HAPROXY_{0}_BACKEND_HEAD']
        return self.t['BACKEND_HEAD'].value

    def haproxy_http_frontend_acl(self, app):
        if 'HAPROXY_{0}_HTTP_FRONTEND_ACL' in app.labels:
            return app.labels['HAPROXY_{0}_HTTP_FRONTEND_ACL']
        return self.t['HTTP_FRONTEND_ACL'].value

    def haproxy_map_http_frontend_acl(self, app):
        if 'HAPROXY_{0}_HTTP_FRONTEND_ACL' in app.labels:
            return app.labels['HAPROXY_{0}_HTTP_FRONTEND_ACL']
        return self.t['MAP_HTTP_FRONTEND_ACL'].value

    def haproxy_http_frontend_acl_only(self, app):
        if 'HAPROXY_{0}_HTTP_FRONTEND_ACL_ONLY' in app.labels:
            return app.labels['HAPROXY_{0}_HTTP_FRONTEND_ACL_ONLY']
        return self.t['HTTP_FRONTEND_ACL_ONLY'].value

    def haproxy_map_http_frontend_acl_only(self, app):
        if 'HAPROXY_{0}_HTTP_FRONTEND_ACL_ONLY' in app.labels:
            return app.labels['HAPROXY_{0}_HTTP_FRONTEND_ACL_ONLY']
        return self.t['MAP_HTTP_FRONTEND_ACL_ONLY'].value

    def haproxy_http_frontend_routing_only(self, app):
        if 'HAPROXY_{0}_HTTP_FRONTEND_ROUTING_ONLY' in app.labels:
            return app.labels['HAPROXY_{0}_HTTP_FRONTEND_ROUTING_ONLY']
        return self.t['HTTP_FRONTEND_ROUTING_ONLY'].value

    def haproxy_http_frontend_routing_only_with_auth(self, app):
        if 'HAPROXY_{0}_HTTP_FRONTEND_ROUTING_ONLY_WITH_AUTH' in app.labels:
            return app.\
                labels['HAPROXY_{0}_HTTP_FRONTEND_ROUTING_ONLY_WITH_AUTH']
        return self.t['HTTP_FRONTEND_ROUTING_ONLY_WITH_AUTH'].value

    def haproxy_http_frontend_acl_with_path(self, app):
        if 'HAPROXY_{0}_HTTP_FRONTEND_ACL_WITH_PATH' in app.labels:
            return app.labels['HAPROXY_{0}_HTTP_FRONTEND_ACL_WITH_PATH']
        return self.t['HTTP_FRONTEND_ACL_WITH_PATH'].value

    def haproxy_http_frontend_acl_only_with_path(self, app):
        if 'HAPROXY_{0}_HTTP_FRONTEND_ACL_ONLY_WITH_PATH' in app.labels:
            return app.labels['HAPROXY_{0}_HTTP_FRONTEND_ACL_ONLY_WITH_PATH']
        return self.t['HTTP_FRONTEND_ACL_ONLY_WITH_PATH'].value

    def haproxy_http_frontend_acl_only_with_path_and_auth(self, app):
        if 'HAPROXY_{0}_HTTP_FRONTEND_ACL_ONLY_WITH_PATH_AND_AUTH'\
         in app.labels:
            return\
             app.\
             labels['HAPROXY_{0}_HTTP_FRONTEND_ACL_ONLY_WITH_PATH_AND_AUTH']
        return self.t['HTTP_FRONTEND_ACL_ONLY_WITH_PATH_AND_AUTH'].value

    def haproxy_https_frontend_acl_only_with_path(self, app):
        if 'HAPROXY_{0}_HTTPS_FRONTEND_ACL_ONLY_WITH_PATH' in app.labels:
            return app.labels['HAPROXY_{0}_HTTPS_FRONTEND_ACL_ONLY_WITH_PATH']
        return self.t['HTTPS_FRONTEND_ACL_ONLY_WITH_PATH'].value

    def haproxy_http_frontend_routing_only_with_path(self, app):
        if 'HAPROXY_{0}_HTTP_FRONTEND_ROUTING_ONLY_WITH_PATH' in app.labels:
            return \
                app.labels['HAPROXY_{0}_HTTP_FRONTEND_ROUTING_ONLY_WITH_PATH']
        return self.t['HTTP_FRONTEND_ROUTING_ONLY_WITH_PATH'].value

    def haproxy_http_frontend_routing_only_with_path_and_auth(self, app):
        if 'HAPROXY_{0}_HTTP_FRONTEND_ROUTING_ONLY_WITH_PATH_AND_AUTH'\
         in app.labels:
            return\
             app.\
             labels[
                'HAPROXY_{0}_HTTP_FRONTEND_ROUTING_ONLY_WITH_PATH_AND_AUTH']
        return self.t['HTTP_FRONTEND_ROUTING_ONLY_WITH_PATH_AND_AUTH'].value

    def haproxy_http_frontend_appid_acl(self, app):
        if 'HAPROXY_{0}_HTTP_FRONTEND_APPID_ACL' in app.labels:
            return app.labels['HAPROXY_{0}_HTTP_FRONTEND_APPID_ACL']
        return self.t['HTTP_FRONTEND_APPID_ACL'].value

    def haproxy_map_http_frontend_appid_acl(self, app):
        if 'HAPROXY_{0}_HTTP_FRONTEND_APPID_ACL' in app.labels:
            return app.labels['HAPROXY_{0}_HTTP_FRONTEND_APPID_ACL']
        return self.t['MAP_HTTP_FRONTEND_APPID_ACL'].value

    def haproxy_https_frontend_acl(self, app):
        if 'HAPROXY_{0}_HTTPS_FRONTEND_ACL' in app.labels:
            return app.labels['HAPROXY_{0}_HTTPS_FRONTEND_ACL']
        return self.t['HTTPS_FRONTEND_ACL'].value

    def haproxy_map_https_frontend_acl(self, app):
        if 'HAPROXY_{0}_HTTPS_FRONTEND_ACL' in app.labels:
            return app.labels['HAPROXY_{0}_HTTPS_FRONTEND_ACL']
        return self.t['MAP_HTTPS_FRONTEND_ACL'].value

    def haproxy_https_frontend_acl_with_path(self, app):
        if 'HAPROXY_{0}_HTTPS_FRONTEND_ACL_WITH_PATH' in app.labels:
            return app.labels['HAPROXY_{0}_HTTPS_FRONTEND_ACL_WITH_PATH']
        return self.t['HTTPS_FRONTEND_ACL_WITH_PATH'].value

    def haproxy_backend_http_options(self, app):
        if 'HAPROXY_{0}_BACKEND_HTTP_OPTIONS' in app.labels:
            return app.labels['HAPROXY_{0}_BACKEND_HTTP_OPTIONS']
        return self.t['BACKEND_HTTP_OPTIONS'].value

    def haproxy_backend_http_healthcheck_options(self, app):
        if 'HAPROXY_{0}_BACKEND_HTTP_HEALTHCHECK_OPTIONS' in app.labels:
            return app.labels['HAPROXY_{0}_BACKEND_HTTP_HEALTHCHECK_OPTIONS']
        return self.t['BACKEND_HTTP_HEALTHCHECK_OPTIONS'].value

    def haproxy_backend_tcp_healthcheck_options(self, app):
        if 'HAPROXY_{0}_BACKEND_TCP_HEALTHCHECK_OPTIONS' in app.labels:
            return app.labels['HAPROXY_{0}_BACKEND_TCP_HEALTHCHECK_OPTIONS']
        return self.t['BACKEND_TCP_HEALTHCHECK_OPTIONS'].value

    def haproxy_backend_sticky_options(self, app):
        if 'HAPROXY_{0}_BACKEND_STICKY_OPTIONS' in app.labels:
            return app.labels['HAPROXY_{0}_BACKEND_STICKY_OPTIONS']
        return self.t['BACKEND_STICKY_OPTIONS'].value

    def haproxy_backend_server_options(self, app):
        if 'HAPROXY_{0}_BACKEND_SERVER_OPTIONS' in app.labels:
            return app.labels['HAPROXY_{0}_BACKEND_SERVER_OPTIONS']
        return self.t['BACKEND_SERVER_OPTIONS'].value

    def haproxy_http_backend_proxypass_glue(self, app):
        if 'HAPROXY_{0}_HTTP_BACKEND_PROXYPASS_GLUE' in app.labels:
            return app.labels['HAPROXY_{0}_HTTP_BACKEND_PROXYPASS_GLUE']
        return self.t['HTTP_BACKEND_PROXYPASS_GLUE'].value

    def haproxy_http_backend_revproxy_glue(self, app):
        if 'HAPROXY_{0}_HTTP_BACKEND_REVPROXY_GLUE' in app.labels:
            return app.labels['HAPROXY_{0}_HTTP_BACKEND_REVPROXY_GLUE']
        return self.t['HTTP_BACKEND_REVPROXY_GLUE'].value

    def haproxy_http_backend_redir(self, app):
        if 'HAPROXY_{0}_HTTP_BACKEND_REDIR' in app.labels:
            return app.labels['HAPROXY_{0}_HTTP_BACKEND_REDIR']
        return self.t['HTTP_BACKEND_REDIR'].value

    def haproxy_backend_server_http_healthcheck_options(self, app):
        if 'HAPROXY_{0}_BACKEND_SERVER_HTTP_HEALTHCHECK_OPTIONS' in \
                app.labels:
            return self.__blank_prefix_or_empty(
                app.labels['HAPROXY_{0}_BACKEND' +
                           '_SERVER_HTTP_HEALTHCHECK_OPTIONS']
                .strip())
        return self.__blank_prefix_or_empty(
            self.t['BACKEND_SERVER_HTTP_HEALTHCHECK_OPTIONS'].value.strip())

    def haproxy_backend_server_tcp_healthcheck_options(self, app):
        if 'HAPROXY_{0}_BACKEND_SERVER_TCP_HEALTHCHECK_OPTIONS' in app.labels:
            return self.__blank_prefix_or_empty(
                app.labels['HAPROXY_{0}_BACKEND_'
                           'SERVER_TCP_HEALTHCHECK_OPTIONS']
                .strip())
        return self.__blank_prefix_or_empty(
            self.t['BACKEND_SERVER_TCP_HEALTHCHECK_OPTIONS'].value.strip())

    def haproxy_frontend_backend_glue(self, app):
        if 'HAPROXY_{0}_FRONTEND_BACKEND_GLUE' in app.labels:
            return app.labels['HAPROXY_{0}_FRONTEND_BACKEND_GLUE']
        return self.t['FRONTEND_BACKEND_GLUE'].value

    def haproxy_http_backend_network_allowed_acl(self, app):
        if 'HAPROXY_{0}_HTTP_BACKEND_NETWORK_ALLOWED_ACL' in app.labels:
            return app.labels['HAPROXY_{0}_HTTP_BACKEND_NETWORK_ALLOWED_ACL']
        return self.t['HTTP_BACKEND_NETWORK_ALLOWED_ACL'].value

    def haproxy_tcp_backend_network_allowed_acl(self, app):
        if 'HAPROXY_{0}_TCP_BACKEND_NETWORK_ALLOWED_ACL' in app.labels:
            return app.labels['HAPROXY_{0}_TCP_BACKEND_NETWORK_ALLOWED_ACL']
        return self.t['TCP_BACKEND_NETWORK_ALLOWED_ACL'].value

    def __blank_prefix_or_empty(self, s):
        if s:
            return ' ' + s
        else:
            return s


def string_to_bool(s):
    return s.lower() in ["true", "t", "yes", "y"]


def set_hostname(x, k, v):
    x.hostname = v.lower()


def set_path(x, k, v):
    x.path = v
    if x.backend_weight == 0:
        x.backend_weight = 1


def set_sticky(x, k, v):
    x.sticky = string_to_bool(v)


def set_enabled(x, k, v):
    x.enabled = string_to_bool(v)


def set_redirect_http_to_https(x, k, v):
    x.redirectHttpToHttps = string_to_bool(v)


def set_auth(x, k, v):
    x.authRealm, x.authUser, x.authPasswd = v.split(':')


def set_use_hsts(x, k, v):
    x.useHsts = string_to_bool(v)


def set_sslCert(x, k, v):
    x.sslCert = v


def set_bindOptions(x, k, v):
    x.bindOptions = v


def set_bindAddr(x, k, v):
    x.bindAddr = v


def set_port(x, k, v):
    x.servicePort = int(v)


def set_healthcheck_port_index(x, k, v):
    x.healthcheck_port_index = int(v)


def set_backend_weight(x, k, v):
    x.backend_weight = int(v)


def set_mode(x, k, v):
    x.mode = v.lower()


def set_balance(x, k, v):
    x.balance = v


def set_label(x, k, v):
    x.labels[k] = v


def set_group(x, k, v):
    x.haproxy_groups = v.split(',')


def set_proxypath(x, k, v):
    x.proxypath = v


def set_revproxypath(x, k, v):
    x.revproxypath = v


def set_redirpath(x, k, v):
    x.redirpath = v


def set_network_allowed(x, k, v):
    x.network_allowed = v


class Label:
    def __init__(self, name, func, description, perServicePort=True):
        self.name = name
        self.perServicePort = perServicePort
        if perServicePort:
            self.full_name = 'HAPROXY_{0}_' + name
        else:
            self.full_name = 'HAPROXY_' + name
        self.func = func
        self.description = description


labels = []
labels.append(Label(name='AUTH',
                    func=set_auth,
                    description='''\
The http basic auth definition. \
For details on configuring auth, see: \
https://github.com/mesosphere/marathon-lb/wiki/HTTP-Basic-Auth

Ex: `HAPROXY_0_AUTH = realm:username:encryptedpassword`'''))
labels.append(Label(name='VHOST',
                    func=set_hostname,
                    description='''\
The Marathon HTTP Virtual Host proxy hostname(s) to gather.

If you have multiple backends which share VHosts or paths, you may need to
manually specify ordering of the backend ACLs with
`HAPROXY_{n}_BACKEND_WEIGHT`. In HAProxy, the `use_backend` directive is
evaluated in the order it appears in the configuration.

Ex: `HAPROXY_0_VHOST = 'marathon.mesosphere.com'`

Ex: `HAPROXY_0_VHOST = 'marathon.mesosphere.com,marathon'`
                    '''))
labels.append(Label(name='GROUP',
                    func=set_group,
                    description='''\
HAProxy group per service. This helps us have different HAProxy groups
per service port. This overrides `HAPROXY_GROUP` for the particular service.
If you have both external and internal services running on same set of
instances on different ports, you can use this feature to add them to
different haproxy configs.

Ex: `HAPROXY_0_GROUP = 'external'`

Ex: `HAPROXY_1_GROUP = 'internal'`

Now if you run marathon_lb with --group external, it just adds the
service on `HAPROXY_0_PORT` (or first service port incase `HAPROXY_0_HOST`
is not configured) to haproxy config and similarly if you run it with
--group internal, it adds service on `HAPROXY_1_PORT` to haproxy config.
If the configuration is a combination of `HAPROXY_GROUP` and
`HAPROXY_{n}_GROUP`, the more specific definition takes precedence.

Ex: `HAPROXY_0_GROUP = 'external'`

Ex: `HAPROXY_GROUP   = 'internal'`

Considering the above example where the configuration is hybrid,
a service running on `HAPROXY_0_PORT` is associated with just 'external'
HAProxy group and not 'internal' group. And since there is no HAProxy
group mentioned for second service (`HAPROXY_1_GROUP` not defined)
it falls back to default `HAPROXY_GROUP` and gets associated with
'internal' group.

Load balancers with the group '*' will collect all groups.
    '''))
labels.append(Label(name='DEPLOYMENT_GROUP',
                    func=None,
                    description='''\
Deployment group to which this app belongs.
                    ''',
                    perServicePort=False))
labels.append(Label(name='DEPLOYMENT_ALT_PORT',
                    func=None,
                    description='''\
Alternate service port to be used during a blue/green deployment.
                    ''',
                    perServicePort=False))
labels.append(Label(name='DEPLOYMENT_COLOUR',
                    func=None,
                    description='''\
Blue/green deployment colour. Used by the bluegreen_deploy.py script
to determine the state of a deploy. You generally do not need to modify
this unless you implement your own deployment orchestrator.
                    ''',
                    perServicePort=False))
labels.append(Label(name='DEPLOYMENT_STARTED_AT',
                    func=None,
                    description='''\
The time at which a deployment started. You generally do not need
to modify this unless you implement your own deployment orchestrator.
                    ''',
                    perServicePort=False))
labels.append(Label(name='DEPLOYMENT_TARGET_INSTANCES',
                    func=None,
                    description='''\
The target number of app instances to seek during deployment. You
generally do not need to modify this unless you implement your
own deployment orchestrator.
                    ''',
                    perServicePort=False))
labels.append(Label(name='PATH',
                    func=set_path,
                    description='''\
The HTTP path to match, starting at the beginning. To specify multiple paths,
pass a space separated list. The syntax matches that of the `path_beg` config
option in HAProxy. To use the path routing, you must also define a VHost.

If you have multiple backends which share VHosts or paths, you may need to
manually specify ordering of the backend ACLs with
`HAPROXY_{n}_BACKEND_WEIGHT`. In HAProxy, the `use_backend` directive is
evaluated in the order it appears in the configuration.

Ex: `HAPROXY_0_PATH = '/v2/api/derp'`

Ex: `HAPROXY_0_PATH = '-i /multiple /paths'`
                    '''))
labels.append(Label(name='STICKY',
                    func=set_sticky,
                    description='''\
Enable sticky request routing for the service.

Ex: `HAPROXY_0_STICKY = true`
                    '''))
labels.append(Label(name='ENABLED',
                    func=set_enabled,
                    description='''\
Enable this backend. By default, all backends are enabled. To disable
backends by default, specify the `--strict-mode` flag.

Ex: `HAPROXY_0_ENABLED = true`
                    '''))
labels.append(Label(name='REDIRECT_TO_HTTPS',
                    func=set_redirect_http_to_https,
                    description='''\
Redirect HTTP traffic to HTTPS. Requires at least a VHost be set.

Ex: `HAPROXY_0_REDIRECT_TO_HTTPS = true`
                    '''))
labels.append(Label(name='USE_HSTS',
                    func=set_use_hsts,
                    description='''\
Enable the HSTS response header for HTTP clients which support it.

Ex: `HAPROXY_0_USE_HSTS = true`
                    '''))
labels.append(Label(name='SSL_CERT',
                    func=set_sslCert,
                    description='''\
Enable the given SSL certificate for TLS/SSL traffic.

Ex: `HAPROXY_0_SSL_CERT = '/etc/ssl/cert.pem'`
                    '''))
labels.append(Label(name='BIND_OPTIONS',
                    func=set_bindOptions,
                    description='''\
Set additional bind options

Ex: `HAPROXY_0_BIND_OPTIONS = 'ciphers AES128+EECDH:AES128+EDH force-tlsv12\
 no-sslv3 no-tlsv10'`
                    '''))
labels.append(Label(name='BIND_ADDR',
                    func=set_bindAddr,
                    description='''\
Bind to the specific address for the service.

Ex: `HAPROXY_0_BIND_ADDR = '10.0.0.42'`
                    '''))
labels.append(Label(name='PORT',
                    func=set_port,
                    description='''\
Bind to the specific port for the service.
This overrides the servicePort which has to be unique.

Ex: `HAPROXY_0_PORT = 80`
                    '''))
labels.append(Label(name='MODE',
                    func=set_mode,
                    description='''\
Set the connection mode to either TCP or HTTP. The default is TCP.

Ex: `HAPROXY_0_MODE = 'http'`
                    '''))
labels.append(Label(name='BALANCE',
                    func=set_balance,
                    description='''\
Set the load balancing algorithm to be used in a backend. The default is
roundrobin.

Ex: `HAPROXY_0_BALANCE = 'leastconn'`
                    '''))

labels.append(Label(name='HTTP_BACKEND_PROXYPASS_PATH',
                    func=set_proxypath,
                    description='''\
Set the location to use for mapping local server URLs to remote servers + URL.
Ex: `HAPROXY_0_HTTP_BACKEND_PROXYPASS_PATH = '/path/to/redirect'`
                    '''))

labels.append(Label(name='HTTP_BACKEND_REVPROXY_PATH',
                    func=set_revproxypath,
                    description='''\
Set the URL in HTTP response headers sent from a reverse proxied server. \
It only updates Location, Content-Location and URL.
Ex: `HAPROXY_0_HTTP_BACKEND_REVPROXY_PATH = '/my/content'`
                    '''))

labels.append(Label(name='HTTP_BACKEND_REDIR',
                    func=set_redirpath,
                    description='''\
Set the path to redirect the root of the domain to
Ex: `HAPROXY_0_HTTP_BACKEND_REDIR = '/my/content'`
                    '''))
labels.append(Label(name='BACKEND_WEIGHT',
                    func=set_backend_weight,
                    description='''\
Some ACLs may be affected by order. For example, if you're using VHost
and path ACLs that are shared amongst backends, the ordering of the ACLs
will matter. With HAPROXY_{n}_BACKEND_WEIGHT you can change the ordering
by specifying a weight. Backends are sorted from largest to smallest
weight.

By default, any backends which use `HAPROXY_{n}_PATH` will have a
weight of 1, if the default weight is used (which is 0).

Ex: `HAPROXY_0_BACKEND_WEIGHT = 1`
                    '''))

labels.append(Label(name='BACKEND_NETWORK_ALLOWED_ACL',
                    func=set_network_allowed,
                    description='''\
Set the IPs (or IP ranges) having access to the backend. \
By default every IP is allowed.

Ex: `HAPROXY_0_BACKEND_NETWORK_ALLOWED_ACL = '10.1.40.0/24 10.1.55.43'`
                    '''))

labels.append(Label(name='BACKEND_HEALTHCHECK_PORT_INDEX',
                    func=set_healthcheck_port_index,
                    description='''\
Set the index of the port dedicated for the healthchecks of the backends
behind a given service port.

By default, the index will be the same as the one of the service port.

Ex: An app exposes two ports, one for the application,
one for its healthchecks:

portMappings": [
  {
    "containerPort": 9000,
    "hostPort": 0,
    "servicePort": 0,
    "protocol": "tcp"
  },
  {
    "containerPort": 9001,
    "hostPort": 0,
    "servicePort": 0,
    "protocol": "tcp"
  }
]

HAPROXY_0_BACKEND_HEALTHCHECK_PORT_INDEX=1 will make it so that the port 9001
is used to perform the backend healthchecks.
                    ''',
                    ))
labels.append(Label(name='FRONTEND_HEAD',
                    func=set_label,
                    description=''))
labels.append(Label(name='USERLIST_HEAD',
                    func=set_label,
                    description=''))
labels.append(Label(name='BACKEND_REDIRECT_HTTP_TO_HTTPS',
                    func=set_label,
                    description=''))
labels.append(Label(name='BACKEND_REDIRECT_HTTP_TO_HTTPS_WITH_PATH',
                    func=set_label,
                    description=''))
labels.append(Label(name='BACKEND_HEAD',
                    func=set_label,
                    description=''))
labels.append(Label(name='HTTP_FRONTEND_ACL',
                    func=set_label,
                    description=''))
labels.append(Label(name='MAP_HTTP_FRONTEND_ACL',
                    func=set_label,
                    description=''))
labels.append(Label(name='HTTP_FRONTEND_ACL_ONLY',
                    func=set_label,
                    description=''))
labels.append(Label(name='MAP_HTTP_FRONTEND_ACL_ONLY',
                    func=set_label,
                    description=''))
labels.append(Label(name='HTTP_FRONTEND_ROUTING_ONLY',
                    func=set_label,
                    description=''))
labels.append(Label(name='HTTP_FRONTEND_ROUTING_ONLY_WITH_AUTH',
                    func=set_label,
                    description=''))
labels.append(Label(name='HTTP_FRONTEND_ACL_WITH_AUTH',
                    func=set_label,
                    description=''))
labels.append(Label(name='HTTP_FRONTEND_ACL_WITH_PATH',
                    func=set_label,
                    description=''))
labels.append(Label(name='HTTP_FRONTEND_ACL_WITH_AUTH_AND_PATH',
                    func=set_label,
                    description=''))
labels.append(Label(name='HTTP_FRONTEND_ACL_ONLY_WITH_PATH',
                    func=set_label,
                    description=''))
labels.append(Label(name='HTTP_FRONTEND_ACL_ONLY_WITH_PATH_AND_AUTH',
                    func=set_label,
                    description=''))
labels.append(Label(name='HTTPS_FRONTEND_ACL_ONLY_WITH_PATH',
                    func=set_label,
                    description=''))
labels.append(Label(name='HTTP_FRONTEND_ROUTING_ONLY_WITH_PATH',
                    func=set_label,
                    description=''))
labels.append(Label(name='HTTP_FRONTEND_ROUTING_ONLY_WITH_PATH_AND_AUTH',
                    func=set_label,
                    description=''))
labels.append(Label(name='HTTP_FRONTEND_APPID_ACL',
                    func=set_label,
                    description=''))
labels.append(Label(name='MAP_HTTP_FRONTEND_APPID_ACL',
                    func=set_label,
                    description=''))
labels.append(Label(name='HTTPS_FRONTEND_ACL',
                    func=set_label,
                    description=''))
labels.append(Label(name='MAP_HTTPS_FRONTEND_ACL',
                    func=set_label,
                    description=''))
labels.append(Label(name='HTTPS_FRONTEND_ACL_WITH_AUTH',
                    func=set_label,
                    description=''))
labels.append(Label(name='HTTPS_FRONTEND_ACL_WITH_PATH',
                    func=set_label,
                    description=''))
labels.append(Label(name='HTTPS_FRONTEND_ACL_WITH_AUTH_AND_PATH',
                    func=set_label,
                    description=''))
labels.append(Label(name='BACKEND_HTTP_OPTIONS',
                    func=set_label,
                    description=''))
labels.append(Label(name='HTTP_BACKEND_PROXYPASS_GLUE',
                    func=set_label,
                    description=''))
labels.append(Label(name='HTTP_BACKEND_REVPROXY_GLUE',
                    func=set_label,
                    description=''))
labels.append(Label(name='BACKEND_HSTS_OPTIONS',
                    func=set_label,
                    description=''))
labels.append(Label(name='BACKEND_HTTP_HEALTHCHECK_OPTIONS',
                    func=set_label,
                    description=''))
labels.append(Label(name='BACKEND_TCP_HEALTHCHECK_OPTIONS',
                    func=set_label,
                    description=''))
labels.append(Label(name='BACKEND_STICKY_OPTIONS',
                    func=set_label,
                    description=''))
labels.append(Label(name='BACKEND_SERVER_OPTIONS',
                    func=set_label,
                    description=''))
labels.append(Label(name='BACKEND_SERVER_TCP_HEALTHCHECK_OPTIONS',
                    func=set_label,
                    description=''))
labels.append(Label(name='BACKEND_SERVER_HTTP_HEALTHCHECK_OPTIONS',
                    func=set_label,
                    description=''))
labels.append(Label(name='FRONTEND_BACKEND_GLUE',
                    func=set_label,
                    description=''))
labels.append(Label(name='HTTP_BACKEND_NETWORK_ALLOWED_ACL',
                    func=set_label,
                    description=''))
labels.append(Label(name='TCP_BACKEND_NETWORK_ALLOWED_ACL',
                    func=set_label,
                    description=''))

labels.sort(key=lambda l: l.name)

label_keys = {}
for label in labels:
    if not label.func:
        continue
    label_keys[label.full_name] = label.func
