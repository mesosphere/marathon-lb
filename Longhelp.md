# marathon-lb
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

```
usage: marathon_lb.py [-h] [--longhelp] [--marathon MARATHON [MARATHON ...]]
                      [--haproxy-config HAPROXY_CONFIG] [--group GROUP]
                      [--command COMMAND]
                      [--max-reload-retries MAX_RELOAD_RETRIES]
                      [--reload-interval RELOAD_INTERVAL] [--strict-mode]
                      [--sse] [--health-check]
                      [--lru-cache-capacity LRU_CACHE_CAPACITY]
                      [--haproxy-map] [--dont-bind-http-https]
                      [--ssl-certs SSL_CERTS] [--skip-validation] [--dry]
                      [--min-serv-port-ip-per-task MIN_SERV_PORT_IP_PER_TASK]
                      [--max-serv-port-ip-per-task MAX_SERV_PORT_IP_PER_TASK]
                      [--syslog-socket SYSLOG_SOCKET]
                      [--log-format LOG_FORMAT] [--log-level LOG_LEVEL]
                      [--marathon-auth-credential-file MARATHON_AUTH_CREDENTIAL_FILE]
                      [--auth-credentials AUTH_CREDENTIALS]
                      [--dcos-auth-credentials DCOS_AUTH_CREDENTIALS]
                      [--marathon-ca-cert MARATHON_CA_CERT]

Marathon HAProxy Load Balancer

optional arguments:
  -h, --help            show this help message and exit
  --longhelp            Print out configuration details (default: False)
  --marathon MARATHON [MARATHON ...], -m MARATHON [MARATHON ...]
                        [required] Marathon endpoint, eg. -m
                        http://marathon1:8080 http://marathon2:8080 (default:
                        ['http://master.mesos:8080'])
  --haproxy-config HAPROXY_CONFIG
                        Location of haproxy configuration (default:
                        /etc/haproxy/haproxy.cfg)
  --group GROUP         [required] Only generate config for apps which list
                        the specified names. Use '*' to match all groups,
                        including those without a group specified. (default:
                        [])
  --command COMMAND, -c COMMAND
                        If set, run this command to reload haproxy. (default:
                        None)
  --max-reload-retries MAX_RELOAD_RETRIES
                        Max reload retries before failure. Reloads happen
                        every --reload-interval seconds. Set to 0 to disable
                        or -1 for infinite retries. (default: 10)
  --reload-interval RELOAD_INTERVAL
                        Wait this number of seconds betwee nreload retries.
                        (default: 10)
  --strict-mode         If set, backends are only advertised if
                        HAPROXY_{n}_ENABLED=true. Strict mode will be enabled
                        by default in a future release. (default: False)
  --sse, -s             Use Server Sent Events (default: False)
  --health-check, -H    If set, respect Marathon's health check statuses
                        before adding the app instance into the backend pool.
                        (default: False)
  --lru-cache-capacity LRU_CACHE_CAPACITY
                        LRU cache size (in number of items). This should be at
                        least as large as the number of tasks exposed via
                        marathon-lb. (default: 1000)
  --haproxy-map         Use HAProxy maps for domain name to backendmapping.
                        (default: False)
  --dont-bind-http-https
                        Don't bind to HTTP and HTTPS frontends. (default:
                        False)
  --ssl-certs SSL_CERTS
                        List of SSL certificates separated by commafor
                        frontend marathon_https_inEx:
                        /etc/ssl/site1.co.pem,/etc/ssl/site2.co.pem (default:
                        /etc/ssl/cert.pem)
  --skip-validation     Skip haproxy config file validation (default: False)
  --dry, -d             Only print configuration to console (default: False)
  --min-serv-port-ip-per-task MIN_SERV_PORT_IP_PER_TASK
                        Minimum port number to use when auto-assigning service
                        ports for IP-per-task applications (default: 10050)
  --max-serv-port-ip-per-task MAX_SERV_PORT_IP_PER_TASK
                        Maximum port number to use when auto-assigning service
                        ports for IP-per-task applications (default: 10100)
  --syslog-socket SYSLOG_SOCKET
                        Socket to write syslog messages to. Use '/dev/null' to
                        disable logging to syslog (default: /var/run/syslog)
  --log-format LOG_FORMAT
                        Set log message format (default: %(asctime)-15s
                        %(name)s: %(message)s)
  --log-level LOG_LEVEL
                        Set log level (default: DEBUG)
  --marathon-auth-credential-file MARATHON_AUTH_CREDENTIAL_FILE
                        Path to file containing a user/pass for the Marathon
                        HTTP API in the format of 'user:pass'. (default: None)
  --auth-credentials AUTH_CREDENTIALS
                        user/pass for the Marathon HTTP API in the format of
                        'user:pass'. (default: None)
  --dcos-auth-credentials DCOS_AUTH_CREDENTIALS
                        DC/OS service account credentials (default: None)
  --marathon-ca-cert MARATHON_CA_CERT
                        CA certificate for Marathon HTTPS connections
                        (default: None)
```
## Templates

The following is a list of the available HAProxy templates.
Some templates are global-only (such as `HAPROXY_HEAD`), but most may
be overridden on a per service port basis using the
`HAPROXY_{n}_...` syntax.

## `HAPROXY_BACKEND_HEAD`
  *Overridable per app*

Specified as `HAPROXY_BACKEND_HEAD` template or with label `HAPROXY_{n}_BACKEND_HEAD`.

Defines the type of load balancing, roundrobin by default,
and connection mode, TCP or HTTP.


**Default template for `HAPROXY_BACKEND_HEAD`:**
```

backend {backend}
  balance {balance}
  mode {mode}
```
## `HAPROXY_BACKEND_HSTS_OPTIONS`
  *Overridable per app*

Specified as `HAPROXY_BACKEND_HSTS_OPTIONS` template or with label `HAPROXY_{n}_BACKEND_HSTS_OPTIONS`.

This template is used for the backend where the
`HAPROXY_{n}_USE_HSTS` label is set to true.


**Default template for `HAPROXY_BACKEND_HSTS_OPTIONS`:**
```
  rspadd  Strict-Transport-Security:\ max-age=15768000
```
## `HAPROXY_BACKEND_HTTP_HEALTHCHECK_OPTIONS`
  *Overridable per app*

Specified as `HAPROXY_BACKEND_HTTP_HEALTHCHECK_OPTIONS` template or with label `HAPROXY_{n}_BACKEND_HTTP_HEALTHCHECK_OPTIONS`.

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
  

**Default template for `HAPROXY_BACKEND_HTTP_HEALTHCHECK_OPTIONS`:**
```
  option  httpchk GET {healthCheckPath}
  timeout check {healthCheckTimeoutSeconds}s
```
## `HAPROXY_BACKEND_HTTP_OPTIONS`
  *Overridable per app*

Specified as `HAPROXY_BACKEND_HTTP_OPTIONS` template or with label `HAPROXY_{n}_BACKEND_HTTP_OPTIONS`.

Sets HTTP headers, for example X-Forwarded-For and X-Forwarded-Proto.


**Default template for `HAPROXY_BACKEND_HTTP_OPTIONS`:**
```
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
```
## `HAPROXY_BACKEND_REDIRECT_HTTP_TO_HTTPS`
  *Overridable per app*

Specified as `HAPROXY_BACKEND_REDIRECT_HTTP_TO_HTTPS` template or with label `HAPROXY_{n}_BACKEND_REDIRECT_HTTP_TO_HTTPS`.

This template is used with backends where the
`HAPROXY_{n}_REDIRECT_TO_HTTPS` label is set to true


**Default template for `HAPROXY_BACKEND_REDIRECT_HTTP_TO_HTTPS`:**
```
  redirect scheme https code 301 if !{{ ssl_fc }} host_{cleanedUpHostname}
```
## `HAPROXY_BACKEND_REDIRECT_HTTP_TO_HTTPS_WITH_PATH`
  *Overridable per app*

Specified as `HAPROXY_BACKEND_REDIRECT_HTTP_TO_HTTPS_WITH_PATH` template or with label `HAPROXY_{n}_BACKEND_REDIRECT_HTTP_TO_HTTPS_WITH_PATH`.

Same as `HAPROXY_BACKEND_REDIRECT_HTTP_TO_HTTPS`,
but includes a path.


**Default template for `HAPROXY_BACKEND_REDIRECT_HTTP_TO_HTTPS_WITH_PATH`:**
```
  redirect scheme https code 301 if !{{ ssl_fc }} host_{cleanedUpHostname} path_{backend}
```
## `HAPROXY_BACKEND_SERVER_HTTP_HEALTHCHECK_OPTIONS`
  *Overridable per app*

Specified as `HAPROXY_BACKEND_SERVER_HTTP_HEALTHCHECK_OPTIONS` template or with label `HAPROXY_{n}_BACKEND_SERVER_HTTP_HEALTHCHECK_OPTIONS`.

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
  

**Default template for `HAPROXY_BACKEND_SERVER_HTTP_HEALTHCHECK_OPTIONS`:**
```
  check inter {healthCheckIntervalSeconds}s fall {healthCheckFalls}{healthCheckPortOptions}
```
## `HAPROXY_BACKEND_SERVER_OPTIONS`
  *Overridable per app*

Specified as `HAPROXY_BACKEND_SERVER_OPTIONS` template or with label `HAPROXY_{n}_BACKEND_SERVER_OPTIONS`.

The options for each server added to a backend.
    

**Default template for `HAPROXY_BACKEND_SERVER_OPTIONS`:**
```
  server {serverName} {host_ipv4}:{port}{cookieOptions}{healthCheckOptions}{otherOptions}
```
## `HAPROXY_BACKEND_SERVER_TCP_HEALTHCHECK_OPTIONS`
  *Overridable per app*

Specified as `HAPROXY_BACKEND_SERVER_TCP_HEALTHCHECK_OPTIONS` template or with label `HAPROXY_{n}_BACKEND_SERVER_TCP_HEALTHCHECK_OPTIONS`.

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
  

**Default template for `HAPROXY_BACKEND_SERVER_TCP_HEALTHCHECK_OPTIONS`:**
```
  check inter {healthCheckIntervalSeconds}s fall {healthCheckFalls}{healthCheckPortOptions}
```
## `HAPROXY_BACKEND_STICKY_OPTIONS`
  *Overridable per app*

Specified as `HAPROXY_BACKEND_STICKY_OPTIONS` template or with label `HAPROXY_{n}_BACKEND_STICKY_OPTIONS`.

Sets a cookie for services where `HAPROXY_{n}_STICKY` is true.
    

**Default template for `HAPROXY_BACKEND_STICKY_OPTIONS`:**
```
  cookie mesosphere_server_id insert indirect nocache
```
## `HAPROXY_BACKEND_TCP_HEALTHCHECK_OPTIONS`
  *Overridable per app*

Specified as `HAPROXY_BACKEND_TCP_HEALTHCHECK_OPTIONS` template or with label `HAPROXY_{n}_BACKEND_TCP_HEALTHCHECK_OPTIONS`.

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
  

**Default template for `HAPROXY_BACKEND_TCP_HEALTHCHECK_OPTIONS`:**
```
```
## `HAPROXY_FRONTEND_BACKEND_GLUE`
  *Overridable per app*

Specified as `HAPROXY_FRONTEND_BACKEND_GLUE` template or with label `HAPROXY_{n}_FRONTEND_BACKEND_GLUE`.

This option glues the backend to the frontend.
    

**Default template for `HAPROXY_FRONTEND_BACKEND_GLUE`:**
```
  use_backend {backend}
```
## `HAPROXY_FRONTEND_HEAD`
  *Overridable per app*

Specified as `HAPROXY_FRONTEND_HEAD` template or with label `HAPROXY_{n}_FRONTEND_HEAD`.

Defines the address and port to bind to for this frontend.


**Default template for `HAPROXY_FRONTEND_HEAD`:**
```

frontend {backend}
  bind {bindAddr}:{servicePort}{sslCert}{bindOptions}
  mode {mode}
```
## `HAPROXY_HEAD`
  *Global*

Specified as `HAPROXY_HEAD` template.

The head of the HAProxy config. This contains global settings
and defaults.


**Default template for `HAPROXY_HEAD`:**
```
global
  daemon
  log /dev/log local0
  log /dev/log local1 notice
  spread-checks 5
  max-spread-checks 15000
  maxconn 50000
  tune.ssl.default-dh-param 2048
  ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:!aNULL:!MD5:!DSS
  ssl-default-bind-options no-sslv3 no-tlsv10 no-tls-tickets
  ssl-default-server-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:!aNULL:!MD5:!DSS
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
  option            dontlognull
  option            http-server-close
  option            redispatch
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
```
## `HAPROXY_HTTPS_FRONTEND_ACL`
  *Overridable per app*

Specified as `HAPROXY_HTTPS_FRONTEND_ACL` template or with label `HAPROXY_{n}_HTTPS_FRONTEND_ACL`.

The ACL that performs the SNI based hostname matching
for the `HAPROXY_HTTPS_FRONTEND_HEAD` template.


**Default template for `HAPROXY_HTTPS_FRONTEND_ACL`:**
```
  use_backend {backend} if {{ ssl_fc_sni {hostname} }}
```
## `HAPROXY_HTTPS_FRONTEND_ACL_ONLY_WITH_PATH`
  *Overridable per app*

Specified as `HAPROXY_HTTPS_FRONTEND_ACL_ONLY_WITH_PATH` template or with label `HAPROXY_{n}_HTTPS_FRONTEND_ACL_ONLY_WITH_PATH`.

Same as HTTP_FRONTEND_ACL_ONLY_WITH_PATH, but for HTTPS.


**Default template for `HAPROXY_HTTPS_FRONTEND_ACL_ONLY_WITH_PATH`:**
```
  acl path_{backend} path_beg {path}
```
## `HAPROXY_HTTPS_FRONTEND_ACL_WITH_AUTH`
  *Overridable per app*

Specified as `HAPROXY_HTTPS_FRONTEND_ACL_WITH_AUTH` template or with label `HAPROXY_{n}_HTTPS_FRONTEND_ACL_WITH_AUTH`.

The ACL that glues a backend to the corresponding virtual host
of the `HAPROXY_HTTPS_FRONTEND_HEAD` thru HTTP basic auth.


**Default template for `HAPROXY_HTTPS_FRONTEND_ACL_WITH_AUTH`:**
```
  acl auth_{cleanedUpHostname} http_auth(user_{backend})
  http-request auth realm "{realm}" if {{ ssl_fc_sni {hostname} }} !auth_{cleanedUpHostname}
  use_backend {backend} if {{ ssl_fc_sni {hostname} }}
```
## `HAPROXY_HTTPS_FRONTEND_ACL_WITH_AUTH_AND_PATH`
  *Overridable per app*

Specified as `HAPROXY_HTTPS_FRONTEND_ACL_WITH_AUTH_AND_PATH` template or with label `HAPROXY_{n}_HTTPS_FRONTEND_ACL_WITH_AUTH_AND_PATH`.

The ACL that glues a backend to the corresponding virtual host with path
of the `HAPROXY_HTTPS_FRONTEND_HEAD` thru HTTP basic auth.


**Default template for `HAPROXY_HTTPS_FRONTEND_ACL_WITH_AUTH_AND_PATH`:**
```
  acl auth_{cleanedUpHostname} http_auth(user_{backend})
  http-request auth realm "{realm}" if {{ ssl_fc_sni {hostname} }} path_{backend} !auth_{cleanedUpHostname}
  use_backend {backend} if {{ ssl_fc_sni {hostname} }} path_{backend}
```
## `HAPROXY_HTTPS_FRONTEND_ACL_WITH_PATH`
  *Overridable per app*

Specified as `HAPROXY_HTTPS_FRONTEND_ACL_WITH_PATH` template or with label `HAPROXY_{n}_HTTPS_FRONTEND_ACL_WITH_PATH`.

The ACL that performs the SNI based hostname matching with path
for the `HAPROXY_HTTPS_FRONTEND_HEAD` template.


**Default template for `HAPROXY_HTTPS_FRONTEND_ACL_WITH_PATH`:**
```
  use_backend {backend} if {{ ssl_fc_sni {hostname} }} path_{backend}
```
## `HAPROXY_HTTPS_FRONTEND_AUTH_ACL_ONLY`
  *Overridable per app*

Specified as `HAPROXY_HTTPS_FRONTEND_AUTH_ACL_ONLY` template or with label `HAPROXY_{n}_HTTPS_FRONTEND_AUTH_ACL_ONLY`.

The http auth ACL to the corresponding virtual host.


**Default template for `HAPROXY_HTTPS_FRONTEND_AUTH_ACL_ONLY`:**
```
  acl auth_{cleanedUpHostname} http_auth(user_{backend})
```
## `HAPROXY_HTTPS_FRONTEND_AUTH_REQUEST_ONLY`
  *Overridable per app*

Specified as `HAPROXY_HTTPS_FRONTEND_AUTH_REQUEST_ONLY` template or with label `HAPROXY_{n}_HTTPS_FRONTEND_AUTH_REQUEST_ONLY`.

The http auth request to the corresponding virtual host.


**Default template for `HAPROXY_HTTPS_FRONTEND_AUTH_REQUEST_ONLY`:**
```
  http-request auth realm "{realm}" if {{ ssl_fc_sni {hostname} }} !auth_{cleanedUpHostname}
```
## `HAPROXY_HTTPS_FRONTEND_HEAD`
  *Global*

Specified as `HAPROXY_HTTPS_FRONTEND_HEAD` template.

An HTTPS frontend for encrypted connections that binds to port *:443 by
default and gathers all virtual hosts as defined by the
`HAPROXY_{n}_VHOST` label. You must modify this file to
include your certificate.


**Default template for `HAPROXY_HTTPS_FRONTEND_HEAD`:**
```

frontend marathon_https_in
  bind *:443 ssl {sslCerts}
  mode http
```
## `HAPROXY_HTTPS_FRONTEND_ROUTING_ONLY_WITH_PATH_AND_AUTH`
  *Overridable per app*

Specified as `HAPROXY_HTTPS_FRONTEND_ROUTING_ONLY_WITH_PATH_AND_AUTH` template or with label `HAPROXY_{n}_HTTPS_FRONTEND_ROUTING_ONLY_WITH_PATH_AND_AUTH`.

This is the counterpart to `HAPROXY_HTTP_FRONTEND_ACL_ONLY_WITH_PATH` which
glues the acl names to the appropriate backend


**Default template for `HAPROXY_HTTPS_FRONTEND_ROUTING_ONLY_WITH_PATH_AND_AUTH`:**
```
  http-request auth realm "{realm}" if host_{cleanedUpHostname} path_{backend} !auth_{cleanedUpHostname}
  use_backend {backend} if host_{cleanedUpHostname} path_{backend}
```
## `HAPROXY_HTTP_BACKEND_ACL_ALLOW_DENY`
  *Global*

Specified as `HAPROXY_HTTP_BACKEND_ACL_ALLOW_DENY` template.

This option denies all IPs (or IP ranges) not explicitly allowed to access the HTTP backend.
Use with `HAPROXY_HTTP_BACKEND_NETWORK_ALLOWED_ACL`.


**Default template for `HAPROXY_HTTP_BACKEND_ACL_ALLOW_DENY`:**
```
  http-request allow if network_allowed
  http-request deny
```
## `HAPROXY_HTTP_BACKEND_NETWORK_ALLOWED_ACL`
  *Overridable per app*

Specified as `HAPROXY_HTTP_BACKEND_NETWORK_ALLOWED_ACL` template or with label `HAPROXY_{n}_HTTP_BACKEND_NETWORK_ALLOWED_ACL`.

This option set the IPs (or IP ranges) having access to the HTTP backend.


**Default template for `HAPROXY_HTTP_BACKEND_NETWORK_ALLOWED_ACL`:**
```
  acl network_allowed src {network_allowed}
```
## `HAPROXY_HTTP_BACKEND_PROXYPASS_GLUE`
  *Overridable per app*

Specified as `HAPROXY_HTTP_BACKEND_PROXYPASS_GLUE` template or with label `HAPROXY_{n}_HTTP_BACKEND_PROXYPASS_GLUE`.

Backend glue for `HAPROXY_{n}_HTTP_BACKEND_PROXYPASS_PATH`.


**Default template for `HAPROXY_HTTP_BACKEND_PROXYPASS_GLUE`:**
```
  http-request set-header Host {hostname}
  reqirep  "^([^ :]*)\ {proxypath}/?(.*)" "\1\ /\2"
```
## `HAPROXY_HTTP_BACKEND_REDIR`
  *Overridable per app*

Specified as `HAPROXY_HTTP_BACKEND_REDIR` template or with label `HAPROXY_{n}_HTTP_BACKEND_REDIR`.

Set the path to redirect the root of the domain to
Ex: HAPROXY_0_HTTP_BACKEND_REDIR = '/my/content'


**Default template for `HAPROXY_HTTP_BACKEND_REDIR`:**
```
  acl is_root path -i /
  acl is_domain hdr(host) -i {hostname}
  redirect code 301 location {redirpath} if is_domain is_root
```
## `HAPROXY_HTTP_BACKEND_REVPROXY_GLUE`
  *Overridable per app*

Specified as `HAPROXY_HTTP_BACKEND_REVPROXY_GLUE` template or with label `HAPROXY_{n}_HTTP_BACKEND_REVPROXY_GLUE`.

Backend glue for `HAPROXY_{n}_HTTP_BACKEND_REVPROXY_PATH`.


**Default template for `HAPROXY_HTTP_BACKEND_REVPROXY_GLUE`:**
```
  acl hdr_location res.hdr(Location) -m found
  rspirep "^Location: (https?://{hostname}(:[0-9]+)?)?(/.*)" "Location:   {rootpath} if hdr_location"
```
## `HAPROXY_HTTP_FRONTEND_ACL`
  *Overridable per app*

Specified as `HAPROXY_HTTP_FRONTEND_ACL` template or with label `HAPROXY_{n}_HTTP_FRONTEND_ACL`.

The ACL that glues a backend to the corresponding virtual host
of the `HAPROXY_HTTP_FRONTEND_HEAD`


**Default template for `HAPROXY_HTTP_FRONTEND_ACL`:**
```
  acl host_{cleanedUpHostname} hdr(host) -i {hostname}
  use_backend {backend} if host_{cleanedUpHostname}
```
## `HAPROXY_HTTP_FRONTEND_ACL_ONLY`
  *Overridable per app*

Specified as `HAPROXY_HTTP_FRONTEND_ACL_ONLY` template or with label `HAPROXY_{n}_HTTP_FRONTEND_ACL_ONLY`.

Define the ACL matching a particular hostname, but unlike
`HAPROXY_HTTP_FRONTEND_ACL`, only do the ACL portion. Does not glue
the ACL to the backend. This is useful only in the case of multiple
vhosts routing to the same backend.


**Default template for `HAPROXY_HTTP_FRONTEND_ACL_ONLY`:**
```
  acl host_{cleanedUpHostname} hdr(host) -i {hostname}
```
## `HAPROXY_HTTP_FRONTEND_ACL_ONLY_WITH_PATH`
  *Overridable per app*

Specified as `HAPROXY_HTTP_FRONTEND_ACL_ONLY_WITH_PATH` template or with label `HAPROXY_{n}_HTTP_FRONTEND_ACL_ONLY_WITH_PATH`.

Define the ACL matching a particular hostname with path, but unlike
`HAPROXY_HTTP_FRONTEND_ACL_WITH_PATH`, only do the ACL portion. Does not glue
the ACL to the backend. This is useful only in the case of multiple
vhosts routing to the same backend


**Default template for `HAPROXY_HTTP_FRONTEND_ACL_ONLY_WITH_PATH`:**
```
  acl path_{backend} path_beg {path}
```
## `HAPROXY_HTTP_FRONTEND_ACL_ONLY_WITH_PATH_AND_AUTH`
  *Overridable per app*

Specified as `HAPROXY_HTTP_FRONTEND_ACL_ONLY_WITH_PATH_AND_AUTH` template or with label `HAPROXY_{n}_HTTP_FRONTEND_ACL_ONLY_WITH_PATH_AND_AUTH`.

Define the ACL matching a particular hostname with path and auth, but unlike
`HAPROXY_HTTP_FRONTEND_ACL_WITH_PATH`, only do the ACL portion. Does not glue
the ACL to the backend. This is useful only in the case of multiple
vhosts routing to the same backend


**Default template for `HAPROXY_HTTP_FRONTEND_ACL_ONLY_WITH_PATH_AND_AUTH`:**
```
  acl path_{backend} path_beg {path}
  acl auth_{cleanedUpHostname} http_auth(user_{backend})
```
## `HAPROXY_HTTP_FRONTEND_ACL_WITH_AUTH`
  *Overridable per app*

Specified as `HAPROXY_HTTP_FRONTEND_ACL_WITH_AUTH` template or with label `HAPROXY_{n}_HTTP_FRONTEND_ACL_WITH_AUTH`.

The ACL that glues a backend to the corresponding virtual host
of the `HAPROXY_HTTP_FRONTEND_HEAD` thru HTTP basic auth.


**Default template for `HAPROXY_HTTP_FRONTEND_ACL_WITH_AUTH`:**
```
  acl host_{cleanedUpHostname} hdr(host) -i {hostname}
  acl auth_{cleanedUpHostname} http_auth(user_{backend})
  http-request auth realm "{realm}" if host_{cleanedUpHostname} !auth_{cleanedUpHostname}
  use_backend {backend} if host_{cleanedUpHostname}
```
## `HAPROXY_HTTP_FRONTEND_ACL_WITH_AUTH_AND_PATH`
  *Overridable per app*

Specified as `HAPROXY_HTTP_FRONTEND_ACL_WITH_AUTH_AND_PATH` template or with label `HAPROXY_{n}_HTTP_FRONTEND_ACL_WITH_AUTH_AND_PATH`.

The ACL that glues a backend to the corresponding virtual host with path
of the `HAPROXY_HTTP_FRONTEND_HEAD` thru HTTP basic auth.


**Default template for `HAPROXY_HTTP_FRONTEND_ACL_WITH_AUTH_AND_PATH`:**
```
  acl host_{cleanedUpHostname} hdr(host) -i {hostname}
  acl auth_{cleanedUpHostname} http_auth(user_{backend})
  acl path_{backend} path_beg {path}
  http-request auth realm "{realm}" if host_{cleanedUpHostname} path_{backend} !auth_{cleanedUpHostname}
  use_backend {backend} if host_{cleanedUpHostname} path_{backend}
```
## `HAPROXY_HTTP_FRONTEND_ACL_WITH_PATH`
  *Overridable per app*

Specified as `HAPROXY_HTTP_FRONTEND_ACL_WITH_PATH` template or with label `HAPROXY_{n}_HTTP_FRONTEND_ACL_WITH_PATH`.

The ACL that glues a backend to the corresponding virtual host with path
of the `HAPROXY_HTTP_FRONTEND_HEAD`.


**Default template for `HAPROXY_HTTP_FRONTEND_ACL_WITH_PATH`:**
```
  acl host_{cleanedUpHostname} hdr(host) -i {hostname}
  acl path_{backend} path_beg {path}
  use_backend {backend} if host_{cleanedUpHostname} path_{backend}
```
## `HAPROXY_HTTP_FRONTEND_APPID_ACL`
  *Overridable per app*

Specified as `HAPROXY_HTTP_FRONTEND_APPID_ACL` template or with label `HAPROXY_{n}_HTTP_FRONTEND_APPID_ACL`.

The ACL that glues a backend to the corresponding app
of the `HAPROXY_HTTP_FRONTEND_APPID_HEAD`.


**Default template for `HAPROXY_HTTP_FRONTEND_APPID_ACL`:**
```
  acl app_{cleanedUpAppId} hdr(x-marathon-app-id) -i {appId}
  use_backend {backend} if app_{cleanedUpAppId}
```
## `HAPROXY_HTTP_FRONTEND_APPID_HEAD`
  *Global*

Specified as `HAPROXY_HTTP_FRONTEND_APPID_HEAD` template.

An HTTP frontend that binds to port *:9091 by default and gathers
all apps in HTTP mode.
To use this frontend to forward to your app, configure the app with
`HAPROXY_0_MODE=http` then you can access it via a call to the :9091
with the header "X-Marathon-App-Id" set to the Marathon AppId.
Note multiple HTTP ports being exposed by the same marathon app are not
supported. Only the first HTTP port is available via this frontend.


**Default template for `HAPROXY_HTTP_FRONTEND_APPID_HEAD`:**
```

frontend marathon_http_appid_in
  bind *:9091
  mode http
```
## `HAPROXY_HTTP_FRONTEND_HEAD`
  *Global*

Specified as `HAPROXY_HTTP_FRONTEND_HEAD` template.

An HTTP frontend that binds to port *:80 by default and gathers
all virtual hosts as defined by the `HAPROXY_{n}_VHOST` label.


**Default template for `HAPROXY_HTTP_FRONTEND_HEAD`:**
```

frontend marathon_http_in
  bind *:80
  mode http
```
## `HAPROXY_HTTP_FRONTEND_ROUTING_ONLY`
  *Overridable per app*

Specified as `HAPROXY_HTTP_FRONTEND_ROUTING_ONLY` template or with label `HAPROXY_{n}_HTTP_FRONTEND_ROUTING_ONLY`.

This is the counterpart to `HAPROXY_HTTP_FRONTEND_ACL_ONLY` which
glues the acl name to the appropriate backend.


**Default template for `HAPROXY_HTTP_FRONTEND_ROUTING_ONLY`:**
```
  use_backend {backend} if host_{cleanedUpHostname}
```
## `HAPROXY_HTTP_FRONTEND_ROUTING_ONLY_WITH_AUTH`
  *Overridable per app*

Specified as `HAPROXY_HTTP_FRONTEND_ROUTING_ONLY_WITH_AUTH` template or with label `HAPROXY_{n}_HTTP_FRONTEND_ROUTING_ONLY_WITH_AUTH`.

This is the counterpart to `HAPROXY_HTTP_FRONTEND_ACL_ONLY` which
glues the acl name to the appropriate backend, and add http basic auth.


**Default template for `HAPROXY_HTTP_FRONTEND_ROUTING_ONLY_WITH_AUTH`:**
```
  acl auth_{cleanedUpHostname} http_auth(user_{backend})
  http-request auth realm "{realm}" if host_{cleanedUpHostname} !auth_{cleanedUpHostname}
  use_backend {backend} if host_{cleanedUpHostname}
```
## `HAPROXY_HTTP_FRONTEND_ROUTING_ONLY_WITH_PATH`
  *Overridable per app*

Specified as `HAPROXY_HTTP_FRONTEND_ROUTING_ONLY_WITH_PATH` template or with label `HAPROXY_{n}_HTTP_FRONTEND_ROUTING_ONLY_WITH_PATH`.

This is the counterpart to `HAPROXY_HTTP_FRONTEND_ACL_ONLY_WITH_PATH` which
glues the acl names to the appropriate backend


**Default template for `HAPROXY_HTTP_FRONTEND_ROUTING_ONLY_WITH_PATH`:**
```
  use_backend {backend} if host_{cleanedUpHostname} path_{backend}
```
## `HAPROXY_HTTP_FRONTEND_ROUTING_ONLY_WITH_PATH_AND_AUTH`
  *Overridable per app*

Specified as `HAPROXY_HTTP_FRONTEND_ROUTING_ONLY_WITH_PATH_AND_AUTH` template or with label `HAPROXY_{n}_HTTP_FRONTEND_ROUTING_ONLY_WITH_PATH_AND_AUTH`.

This is the counterpart to `HAPROXY_HTTP_FRONTEND_ACL_ONLY_WITH_PATH` which
glues the acl names to the appropriate backend


**Default template for `HAPROXY_HTTP_FRONTEND_ROUTING_ONLY_WITH_PATH_AND_AUTH`:**
```
  http-request auth realm "{realm}" if host_{cleanedUpHostname} path_{backend} !auth_{cleanedUpHostname}
  use_backend {backend} if host_{cleanedUpHostname} path_{backend}
```
## `HAPROXY_MAP_HTTPS_FRONTEND_ACL`
  *Overridable per app*

Specified as `HAPROXY_MAP_HTTPS_FRONTEND_ACL` template or with label `HAPROXY_{n}_MAP_HTTPS_FRONTEND_ACL`.

The ACL that performs the SNI based hostname matching
for the `HAPROXY_HTTPS_FRONTEND_HEAD` template using haproxy maps


**Default template for `HAPROXY_MAP_HTTPS_FRONTEND_ACL`:**
```
  use_backend %[ssl_fc_sni,lower,map({haproxy_dir}/domain2backend.map)]
```
## `HAPROXY_MAP_HTTP_FRONTEND_ACL`
  *Overridable per app*

Specified as `HAPROXY_MAP_HTTP_FRONTEND_ACL` template or with label `HAPROXY_{n}_MAP_HTTP_FRONTEND_ACL`.

The ACL that glues a backend to the corresponding virtual host
of the `HAPROXY_HTTP_FRONTEND_HEAD` using haproxy maps.


**Default template for `HAPROXY_MAP_HTTP_FRONTEND_ACL`:**
```
  use_backend %[req.hdr(host),lower,regsub(:.*$,,),map({haproxy_dir}/domain2backend.map)]
```
## `HAPROXY_MAP_HTTP_FRONTEND_ACL_ONLY`
  *Overridable per app*

Specified as `HAPROXY_MAP_HTTP_FRONTEND_ACL_ONLY` template or with label `HAPROXY_{n}_MAP_HTTP_FRONTEND_ACL_ONLY`.

Define the ACL matching a particular hostname, This is useful only in the case
 of multiple vhosts routing to the same backend in haproxy map.


**Default template for `HAPROXY_MAP_HTTP_FRONTEND_ACL_ONLY`:**
```
  use_backend %[req.hdr(host),lower,regsub(:.*$,,),map({haproxy_dir}/domain2backend.map)]
```
## `HAPROXY_MAP_HTTP_FRONTEND_APPID_ACL`
  *Overridable per app*

Specified as `HAPROXY_MAP_HTTP_FRONTEND_APPID_ACL` template or with label `HAPROXY_{n}_MAP_HTTP_FRONTEND_APPID_ACL`.

The ACL that glues a backend to the corresponding app
of the `HAPROXY_HTTP_FRONTEND_APPID_HEAD` using haproxy maps.


**Default template for `HAPROXY_MAP_HTTP_FRONTEND_APPID_ACL`:**
```
  use_backend %[req.hdr(x-marathon-app-id),lower,map({haproxy_dir}/app2backend.map)]
```
## `HAPROXY_TCP_BACKEND_ACL_ALLOW_DENY`
  *Global*

Specified as `HAPROXY_TCP_BACKEND_ACL_ALLOW_DENY` template.

This option denies all IPs (or IP ranges) not explicitly allowed to access the TCP backend.
Use with HAPROXY_TCP_BACKEND_ACL_ALLOW_DENY.


**Default template for `HAPROXY_TCP_BACKEND_ACL_ALLOW_DENY`:**
```
  tcp-request content accept if network_allowed
  tcp-request content reject
```
## `HAPROXY_TCP_BACKEND_NETWORK_ALLOWED_ACL`
  *Overridable per app*

Specified as `HAPROXY_TCP_BACKEND_NETWORK_ALLOWED_ACL` template or with label `HAPROXY_{n}_TCP_BACKEND_NETWORK_ALLOWED_ACL`.

This option set the IPs (or IP ranges) having access to the TCP backend.


**Default template for `HAPROXY_TCP_BACKEND_NETWORK_ALLOWED_ACL`:**
```
  acl network_allowed src {network_allowed}
```
## `HAPROXY_USERLIST_HEAD`
  *Overridable per app*

Specified as `HAPROXY_USERLIST_HEAD` template or with label `HAPROXY_{n}_USERLIST_HEAD`.

The userlist for basic HTTP auth.


**Default template for `HAPROXY_USERLIST_HEAD`:**
```

userlist user_{backend}
  user {user} password {passwd}
```
## Other Labels
These labels may be used to configure other app settings.

## `HAPROXY_{n}_AUTH`
  *per service port*

Specified as `HAPROXY_{n}_AUTH`.

The http basic auth definition. For details on configuring auth, see: https://github.com/mesosphere/marathon-lb/wiki/HTTP-Basic-Auth

Ex: `HAPROXY_0_AUTH = realm:username:encryptedpassword`

## `HAPROXY_{n}_BACKEND_HEALTHCHECK_PORT_INDEX`
  *per service port*

Specified as `HAPROXY_{n}_BACKEND_HEALTHCHECK_PORT_INDEX`.

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
                    

## `HAPROXY_{n}_BACKEND_NETWORK_ALLOWED_ACL`
  *per service port*

Specified as `HAPROXY_{n}_BACKEND_NETWORK_ALLOWED_ACL`.

Set the IPs (or IP ranges) having access to the backend. By default every IP is allowed.

Ex: `HAPROXY_0_BACKEND_NETWORK_ALLOWED_ACL = '10.1.40.0/24 10.1.55.43'`
                    

## `HAPROXY_{n}_BACKEND_WEIGHT`
  *per service port*

Specified as `HAPROXY_{n}_BACKEND_WEIGHT`.

Some ACLs may be affected by order. For example, if you're using VHost
and path ACLs that are shared amongst backends, the ordering of the ACLs
will matter. With HAPROXY_{n}_BACKEND_WEIGHT you can change the ordering
by specifying a weight. Backends are sorted from largest to smallest
weight.

By default, any backends which use `HAPROXY_{n}_PATH` will have a
weight of 1, if the default weight is used (which is 0).

Ex: `HAPROXY_0_BACKEND_WEIGHT = 1`
                    

## `HAPROXY_{n}_BALANCE`
  *per service port*

Specified as `HAPROXY_{n}_BALANCE`.

Set the load balancing algorithm to be used in a backend. The default is
roundrobin.

Ex: `HAPROXY_0_BALANCE = 'leastconn'`
                    

## `HAPROXY_{n}_BIND_ADDR`
  *per service port*

Specified as `HAPROXY_{n}_BIND_ADDR`.

Bind to the specific address for the service.

Ex: `HAPROXY_0_BIND_ADDR = '10.0.0.42'`
                    

## `HAPROXY_{n}_BIND_OPTIONS`
  *per service port*

Specified as `HAPROXY_{n}_BIND_OPTIONS`.

Set additional bind options

Ex: `HAPROXY_0_BIND_OPTIONS = 'ciphers AES128+EECDH:AES128+EDH force-tlsv12 no-sslv3 no-tlsv10'`
                    

## `HAPROXY_DEPLOYMENT_ALT_PORT`
  *per app*

Specified as `HAPROXY_DEPLOYMENT_ALT_PORT`.

Alternate service port to be used during a blue/green deployment.
                    

## `HAPROXY_DEPLOYMENT_COLOUR`
  *per app*

Specified as `HAPROXY_DEPLOYMENT_COLOUR`.

Blue/green deployment colour. Used by the bluegreen_deploy.py script
to determine the state of a deploy. You generally do not need to modify
this unless you implement your own deployment orchestrator.
                    

## `HAPROXY_DEPLOYMENT_GROUP`
  *per app*

Specified as `HAPROXY_DEPLOYMENT_GROUP`.

Deployment group to which this app belongs.
                    

## `HAPROXY_DEPLOYMENT_STARTED_AT`
  *per app*

Specified as `HAPROXY_DEPLOYMENT_STARTED_AT`.

The time at which a deployment started. You generally do not need
to modify this unless you implement your own deployment orchestrator.
                    

## `HAPROXY_DEPLOYMENT_TARGET_INSTANCES`
  *per app*

Specified as `HAPROXY_DEPLOYMENT_TARGET_INSTANCES`.

The target number of app instances to seek during deployment. You
generally do not need to modify this unless you implement your
own deployment orchestrator.
                    

## `HAPROXY_{n}_ENABLED`
  *per service port*

Specified as `HAPROXY_{n}_ENABLED`.

Enable this backend. By default, all backends are enabled. To disable
backends by default, specify the `--strict-mode` flag.

Ex: `HAPROXY_0_ENABLED = true`
                    

## `HAPROXY_{n}_GROUP`
  *per service port*

Specified as `HAPROXY_{n}_GROUP` or `HAPROXY_GROUP`.

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
    

## `HAPROXY_{n}_HTTP_BACKEND_PROXYPASS_PATH`
  *per service port*

Specified as `HAPROXY_{n}_HTTP_BACKEND_PROXYPASS_PATH`.

Set the location to use for mapping local server URLs to remote servers + URL.
Ex: `HAPROXY_0_HTTP_BACKEND_PROXYPASS_PATH = '/path/to/redirect'`
                    

## `HAPROXY_{n}_HTTP_BACKEND_REVPROXY_PATH`
  *per service port*

Specified as `HAPROXY_{n}_HTTP_BACKEND_REVPROXY_PATH`.

Set the URL in HTTP response headers sent from a reverse proxied server. It only updates Location, Content-Location and URL.
Ex: `HAPROXY_0_HTTP_BACKEND_REVPROXY_PATH = '/my/content'`
                    

## `HAPROXY_{n}_MODE`
  *per service port*

Specified as `HAPROXY_{n}_MODE`.

Set the connection mode to either TCP or HTTP. The default is TCP.

Ex: `HAPROXY_0_MODE = 'http'`
                    

## `HAPROXY_{n}_PATH`
  *per service port*

Specified as `HAPROXY_{n}_PATH`.

The HTTP path to match, starting at the beginning. To specify multiple paths,
pass a space separated list. The syntax matches that of the `path_beg` config
option in HAProxy. To use the path routing, you must also define a VHost.

If you have multiple backends which share VHosts or paths, you may need to
manually specify ordering of the backend ACLs with
`HAPROXY_{n}_BACKEND_WEIGHT`. In HAProxy, the `use_backend` directive is
evaluated in the order it appears in the configuration.

Ex: `HAPROXY_0_PATH = '/v2/api/derp'`

Ex: `HAPROXY_0_PATH = '-i /multiple /paths'`
                    

## `HAPROXY_{n}_PORT`
  *per service port*

Specified as `HAPROXY_{n}_PORT`.

Bind to the specific port for the service.
This overrides the servicePort which has to be unique.

Ex: `HAPROXY_0_PORT = 80`
                    

## `HAPROXY_{n}_REDIRECT_TO_HTTPS`
  *per service port*

Specified as `HAPROXY_{n}_REDIRECT_TO_HTTPS`.

Redirect HTTP traffic to HTTPS. Requires at least a VHost be set.

Ex: `HAPROXY_0_REDIRECT_TO_HTTPS = true`
                    

## `HAPROXY_{n}_SSL_CERT`
  *per service port*

Specified as `HAPROXY_{n}_SSL_CERT`.

Enable the given SSL certificate for TLS/SSL traffic.

Ex: `HAPROXY_0_SSL_CERT = '/etc/ssl/cert.pem'`
                    

## `HAPROXY_{n}_STICKY`
  *per service port*

Specified as `HAPROXY_{n}_STICKY`.

Enable sticky request routing for the service.

Ex: `HAPROXY_0_STICKY = true`
                    

## `HAPROXY_{n}_USE_HSTS`
  *per service port*

Specified as `HAPROXY_{n}_USE_HSTS`.

Enable the HSTS response header for HTTP clients which support it.

Ex: `HAPROXY_0_USE_HSTS = true`
                    

## `HAPROXY_{n}_VHOST`
  *per service port*

Specified as `HAPROXY_{n}_VHOST`.

The Marathon HTTP Virtual Host proxy hostname(s) to gather.

If you have multiple backends which share VHosts or paths, you may need to
manually specify ordering of the backend ACLs with
`HAPROXY_{n}_BACKEND_WEIGHT`. In HAProxy, the `use_backend` directive is
evaluated in the order it appears in the configuration.

Ex: `HAPROXY_0_VHOST = 'marathon.mesosphere.com'`

Ex: `HAPROXY_0_VHOST = 'marathon.mesosphere.com,marathon'`
                    


