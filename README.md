# marathon-lb [![Build Status](https://travis-ci.org/mesosphere/marathon-lb.svg?branch=master)](https://travis-ci.org/mesosphere/marathon-lb)
Marathon-lb is a tool for managing HAProxy, by consuming [Marathon's](https://github.com/mesosphere/marathon) app state.

### Features

 * **Stateless design**: no direct dependency on any third-party state store like ZooKeeper or etcd (_except through Marathon_)
 * **Real-time LB updates**, via [Marathon's event bus](https://mesosphere.github.io/marathon/docs/event-bus.html)
 * Support for Marathon's **health checks**
 * **Multi-cert SSL** support
 * Per-service **HAProxy templates**
 * DCOS integration
 * Automated Docker image builds ([mesosphere/marathon-lb](https://hub.docker.com/r/mesosphere/marathon-lb))
 * Global HAProxy templates which can be supplied at launch

## Architecture
The marathon-lb script `marathon_lb.py` connects to the marathon API
to retrieve all running apps, generates a HAProxy config and reloads HAProxy.
By default, marathon-lb binds to the service port of every application and
sends incoming requests to the application instances.

Services are exposed on their service port (see
[Service Discovery & Load Balancing](https://mesosphere.github.io/marathon/docs/service-discovery-load-balancing)
for reference) as defined in their Marathon definition. Furthermore, apps are
only exposed on LBs which have the same LB tag (or group) as defined in the Marathon
app's labels (using `HAPROXY_GROUP`). HAProxy parameters can be tuned by specify labels in your app.

To create a virtual host or hosts the `HAPROXY_{n}_VHOST` label needs to be set on the
given application. Applications with a vhost set will be exposed on ports 80
and 443, in addition to their service port. Multiple virtual hosts may be specified
in `HAPROXY_{n}_VHOST` using a comma as a delimiter between hostnames.

All applications are also exposed on port 9091, using the `X-Marathon-App-Id`
HTTP header. See the documentation for `HAPROXY_HTTP_FRONTEND_APPID_HEAD` in
the [templates section](#templates)

You can access the HAProxy statistics via `:9090/haproxy?stats`, and you can
retrieve the current HAProxy config from the `:9090/_haproxy_getconfig` endpoint.

## Deployment
The package is currently available [from the multiverse](https://github.com/mesosphere/multiverse).
To deploy the marathon-lb on the public slaves in your DCOS cluster,
simply run:

```
dcos package install marathon-lb
```

To configure a custom ssl-certificate, set the dcos cli option `ssl-cert`
to your concatenated cert and private key in .pem format. For more details
see the [HAProxy documentation](https://cbonte.github.io/haproxy-dconv/configuration-1.7.html#crt (Bind options)).

For further customization, templates can be added by pointing the dcos cli
option `template-url` to a tarball containing a directory `templates/`.
See [comments in script](marathon_lb.py) on how to name those.

### Docker
Synopsis: `docker run -e PORTS=$portnumber --net=host mesosphere/marathon-lb sse|event|poll ...`

You must set `PORTS` environment variable to allow haproxy bind to this port.
Syntax: `docker run -e PORTS=9090 mesosphere/marathon-lb sse [other args]`

You can pass in your own certificates for the SSL frontend by setting
the `HAPROXY_SSL_CERT` environment variable.

#### `sse` mode
In SSE mode, the script connects to the marathon events endpoint to get
notified about state changes. This only works with Marathon 0.11.0 or
newer versions.

Syntax: `docker run mesosphere/marathon-lb sse [other args]`

#### `event` mode
In event mode, the script registers a HTTP callback in marathon to get
notified when state changes.

Syntax: `docker run mesosphere/marathon-lb event callback-addr:port [other args]`

#### `poll` mode
If you can't use the HTTP callbacks, the script can poll the APIs to get
the schedulers state periodically.

Syntax: `docker run mesosphere/marathon-lb poll [other args]`

To change the poll interval (defaults to 60s), you can set the `POLL_INTERVAL`
environment variable.

### Direct invocation
You can also run the update script directly.
To generate an HAProxy configuration from Marathon running at `localhost:8080` with the `marathon_lb.py` script, run:

``` console
$ ./marathon_lb.py --marathon http://localhost:8080 --group external
```

It is possible to pass `--auth-credentials=` option if your Marathon requires authentication:
```
$ ./marathon_lb.py --marathon http://localhost:8080 --auth-credentials=admin:password
```

This will refresh `haproxy.cfg`, and if there were any changes, then it will
automatically reload HAProxy. Only apps with the label `HAPROXY_GROUP=external`
will be exposed on this LB.

`marathon_lb.py` has a lot of additional functionality like sticky sessions, HTTP to HTTPS redirection, SSL offloading, virtual host support and templating capabilities.

To get the full documentation run:
``` console
$ ./marathon_lb.py --help
```

### Providing SSL certificates
You can provide your SSL certificate paths to be placed in frontend marathon_https_in section with `--ssl-certs`.

``` console
$ ./marathon_lb.py --marathon http://localhost:8080 --group external --ssl-certs /etc/ssl/site1.co,/etc/ssl/site2.co
```

If you are using the script directly, you have two options:

 * Provide nothing and config will use `/etc/ssl/mesosphere.com.pem` as the certificate path. Put the certificate in this path or edit the file for the correct path.
 * Provide `--ssl-certs` command line argument and config will use these paths.

If you are using the provided `run` script or Docker image, you have three options:

 * Provide your certificate text in `HAPROXY_SSL_CERT` environment variable. Contents will be written to `/etc/ssl/mesosphere.com.pem`. Config will use this path unless you specified extra certificate paths as in the next option.
 * Provide SSL certificate paths with `--ssl-certs` command line argument. Your config will use these certificate paths.
 * Provide nothing and it will create self-signed certificate on `/etc/ssl/mesosphere.com.pem` and config will use it.


### Skipping configuration validation
You can skip the configuration file validation (via calling HAProxy service) process if you don't have HAProxy installed. This is especially useful if you are running HAProxy on Docker containers.

``` console
$ ./marathon_lb.py --marathon http://localhost:8080 --group external --skip-validation
```


## HAProxy configuration

### App labels
App labels are specified in the Marathon app definition. These can be used to override HAProxy behaviour. For example, to specify the `external` group for an app with a virtual host named `service.mesosphere.com`:

```json
{
  "id": "http-service",
  "labels": {
    "HAPROXY_GROUP":"external",
    "HAPROXY_0_VHOST":"service.mesosphere.com"
  }
}
```

Some labels are specified _per service port_. These are denoted with the `{n}` parameter in the label key, where `{n}` corresponds to the service port index, beginning at `0`.

The full list of labels which can be specified are:
```
  HAPROXY_GROUP
    The group of marathon-lb instances that point to the service.
    This is a global group for all services running on different vhosts in a application
    This can be overrided for each service port. If it is not overriden this will be default group.
    Load balancers with the group '*' will collect all groups.

  HAPROXY_DEPLOYMENT_GROUP
    Deployment group to which this app belongs.

  HAPROXY_DEPLOYMENT_ALT_PORT
    Alternate service port to be used during a blue/green deployment.

  HAPROXY_DEPLOYMENT_COLOUR
    Blue/green deployment colour. Used by the bluegreen_deploy.py script to determine the state of a deploy. You generally do not need to modify this unless you implement your own deployment orchestrator.

  HAPROXY_DEPLOYMENT_STARTED_AT
    The time at which a deployment started. You generally do not need to modify this unless you implement your own deployment orchestrator.

  HAPROXY_DEPLOYMENT_TARGET_INSTANCES
    The target number of app instances to seek during deployment. You generally do not need to modify this unless you implement your own deployment orchestrator.

  HAPROXY_{n}_VHOST
    The Marathon HTTP Virtual Host proxy hostname(s) to gather.
    Ex: HAPROXY_0_VHOST = 'marathon.mesosphere.com'
    Ex: HAPROXY_0_VHOST = 'marathon.mesosphere.com,marathon'

  HAPROXY_{n}_PATH
    The HTTP path to match, starting at the beginning. To specify multiple paths,
    pass a space separated list. The syntax matches that of the `path_beg` config
    option in HAProxy. To use the path routing, you must also define a VHost.
    Ex: HAPROXY_0_PATH = '/v2/api/derp'
    Ex: HAPROXY_0_PATH = '-i /multiple /paths'

  HAPROXY_{n}_STICKY
    Enable sticky request routing for the service.
    Ex: HAPROXY_0_STICKY = true

  HAPROXY_{n}_REDIRECT_TO_HTTPS
    Redirect HTTP traffic to HTTPS. Requires at least a VHost be set.
    Ex: HAPROXY_0_REDIRECT_TO_HTTPS = true

  HAPROXY_{n}_USE_HSTS
    Enable the HSTS response header for HTTP clients which support it.
    Ex: HAPROXY_0_USE_HSTS = true

  HAPROXY_{n}_SSL_CERT
    Enable the given SSL certificate for TLS/SSL traffic.
    Ex: HAPROXY_0_SSL_CERT = '/etc/ssl/certs/marathon.mesosphere.com'

  HAPROXY_{n}_BIND_OPTIONS
    Set additional bind options
    Ex: HAPROXY_0_BIND_OPTIONS = 'ciphers AES128+EECDH:AES128+EDH force-tlsv12 no-sslv3'

  HAPROXY_{n}_BIND_ADDR
    Bind to the specific address for the service.
    Ex: HAPROXY_0_BIND_ADDR = '10.0.0.42'

  HAPROXY_{n}_PORT
    Bind to the specific port for the service.
    This overrides the servicePort which has to be unique.
    Ex: HAPROXY_0_PORT = 80

  HAPROXY_{n}_GROUP
    Haproxy group per service. This helps us have different HA Proxy groups per service port.
    This overrides HAPROXY_GROUP for the particular service.
    If you have both external and internal services running on same set of instances on
    different ports, you can use this feature to add them to different haproxy configs.
    Ex: HAPROXY_0_GROUP = 'external'
        HAPROXY_1_GROUP = 'internal'

    Now if you run marathon_lb with --group external, it just adds the service on HAPROXY_0_PORT
    (or first service port incase HAPROXY_0_HOST is not configured) to haproxy config and similarly
    if you run it with --group internal, it adds service on HAPROXY_1_PORT to haproxy config.
    If the configuration is a combination of HAPROXY_GROUP and HAPROXY_{n}_GROUP,
    the more specific definition takes precedence.
    Ex: HAPROXY_0_GROUP = 'external'
        HAPROXY_GROUP   = 'internal'

    Considering the above example where the configuration is hybrid, Service running on
    HAPROXY_0_PORT is associated with just 'external' haproxy group and not 'internal' group.
    And since there is no Haproxy group mentioned for second service (HAPROXY_1_GROUP not defined)
    it falls back to default HAPROXY_GROUP and gets associated with 'internal' group.


  HAPROXY_{n}_MODE
    Set the connection mode to either TCP or HTTP. The default is TCP.
    Ex: HAPROXY_0_MODE = 'http'

  HAPROXY_{n}_BALANCE
    Set the load balancing algorithm to be used in a backend. The default is roundrobin.
    Ex: HAPROXY_0_BALANCE = 'leastconn'
    
  HAPROXY_{0}_HTTP_BACKEND_PROXYPASS
    Set the location to use for mapping local server URLs to remote servers + URL.
    Ex: HAPROXY_0_HTTP_BACKEND_PROXYPASS = '/path/to/redirect'

  HAPROXY_{0}_HTTP_BACKEND_REVPROXY
    Set the URL in HTTP response headers sent from a reverse proxied server. It only updates Location, Content-Location and URL.
    Ex: HAPROXY_0_HTTP_BACKEND_REVPROXY = '/my/content'
    
  HAPROXY_{0}_HTTP_BACKEND_REDIR
    Set the path to redirect the root of the domain to
    Ex: HAPROXY_0_HTTP_BACKEND_REDIR = '/my/content'
```

### Templates

Marathon-lb searches for configuration files in the `templates/`
directory. The `templates/` directory is located in a relative
path from where the script is run. Some templates can also be
[overridden _per app service port_](#overridable-templates). You may add your
own templates to the Docker image, or provide them at startup.

```
  HAPROXY_HEAD
    The head of the HAProxy config. This contains global settings
    and defaults.

  HAPROXY_HTTP_FRONTEND_HEAD
    An HTTP frontend that binds to port *:80 by default and gathers
    all virtual hosts as defined by the HAPROXY_{n}_VHOST variable.

  HAPROXY_HTTP_FRONTEND_APPID_HEAD
    An HTTP frontend that binds to port *:9091 by default and gathers
    all apps in HTTP mode.
    To use this frontend to forward to your app, configure the app with
    "HAPROXY_0_MODE=http" then you can access it via a call to the :9091 with
    the header "X-Marathon-App-Id" set to the Marathon AppId.
    Note multiple HTTP ports being exposed by the same marathon app are not
    supported. Only the first HTTP port is available via this frontend.

  HAPROXY_HTTPS_FRONTEND_HEAD
    An HTTPS frontend for encrypted connections that binds to port *:443 by
    default and gathers all virtual hosts as defined by the
    HAPROXY_{n}_VHOST variable. You must modify this file to
    include your certificate.

  HAPROXY_BACKEND_REDIRECT_HTTP_TO_HTTPS
    This template is used with backends where the
    HAPROXY_{n}_REDIRECT_TO_HTTPS label is set to true.

  HAPROXY_BACKEND_REDIRECT_HTTP_TO_HTTPS_WITH_PATH
    Same as HAPROXY_BACKEND_REDIRECT_HTTP_TO_HTTPS,
    but includes a path.

  HAPROXY_BACKEND_HSTS_OPTIONS
    This template is used for the backend where the
    HAPROXY_{n}_USE_HSTS label is set to true.

  HAPROXY_BACKEND_HTTP_OPTIONS
    Sets HTTP headers, for example X-Forwarded-For and X-Forwarded-Proto.

  HAPROXY_BACKEND_HTTP_HEALTHCHECK_OPTIONS
    Sets HTTP health check options, for example timeout check and httpchk GET.
    Parameters of the first health check for this service are exposed as:
      * healthCheckPortIndex
      * healthCheckPort
      * healthCheckProtocol
      * healthCheckPath
      * healthCheckTimeoutSeconds
      * healthCheckIntervalSeconds
      * healthCheckIgnoreHttp1xx
      * healthCheckGracePeriodSeconds
      * healthCheckMaxConsecutiveFailures
      * healthCheckFalls is set to healthCheckMaxConsecutiveFailures + 1
      * healthCheckPortOptions is set to " port {healthCheckPort}"
    Defaults to empty string.
    Example:
      option  httpchk GET {healthCheckPath}
      timeout check {healthCheckTimeoutSeconds}s


  HAPROXY_BACKEND_TCP_HEALTHCHECK_OPTIONS
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
      * healthCheckPortOptions is set to " port {healthCheckPort}"
    Defaults to empty string.
    Example:
      timeout check {healthCheckTimeoutSeconds}s

  HAPROXY_BACKEND_STICKY_OPTIONS
    Sets a cookie for services where HAPROXY_{n}_STICKY is true.

  HAPROXY_FRONTEND_HEAD
    Defines the address and port to bind to.

  HAPROXY_BACKEND_HEAD
    Defines the type of load balancing, roundrobin by default,
    and connection mode, TCP or HTTP.

  HAPROXY_HTTP_FRONTEND_ACL
    The ACL that glues a backend to the corresponding virtual host
    of the HAPROXY_HTTP_FRONTEND_HEAD.

  HAPROXY_HTTP_FRONTEND_ACL_ONLY
    Define the ACL matching a particular hostname, but unlike
    HAPROXY_HTTP_FRONTEND_ACL, only do the ACL portion. Does not glue
    the ACL to the backend. This is useful only in the case of multiple
    vhosts routing to the same backend

  HAPROXY_HTTP_FRONTEND_ROUTING_ONLY
    This is the counterpart to HAPROXY_HTTP_FRONTEND_ACL_ONLY which
    glues the acl name to the appropriate backend.

  HAPROXY_HTTP_FRONTEND_ACL_WITH_PATH
    The ACL that glues a backend to the corresponding virtual host with path
    of the HAPROXY_HTTP_FRONTEND_HEAD.

  HAPROXY_HTTP_FRONTEND_ACL_ONLY_WITH_PATH
    Define the ACL matching a particular hostname with path, but unlike
    HAPROXY_HTTP_FRONTEND_ACL_WITH_PATH, only do the ACL portion. Does not glue
    the ACL to the backend. This is useful only in the case of multiple
    vhosts routing to the same backend

  HAPROXY_HTTP_FRONTEND_ACL_ONLY_WITH_PATH
    Same as HAPROXY_HTTP_FRONTEND_ACL_ONLY_WITH_PATH except for HTTPS.

  HAPROXY_HTTP_FRONTEND_ROUTING_ONLY_WITH_PATH
    This is the counterpart to HAPROXY_HTTP_FRONTEND_ACL_ONLY_WITH_PATH which
    glues the acl names to the appropriate backend.

  HAPROXY_HTTP_FRONTEND_APPID_ACL
    The ACL that glues a backend to the corresponding app
    of the HAPROXY_HTTP_FRONTEND_APPID_HEAD.

  HAPROXY_HTTPS_FRONTEND_ACL
    The ACL that performs the SNI based hostname matching
    for the HAPROXY_HTTPS_FRONTEND_HEAD.

  HAPROXY_HTTPS_FRONTEND_ACL_WITH_PATH
    The ACL that performs the SNI based hostname matching with path
    for the HAPROXY_HTTPS_FRONTEND_HEAD.

  HAPROXY_BACKEND_SERVER_OPTIONS
    The options for each physical server added to a backend.


  HAPROXY_BACKEND_SERVER_HTTP_HEALTHCHECK_OPTIONS
    Sets HTTP health check options for a single server, e.g. check inter.
    Parameters of the first health check for this service are exposed as:
      * healthCheckPortIndex
      * healthCheckPort
      * healthCheckProtocol
      * healthCheckPath
      * healthCheckTimeoutSeconds
      * healthCheckIntervalSeconds
      * healthCheckIgnoreHttp1xx
      * healthCheckGracePeriodSeconds
      * healthCheckMaxConsecutiveFailures
      * healthCheckFalls is set to healthCheckMaxConsecutiveFailures + 1
      * healthCheckPortOptions is set to " port {healthCheckPort}"
    Defaults to empty string.
    Example:
      check inter {healthCheckIntervalSeconds}s fall {healthCheckFalls}

  HAPROXY_BACKEND_SERVER_TCP_HEALTHCHECK_OPTIONS
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
      * healthCheckPortOptions is set to " port {healthCheckPort}"

    Defaults to empty string.
    Example:
      check inter {healthCheckIntervalSeconds}s fall {healthCheckFalls}

  HAPROXY_FRONTEND_BACKEND_GLUE
    This option glues the backend to the frontend.
    
  HAPROXY_HTTP_BACKEND_PROXYPASS 
    This option enable proxypass features in apache to work

  
  HAPROXY_HTTP_BACKEND_REVPROXY
    This option enables reverse proxy option as use in apache to work
  
  HAPROXY_HTTP_BACKEND_REDIR 
    This option enables a simple redirection of the root URL to another location.
```
#### Overridable templates

Some templates may be overridden using app labels,
as per the [labels section](#app-labels). Strings are interpreted as literal
HAProxy configuration parameters, with substitutions respected (as per the
[templates section](#templates)). The HAProxy configuration will be validated
for correctness before reloading HAProxy after changes. **Note:** Since the
HAProxy config is checked before reloading, if an app's HAProxy
labels aren't syntactically correct, HAProxy will not be reloaded and may
result in stale config.

Here is an example for a service called `http-service` which requires that
`http-keep-alive` be disabled:

```json
{
  "id": "http-service",
  "labels":{
    "HAPROXY_GROUP":"external",
    "HAPROXY_0_BACKEND_HTTP_OPTIONS":"  option forwardfor\n  no option http-keep-alive\n  http-request set-header X-Forwarded-Port %[dst_port]\n  http-request add-header X-Forwarded-Proto https if { ssl_fc }\n"
  }
}
```

The full list of per service port templates which can be specified are:
```
HAPROXY_{n}_FRONTEND_HEAD
HAPROXY_{n}_BACKEND_REDIRECT_HTTP_TO_HTTPS
HAPROXY_{n}_BACKEND_HEAD
HAPROXY_{n}_HTTP_FRONTEND_ACL
HAPROXY_{n}_HTTP_FRONTEND_ACL_ONLY
HAPROXY_{n}_HTTP_FRONTEND_ROUTING_ONLY
HAPROXY_{n}_HTTP_FRONTEND_ACL_WITH_PATH
HAPROXY_{n}_HTTP_FRONTEND_ACL_ONLY_WITH_PATH
HAPROXY_{n}_HTTPS_FRONTEND_ACL_ONLY_WITH_PATH
HAPROXY_{n}_HTTP_FRONTEND_ROUTING_ONLY_WITH_PATH
HAPROXY_{n}_HTTP_FRONTEND_APPID_ACL
HAPROXY_{n}_HTTPS_FRONTEND_ACL
HAPROXY_{n}_HTTPS_FRONTEND_ACL_WITH_PATH
HAPROXY_{n}_BACKEND_HTTP_OPTIONS
HAPROXY_{n}_BACKEND_HSTS_OPTIONS
HAPROXY_{n}_BACKEND_HTTP_HEALTHCHECK_OPTIONS
HAPROXY_{n}_BACKEND_TCP_HEALTHCHECK_OPTIONS
HAPROXY_{n}_BACKEND_STICKY_OPTIONS
HAPROXY_{n}_BACKEND_SERVER_OPTIONS
HAPROXY_{n}_BACKEND_SERVER_TCP_HEALTHCHECK_OPTIONS
HAPROXY_{n}_BACKEND_SERVER_HTTP_HEALTHCHECK_OPTIONS
HAPROXY_{n}_FRONTEND_BACKEND_GLUE
```

## Zero downtime deployments

Marathon-lb is able to perform canary style blue/green deployment with zero downtime. To execute such deployments, you must follow certain patterns when using Marathon.

The deployment method is described [in this Marathon document](https://mesosphere.github.io/marathon/docs/blue-green-deploy.html). Marathon-lb provides an implementation of the aforementioned deployment method with the script [`bluegreen_deploy.py`](bluegreen_deploy.py). To perform a zero downtime deploy using `bluegreen_deploy.py`, you must:


- Specify the `HAPROXY_DEPLOYMENT_GROUP` and `HAPROXY_DEPLOYMENT_ALT_PORT` labels in your app template
  - `HAPROXY_DEPLOYMENT_GROUP`: This label uniquely identifies a pair of apps belonging to a blue/green deployment, and will be used as the app name in the HAProxy configuration
  - `HAPROXY_DEPLOYMENT_ALT_PORT`: An alternate service port is required because Marathon requires service ports to be unique across all apps
- Only use 1 service port: multiple ports are not yet implemented
- Use the provided `bluegreen_deploy.py` script to orchestrate the deploy: the script will make API calls to Marathon, and use the HAProxy stats endpoint to gracefully terminate instances
- The marathon-lb container must be run in privileged mode (to execute `iptables` commands) due to the issues outlined in the excellent blog post by the [Yelp engineering team found here](http://engineeringblog.yelp.com/2015/04/true-zero-downtime-haproxy-reloads.html)
- If you have long-lived TCP connections using the same HAProxy instances, it may cause the deploy to take longer than necessary. The script will wait up to 5 minutes (by default) for connections to drain from HAProxy between steps, but any long-lived TCP connections will cause old instances of HAProxy to stick around.

An example minimal configuration for a [test instance of nginx is included here](tests/1-nginx.json). You might execute a deployment from a CI tool like Jenkins with:

```
./bluegreen_deploy.py -j 1-nginx.json -m http://master.mesos:8080 -f -l http://marathon-lb.marathon.mesos:9090 --syslog-socket /dev/null
```

Zero downtime deployments are accomplished through the use of a Lua module, which reports the number of HAProxy processes which are currently running by hitting the stats endpoint at the `/_haproxy_getpids`. After a restart, there will be multiple HAProxy PIDs until all remaining connections have gracefully terminated. By waiting for all connections to complete, you may safely and deterministically drain tasks. A caveat of this, however, is that if you have any long-lived connections on the same LB, HAProxy will continue to run and serve those connections until they complete, thereby breaking this technique.
