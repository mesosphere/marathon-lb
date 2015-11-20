# marathon-lb
Script to update HAProxy based on marathon state.

You can run the script directly, or using the Docker image.

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

To create a virtual host the `HAPROXY_0_VHOST` label needs to be set on the
given application.

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
Synopsis: `docker run mesosphere/marathon-lb event|poll ...`

You can pass in your own certificates for the SSL frontend by setting
the `HAPROXY_SSL_CERT` environment variable.

#### sse mode
In SSE mode, the script connects to the marathon events endpoint to get
notified about state changes.

Syntax: `docker run mesosphere/marathon-lb sse [other args]`

#### event mode
In event mode, the script registers a http callback in marathon to get
notified when state changes.

Syntax: `docker run mesosphere/marathon-lb event callback-addr:port [other args]`

#### poll mode
If you can't use the http callbacks, the script can poll the APIs to get
the schedulers state periodically.

Synatax: `docker run mesosphere/marathon-lb poll [other args]`

To change the poll interval (defaults to 60s), you can set the `POLL_INTERVAL`
environment variable.

### Direct invocation
You can also run the update script directly.
To generate an HAProxy configuration from Marathon running at `localhost:8080` with the `marathon_lb.py` script, run:

``` console
$ ./marathon_lb.py --marathon http://localhost:8080 --haproxy-config /etc/haproxy/haproxy.cfg --group external
```

This will refresh haproxy.cfg, and if there were any changes, then it will
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
$ ./marathon_lb.py --marathon http://localhost:8080 --haproxy-config /etc/haproxy/haproxy.cfg --group external --ssl-certs /etc/ssl/site1.co,/etc/ssl/site2.co
```

If you are using the script directly, you have two options:

 * Provide nothing and config will use `/etc/ssl/mesosphere.com.pem` as the certificate path. Put the certificate in this path or edit the file for the correct path.
 * Provide --ssl-certs command line argument and config will use these paths.

If you are using run.sh or Docker image, you have three options:

 * Provide your certificate text in HAPROXY_SSL_CERT environment variable. Contents will be written to `/etc/ssl/mesosphere.com.pem`. Config will use this path unless you specified extra certificate paths as in the next option.
 * Provide ssl certificate paths with --ssl-certs command line argument. Your config will use these certificate paths.
 * Provide nothing and it will create self-signed certificate on `/etc/ssl/mesosphere.com.pem` and config will use it.


### Skipping configuration validation
You can skip the configuration file validation (via calling haproxy service) process if you don't have haproxy installed. This is especially useful if you are running HAProxy on Docker containers.

``` console
$ ./marathon_lb.py --marathon http://localhost:8080 --haproxy-config /etc/haproxy/haproxy.cfg --group external --skip-validation
```


## HAProxy configuration

### App Labels
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
    Load balancers with the group '*' will collect all groups.

  HAPROXY_{n}_VHOST
    The Marathon HTTP Virtual Host proxy hostname to gather.
    Ex: HAPROXY_0_VHOST = 'marathon.mesosphere.com'

  HAPROXY_{n}_STICKY
    Enable sticky request routing for the service.
    Ex: HAPROXY_0_STICKY = true

  HAPROXY_{n}_REDIRECT_TO_HTTPS
    Redirect HTTP traffic to HTTPS.
    Ex: HAPROXY_0_REDIRECT_TO_HTTPS = true

  HAPROXY_{n}_SSL_CERT
    Enable the given SSL certificate for TLS/SSL traffic.
    Ex: HAPROXY_0_SSL_CERT = '/etc/ssl/certs/marathon.mesosphere.com'

  HAPROXY_{n}_BIND_ADDR
    Bind to the specific address for the service.
    Ex: HAPROXY_0_BIND_ADDR = '10.0.0.42'

  HAPROXY_{n}_PORT
    Bind to the specific port for the service.
    This overrides the servicePort which has to be unique.
    Ex: HAPROXY_0_PORT = 80

  HAPROXY_{n}_MODE
    Set the connection mode to either TCP or HTTP. The default is TCP.
    Ex: HAPROXY_0_MODE = 'http'
```

### Templates

The marathon-lb searches for configuration files in the `templates/`
directory. The `templates/` directory contains marathon-lb configuration
settings and example usage. The `templates/` directory is located in a relative
path from where the script is run. Some templates can also be
[overridden _per app service port_](#overridable-templates).

```
  HAPROXY_HEAD
    The head of the HAProxy config. This contains global settings
    and defaults.

  HAPROXY_HTTP_FRONTEND_HEAD
    An HTTP frontend that binds to port *:80 by default and gathers
    all virtual hosts as defined by the HAPROXY_{n}_VHOST variable.

  HAPROXY_HTTP_FRONTEND_APPID_HEAD
    An HTTP frontend that binds to port *:81 by default and gathers
    all apps in http mode.
    To use this frontend to forward to your app, configure the app with
    "HAPROXY_0_MODE=http" then you can access it via a call to the :81 with
    the header "X-Marathon-App-Id" set to the Marathon AppId.
    Note multiple http ports being exposed by the same marathon app are not
    supported. Only the first http port is available via this frontend.

  HAPROXY_HTTPS_FRONTEND_HEAD
    An HTTPS frontend for encrypted connections that binds to port *:443 by
    default and gathers all virtual hosts as defined by the
    HAPROXY_{n}_VHOST variable. You must modify this file to
    include your certificate.

  HAPROXY_BACKEND_REDIRECT_HTTP_TO_HTTPS
    This template is used with backends where the
    HAPROXY_{n}_REDIRECT_TO_HTTPS label is defined.

  HAPROXY_BACKEND_HTTP_OPTIONS
    Sets HTTP headers, for example X-Forwarded-For and X-Forwarded-Proto.

  HAPROXY_BACKEND_HTTP_HEALTHCHECK_OPTIONS
    Sets HTTP health check options, for example timeout check and httpchk GET.
    Parameters of the first health check for this service are exposed as:
      * healthCheckPortIndex
      * healthCheckProtocol
      * healthCheckPath
      * healthCheckTimeoutSeconds
      * healthCheckIntervalSeconds
      * healthCheckIgnoreHttp1xx
      * healthCheckGracePeriodSeconds
      * healthCheckMaxConsecutiveFailures
      * healthCheckFalls is set to healthCheckMaxConsecutiveFailures + 1
    Defaults to empty string.
    Example:
      option  httpchk GET {healthCheckPath}
      timeout check {healthCheckTimeoutSeconds}s


  HAPROXY_BACKEND_TCP_HEALTHCHECK_OPTIONS
    Sets TCP health check options, for example timeout check.
    Parameters of the first health check for this service are exposed as:
      * healthCheckPortIndex
      * healthCheckProtocol
      * healthCheckTimeoutSeconds
      * healthCheckIntervalSeconds
      * healthCheckGracePeriodSeconds
      * healthCheckMaxConsecutiveFailures
      * healthCheckFalls is set to healthCheckMaxConsecutiveFailures + 1
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

  HAPROXY_HTTP_FRONTEND_APPID_ACL
    The ACL that glues a backend to the corresponding app
    of the HAPROXY_HTTP_FRONTEND_APPID_HEAD.

  HAPROXY_HTTPS_FRONTEND_ACL
    The ACL that performs the SNI based hostname matching
    for the HAPROXY_HTTPS_FRONTEND_HEAD.

  HAPROXY_BACKEND_SERVER_OPTIONS
    The options for each physical server added to a backend.


  HAPROXY_BACKEND_SERVER_HTTP_HEALTHCHECK_OPTIONS
    Sets HTTP health check options for a single server, e.g. check inter.
    Parameters of the first health check for this service are exposed as:
      * healthCheckPortIndex
      * healthCheckProtocol
      * healthCheckPath
      * healthCheckTimeoutSeconds
      * healthCheckIntervalSeconds
      * healthCheckIgnoreHttp1xx
      * healthCheckGracePeriodSeconds
      * healthCheckMaxConsecutiveFailures
      * healthCheckFalls is set to healthCheckMaxConsecutiveFailures + 1
    Defaults to empty string.
    Example:
      check inter {healthCheckIntervalSeconds}s fall {healthCheckFalls}

  HAPROXY_BACKEND_SERVER_TCP_HEALTHCHECK_OPTIONS
    Sets TCP health check options for a single server, e.g. check inter.
    Parameters of the first health check for this service are exposed as:
      * healthCheckPortIndex
      * healthCheckProtocol
      * healthCheckTimeoutSeconds
      * healthCheckIntervalSeconds
      * healthCheckGracePeriodSeconds
      * healthCheckMaxConsecutiveFailures
      * healthCheckFalls is set to healthCheckMaxConsecutiveFailures + 1
    Defaults to empty string.
    Example:
      check inter {healthCheckIntervalSeconds}s fall {healthCheckFalls}

  HAPROXY_FRONTEND_BACKEND_GLUE
    This option glues the backend to the frontend.
```
#### Overridable templates

Some templates may be overridden using app labels,
as per the [labels section](#app-labels). Strings are interpreted as literal
HAProxy configuration parameters, with substitutions respected (as per the [templates section](#templates)). The HAProxy configuration will be validated
for correctness before reloading HAProxy after changes. **Note:** Since the HAProxy config is checked before reloading, if an app's HAProxy
labels aren't syntactically correct, HAProxy will not be reloaded and may
result is stale config.

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
  HAPROXY_{n}_HTTPS_FRONTEND_ACL
  HAPROXY_{n}_HTTP_FRONTEND_APPID_ACL
  HAPROXY_{n}_BACKEND_HTTP_OPTIONS
  HAPROXY_{n}_BACKEND_TCP_HEALTHCHECK_OPTIONS
  HAPROXY_{n}_BACKEND_HTTP_HEALTHCHECK_OPTIONS
  HAPROXY_{n}_BACKEND_STICKY_OPTIONS
  HAPROXY_{n}_FRONTEND_BACKEND_GLUE
  HAPROXY_{n}_BACKEND_SERVER_TCP_HEALTHCHECK_OPTIONS
  HAPROXY_{n}_BACKEND_SERVER_HTTP_HEALTHCHECK_OPTIONS
  HAPROXY_{n}_BACKEND_SERVER_OPTIONS
```
