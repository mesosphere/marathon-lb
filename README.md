# marathon-lb [![Build Status](https://travis-ci.org/mesosphere/marathon-lb.svg?branch=master)](https://travis-ci.org/mesosphere/marathon-lb)

Marathon-lb is a tool for managing HAProxy, by consuming
[Marathon's](https://github.com/mesosphere/marathon) app state. HAProxy is a
fast, efficient, battle-tested, highly available load balancer with many advanced features which power a number of high-profile websites.

### Features

 * **Stateless design**: no direct dependency on any third-party state store like ZooKeeper or etcd (_except through Marathon_)
 * **Idempotent and deterministic**: scales horizontally
 * **Highly scalable**: [can achieve line-rate](http://www.haproxy.org/10g.html) per instance, with multiple instances providing fault-tolerance and greater throughput
 * **Real-time LB updates**, via [Marathon's event bus](https://mesosphere.github.io/marathon/docs/event-bus.html)
 * Support for Marathon's **health checks**
 * **Multi-cert TLS/SSL** support
 * [Zero-downtime deployments](#zero-downtime-deployments)
 * Per-service **HAProxy templates**
 * DC/OS integration
 * Automated Docker image builds ([mesosphere/marathon-lb](https://hub.docker.com/r/mesosphere/marathon-lb))
 * Global HAProxy templates which can be supplied at launch
 * Supports IP-per-task integration, such as [Project Calico](https://github.com/projectcalico/calico-containers)

### Getting started

 * [Using marathon-lb](https://docs.mesosphere.com/usage/service-discovery/marathon-lb/using-marathon-lb/)
 * [Advanced features of marathon-lb](https://docs.mesosphere.com/administration/service-discovery/service-discovery-and-load-balancing-with-marathon-lb/advanced-features-of-marathon-lb/)
 * [Securing your service with TLS/SSL (blog post)](https://mesosphere.com/blog/2016/04/06/lets-encrypt-dcos/)

Take a look at [the marathon-lb wiki](https://github.com/mesosphere/marathon-lb/wiki) for example usage, templates, and more.

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
the [templates section](Longhelp.md#templates)

You can access the HAProxy statistics via `:9090/haproxy?stats`, and you can
retrieve the current HAProxy config from the `:9090/_haproxy_getconfig` endpoint.

## Deployment
The package is currently available [from the universe](https://github.com/mesosphere/universe).
To deploy marathon-lb on the public slaves in your DC/OS cluster,
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
the `HAPROXY_SSL_CERT` environment variable. If you need more than one
certificate you can specify additional ones by setting `HAPROXY_SSL_CERT0` - `HAPROXY_SSL_CERT100`.

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

 * Provide nothing and config will use `/etc/ssl/cert.pem` as the certificate path. Put the certificate in this path or edit the file for the correct path.
 * Provide `--ssl-certs` command line argument and config will use these paths.

If you are using the provided `run` script or Docker image, you have three options:

 * Provide your certificate text in `HAPROXY_SSL_CERT` environment variable. Contents will be written to `/etc/ssl/cert.pem`. Config will use this path unless you specified extra certificate paths as in the next option.
 * Provide SSL certificate paths with `--ssl-certs` command line argument. Your config will use these certificate paths.
 * Provide nothing and it will create self-signed certificate on `/etc/ssl/cert.pem` and config will use it.


### Skipping configuration validation
You can skip the configuration file validation (via calling HAProxy service) process if you don't have HAProxy installed. This is especially useful if you are running HAProxy on Docker containers.

``` console
$ ./marathon_lb.py --marathon http://localhost:8080 --group external --skip-validation
```

### Using Haproxy maps for backend lookup.
You can use haproxy maps to speed up web application (vhosts) to backend lookup. This can be very useful for large installations where vhost to backend lookup can take considerable time. This can be done by using --haproxy-map flag.

```console 
$ ./marathon_lb.py --marathon http://localhost:8080 --group external --haproxy-map
```
Currently it creates a lookup dictionary only for host header(both http and https) and x-marathon-app-id header. But for path based routing and auth, it uses the usual backend rules comparison.

### API endpoints

Marathon-lb exposes a few endpoints on port 9090 (by default). They are:

| Endpoint                      | Description                                                                                                                                                                                                                                                                                                               |
|-------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `:9090/haproxy?stats`         | HAProxy stats endpoint. This produces an HTML page which can be viewed in your browser, providing various statistics about the current HAProxy instance.                                                                                                                                                                  |
| `:9090/haproxy?stats;csv`     | This is a CSV version of the stats above, which can be consumed by other tools. For example, it's used in the [`zdd.py`](zdd.py) script.                                                                                                                                                        |
| `:9090/_haproxy_health_check` | HAProxy health check endpoint. Returns `200 OK` if HAProxy is healthy.                                                                                                                                                                                                                                                    |
| `:9090/_haproxy_getconfig`    | Returns the HAProxy config file as it was when HAProxy was started. Implemented in [`getconfig.lua`](getconfig.lua).                                                                                                                                                                                                      |
| `:9090/_haproxy_getpids`      | Returns the PIDs for all HAProxy instances within the current process namespace. This literally returns `$(pidof haproxy)`. Implemented in [`getpids.lua`](getpids.lua). This is also used by the [`zdd.py`](zdd.py) script to determine if connections have finished draining during a deploy. |


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

See [the configuration doc for the full list](Longhelp.md#other-labels)
of labels.

### Templates

Marathon-lb searches for configuration files in the `templates/`
directory. The `templates/` directory is located in a relative
path from where the script is run. Some templates can also be
[overridden _per app service port_](#overridable-templates). You may add your
own templates to the Docker image, or provide them at startup.

See [the configuration doc for the full list](Longhelp.md#templates)
of templates.

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

The full list of per service port templates which can be specified
are [documented here](Longhelp.md#templates).

## Operational Best Practices

 * Use service ports within the reserved range (which is 10000 to 10100 by default). This will prevent port conflicts, and ensure reloads don't result in connection errors.
 * Avoid using the `HAPROXY_{n}_PORT` label; prefer defining service ports.
 * Consider running multiple marathon-lb instances. In practice, 2 or more should be used to provide high availability. Note: **do not** run marathon-lb on every node in your cluster. This is considered an anti-pattern due to the implications of hammering the Marathon API and excess health checking.
 * Consider using a dedicated load balancer in front of marathon-lb to permit upgrades/changes. Common choices include an ELB (on AWS) or a hardware load balancer for on-premise installations.
 * Use separate marathon-lb groups (specified with `--group`) for internal and external load balancing. On DC/OS, the default group is `external`. A simple `options.json` for an internal load balancer would be:

 ```json
   {
     "marathon-lb": {
       "name": "marathon-lb-internal",
       "haproxy-group": "internal",
       "bind-http-https": false,
       "role": ""
     }
   }
 ```
 * For HTTP services, consider setting VHost (and optionally a path) to access the service on ports 80 and 443. Alternatively, the service can be accessed on port 9091 using the `X-Marathon-App-Id` header. For example, to access an app with the ID `tweeter`:

  ```
  $ curl -vH "X-Marathon-App-Id: /tweeter" marathon-lb.marathon.mesos:9091/
  *   Trying 10.0.4.74...
  * Connected to marathon-lb.marathon.mesos (10.0.4.74) port 9091 (#0)
  > GET / HTTP/1.1
  > Host: marathon-lb.marathon.mesos:9091
  > User-Agent: curl/7.48.0
  > Accept: */*
  > X-Marathon-App-Id: /tweeter
  >
  < HTTP/1.1 200 OK
  ```

## Zero-downtime deployments

Marathon-lb is able to perform canary style blue/green deployment with zero downtime. To execute such deployments, you must follow certain patterns when using Marathon.

The deployment method is described [in this Marathon document](https://mesosphere.github.io/marathon/docs/blue-green-deploy.html). Marathon-lb provides an implementation of the aforementioned deployment method with the script [`zdd.py`](zdd.py). To perform a zero downtime deploy using `zdd.py`, you must:


- Specify the `HAPROXY_DEPLOYMENT_GROUP` and `HAPROXY_DEPLOYMENT_ALT_PORT` labels in your app template
  - `HAPROXY_DEPLOYMENT_GROUP`: This label uniquely identifies a pair of apps belonging to a blue/green deployment, and will be used as the app name in the HAProxy configuration
  - `HAPROXY_DEPLOYMENT_ALT_PORT`: An alternate service port is required because Marathon requires service ports to be unique across all apps
- Only use 1 service port: multiple ports are not yet implemented
- Use the provided `zdd.py` script to orchestrate the deploy: the script will make API calls to Marathon, and use the HAProxy stats endpoint to gracefully terminate instances
- The marathon-lb container must be run in privileged mode (to execute `iptables` commands) due to the issues outlined in the excellent blog post by the [Yelp engineering team found here](http://engineeringblog.yelp.com/2015/04/true-zero-downtime-haproxy-reloads.html)
- If you have long-lived TCP connections using the same HAProxy instances, it may cause the deploy to take longer than necessary. The script will wait up to 5 minutes (by default) for connections to drain from HAProxy between steps, but any long-lived TCP connections will cause old instances of HAProxy to stick around.

An example minimal configuration for a [test instance of nginx is included here](tests/1-nginx.json). You might execute a deployment from a CI tool like Jenkins with:

```
./zdd.py -j 1-nginx.json -m http://master.mesos:8080 -f -l http://marathon-lb.marathon.mesos:9090 --syslog-socket /dev/null
```

Zero downtime deployments are accomplished through the use of a Lua module, which reports the number of HAProxy processes which are currently running by hitting the stats endpoint at the `/_haproxy_getpids`. After a restart, there will be multiple HAProxy PIDs until all remaining connections have gracefully terminated. By waiting for all connections to complete, you may safely and deterministically drain tasks. A caveat of this, however, is that if you have any long-lived connections on the same LB, HAProxy will continue to run and serve those connections until they complete, thereby breaking this technique.

The ZDD script includes the ability to specify a pre-kill hook, which is executed before draining tasks are terminated. This allows you to run your own automated checks against the old and new app before the deploy continues.

## Mesos with IP-per-task support

Marathon-lb supports load balancing for applications that use the Mesos IP-per-task
feature, whereby each task is assigned unique, accessible, IP addresses.  For these
tasks services are directly accessible via the configured discovery ports and there
is no host port mapping.  Note, that due to limitations with Marathon (see
[mesosphere/marathon#3636](https://github.com/mesosphere/marathon/issues/3636))
configured service ports are not exposed to marathon-lb for IP-per-task apps.

For these apps, if the service ports are missing from the Marathon app data,
marathon-lb will automatically assign port values from a configurable range.  The range
is configured using the `--min-serv-port-ip-per-task` and `--max-serv-port-ip-per-task`
options. While port assignment is deterministic, the assignment is not guaranteed if
you change the current set of deployed apps. In other words, when you deploy a new
app, the port assignments may change.

## Contributing

PRs are welcome, but here are a few general guidelines:

 - Avoid making changes which may break existing behaviour
 - Document new features
 - Update/include tests for new functionality
 - Use the pre-commit hook to automatically generate docs:
   ```
   bash /path/to/marathon-lb/scripts/install-git-hooks.sh
   ```
