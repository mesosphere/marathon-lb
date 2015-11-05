# marathon-lb
Script to update haproxy based on marathon state.

You can run the script directly or using the Docker image.

## Architecture
The marathon-lb script `marathon-update-haproxy.py` connect to the marathon API
to retrieve all apps running, generates a haproxy config and reloads haproxy.
By default, marathon-lb binds to the service port of every application and
sends incoming requests to the application instances.
To create a virtual host the HAPROXY_0_VHOST label needs to be set on the
given application.

See [comments in script](marathon-update-haproxy.py) for all available options.

## Deployment
To deploy the marathon-lb on the public slaves in your DCOS cluster,
simply run:

```
dcos package install marathon-lb
```

To configure a custom ssl-certificate, set the dcos cli option `ssl-cert`
to your concatenated cert and private key in .pem format. For more details
see the [haproxy documentation](https://cbonte.github.io/haproxy-dconv/configuration-1.7.html#crt (Bind options)).

## Caveats and Limitations
Since marathon-lb needs to bind to the service ports dynamically and allocating
them is not possible with a simple marathon scheduled application, this
implementation it prone to port conflicts. To avoid those, ideally you only run
this service in your public slaves.

### Docker
Synopsis: `docker run mesosphere/marathon-lb event|poll ...`

You can pass in your own certificates for the SSL frontend by setting
the HAPROXY_SSL_CERT environment variable.

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

To change the poll interval (defaults to 60s), you can set the POLL_INTERVALL
environment variable.

### Direct invocation
You can also run the update script directly.
To generate an HAProxy configuration from Marathon running at `localhost:8080` with the `marathon-update-haproxy.py` script, run:

``` console
$ ./marathon-update-haproxy.py --marathon http://localhost:8080 --haproxy-config /etc/haproxy/haproxy.cfg
```

This will refresh haproxy.cfg, and if there were any changes, then it will automatically reload HAproxy.

`marathon-update-haproxy.py` has a lot of additional functionality like sticky sessions, HTTP to HTTPS redirection, SSL offloading,
VHost support and templating capabilities.

To get the full documentation run:
``` console
$ ./marathon-update-haproxy.py --help
```
