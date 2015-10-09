# marathon-lb
Script to update haproxy based on mesos and marathon state.

You can run the script directly or using the Docker image.

See [comments in script](mesos-update-haproxy.py) for more details.

# Docker
Synopsis: `docker run mesosphere/marathon-lb event|poll ...`

You can pass in your own certificates for the SSL frontend by setting
the HAPROXY_SSL_CERT environment variable.

## sse mode
In SSE mode, the script connects to the marathon events endpoint to get
notified about state changes.

Syntax: `docker run mesosphere/marathon-lb sse [other args]`

## event mode
In event mode, the script registers a http callback in marathon to get
notified when state changes.

Syntax: `docker run mesosphere/marathon-lb event callback-addr:port [other args]`

## poll mode
If you can't use the http callbacks, the script can poll the APIs to get
the schedulers state periodically.

Synatax: `docker run mesosphere/marathon-lb poll [other args]`

To change the poll interval (defaults to 60s), you can set the POLL_INTERVALL
environment variable.
