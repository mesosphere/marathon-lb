# mesos-lb
Script to update haproxy based on mesos and marathon state.

You can run the script directly or using the Docker image.

See [comments in script](mesos-update-haproxy.py) for more details.

# Docker
Synopsis: `docker run mesosphere/mesos-lb event|poll ...`

## event mode
In event mode, the script registers a http callback in marathon to get
notified when state changes.

Syntax: `docker run mesosphere/mesos-lb event callback-addr:port [other args]`

## poll mode
If you can't use the http callbacks, the script can poll the APIs to get
the schedulers state periodically.

Synatax: `docker run mesosphere/mesos-lb poll [other args]`

To change the poll interval (defaults to 60s), you can set the POLL_INTERVALL
environment variable.
