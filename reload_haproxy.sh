#!/bin/bash

socat /var/run/haproxy/socket - <<< "show servers state" > /var/state/haproxy/global

# "sv reload ${HAPROXY_SERVICE}" will be added here by /marathon-lb/run:
