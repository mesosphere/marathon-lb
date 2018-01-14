#!/bin/bash
socat /var/run/haproxy/socket - <<< "show servers state" > /var/state/haproxy/global