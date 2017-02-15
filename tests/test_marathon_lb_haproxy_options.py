import os

from tests.test_marathon_lb import TestMarathonUpdateHaproxy


def template_option(opt):
    return '  option            {opt}\n'.format(opt=opt)


base_config_prefix = '''global
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
'''

base_config_suffix = '''\
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
'''


class TestAdditionalOptions(TestMarathonUpdateHaproxy):

    def setUp(self):
        self.maxDiff = None
        os.environ['HAPROXY_GLOBAL_DEFAULT_OPTIONS'] = 'httplog,tcplog'
        base_config = base_config_prefix
        base_config += template_option('httplog')
        base_config += template_option('tcplog')
        base_config += base_config_suffix
        self.base_config = base_config


class TestDuplicatedOptions(TestMarathonUpdateHaproxy):

    def setUp(self):
        self.maxDiff = None
        os.environ['HAPROXY_GLOBAL_DEFAULT_OPTIONS'] = \
            'httplog,tcplog,dontlognull,tcplog'
        base_config = base_config_prefix
        base_config += template_option('dontlognull')
        base_config += template_option('httplog')
        base_config += template_option('tcplog')
        base_config += base_config_suffix
        self.base_config = base_config
