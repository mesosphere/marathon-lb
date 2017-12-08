import copy
import json
import unittest
import os

import marathon_lb


class TestMarathonUpdateHaproxy(unittest.TestCase):

    def setUp(self):
        if 'HAPROXY_GLOBAL_DEFAULT_OPTIONS' in os.environ:
            del os.environ['HAPROXY_GLOBAL_DEFAULT_OPTIONS']
        self.base_config = '''global
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
'''

    def test_config_no_apps(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http

frontend marathon_http_appid_in
  bind *:9091
  mode http

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
'''
        print("actual config:\n")
        print(config)
        self.assertMultiLineEqual(config, expected)

    def test_config_env_template(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        os.environ["HAPROXY_HTTP_FRONTEND_HEAD"] = '''
frontend changed_frontend
  bind *:80
  mode http
'''
        templater = marathon_lb.ConfigTemplater()
        del os.environ["HAPROXY_HTTP_FRONTEND_HEAD"]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend changed_frontend
  bind *:80
  mode http

frontend marathon_http_appid_in
  bind *:9091
  mode http

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
'''
        print("actual config:\n")
        print(config)
        self.assertMultiLineEqual(config, expected)

    def test_config_with_ssl_no_apps(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = "/etc/haproxy/mysite.com.pem"
        templater = marathon_lb.ConfigTemplater()

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http

frontend marathon_http_appid_in
  bind *:9091
  mode http

frontend marathon_https_in
  bind *:443 ssl crt /etc/haproxy/mysite.com.pem
  mode http
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_with_multissl_no_apps(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = "/etc/haproxy/mysite1.com.pem,/etc/haproxy/mysite2.com.pem"
        templater = marathon_lb.ConfigTemplater()

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http

frontend marathon_http_appid_in
  bind *:9091
  mode http

frontend marathon_https_in
'''
        expected += "  bind *:443 ssl crt /etc/haproxy/mysite1.com.pem " \
                    "crt /etc/haproxy/mysite2.com.pem"
        expected += "\n  mode http\n"
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.groups = ['external']
        app.add_backend("agent1", "1.1.1.1", 1024, False)
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
  server agent1_1_1_1_1_1024 1.1.1.1:1024 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_healthcheck_command(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {
            "path": "/",
            "protocol": "COMMAND",
            "command": {
                "value": "curl -f -X GET http://$HOST:$PORT0/health"
            },
            # no portIndex
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.groups = ['external']
        app.add_backend("agent1", "1.1.1.1", 1024, False)
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http

frontend marathon_http_appid_in
  bind *:9091
  mode http

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http

frontend nginx_10000
  bind *:10000
  mode tcp
  use_backend nginx_10000

backend nginx_10000
  balance roundrobin
  mode tcp
  server agent1_1_1_1_1_1024 1.1.1.1:1024 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_vhost(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.hostname = "test.example.com"
        app.groups = ['external']
        app.add_backend("agent1", "1.1.1.1", 1024, False)
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http
  acl host_test_example_com_nginx hdr(host) -i test.example.com
  use_backend nginx_10000 if host_test_example_com_nginx

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
  use_backend nginx_10000 if { ssl_fc_sni test.example.com }

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
  server agent1_1_1_1_1_1024 1.1.1.1:1024 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_multiple_vhost(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.hostname = "test.example.com,test"
        app.groups = ['external']
        app.add_backend("agent1", "192.0.2.1", 1234, False)
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http
  acl host_test_example_com_nginx hdr(host) -i test.example.com
  acl host_test_example_com_nginx hdr(host) -i test
  use_backend nginx_10000 if host_test_example_com_nginx

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
  use_backend nginx_10000 if { ssl_fc_sni test.example.com }
  use_backend nginx_10000 if { ssl_fc_sni test }

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
  server agent1_192_0_2_1_1234 192.0.2.1:1234 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_vhost_and_redirect(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.hostname = "test.example.com"
        app.groups = ['external']
        app.add_backend("agent1", "1.1.1.1", 1024, False)
        app.redirectHttpToHttps = True
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http
  acl host_test_example_com_nginx hdr(host) -i test.example.com
  redirect scheme https code 301 if !{ ssl_fc } host_test_example_com_nginx

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
  use_backend nginx_10000 if { ssl_fc_sni test.example.com }

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
  server agent1_1_1_1_1_1024 1.1.1.1:1024 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_multiple_vhost_and_redirect(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.hostname = "test.example.com,test"
        app.groups = ['external']
        app.redirectHttpToHttps = True
        app.add_backend("agent1", "192.0.2.1", 1234, False)
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http
  acl host_test_example_com_nginx hdr(host) -i test.example.com
  acl host_test_example_com_nginx hdr(host) -i test
  redirect scheme https code 301 if !{ ssl_fc } host_test_example_com_nginx

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
  use_backend nginx_10000 if { ssl_fc_sni test.example.com }
  use_backend nginx_10000 if { ssl_fc_sni test }

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
  server agent1_192_0_2_1_1234 192.0.2.1:1234 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_vhost_with_auth(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.hostname = "test.example.com"
        app.groups = ['external']
        app.authRealm = "realm"
        app.authUser = "testuser"
        app.authPasswd = "testpasswd"
        app.add_backend("agent1", "1.1.1.1", 1024, False)
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
userlist user_nginx_10000
  user testuser password testpasswd

frontend marathon_http_in
  bind *:80
  mode http
  acl host_test_example_com_nginx hdr(host) -i test.example.com
  acl auth_test_example_com_nginx http_auth(user_nginx_10000)
  http-request auth realm "realm" if host_test_example_com_nginx \
!auth_test_example_com_nginx
  use_backend nginx_10000 if host_test_example_com_nginx

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
  acl auth_test_example_com_nginx http_auth(user_nginx_10000)
  http-request auth realm "realm" if { ssl_fc_sni test.example.com } \
!auth_test_example_com_nginx
  use_backend nginx_10000 if { ssl_fc_sni test.example.com }

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
  server agent1_1_1_1_1_1024 1.1.1.1:1024 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_multiple_vhost_and_auth(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.hostname = "test.example.com,test"
        app.authRealm = "realm"
        app.authUser = "testuser"
        app.authPasswd = "testpasswd"
        app.groups = ['external']
        app.add_backend("agent1", "192.0.2.1", 1234, False)
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
userlist user_nginx_10000
  user testuser password testpasswd

frontend marathon_http_in
  bind *:80
  mode http
  acl host_test_example_com_nginx hdr(host) -i test.example.com
  acl host_test_example_com_nginx hdr(host) -i test
  acl auth_test_example_com_nginx http_auth(user_nginx_10000)
  http-request auth realm "realm" if host_test_example_com_nginx \
!auth_test_example_com_nginx
  use_backend nginx_10000 if host_test_example_com_nginx

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
  acl auth_test_example_com_nginx http_auth(user_nginx_10000)
  http-request auth realm "realm" if { ssl_fc_sni test.example.com } \
!auth_test_example_com_nginx
  use_backend nginx_10000 if { ssl_fc_sni test.example.com }
  acl auth_test_example_com_nginx http_auth(user_nginx_10000)
  http-request auth realm "realm" if { ssl_fc_sni test } \
!auth_test_example_com_nginx
  use_backend nginx_10000 if { ssl_fc_sni test }

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
  server agent1_192_0_2_1_1234 192.0.2.1:1234 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_vhost_with_path_and_auth(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.hostname = "test.example.com"
        app.path = '/some/path'
        app.groups = ['external']
        app.authRealm = "realm"
        app.authUser = "testuser"
        app.authPasswd = "testpasswd"
        app.add_backend("agent1", "1.1.1.1", 1024, False)
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
userlist user_nginx_10000
  user testuser password testpasswd

frontend marathon_http_in
  bind *:80
  mode http
  acl host_test_example_com_nginx hdr(host) -i test.example.com
  acl auth_test_example_com_nginx http_auth(user_nginx_10000)
  acl path_nginx_10000 path_beg /some/path
  http-request auth realm "realm" if host_test_example_com_nginx \
path_nginx_10000 !auth_test_example_com_nginx
  use_backend nginx_10000 if host_test_example_com_nginx path_nginx_10000

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
  acl path_nginx_10000 path_beg /some/path
  acl auth_test_example_com_nginx http_auth(user_nginx_10000)
  http-request auth realm "realm" if { ssl_fc_sni test.example.com } \
path_nginx_10000 !auth_test_example_com_nginx
  use_backend nginx_10000 if { ssl_fc_sni test.example.com } path_nginx_10000

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
  server agent1_1_1_1_1_1024 1.1.1.1:1024 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_multiple_vhost_with_path_and_auth(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.hostname = "test.example.com,test"
        app.path = '/some/path'
        app.groups = ['external']
        app.authRealm = "realm"
        app.authUser = "testuser"
        app.authPasswd = "testpasswd"
        app.add_backend("agent1", "192.0.2.1", 1234, False)
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
userlist user_nginx_10000
  user testuser password testpasswd

frontend marathon_http_in
  bind *:80
  mode http
  acl path_nginx_10000 path_beg /some/path
  acl auth_test_example_com_nginx http_auth(user_nginx_10000)
  acl host_test_example_com_nginx hdr(host) -i test.example.com
  acl host_test_example_com_nginx hdr(host) -i test
  http-request auth realm "realm" if host_test_example_com_nginx \
path_nginx_10000 !auth_test_example_com_nginx
  use_backend nginx_10000 if host_test_example_com_nginx path_nginx_10000

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
  acl path_nginx_10000 path_beg /some/path
  acl auth_test_example_com_nginx http_auth(user_nginx_10000)
  http-request auth realm "realm" if { ssl_fc_sni test.example.com } \
path_nginx_10000 !auth_test_example_com_nginx
  use_backend nginx_10000 if { ssl_fc_sni test.example.com } ''' + \
                                      '''path_nginx_10000
  acl auth_test_example_com_nginx http_auth(user_nginx_10000)
  http-request auth realm "realm" if { ssl_fc_sni test } \
path_nginx_10000 !auth_test_example_com_nginx
  use_backend nginx_10000 if { ssl_fc_sni test } path_nginx_10000

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
  server agent1_192_0_2_1_1234 192.0.2.1:1234 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_vhost_with_path(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.hostname = "test.example.com"
        app.path = '/some/path'
        app.groups = ['external']
        app.add_backend("agent1", "1.1.1.1", 1024, False)
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http
  acl host_test_example_com_nginx hdr(host) -i test.example.com
  acl path_nginx_10000 path_beg /some/path
  use_backend nginx_10000 if host_test_example_com_nginx path_nginx_10000

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
  acl path_nginx_10000 path_beg /some/path
  use_backend nginx_10000 if { ssl_fc_sni test.example.com } path_nginx_10000

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
  server agent1_1_1_1_1_1024 1.1.1.1:1024 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_multiple_vhost_with_path(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.hostname = "test.example.com,test"
        app.path = '/some/path'
        app.groups = ['external']
        app.add_backend("agent1", "192.0.2.1", 1234, False)
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http
  acl path_nginx_10000 path_beg /some/path
  acl host_test_example_com_nginx hdr(host) -i test.example.com
  acl host_test_example_com_nginx hdr(host) -i test
  use_backend nginx_10000 if host_test_example_com_nginx path_nginx_10000

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
  acl path_nginx_10000 path_beg /some/path
  use_backend nginx_10000 if { ssl_fc_sni test.example.com } ''' + \
                                      '''path_nginx_10000
  use_backend nginx_10000 if { ssl_fc_sni test } path_nginx_10000

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
  server agent1_192_0_2_1_1234 192.0.2.1:1234 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_vhost_with_path_and_redirect(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.hostname = "test.example.com"
        app.path = '/some/path'
        app.groups = ['external']
        app.add_backend("agent1", "1.1.1.1", 1024, False)
        app.redirectHttpToHttps = True
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http
  acl host_test_example_com_nginx hdr(host) -i test.example.com
  acl path_nginx_10000 path_beg /some/path
  redirect scheme https code 301 if !{ ssl_fc } host_test_example_com_nginx\
 path_nginx_10000

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
  acl path_nginx_10000 path_beg /some/path
  use_backend nginx_10000 if { ssl_fc_sni test.example.com } path_nginx_10000

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
  server agent1_1_1_1_1_1024 1.1.1.1:1024 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_multiple_vhost_with_path_and_redirect(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.hostname = "test.example.com,test"
        app.path = '/some/path'
        app.groups = ['external']
        app.redirectHttpToHttps = True
        app.add_backend("agent1", "192.0.2.1", 1234, False)
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http
  acl path_nginx_10000 path_beg /some/path
  acl host_test_example_com_nginx hdr(host) -i test.example.com
  acl host_test_example_com_nginx hdr(host) -i test
  redirect scheme https code 301 if !{ ssl_fc } host_test_example_com_nginx\
 path_nginx_10000

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
  acl path_nginx_10000 path_beg /some/path
  use_backend nginx_10000 if { ssl_fc_sni test.example.com } ''' + \
                                      '''path_nginx_10000
  use_backend nginx_10000 if { ssl_fc_sni test } path_nginx_10000

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
  server agent1_192_0_2_1_1234 192.0.2.1:1234 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_multiple_vhost_path_redirect_hsts(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.hostname = "test.example.com,test"
        app.path = '/some/path'
        app.groups = ['external']
        app.redirectHttpToHttps = True
        app.useHsts = True
        app.add_backend("agent1", "192.0.2.1", 1234, False)
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http
  acl path_nginx_10000 path_beg /some/path
  acl host_test_example_com_nginx hdr(host) -i test.example.com
  acl host_test_example_com_nginx hdr(host) -i test
  redirect scheme https code 301 if !{ ssl_fc } host_test_example_com_nginx\
 path_nginx_10000

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
  acl path_nginx_10000 path_beg /some/path
  use_backend nginx_10000 if { ssl_fc_sni test.example.com } ''' + \
                                      '''path_nginx_10000
  use_backend nginx_10000 if { ssl_fc_sni test } path_nginx_10000

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend nginx_10000
  balance roundrobin
  mode http
  rspadd  Strict-Transport-Security:\ max-age=15768000
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
  server agent1_192_0_2_1_1234 192.0.2.1:1234 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_balance(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.balance = "leastconn"
        app.groups = ['external']
        app.add_backend("agent1", "1.1.1.1", 1024, False)
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend nginx_10000
  balance leastconn
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
  server agent1_1_1_1_1_1024 1.1.1.1:1024 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_bridge_app_marathon15(self):
        with open('tests/marathon15_apps.json') as data_file:
            apps = json.load(data_file)

        class Marathon:
            def __init__(self, data):
                self.data = data

            def list(self):
                return self.data

            def health_check(self):
                return True

            def strict_mode(self):
                return False

        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        apps = marathon_lb.get_apps(Marathon(apps['apps']))
        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http
  acl host_myvhost_com_pywebserver hdr(host) -i myvhost.com
  use_backend pywebserver_10101 if host_myvhost_com_pywebserver

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__pywebserver hdr(x-marathon-app-id) -i /pywebserver
  use_backend pywebserver_10101 if app__pywebserver

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
  use_backend pywebserver_10101 if { ssl_fc_sni myvhost.com }

frontend pywebserver_10101
  bind *:10101
  mode http
  use_backend pywebserver_10101

backend pywebserver_10101
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  server 10_0_2_148_1565 10.0.2.148:1565
'''
        self.assertMultiLineEqual(config, expected)

    def test_zdd_app(self):
        with open('tests/zdd_apps.json') as data_file:
            zdd_apps = json.load(data_file)

        class Marathon:
            def __init__(self, data):
                self.data = data

            def list(self):
                return self.data

            def health_check(self):
                return True

            def strict_mode(self):
                return False

        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        apps = marathon_lb.get_apps(Marathon(zdd_apps['apps']))
        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 15s
  server 10_0_1_147_25724 10.0.1.147:25724 check inter 3s fall 11
  server 10_0_6_25_16916 10.0.6.25:16916 check inter 3s fall 11
  server 10_0_6_25_23336 10.0.6.25:23336 check inter 3s fall 11
  server 10_0_6_25_31184 10.0.6.25:31184 check inter 3s fall 11 disabled
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_healthcheck_port(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "port": 1024,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.groups = ['external']
        app.add_backend("agent1", "1.1.1.1", 1024, False)
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
  server agent1_1_1_1_1_1024 1.1.1.1:1024 check inter 2s fall 11 port 1024
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_healthcheck_port_using_another_portindex(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.groups = ['external']
        app.add_backend("agent1", "192.0.2.1", 1024, False)
        app.healthcheck_port_index = 1
        admin_app = marathon_lb.MarathonService('/nginx', 10001, healthCheck,
                                                strictMode)
        admin_app.groups = ['external']
        admin_app.add_backend("agent1", "192.0.2.1", 1025, False)
        apps = [app, admin_app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

frontend nginx_10001
  bind *:10001
  mode http
  use_backend nginx_10001

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
  server agent1_192_0_2_1_1024 192.0.2.1:1024 check inter 2s fall 11 port 1025

backend nginx_10001
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
  server agent1_192_0_2_1_1025 192.0.2.1:1025 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_healthcheck_port_diff_portindex_and_group(self):
        apps = dict()
        groups = ['external', 'internal']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.groups = ['external']
        app.add_backend("agent1", "192.0.2.1", 1024, False)
        app.healthcheck_port_index = 1
        admin_app = marathon_lb.MarathonService('/nginx', 10001, healthCheck,
                                                strictMode)
        admin_app.groups = ['internal']
        admin_app.add_backend("agent1", "192.0.2.1", 1025, False)
        apps = [app, admin_app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

frontend nginx_10001
  bind *:10001
  mode http
  use_backend nginx_10001

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
  server agent1_192_0_2_1_1024 192.0.2.1:1024 check inter 2s fall 11 port 1025

backend nginx_10001
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
  server agent1_192_0_2_1_1025 192.0.2.1:1025 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_healthcheck_port_portindex_out_of_range(self):
        """
        see marathon_lb.get_backend_port(apps, app, idx) for impl.

        if app.healthcheck_port_index has a out of bounds value,
        then the app idx-th backend is returned instead.
        :return:
        """
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.groups = ['external']
        app.add_backend("agent1", "192.0.2.1", 1024, False)
        app.healthcheck_port_index = 3
        admin_app = marathon_lb.MarathonService('/nginx', 10001, healthCheck,
                                                strictMode)
        admin_app.groups = ['external']
        admin_app.add_backend("agent1", "192.0.2.1", 1025, False)
        apps = [app, admin_app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

frontend nginx_10001
  bind *:10001
  mode http
  use_backend nginx_10001

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
  server agent1_192_0_2_1_1024 192.0.2.1:1024 check inter 2s fall 11 port 1024

backend nginx_10001
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
  server agent1_192_0_2_1_1025 192.0.2.1:1025 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_tcp_healthcheck(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {
            "protocol": "TCP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.groups = ['external']
        app.add_backend("agent1", "1.1.1.1", 1024, False)
        app.hostname = "test.example.com"
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http
  acl host_test_example_com_nginx hdr(host) -i test.example.com
  use_backend nginx_10000 if host_test_example_com_nginx

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
  use_backend nginx_10000 if { ssl_fc_sni test.example.com }

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  server agent1_1_1_1_1_1024 1.1.1.1:1024 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_haproxy_group_fallback(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {}
        app1 = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                           strictMode)
        app1.groups = ['external', 'internal']
        app1.add_backend("agent1", "1.1.1.1", 1024, False)
        app2 = marathon_lb.MarathonService('/nginx', 10001, healthCheck,
                                           strictMode)
        app2.groups = ['external', 'internal']
        app2.add_backend("agent1", "1.1.1.1", 1025, False)
        apps = [app1, app2]
        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http

frontend marathon_http_appid_in
  bind *:9091
  mode http

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http

frontend nginx_10000
  bind *:10000
  mode tcp
  use_backend nginx_10000

frontend nginx_10001
  bind *:10001
  mode tcp
  use_backend nginx_10001

backend nginx_10000
  balance roundrobin
  mode tcp
  server agent1_1_1_1_1_1024 1.1.1.1:1024

backend nginx_10001
  balance roundrobin
  mode tcp
  server agent1_1_1_1_1_1025 1.1.1.1:1025
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_haproxy_group_per_service(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {}
        app1 = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                           strictMode)
        app1.haproxy_groups = ['external']
        app1.add_backend("agent1", "1.1.1.1", 1024, False)
        app2 = marathon_lb.MarathonService('/nginx', 10001, healthCheck,
                                           strictMode)
        app2.haproxy_groups = ['internal']
        app2.add_backend("agent1", "1.1.1.1", 1025, False)
        apps = [app1, app2]
        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http

frontend marathon_http_appid_in
  bind *:9091
  mode http

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http

frontend nginx_10000
  bind *:10000
  mode tcp
  use_backend nginx_10000

backend nginx_10000
  balance roundrobin
  mode tcp
  server agent1_1_1_1_1_1024 1.1.1.1:1024
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_haproxy_group_hybrid(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {}
        app1 = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                           strictMode)
        app1.haproxy_groups = ['internal']
        app1.add_backend("agent1", "1.1.1.1", 1024, False)
        app2 = marathon_lb.MarathonService('/nginx', 10001, healthCheck,
                                           strictMode)
        app2.groups = ['external']
        app2.add_backend("agent1", "1.1.1.1", 1025, False)
        apps = [app1, app2]
        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http

frontend marathon_http_appid_in
  bind *:9091
  mode http

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http

frontend nginx_10001
  bind *:10001
  mode tcp
  use_backend nginx_10001

backend nginx_10001
  balance roundrobin
  mode tcp
  server agent1_1_1_1_1_1025 1.1.1.1:1025
'''
        self.assertMultiLineEqual(config, expected)

        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_proxypass(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {}
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.groups = ['external']
        app.hostname = 'test.example.com'
        app.proxypath = '/test/'
        app.add_backend("agent1", "1.1.1.1", 1024, False)
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http
  acl host_test_example_com_nginx hdr(host) -i test.example.com
  use_backend nginx_10000 if host_test_example_com_nginx

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
  use_backend nginx_10000 if { ssl_fc_sni test.example.com }

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  http-request set-header Host test.example.com
  reqirep  "^([^ :]*)\ /test//?(.*)" "\\1\ /\\2"
  server agent1_1_1_1_1_1024 1.1.1.1:1024
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_revproxy(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {}
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.groups = ['external']
        app.hostname = 'test.example.com'
        app.revproxypath = '/test'
        app.add_backend("agent1", "1.1.1.1", 1024, False)
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http
  acl host_test_example_com_nginx hdr(host) -i test.example.com
  use_backend nginx_10000 if host_test_example_com_nginx

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
  use_backend nginx_10000 if { ssl_fc_sni test.example.com }

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  acl hdr_location res.hdr(Location) -m found
  rspirep "^Location: (https?://test.example.com(:[0-9]+)?)?(/.*)" "Location: \
  /test if hdr_location"
  server agent1_1_1_1_1_1024 1.1.1.1:1024
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_redirect(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {}
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.groups = ['external']
        app.hostname = 'test.example.com'
        app.redirpath = '/test'
        app.add_backend("agent1", "1.1.1.1", 1024, False)
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http
  acl host_test_example_com_nginx hdr(host) -i test.example.com
  use_backend nginx_10000 if host_test_example_com_nginx

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
  use_backend nginx_10000 if { ssl_fc_sni test.example.com }

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  acl is_root path -i /
  acl is_domain hdr(host) -i test.example.com
  redirect code 301 location /test if is_domain is_root
  server agent1_1_1_1_1_1024 1.1.1.1:1024
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_sticky(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {}
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.groups = ['external']
        app.add_backend("agent1", "1.1.1.1", 1024, False)
        app.sticky = True
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http

frontend marathon_http_appid_in
  bind *:9091
  mode http

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http

frontend nginx_10000
  bind *:10000
  mode tcp
  use_backend nginx_10000

backend nginx_10000
  balance roundrobin
  mode tcp
  cookie mesosphere_server_id insert indirect nocache
  server agent1_1_1_1_1_1024 1.1.1.1:1024 check cookie d6ad48c81f
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_multi_app_multiple_vhost_with_path(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.hostname = "test.example.com,test"
        app.path = '/some/path'
        app.groups = ['external']
        app1 = copy.deepcopy(app)
        app2 = copy.deepcopy(app)
        app3 = copy.deepcopy(app)
        app.add_backend("agent1", "192.0.2.1", 1234, False)
        app1.backend_weight = 1
        app1.appId += '1'
        app1.add_backend("agent1", "192.0.2.1", 2234, False)
        app2.backend_weight = 2
        app2.appId += '2'
        app2.add_backend("agent1", "192.0.2.1", 3234, False)
        app3.backend_weight = 3
        app3.appId += '3'
        app3.add_backend("agent1", "192.0.2.1", 4234, False)
        apps = [app, app1, app2, app3]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http
  acl path_nginx3_10000 path_beg /some/path
  acl host_test_example_com_nginx3 hdr(host) -i test.example.com
  acl host_test_example_com_nginx3 hdr(host) -i test
  use_backend nginx3_10000 if host_test_example_com_nginx3 path_nginx3_10000
  acl path_nginx2_10000 path_beg /some/path
  acl host_test_example_com_nginx2 hdr(host) -i test.example.com
  acl host_test_example_com_nginx2 hdr(host) -i test
  use_backend nginx2_10000 if host_test_example_com_nginx2 path_nginx2_10000
  acl path_nginx1_10000 path_beg /some/path
  acl host_test_example_com_nginx1 hdr(host) -i test.example.com
  acl host_test_example_com_nginx1 hdr(host) -i test
  use_backend nginx1_10000 if host_test_example_com_nginx1 path_nginx1_10000
  acl path_nginx_10000 path_beg /some/path
  acl host_test_example_com_nginx hdr(host) -i test.example.com
  acl host_test_example_com_nginx hdr(host) -i test
  use_backend nginx_10000 if host_test_example_com_nginx path_nginx_10000

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx
  acl app__nginx1 hdr(x-marathon-app-id) -i /nginx1
  use_backend nginx1_10000 if app__nginx1
  acl app__nginx2 hdr(x-marathon-app-id) -i /nginx2
  use_backend nginx2_10000 if app__nginx2
  acl app__nginx3 hdr(x-marathon-app-id) -i /nginx3
  use_backend nginx3_10000 if app__nginx3

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
  acl path_nginx3_10000 path_beg /some/path
  use_backend nginx3_10000 if { ssl_fc_sni test.example.com } path_nginx3_10000
  use_backend nginx3_10000 if { ssl_fc_sni test } path_nginx3_10000
  acl path_nginx2_10000 path_beg /some/path
  use_backend nginx2_10000 if { ssl_fc_sni test.example.com } path_nginx2_10000
  use_backend nginx2_10000 if { ssl_fc_sni test } path_nginx2_10000
  acl path_nginx1_10000 path_beg /some/path
  use_backend nginx1_10000 if { ssl_fc_sni test.example.com } path_nginx1_10000
  use_backend nginx1_10000 if { ssl_fc_sni test } path_nginx1_10000
  acl path_nginx_10000 path_beg /some/path
  use_backend nginx_10000 if { ssl_fc_sni test.example.com } path_nginx_10000
  use_backend nginx_10000 if { ssl_fc_sni test } path_nginx_10000

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

frontend nginx1_10000
  bind *:10000
  mode http
  use_backend nginx1_10000

frontend nginx2_10000
  bind *:10000
  mode http
  use_backend nginx2_10000

frontend nginx3_10000
  bind *:10000
  mode http
  use_backend nginx3_10000

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
  server agent1_192_0_2_1_1234 192.0.2.1:1234 check inter 2s fall 11

backend nginx1_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
  server agent1_192_0_2_1_2234 192.0.2.1:2234 check inter 2s fall 11

backend nginx2_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
  server agent1_192_0_2_1_3234 192.0.2.1:3234 check inter 2s fall 11

backend nginx3_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
  server agent1_192_0_2_1_4234 192.0.2.1:4234 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_haproxy_map(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {}
        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 15,
            "intervalSeconds": 3,
            "timeoutSeconds": 15,
            "maxConsecutiveFailures": 10
        }

        app1 = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                           strictMode)
        app1.hostname = "server.nginx.net,server.nginx1.net"
        app1.haproxy_groups = ['external']
        app1.add_backend("agent1", "1.1.1.1", 1024, False)
        app2 = marathon_lb.MarathonService('/apache', 10001, healthCheck,
                                           strictMode)
        app2.hostname = "server.apache.net"
        app2.haproxy_groups = ['external']
        app2.add_backend("agent2", "2.2.2.2", 1025, False)
        apps = [app1, app2]
        haproxy_map = True
        domain_map_array = []
        app_map_array = []
        config_file = "/etc/haproxy/haproxy.cfg"
        config = marathon_lb.config(apps, groups, bind_http_https, ssl_certs,
                                    templater, haproxy_map, domain_map_array,
                                    app_map_array, config_file)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http
  use_backend %[req.hdr(host),lower,regsub(:.*$,,),\
map(/etc/haproxy/domain2backend.map)]

frontend marathon_http_appid_in
  bind *:9091
  mode http
  use_backend %[req.hdr(x-marathon-app-id),lower,\
map(/etc/haproxy/app2backend.map)]

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
  use_backend %[ssl_fc_sni,lower,map(/etc/haproxy/domain2backend.map)]

frontend apache_10001
  bind *:10001
  mode http
  use_backend apache_10001

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend apache_10001
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 15s
  server agent2_2_2_2_2_1025 2.2.2.2:1025 check inter 3s fall 11

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 15s
  server agent1_1_1_1_1_1024 1.1.1.1:1024 check inter 3s fall 11
'''
        self.assertMultiLineEqual(config, expected)

        # Check the domain map
        domain_config_map = {}
        for element in domain_map_array:
            for key, value in list(element.items()):
                domain_config_map[key] = value
        expected_domain_map = {}
        expected_domain_map["server.nginx.net"] = "nginx_10000"
        expected_domain_map["server.nginx1.net"] = "nginx_10000"
        expected_domain_map["server.apache.net"] = "apache_10001"
        self.assertEqual(domain_config_map, expected_domain_map)

        # Check the app map
        app_config_map = {}
        for element in app_map_array:
            for key, value in list(element.items()):
                app_config_map[key] = value
        expected_app_map = {}
        expected_app_map["/apache"] = "apache_10001"
        expected_app_map["/nginx"] = "nginx_10000"
        self.assertEqual(app_config_map, expected_app_map)

    def test_config_haproxy_map_hybrid(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {}
        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 15,
            "intervalSeconds": 3,
            "timeoutSeconds": 15,
            "maxConsecutiveFailures": 10
        }

        app1 = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                           strictMode)
        app1.hostname = "server.nginx.net,server.nginx1.net"
        app1.haproxy_groups = ['external']
        app1.add_backend("agent1", "1.1.1.1", 1024, False)
        app2 = marathon_lb.MarathonService('/apache', 10001, healthCheck,
                                           strictMode)
        app2.hostname = "server.apache.net"
        app2.path = "/apache"
        app2.haproxy_groups = ['external']
        app2.add_backend("agent2", "2.2.2.2", 1025, False)
        apps = [app1, app2]
        haproxy_map = True
        domain_map_array = []
        app_map_array = []
        config_file = "/etc/haproxy/haproxy.cfg"
        config = marathon_lb.config(apps, groups, bind_http_https, ssl_certs,
                                    templater, haproxy_map, domain_map_array,
                                    app_map_array, config_file)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http
  acl host_server_apache_net_apache hdr(host) -i server.apache.net
  acl path_apache_10001 path_beg /apache
  use_backend apache_10001 if host_server_apache_net_apache path_apache_10001
  use_backend %[req.hdr(host),lower,regsub(:.*$,,),\
map(/etc/haproxy/domain2backend.map)]

frontend marathon_http_appid_in
  bind *:9091
  mode http
  use_backend %[req.hdr(x-marathon-app-id),lower,\
map(/etc/haproxy/app2backend.map)]

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
  acl path_apache_10001 path_beg /apache
  use_backend apache_10001 if { ssl_fc_sni server.apache.net } \
path_apache_10001
  use_backend %[ssl_fc_sni,lower,map(/etc/haproxy/domain2backend.map)]

frontend apache_10001
  bind *:10001
  mode http
  use_backend apache_10001

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend apache_10001
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 15s
  server agent2_2_2_2_2_1025 2.2.2.2:1025 check inter 3s fall 11

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 15s
  server agent1_1_1_1_1_1024 1.1.1.1:1024 check inter 3s fall 11
'''
        self.assertMultiLineEqual(config, expected)

        # Check the domain map
        domain_config_map = {}
        for element in domain_map_array:
            for key, value in list(element.items()):
                domain_config_map[key] = value
        expected_domain_map = {}
        expected_domain_map["server.nginx.net"] = "nginx_10000"
        expected_domain_map["server.nginx1.net"] = "nginx_10000"
        self.assertEqual(domain_config_map, expected_domain_map)

        # Check the app map
        app_config_map = {}
        for element in app_map_array:
            for key, value in list(element.items()):
                app_config_map[key] = value
        expected_app_map = {}
        expected_app_map["/apache"] = "apache_10001"
        expected_app_map["/nginx"] = "nginx_10000"
        self.assertEqual(app_config_map, expected_app_map)

    # Tests a scenario in which two applications are deployed,
    # one with authentication and the other without. The app id
    # of the one without authentication comes before the other
    # one when sorted alphabetically. In this scenario we expect
    # the 'domain2backend.map' use_backend definition to still be defined last.
    def test_config_haproxy_map_auth_noauth(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {}
        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 15,
            "intervalSeconds": 3,
            "timeoutSeconds": 15,
            "maxConsecutiveFailures": 10
        }

        app1 = marathon_lb.MarathonService('/nginx1', 10000, healthCheck,
                                           strictMode)
        app1.hostname = "server.nginx.net"
        app1.haproxy_groups = ['external']
        app1.add_backend("agent1", "1.1.1.1", 1024, False)
        app2 = marathon_lb.MarathonService('/nginx2', 10001, healthCheck,
                                           strictMode)
        app2.hostname = "server.nginx.net"
        app2.authRealm = "realm"
        app2.authUser = "testuser"
        app2.authPasswd = "testpasswd"
        app2.haproxy_groups = ['external']
        app2.add_backend("agent2", "2.2.2.2", 1025, False)
        apps = [app1, app2]
        haproxy_map = True
        domain_map_array = []
        app_map_array = []
        config_file = "/etc/haproxy/haproxy.cfg"
        config = marathon_lb.config(apps, groups, bind_http_https, ssl_certs,
                                    templater, haproxy_map, domain_map_array,
                                    app_map_array, config_file)
        expected = self.base_config + '''
userlist user_nginx2_10001
  user testuser password testpasswd

frontend marathon_http_in
  bind *:80
  mode http
  acl host_server_nginx_net_nginx2 hdr(host) -i server.nginx.net
  acl auth_server_nginx_net_nginx2 http_auth(user_nginx2_10001)
  http-request auth realm "realm" if host_server_nginx_net_nginx2 \
!auth_server_nginx_net_nginx2
  use_backend nginx2_10001 if host_server_nginx_net_nginx2
  use_backend %[req.hdr(host),lower,regsub(:.*$,,),\
map(/etc/haproxy/domain2backend.map)]

frontend marathon_http_appid_in
  bind *:9091
  mode http
  use_backend %[req.hdr(x-marathon-app-id),lower,\
map(/etc/haproxy/app2backend.map)]

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
  acl auth_server_nginx_net_nginx2 http_auth(user_nginx2_10001)
  http-request auth realm "realm" if { ssl_fc_sni server.nginx.net } \
!auth_server_nginx_net_nginx2
  use_backend nginx2_10001 if { ssl_fc_sni server.nginx.net }
  use_backend %[ssl_fc_sni,lower,map(/etc/haproxy/domain2backend.map)]

frontend nginx1_10000
  bind *:10000
  mode http
  use_backend nginx1_10000

frontend nginx2_10001
  bind *:10001
  mode http
  use_backend nginx2_10001

backend nginx1_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 15s
  server agent1_1_1_1_1_1024 1.1.1.1:1024 check inter 3s fall 11

backend nginx2_10001
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 15s
  server agent2_2_2_2_2_1025 2.2.2.2:1025 check inter 3s fall 11
'''
        self.assertMultiLineEqual(config, expected)

        # Check the domain map
        domain_config_map = {}
        for element in domain_map_array:
            for key, value in list(element.items()):
                domain_config_map[key] = value
        expected_domain_map = {}
        expected_domain_map["server.nginx.net"] = "nginx1_10000"
        self.assertEqual(domain_config_map, expected_domain_map)

        # Check the app map
        app_config_map = {}
        for element in app_map_array:
            for key, value in list(element.items()):
                app_config_map[key] = value
        expected_app_map = {}
        expected_app_map["/nginx2"] = "nginx2_10001"
        expected_app_map["/nginx1"] = "nginx1_10000"
        self.assertEqual(app_config_map, expected_app_map)

    def test_config_haproxy_map_hybrid_with_vhost_path(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {}
        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 15,
            "intervalSeconds": 3,
            "timeoutSeconds": 15,
            "maxConsecutiveFailures": 10
        }

        app1 = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                           strictMode)
        app1.hostname = "server.nginx.net,server.nginx1.net"
        app1.haproxy_groups = ['external']
        app1.add_backend("agent1", "1.1.1.1", 1024, False)
        app2 = marathon_lb.MarathonService('/apache', 10001, healthCheck,
                                           strictMode)
        app2.hostname = "server.apache.net,server.apache1.net"
        app2.path = "/apache"
        app2.haproxy_groups = ['external']
        app2.add_backend("agent2", "2.2.2.2", 1025, False)
        apps = [app1, app2]
        haproxy_map = True
        domain_map_array = []
        app_map_array = []
        config_file = "/etc/haproxy/haproxy.cfg"
        config = marathon_lb.config(apps, groups, bind_http_https, ssl_certs,
                                    templater, haproxy_map, domain_map_array,
                                    app_map_array, config_file)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http
  acl path_apache_10001 path_beg /apache
  acl host_server_apache_net_apache hdr(host) -i server.apache.net
  acl host_server_apache_net_apache hdr(host) -i server.apache1.net
  use_backend apache_10001 if host_server_apache_net_apache path_apache_10001
  use_backend %[req.hdr(host),lower,regsub(:.*$,,),\
map(/etc/haproxy/domain2backend.map)]

frontend marathon_http_appid_in
  bind *:9091
  mode http
  use_backend %[req.hdr(x-marathon-app-id),lower,\
map(/etc/haproxy/app2backend.map)]

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
  acl path_apache_10001 path_beg /apache
  use_backend apache_10001 if { ssl_fc_sni server.apache.net } \
path_apache_10001
  use_backend apache_10001 if { ssl_fc_sni server.apache1.net } \
path_apache_10001
  use_backend %[ssl_fc_sni,lower,map(/etc/haproxy/domain2backend.map)]

frontend apache_10001
  bind *:10001
  mode http
  use_backend apache_10001

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend apache_10001
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 15s
  server agent2_2_2_2_2_1025 2.2.2.2:1025 check inter 3s fall 11

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 15s
  server agent1_1_1_1_1_1024 1.1.1.1:1024 check inter 3s fall 11
'''
        self.assertMultiLineEqual(config, expected)

        # Check the domain map
        domain_config_map = {}
        for element in domain_map_array:
            for key, value in list(element.items()):
                domain_config_map[key] = value
        expected_domain_map = {}
        expected_domain_map["server.nginx.net"] = "nginx_10000"
        expected_domain_map["server.nginx1.net"] = "nginx_10000"
        self.assertEqual(domain_config_map, expected_domain_map)

        # Check the app map
        app_config_map = {}
        for element in app_map_array:
            for key, value in list(element.items()):
                app_config_map[key] = value
        expected_app_map = {}
        expected_app_map["/apache"] = "apache_10001"
        expected_app_map["/nginx"] = "nginx_10000"
        self.assertEqual(app_config_map, expected_app_map)

    def test_config_haproxy_map_hybrid_httptohttps_redirect(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {}
        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 15,
            "intervalSeconds": 3,
            "timeoutSeconds": 15,
            "maxConsecutiveFailures": 10
        }

        app1 = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                           strictMode)
        app1.hostname = "server.nginx.net,server.nginx1.net"
        app1.haproxy_groups = ['external']
        app1.add_backend("agent1", "1.1.1.1", 1024, False)
        app2 = marathon_lb.MarathonService('/apache', 10001, healthCheck,
                                           strictMode)
        app2.hostname = "server.apache.net,server.apache1.net"
        app2.haproxy_groups = ['external']
        app2.add_backend("agent2", "2.2.2.2", 1025, False)
        app2.redirectHttpToHttps = True
        apps = [app1, app2]
        haproxy_map = True
        domain_map_array = []
        app_map_array = []
        config_file = "/etc/haproxy/haproxy.cfg"
        config = marathon_lb.config(apps, groups, bind_http_https, ssl_certs,
                                    templater, haproxy_map, domain_map_array,
                                    app_map_array, config_file)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http
  acl host_server_apache_net_apache hdr(host) -i server.apache.net
  acl host_server_apache_net_apache hdr(host) -i server.apache1.net
  redirect scheme https code 301 if !{ ssl_fc } host_server_apache_net_apache
  use_backend %[req.hdr(host),lower,regsub(:.*$,,),\
map(/etc/haproxy/domain2backend.map)]

frontend marathon_http_appid_in
  bind *:9091
  mode http
  use_backend %[req.hdr(x-marathon-app-id),lower,\
map(/etc/haproxy/app2backend.map)]

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
  use_backend %[ssl_fc_sni,lower,map(/etc/haproxy/domain2backend.map)]

frontend apache_10001
  bind *:10001
  mode http
  use_backend apache_10001

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend apache_10001
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 15s
  server agent2_2_2_2_2_1025 2.2.2.2:1025 check inter 3s fall 11

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 15s
  server agent1_1_1_1_1_1024 1.1.1.1:1024 check inter 3s fall 11
'''
        self.assertMultiLineEqual(config, expected)

        # Check the domain map
        domain_config_map = {}
        for element in domain_map_array:
            for key, value in list(element.items()):
                domain_config_map[key] = value
        expected_domain_map = {}
        expected_domain_map["server.nginx.net"] = "nginx_10000"
        expected_domain_map["server.nginx1.net"] = "nginx_10000"
        expected_domain_map["server.apache.net"] = "apache_10001"
        expected_domain_map["server.apache1.net"] = "apache_10001"
        self.assertEqual(domain_config_map, expected_domain_map)

        # Check the app map
        app_config_map = {}
        for element in app_map_array:
            for key, value in list(element.items()):
                app_config_map[key] = value
        expected_app_map = {}
        expected_app_map["/apache"] = "apache_10001"
        expected_app_map["/nginx"] = "nginx_10000"
        self.assertEqual(app_config_map, expected_app_map)

    def test_config_simple_app_proxypass_health_check(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.proxypath = "/proxy/path"
        app.groups = ['external']
        app.add_backend("agent1", "1.1.1.1", 1024, False)
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  http-request set-header Host None
  reqirep  "^([^ :]*)\ /proxy/path/?(.*)" "\\1\ /\\2"
  option  httpchk GET /
  timeout check 10s
  server agent1_1_1_1_1_1024 1.1.1.1:1024 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_revproxy_health_check(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck,
                                          strictMode)
        app.revproxypath = "/proxy/path"
        app.groups = ['external']
        app.add_backend("agent1", "1.1.1.1", 1024, False)
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http

frontend nginx_10000
  bind *:10000
  mode http
  use_backend nginx_10000

backend nginx_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  acl hdr_location res.hdr(Location) -m found
  rspirep "^Location: (https?://None(:[0-9]+)?)?(/.*)" \
"Location:   /proxy/path if hdr_location"
  option  httpchk GET /
  timeout check 10s
  server agent1_1_1_1_1_1024 1.1.1.1:1024 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_strict_mode_on_and_off(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()

        healthCheck = {}
        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 15,
            "intervalSeconds": 3,
            "timeoutSeconds": 15,
            "maxConsecutiveFailures": 10
        }

        app1 = marathon_lb.MarathonService('/nginx1', 10000, healthCheck,
                                           True)
        app1.hostname = "server.nginx.net"
        app1.haproxy_groups = ['external']
        app1.add_backend("agent1", "1.1.1.1", 1024, False)
        app2 = marathon_lb.MarathonService('/nginx2', 10001, healthCheck,
                                           False)
        app2.hostname = "server.nginx.net"
        app2.haproxy_groups = ['external']
        app2.add_backend("agent2", "2.2.2.2", 1025, False)
        apps = [app1, app2]
        haproxy_map = True
        domain_map_array = []
        app_map_array = []
        config_file = "/etc/haproxy/haproxy.cfg"
        config = marathon_lb.config(apps, groups, bind_http_https, ssl_certs,
                                    templater, haproxy_map, domain_map_array,
                                    app_map_array, config_file)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http
  use_backend %[req.hdr(host),lower,regsub(:.*$,,),\
map(/etc/haproxy/domain2backend.map)]

frontend marathon_http_appid_in
  bind *:9091
  mode http
  use_backend %[req.hdr(x-marathon-app-id),lower,\
map(/etc/haproxy/app2backend.map)]

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
  use_backend %[ssl_fc_sni,lower,map(/etc/haproxy/domain2backend.map)]

frontend nginx2_10001
  bind *:10001
  mode http
  use_backend nginx2_10001

backend nginx2_10001
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 15s
  server agent2_2_2_2_2_1025 2.2.2.2:1025 check inter 3s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_backend_disabled_and_enablede(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        strictMode = False

        healthCheck = {}
        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 15,
            "intervalSeconds": 3,
            "timeoutSeconds": 15,
            "maxConsecutiveFailures": 10
        }

        app1 = marathon_lb.MarathonService('/nginx1', 10000, healthCheck,
                                           strictMode)
        app1.hostname = "server.nginx.net"
        app1.haproxy_groups = ['external']
        app1.enabled = False
        app1.add_backend("agent1", "1.1.1.1", 1024, False)
        app2 = marathon_lb.MarathonService('/nginx2', 10001, healthCheck,
                                           strictMode)
        app2.hostname = "server.nginx.net"
        app2.haproxy_groups = ['external']
        app2.enabled = True
        app2.add_backend("agent2", "2.2.2.2", 1025, False)
        apps = [app1, app2]
        haproxy_map = True
        domain_map_array = []
        app_map_array = []
        config_file = "/etc/haproxy/haproxy.cfg"
        config = marathon_lb.config(apps, groups, bind_http_https, ssl_certs,
                                    templater, haproxy_map, domain_map_array,
                                    app_map_array, config_file)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http
  use_backend %[req.hdr(host),lower,regsub(:.*$,,),\
map(/etc/haproxy/domain2backend.map)]

frontend marathon_http_appid_in
  bind *:9091
  mode http
  use_backend %[req.hdr(x-marathon-app-id),lower,\
map(/etc/haproxy/app2backend.map)]

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/cert.pem
  mode http
  use_backend %[ssl_fc_sni,lower,map(/etc/haproxy/domain2backend.map)]

frontend nginx2_10001
  bind *:10001
  mode http
  use_backend nginx2_10001

backend nginx2_10001
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 15s
  server agent2_2_2_2_2_1025 2.2.2.2:1025 check inter 3s fall 11
'''
        self.assertMultiLineEqual(config, expected)


class TestFunctions(unittest.TestCase):

    def test_json_number(self):
        json_value = '1'
        data = marathon_lb.load_json(json_value)
        expected = 1
        self.assertEquals(data, expected)

    def test_json_string(self):
        json_value = '"1"'
        data = marathon_lb.load_json(json_value)
        expected = "1"
        self.assertEquals(data, expected)

    def test_json_nested_null_dict_remain(self):
        json_value = '{"key":null,"key2":"y","key3":{"key4":null,"key5":"x"}}'
        data = marathon_lb.load_json(json_value)
        expected = {'key3': {'key5': 'x'}, 'key2': 'y'}
        self.assertEquals(data, expected)

    def test_json_nested_null_dict(self):
        json_value = '{"key":null,"key2":"y","key3":{"key4":null}}'
        data = marathon_lb.load_json(json_value)
        expected = {'key3': {}, 'key2': 'y'}
        self.assertEquals(data, expected)

    def test_json_simple_list_dict(self):
        json_value = '["k1",{"k2":null,"k3":"v3"},"k4"]'
        data = marathon_lb.load_json(json_value)
        expected = ['k1', {'k3': 'v3'}, 'k4']
        self.assertEquals(data, expected)

    def test_json_nested_null_dict_list(self):
        json_value = '["k1",{"k2":null,"k3":["k4",{"k5":null}]},"k6"]'
        data = marathon_lb.load_json(json_value)
        expected = ['k1', {'k3': ['k4', {}]}, 'k6']
        self.assertEquals(data, expected)
