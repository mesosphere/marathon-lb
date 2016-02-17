import unittest
import json
import marathon_lb


class TestMarathonUpdateHaproxy(unittest.TestCase):
    def setUp(self):
        self.base_config = '''global
  daemon
  log /dev/log local0
  log /dev/log local1 notice
  maxconn 10000
  tune.ssl.default-dh-param 2048
  server-state-file global
  server-state-base /var/state/haproxy/
  lua-load /marathon-lb/getpids.lua
defaults
  load-server-state-from-file global
  log               global
  retries           3
  maxconn           5000
  timeout connect   3s
  timeout client    30s
  timeout server    30s
  option            redispatch
  option            dontlognull
listen stats
  bind 0.0.0.0:9090
  balance
  mode http
  stats enable
  monitor-uri /_haproxy_health_check
  acl getpid path /_haproxy_getpids
  http-request use-service lua.getpids if getpid
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
  bind *:443 ssl crt /etc/ssl/mesosphere.com.pem
  mode http
'''
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

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10,
            "ignoreHttp1xx": False
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck)
        app.groups = ['external']
        app.add_backend("1.1.1.1", 1024, False)
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
  bind *:443 ssl crt /etc/ssl/mesosphere.com.pem
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
  server 1_1_1_1_1024 1.1.1.1:1024 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_healthcheck_command(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()

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
            "maxConsecutiveFailures": 10,
            "ignoreHttp1xx": False
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck)
        app.groups = ['external']
        app.add_backend("1.1.1.1", 1024, False)
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
  bind *:443 ssl crt /etc/ssl/mesosphere.com.pem
  mode http

frontend nginx_10000
  bind *:10000
  mode tcp
  use_backend nginx_10000

backend nginx_10000
  balance roundrobin
  mode tcp
  server 1_1_1_1_1024 1.1.1.1:1024
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_vhost(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10,
            "ignoreHttp1xx": False
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck)
        app.hostname = "test.example.com"
        app.groups = ['external']
        app.add_backend("1.1.1.1", 1024, False)
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http
  acl host_test_example_com hdr(host) -i test.example.com
  use_backend nginx_10000 if host_test_example_com

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/mesosphere.com.pem
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
  server 1_1_1_1_1024 1.1.1.1:1024 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_balance(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10,
            "ignoreHttp1xx": False
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck)
        app.balance = "leastconn"
        app.groups = ['external']
        app.add_backend("1.1.1.1", 1024, False)
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
  bind *:443 ssl crt /etc/ssl/mesosphere.com.pem
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
  server 1_1_1_1_1024 1.1.1.1:1024 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_bluegreen_app(self):
        with open('tests/bluegreen_apps.json') as data_file:
            bluegreen_apps = json.load(data_file)

        class Marathon:
            def __init__(self, data):
                self.data = data

            def list(self):
                return self.data

            def health_check(self):
                return True

        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()
        apps = marathon_lb.get_apps(Marathon(bluegreen_apps['apps']))
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
  bind *:443 ssl crt /etc/ssl/mesosphere.com.pem
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
  server 10_0_6_25_16916 10.0.6.25:16916 check inter 3s fall 11 disabled
  server 10_0_6_25_23336 10.0.6.25:23336 check inter 3s fall 11
  server 10_0_6_25_31184 10.0.6.25:31184 check inter 3s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_multiple_vhost(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10,
            "ignoreHttp1xx": False
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck)
        app.hostname = "test.example.com,test"
        app.groups = ['external']
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = self.base_config + '''
frontend marathon_http_in
  bind *:80
  mode http
  acl host_test_example_com hdr(host) -i test.example.com
  acl host_test_example_com hdr(host) -i test
  use_backend nginx_10000 if host_test_example_com

frontend marathon_http_appid_in
  bind *:9091
  mode http
  acl app__nginx hdr(x-marathon-app-id) -i /nginx
  use_backend nginx_10000 if app__nginx

frontend marathon_https_in
  bind *:443 ssl crt /etc/ssl/mesosphere.com.pem
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
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_healthcheck_port(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()

        healthCheck = {
            "path": "/",
            "protocol": "HTTP",
            "port": 1024,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10,
            "ignoreHttp1xx": False
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck)
        app.groups = ['external']
        app.add_backend("1.1.1.1", 1024, False)
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
  bind *:443 ssl crt /etc/ssl/mesosphere.com.pem
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
  server 1_1_1_1_1024 1.1.1.1:1024 check inter 2s fall 11 port 1024
'''
        self.assertMultiLineEqual(config, expected)
