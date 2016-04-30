import unittest
import copy
import json
import marathon_lb


class TestMarathonUpdateHaproxy(unittest.TestCase):

    def setUp(self):
        self.base_config = '''global
  daemon
  log /dev/log local0
  log /dev/log local1 notice
  maxconn 50000
  tune.ssl.default-dh-param 2048
  ssl-default-bind-ciphers ECDHE-ECDSA-CHACHA20-POLY1305:\
ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:\
ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:\
ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:\
DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:\
ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:\
ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:\
DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:\
DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:\
EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:\
AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS
  ssl-default-bind-options no-sslv3 no-tlsv10 no-tls-tickets
  ssl-default-server-ciphers ECDHE-ECDSA-CHACHA20-POLY1305:\
ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:\
ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:\
ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:\
DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:\
ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:\
ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:\
DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:\
DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:\
EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:\
AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:!DSS
  ssl-default-server-options no-sslv3 no-tlsv10 no-tls-tickets
  stats socket /var/run/haproxy/socket
  server-state-file global
  server-state-base /var/state/haproxy/
  lua-load /marathon-lb/getpids.lua
  lua-load /marathon-lb/getconfig.lua
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
  option            redispatch
  option            http-server-close
  option            dontlognull
listen stats
  bind 0.0.0.0:9090
  balance
  mode http
  stats enable
  monitor-uri /_haproxy_health_check
  acl getpid path /_haproxy_getpids
  http-request use-service lua.getpids if getpid
  acl getconfig path /_haproxy_getconfig
  http-request use-service lua.getconfig if getconfig
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
  server agent1_1_1_1_1_1024 1.1.1.1:1024 check inter 2s fall 11
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
  bind *:443 ssl crt /etc/ssl/mesosphere.com.pem
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
  server agent1_1_1_1_1_1024 1.1.1.1:1024 check inter 2s fall 11
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
  acl host_test_example_com_nginx hdr(host) -i test.example.com
  acl host_test_example_com_nginx hdr(host) -i test
  use_backend nginx_10000 if host_test_example_com_nginx

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

    def test_config_simple_app_vhost_and_redirect(self):
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
  server agent1_1_1_1_1_1024 1.1.1.1:1024 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_multiple_vhost_and_redirect(self):
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
        app.redirectHttpToHttps = True
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

    def test_config_simple_app_vhost_with_auth(self):
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
  bind *:443 ssl crt /etc/ssl/mesosphere.com.pem
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
        app.authRealm = "realm"
        app.authUser = "testuser"
        app.authPasswd = "testpasswd"
        app.groups = ['external']
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
  bind *:443 ssl crt /etc/ssl/mesosphere.com.pem
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
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_vhost_with_path_and_auth(self):
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
  bind *:443 ssl crt /etc/ssl/mesosphere.com.pem
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
        app.path = '/some/path'
        app.groups = ['external']
        app.authRealm = "realm"
        app.authUser = "testuser"
        app.authPasswd = "testpasswd"
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
  bind *:443 ssl crt /etc/ssl/mesosphere.com.pem
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
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_vhost_with_path(self):
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
  bind *:443 ssl crt /etc/ssl/mesosphere.com.pem
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
        app.path = '/some/path'
        app.groups = ['external']
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
  bind *:443 ssl crt /etc/ssl/mesosphere.com.pem
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
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_vhost_with_path_and_redirect(self):
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
  bind *:443 ssl crt /etc/ssl/mesosphere.com.pem
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
        app.path = '/some/path'
        app.groups = ['external']
        app.redirectHttpToHttps = True
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
  bind *:443 ssl crt /etc/ssl/mesosphere.com.pem
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
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_multiple_vhost_path_redirect_hsts(self):
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
        app.path = '/some/path'
        app.groups = ['external']
        app.redirectHttpToHttps = True
        app.useHsts = True
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
  bind *:443 ssl crt /etc/ssl/mesosphere.com.pem
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
  server agent1_1_1_1_1_1024 1.1.1.1:1024 check inter 2s fall 11
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
  server agent1_1_1_1_1_1024 1.1.1.1:1024 check inter 2s fall 11 port 1024
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_tcp_healthcheck(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()

        healthCheck = {
            "protocol": "TCP",
            "portIndex": 0,
            "gracePeriodSeconds": 10,
            "intervalSeconds": 2,
            "timeoutSeconds": 10,
            "maxConsecutiveFailures": 10,
            "ignoreHttp1xx": False
        }
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck)
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
  server agent1_1_1_1_1_1024 1.1.1.1:1024 check inter 2s fall 11
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_haproxy_group_fallback(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()

        healthCheck = {}
        app1 = marathon_lb.MarathonService('/nginx', 10000, healthCheck)
        app1.groups = ['external', 'internal']
        app1.add_backend("agent1", "1.1.1.1", 1024, False)
        app2 = marathon_lb.MarathonService('/nginx', 10001, healthCheck)
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
  bind *:443 ssl crt /etc/ssl/mesosphere.com.pem
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

        healthCheck = {}
        app1 = marathon_lb.MarathonService('/nginx', 10000, healthCheck)
        app1.haproxy_groups = ['external']
        app1.add_backend("agent1", "1.1.1.1", 1024, False)
        app2 = marathon_lb.MarathonService('/nginx', 10001, healthCheck)
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
  bind *:443 ssl crt /etc/ssl/mesosphere.com.pem
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

        healthCheck = {}
        app1 = marathon_lb.MarathonService('/nginx', 10000, healthCheck)
        app1.haproxy_groups = ['internal']
        app1.add_backend("agent1", "1.1.1.1", 1024, False)
        app2 = marathon_lb.MarathonService('/nginx', 10001, healthCheck)
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
  bind *:443 ssl crt /etc/ssl/mesosphere.com.pem
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

        healthCheck = {}
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck)
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
  http-request set-header Host test.example.com
  reqirep  "^([^ :]*)\ /test/(.*)" "\\1\ /\\2"
  server agent1_1_1_1_1_1024 1.1.1.1:1024
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_revproxy(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()

        healthCheck = {}
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck)
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
  acl hdr_location res.hdr(Location) -m found
  rspirep "^Location: (https?://test.example.com(:[0-9]+)?)?(/.*)" "Location: \
  /test if hdr_location"
  server agent1_1_1_1_1_1024 1.1.1.1:1024
'''
        self.assertMultiLineEqual(config, expected)

    def test_config_simple_app_revproxy(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()

        healthCheck = {}
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck)
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

        healthCheck = {}
        app = marathon_lb.MarathonService('/nginx', 10000, healthCheck)
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
  bind *:443 ssl crt /etc/ssl/mesosphere.com.pem
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
        app.path = '/some/path'
        app.groups = ['external']
        app1 = copy.deepcopy(app)
        app2 = copy.deepcopy(app)
        app3 = copy.deepcopy(app)
        app1.backend_weight = 1
        app1.appId += '1'
        app2.backend_weight = 2
        app2.appId += '2'
        app3.backend_weight = 3
        app3.appId += '3'
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
  bind *:443 ssl crt /etc/ssl/mesosphere.com.pem
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

backend nginx1_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s

backend nginx2_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s

backend nginx3_10000
  balance roundrobin
  mode http
  option forwardfor
  http-request set-header X-Forwarded-Port %[dst_port]
  http-request add-header X-Forwarded-Proto https if { ssl_fc }
  option  httpchk GET /
  timeout check 10s
'''
        self.assertMultiLineEqual(config, expected)
