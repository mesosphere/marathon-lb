import unittest
import marathon_lb


class TestMarathonUpdateHaproxy(unittest.TestCase):

    def test_config_no_apps(self):
        apps = dict()
        groups = ['external']
        bind_http_https = True
        ssl_certs = ""
        templater = marathon_lb.ConfigTemplater()

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = '''global
  daemon
  log /dev/log local0
  log /dev/log local1 notice
  maxconn 4096
  tune.ssl.default-dh-param 2048
defaults
  log               global
  retries           3
  maxconn           2000
  timeout connect   5s
  timeout client    50s
  timeout server    50s
  option            redispatch
listen stats
  bind 0.0.0.0:9090
  balance
  mode http
  stats enable
  monitor-uri /_haproxy_health_check

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
        expected = '''global
  daemon
  log /dev/log local0
  log /dev/log local1 notice
  maxconn 4096
  tune.ssl.default-dh-param 2048
defaults
  log               global
  retries           3
  maxconn           2000
  timeout connect   5s
  timeout client    50s
  timeout server    50s
  option            redispatch
listen stats
  bind 0.0.0.0:9090
  balance
  mode http
  stats enable
  monitor-uri /_haproxy_health_check

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
        expected = '''global
  daemon
  log /dev/log local0
  log /dev/log local1 notice
  maxconn 4096
  tune.ssl.default-dh-param 2048
defaults
  log               global
  retries           3
  maxconn           2000
  timeout connect   5s
  timeout client    50s
  timeout server    50s
  option            redispatch
listen stats
  bind 0.0.0.0:9090
  balance
  mode http
  stats enable
  monitor-uri /_haproxy_health_check

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
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = '''global
  daemon
  log /dev/log local0
  log /dev/log local1 notice
  maxconn 4096
  tune.ssl.default-dh-param 2048
defaults
  log               global
  retries           3
  maxconn           2000
  timeout connect   5s
  timeout client    50s
  timeout server    50s
  option            redispatch
listen stats
  bind 0.0.0.0:9090
  balance
  mode http
  stats enable
  monitor-uri /_haproxy_health_check

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
'''
        self.assertMultiLineEqual(config, expected)


    def test_config_healthcheck_command(self):
        self.maxDiff = None
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
        apps = [app]

        config = marathon_lb.config(apps, groups, bind_http_https,
                                    ssl_certs, templater)
        expected = '''global
  daemon
  log /dev/log local0
  log /dev/log local1 notice
  maxconn 4096
  tune.ssl.default-dh-param 2048
defaults
  log               global
  retries           3
  maxconn           2000
  timeout connect   5s
  timeout client    50s
  timeout server    50s
  option            redispatch
listen stats
  bind 0.0.0.0:9090
  balance
  mode http
  stats enable
  monitor-uri /_haproxy_health_check

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
'''
        self.assertMultiLineEqual(config, expected)
