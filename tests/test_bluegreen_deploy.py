import unittest
import bluegreen_deploy
import mock
import json


class Arguments:
    json = 'tests/1-nginx.json'
    force = False
    marathon = "http://marathon"
    marathon_lb = "http://marathon-lb:9090"
    dry_run = True
    initial_instances = 1
    marathon_auth_credential_file = None
    auth_credentials = None


class MyResponse:
    def __init__(self, filename):
        with open(filename) as data_file:
            self.data = json.load(data_file)

    def raise_for_status(self):
        return None

    def json(self):
        return self.data


def _load_listeners():
    with open('tests/haproxy_stats.csv') as f:
        return bluegreen_deploy.parse_haproxy_stats(f.read())


class TestBluegreenDeploy(unittest.TestCase):

    def test_find_drained_task_ids(self):
        listeners = _load_listeners()
        haproxy_instance_count = 2
        apps = json.loads(open('tests/bluegreen_app_blue.json').read())
        app = apps['apps'][0]

        results = \
            bluegreen_deploy.find_drained_task_ids(app,
                                                   listeners,
                                                   haproxy_instance_count)

        assert app['tasks'][0]['id'] in results  # 2 down, no sessions
        assert app['tasks'][1]['id'] not in results  # 1 up, one down
        assert app['tasks'][2]['id'] not in results  # 2 down, one w/ session

    def test_get_svnames_from_tasks(self):
        apps = json.loads(open('tests/bluegreen_app_blue.json').read())
        tasks = apps['apps'][0]['tasks']

        task_svnames = bluegreen_deploy.get_svnames_from_tasks(tasks)

        assert '10_0_6_25_16916' in task_svnames
        assert '10_0_6_25_31184' in task_svnames

    def test_parse_haproxy_stats(self):
        with open('tests/haproxy_stats.csv') as f:
            results = bluegreen_deploy.parse_haproxy_stats(f.read())

            assert results[1].pxname == 'http-in'
            assert results[1].svname == 'IPv4-direct'

            assert results[2].pxname == 'http-out'
            assert results[2].svname == 'IPv4-cached'

    @mock.patch('bluegreen_deploy.fetch_combined_haproxy_stats',
                mock.Mock(side_effect=lambda _: _load_listeners()))
    def test_fetch_app_listeners(self):
        app = {
                'labels': {
                  'HAPROXY_DEPLOYMENT_GROUP': 'foobar',
                  'HAPROXY_0_PORT': '8080'
                }
              }

        app_listeners = bluegreen_deploy.fetch_app_listeners(app, [])

        assert app_listeners[0].pxname == 'foobar_8080'
        assert len(app_listeners) == 1

    @mock.patch('socket.gethostbyname_ex',
                mock.Mock(side_effect=lambda hostname:
                          (hostname, [], ['127.0.0.1', '127.0.0.2'])))
    def test_get_marathon_lb_urls(self):
        marathon_lb_urls = bluegreen_deploy.get_marathon_lb_urls(Arguments())

        assert 'http://127.0.0.1:9090' in marathon_lb_urls
        assert 'http://127.0.0.2:9090' in marathon_lb_urls
        assert 'http://127.0.0.3:9090' not in marathon_lb_urls

    @mock.patch('requests.get',
                mock.Mock(side_effect=lambda k, auth:
                          MyResponse('tests/bluegreen_app_blue.json')))
    def test_simple(self):
        # This test just checks the output of the program against
        # some expected output
        from six import StringIO

        out = StringIO()
        bluegreen_deploy.do_bluegreen_deploy(Arguments(), out)
        output = json.loads(out.getvalue())
        output['labels']['HAPROXY_DEPLOYMENT_STARTED_AT'] = ""

        expected = json.loads('''{
  "acceptedResourceRoles": [
    "*",
    "slave_public"
  ],
  "container": {
    "docker": {
      "forcePullImage": true,
      "image": "brndnmtthws/nginx-echo-sleep",
      "network": "BRIDGE",
      "portMappings": [
        {
          "containerPort": 8080,
          "hostPort": 0,
          "servicePort": 10001
        }
      ]
    },
    "type": "DOCKER"
  },
  "cpus": 0.1,
  "healthChecks": [
    {
      "gracePeriodSeconds": 15,
      "intervalSeconds": 3,
      "maxConsecutiveFailures": 10,
      "path": "/",
      "portIndex": 0,
      "protocol": "HTTP",
      "timeoutSeconds": 15
    }
  ],
  "id": "/nginx-blue",
  "instances": 1,
  "labels": {
    "HAPROXY_0_PORT": "10000",
    "HAPROXY_APP_ID": "nginx",
    "HAPROXY_DEPLOYMENT_ALT_PORT": "10001",
    "HAPROXY_DEPLOYMENT_COLOUR": "blue",
    "HAPROXY_DEPLOYMENT_GROUP": "nginx",
    "HAPROXY_DEPLOYMENT_STARTED_AT": "2016-02-01T15:51:38.184623",
    "HAPROXY_DEPLOYMENT_TARGET_INSTANCES": "3",
    "HAPROXY_GROUP": "external"
  },
  "mem": 65
}
''')
        expected['labels']['HAPROXY_DEPLOYMENT_STARTED_AT'] = ""
        self.assertEqual(output, expected)
