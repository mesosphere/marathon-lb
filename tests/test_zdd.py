import unittest
import json

import mock

import zdd
from zdd_exceptions import InvalidArgException


class Arguments:
    json = 'tests/1-nginx.json'
    force = False
    marathon = "http://marathon"
    marathon_lb = "http://marathon-lb:9090"
    dry_run = True
    initial_instances = 1
    marathon_auth_credential_file = None
    auth_credentials = None
    pre_kill_hook = None
    new_instances = 0
    complete_cur = False
    complete_prev = False
    dcos_auth_credentials = None


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
        return zdd.parse_haproxy_stats(f.read())


class TestBluegreenDeploy(unittest.TestCase):

    @mock.patch('zdd.scale_marathon_app_instances')
    def test_scale_new_app_instances_up_50_percent(self, mock):
        """When scaling new_app instances, increase instances by 50% of
           existing instances if we have not yet met or surpassed the amount
           of instances deployed by old_app
        """
        new_app = {
            'instances': 10,
            'labels': {
                'HAPROXY_DEPLOYMENT_TARGET_INSTANCES': 30
            }
        }
        old_app = {'instances': 30}
        args = Arguments()
        args.initial_instances = 5
        zdd.scale_new_app_instances(args, new_app, old_app)
        mock.assert_called_with(
            args, new_app, 15)

    @mock.patch('zdd.scale_marathon_app_instances')
    def test_scale_new_app_instances_to_target(self, mock):
        """When scaling new instances up, if we have met or surpassed the
           amount of instances deployed for old_app, go right to our
           deployment target amount of instances for new_app
        """
        new_app = {
            'instances': 10,
            'labels': {
                'HAPROXY_DEPLOYMENT_TARGET_INSTANCES': 30
            }
        }
        old_app = {'instances': 8}
        args = Arguments()
        args.initial_instances = 5
        zdd.scale_new_app_instances(args, new_app, old_app)
        mock.assert_called_with(
            args, new_app, 30)

    @mock.patch('zdd.scale_marathon_app_instances')
    def test_scale_new_app_instances_hybrid(self, mock):
        """When scaling new instances up, if we have met or surpassed the
           amount of instances deployed for old_app, go right to our
           deployment target amount of instances for new_app
        """
        new_app = {
            'instances': 10,
            'labels': {
                'HAPROXY_DEPLOYMENT_NEW_INSTANCES': 15,
                'HAPROXY_DEPLOYMENT_TARGET_INSTANCES': 30
            }
        }
        old_app = {'instances': 20}
        args = Arguments()
        args.initial_instances = 5
        zdd.scale_new_app_instances(args, new_app, old_app)
        mock.assert_called_with(
            args, new_app, 15)

    def test_find_drained_task_ids(self):
        listeners = _load_listeners()
        haproxy_instance_count = 2
        apps = json.loads(open('tests/zdd_app_blue.json').read())
        app = apps['apps'][0]

        results = \
            zdd.find_drained_task_ids(app,
                                      listeners,
                                      haproxy_instance_count)

        assert app['tasks'][0]['id'] in results  # 2 l's down, no sessions
        assert app['tasks'][1]['id'] not in results  # 1 l up, 1 down
        assert app['tasks'][2]['id'] not in results  # 2 l's d, 1 w/ scur/qcur

    def test_find_draining_task_ids(self):
        listeners = _load_listeners()
        haproxy_instance_count = 2
        apps = json.loads(open('tests/zdd_app_blue.json').read())
        app = apps['apps'][0]

        results = \
            zdd.find_draining_task_ids(app,
                                       listeners,
                                       haproxy_instance_count)

        assert app['tasks'][0]['id'] in results  # 2 l's down, no sessions
        assert app['tasks'][1]['id'] not in results  # 1 l up, 1 down
        assert app['tasks'][2]['id'] in results  # 2 l's down, 1 w/ scur/qcur

    def test_get_svnames_from_tasks(self):
        apps = json.loads(open('tests/zdd_app_blue.json').read())
        tasks = apps['apps'][0]['tasks']

        task_svnames = zdd.get_svnames_from_tasks(apps, tasks)
        assert '10_0_6_25_16916' in task_svnames
        assert '10_0_6_25_31184' in task_svnames
        assert '10_0_6_25_23336' in task_svnames

    def test_parse_haproxy_stats(self):
        with open('tests/haproxy_stats.csv') as f:
            results = zdd.parse_haproxy_stats(f.read())

            assert results[1].pxname == 'http-in'
            assert results[1].svname == 'IPv4-direct'

            assert results[2].pxname == 'http-out'
            assert results[2].svname == 'IPv4-cached'

    @mock.patch('subprocess.check_call')
    def test_pre_kill_hook(self, mock):
        # TODO(BM): This test is naive. An end-to-end test would be nice.
        args = Arguments()
        args.pre_kill_hook = 'myhook'
        old_app = {
            'id': 'oldApp'
        }
        new_app = {
            'id': 'newApp'
        }
        tasks_to_kill = ['task1', 'task2']

        zdd.execute_pre_kill_hook(args,
                                  old_app,
                                  tasks_to_kill,
                                  new_app)

        mock.assert_called_with([args.pre_kill_hook,
                                 '{"id": "oldApp"}',
                                 '["task1", "task2"]',
                                 '{"id": "newApp"}'])

    @mock.patch('zdd.fetch_combined_haproxy_stats',
                mock.Mock(side_effect=lambda _: _load_listeners()))
    def test_fetch_app_listeners(self):
        app = {
                'labels': {
                  'HAPROXY_DEPLOYMENT_GROUP': 'foobar',
                  'HAPROXY_0_PORT': '8080'
                }
              }

        app_listeners = zdd.fetch_app_listeners(app, [])

        assert app_listeners[0].pxname == 'foobar_8080'
        assert len(app_listeners) == 1

    @mock.patch('socket.gethostbyname_ex',
                mock.Mock(side_effect=lambda hostname:
                          (hostname, [], ['127.0.0.1', '127.0.0.2'])))
    def test_get_marathon_lb_urls(self):
        marathon_lb_urls = zdd.get_marathon_lb_urls(Arguments())

        assert 'http://127.0.0.1:9090' in marathon_lb_urls
        assert 'http://127.0.0.2:9090' in marathon_lb_urls
        assert 'http://127.0.0.3:9090' not in marathon_lb_urls

    @mock.patch('requests.get',
                mock.Mock(side_effect=lambda k, auth:
                          MyResponse('tests/zdd_app_blue.json')))
    def test_simple(self):
        # This test just checks the output of the program against
        # some expected output
        from six import StringIO

        out = StringIO()
        zdd.do_zdd(Arguments(), out)
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
    "HAPROXY_DEPLOYMENT_NEW_INSTANCES": "0",
    "HAPROXY_DEPLOYMENT_STARTED_AT": "2016-02-01T15:51:38.184623",
    "HAPROXY_DEPLOYMENT_TARGET_INSTANCES": "3",
    "HAPROXY_GROUP": "external"
  },
  "mem": 65
}
''')
        expected['labels']['HAPROXY_DEPLOYMENT_STARTED_AT'] = ""
        self.assertEqual(output, expected)

    @mock.patch('requests.get',
                mock.Mock(side_effect=lambda k, auth:
                          MyResponse('tests/zdd_app_blue.json')))
    def test_hybrid(self):
        # This test just checks the output of the program against
        # some expected output
        from six import StringIO

        out = StringIO()
        args = Arguments()
        args.new_instances = 1
        zdd.do_zdd(args, out)
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
    "HAPROXY_DEPLOYMENT_NEW_INSTANCES": "1",
    "HAPROXY_DEPLOYMENT_STARTED_AT": "2016-02-01T15:51:38.184623",
    "HAPROXY_DEPLOYMENT_TARGET_INSTANCES": "3",
    "HAPROXY_GROUP": "external"
  },
  "mem": 65
}
''')
        expected['labels']['HAPROXY_DEPLOYMENT_STARTED_AT'] = ""
        self.assertEqual(output, expected)

    @mock.patch('requests.get',
                mock.Mock(side_effect=lambda k, auth:
                          MyResponse('tests/zdd_app_blue.json')))
    def test_complete_cur_exception(self):
        # This test just checks the output of the program against
        # some expected output

        args = Arguments()
        args.complete_cur = True
        self.assertRaises(InvalidArgException, zdd.do_zdd, args)
