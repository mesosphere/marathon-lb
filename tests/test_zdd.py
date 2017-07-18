import unittest
import json

import mock

import zdd
from zdd_exceptions import InvalidArgException


class Arguments:
    json = None
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


def _arg_cases():
    args1 = Arguments()
    args2 = Arguments()
    args1.json = 'tests/1-nginx.json'
    args2.json = 'tests/1-nginx-marathon1.5.json'
    return [args1, args2]


def _apps_cases():
    apps1 = json.loads(open('tests/zdd_app_blue.json').read())
    apps2 = json.loads(open('tests/zdd_app_blue_marathon1.5.json').read())
    return [apps1, apps2]


class TestBluegreenDeploy(unittest.TestCase):

    @mock.patch('zdd.scale_marathon_app_instances')
    def test_scale_new_app_instances_up_50_percent(self, mock):
        """When scaling new_app instances, increase instances by 50% of
           existing instances if we have not yet met or surpassed the amount
           of instances deployed by old_app
        """
        def run(args):
            args.initial_instances = 5
            new_app = {
                'instances': 10,
                'labels': {
                    'HAPROXY_DEPLOYMENT_TARGET_INSTANCES': 30
                }
            }
            old_app = {'instances': 30}
            zdd.scale_new_app_instances(args, new_app, old_app)
            mock.assert_called_with(
                args, new_app, 15)
        for a in _arg_cases():
            run(a)

    @mock.patch('zdd.scale_marathon_app_instances')
    def test_scale_new_app_instances_to_target(self, mock):
        """When scaling new instances up, if we have met or surpassed the
           amount of instances deployed for old_app, go right to our
           deployment target amount of instances for new_app
        """
        def run(args):
            new_app = {
                'instances': 10,
                'labels': {
                    'HAPROXY_DEPLOYMENT_TARGET_INSTANCES': 30
                }
            }
            old_app = {'instances': 8}
            args.initial_instances = 5
            zdd.scale_new_app_instances(args, new_app, old_app)
            mock.assert_called_with(
                args, new_app, 30)
        for a in _arg_cases():
            run(a)

    @mock.patch('zdd.scale_marathon_app_instances')
    def test_scale_new_app_instances_hybrid(self, mock):
        """When scaling new instances up, if we have met or surpassed the
           amount of instances deployed for old_app, go right to our
           deployment target amount of instances for new_app
        """
        def run(args):
            new_app = {
                'instances': 10,
                'labels': {
                    'HAPROXY_DEPLOYMENT_NEW_INSTANCES': 15,
                    'HAPROXY_DEPLOYMENT_TARGET_INSTANCES': 30
                }
            }
            old_app = {'instances': 20}
            args.initial_instances = 5
            zdd.scale_new_app_instances(args, new_app, old_app)
            mock.assert_called_with(
                args, new_app, 15)
        for a in _arg_cases():
            run(a)

    def test_find_drained_task_ids(self):
        def run(apps):
            listeners = _load_listeners()
            haproxy_instance_count = 2
            app = apps['apps'][0]
            results = zdd.find_drained_task_ids(app,
                                                listeners,
                                                haproxy_instance_count)
            assert app['tasks'][0]['id'] in results  # 2l's down, no sessions
            assert app['tasks'][1]['id'] not in results  # 1l up, 1down
            assert app['tasks'][2]['id'] not in results  # 2l's d, 1w/scur/qcur
        for a in _apps_cases():
            run(a)

    def test_find_draining_task_ids(self):
        def run(apps):
            listeners = _load_listeners()
            haproxy_instance_count = 2
            app = apps['apps'][0]
            results = zdd.find_draining_task_ids(app,
                                                 listeners,
                                                 haproxy_instance_count)
            assert app['tasks'][0]['id'] in results  # 2l's down, no sessions
            assert app['tasks'][1]['id'] not in results  # 1l up, 1 down
            assert app['tasks'][2]['id'] in results  # 2l's down, 1w/scur/qcur
        for a in _apps_cases():
            run(a)

    def test_get_svnames_from_tasks(self):
        def run(apps):
            tasks = apps['apps'][0]['tasks']
            task_svnames = zdd.get_svnames_from_tasks(apps, tasks)
            assert '10_0_6_25_16916' in task_svnames
            assert '10_0_6_25_31184' in task_svnames
            assert '10_0_6_25_23336' in task_svnames
        for a in _apps_cases():
            run(a)

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
        def run(args):
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
        for a in _arg_cases():
            run(a)

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
        def run(args):
            marathon_lb_urls = zdd.get_marathon_lb_urls(args)
            assert 'http://127.0.0.1:9090' in marathon_lb_urls
            assert 'http://127.0.0.2:9090' in marathon_lb_urls
            assert 'http://127.0.0.3:9090' not in marathon_lb_urls
        for a in _arg_cases():
            run(a)

    @mock.patch('requests.get',
                mock.Mock(side_effect=lambda k, auth:
                          MyResponse('tests/zdd_app_blue.json')))
    def test_simple(self):
        # This test just checks the output of the program against
        # some expected output
        from six import StringIO
        args = Arguments()
        args.json = 'tests/1-nginx.json'
        out = StringIO()
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
                          MyResponse('tests/zdd_app_blue_marathon1.5.json')))
    def test_simple_marathon15(self):
        # This test just checks the output of the program against
        # some expected output
        from six import StringIO
        args = Arguments()
        args.json = 'tests/1-nginx-marathon1.5.json'
        out = StringIO()
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
      "image": "brndnmtthws/nginx-echo-sleep"
    },
    "type": "DOCKER",
    "portMappings": [
        {
          "containerPort": 8080,
          "hostPort": 0,
          "servicePort": 10001
        }
      ]
  },
  "networks": [
    {
      "mode": "container/bridge"
    }
  ],
  "cpus": 0.1,
  "healthChecks": [
    {
      "gracePeriodSeconds": 15,
      "intervalSeconds": 3,
      "maxConsecutiveFailures": 10,
      "path": "/",
      "portIndex": 0,
      "protocol": "MESOS_HTTP",
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
        args = Arguments()
        args.json = 'tests/1-nginx.json'
        out = StringIO()
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
                          MyResponse('tests/zdd_app_blue_marathon1.5.json')))
    def test_hybrid_marathon15(self):
        # This test just checks the output of the program against
        # some expected output
        from six import StringIO
        args = Arguments()
        args.json = 'tests/1-nginx-marathon1.5.json'
        out = StringIO()
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
      "image": "brndnmtthws/nginx-echo-sleep"
    },
    "portMappings": [
      {
        "containerPort": 8080,
        "hostPort": 0,
        "servicePort": 10001
      }
    ],
    "type": "DOCKER"
  },
  "networks": [
    {
      "mode": "container/bridge"
    }
  ],
  "cpus": 0.1,
  "healthChecks": [
    {
      "gracePeriodSeconds": 15,
      "intervalSeconds": 3,
      "maxConsecutiveFailures": 10,
      "path": "/",
      "portIndex": 0,
      "protocol": "MESOS_HTTP",
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
        def run(args):
            args.complete_cur = True
            self.assertRaises(InvalidArgException, zdd.do_zdd, args)
        for a in _arg_cases():
            run(a)
