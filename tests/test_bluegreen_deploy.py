import unittest
import bluegreen_deploy
import mock
import json


class Arguments:
    json = 'tests/1-nginx.json'
    force = False
    marathon = "http://marathon"
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


class TestBluegreenDeploy(unittest.TestCase):

    @mock.patch('requests.get',
                mock.Mock(side_effect=lambda k, auth:
                          MyResponse('tests/bluegreen_app_blue.json')))
    def test_simple(self):
        # This test just checks the output of the program against
        # some expected output
        from six import StringIO

        out = StringIO()
        bluegreen_deploy.process_json(Arguments(), out)
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
