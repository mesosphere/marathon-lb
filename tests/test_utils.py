import unittest

from mock import Mock, patch

from common import cleanup_json

import utils
from utils import ServicePortAssigner


class TestUtils(unittest.TestCase):

    def test_get_task_ip_and_ports_ip_per_task(self):
        app = {
            "ipAddress": {
                "discovery": {
                    "ports": [{"number": 123}, {"number": 234}]
                }
            },
        }
        task = {
            "id": "testtaskid",
            "ipAddresses": [{"ipAddress": "1.2.3.4"}]
        }

        result = utils.get_task_ip_and_ports(app, task)
        expected = ("1.2.3.4", [123, 234])

        self.assertEquals(result, expected)

    def test_get_task_ip_and_ports_ip_per_task_no_ip(self):
        app = {
            "ipAddress": {
                "discovery": {
                    "ports": [{"number": 123}, {"number": 234}]
                }
            },
        }
        task = {
            "id": "testtaskid"
        }

        result = utils.get_task_ip_and_ports(app, task)
        expected = (None, None)

        self.assertEquals(result, expected)

    def test_get_task_ip_and_ports_ip_per_task_marathon13(self):
        app = {
            'ipAddress': {},
            'container': {
                'type': 'DOCKER',
                'docker': {
                    'network': 'USER',
                    'portMappings': [
                        {
                            'containerPort': 80,
                            'servicePort': 10000,
                        },
                        {
                            'containerPort': 81,
                            'servicePort': 10001,
                        },
                     ],
                },
            },
        }
        task = {
            "id": "testtaskid",
            "ipAddresses": [{"ipAddress": "1.2.3.4"}]
        }

        result = utils.get_task_ip_and_ports(app, task)
        expected = ("1.2.3.4", [80, 81])

        self.assertEquals(result, expected)

    def test_get_task_ip_and_ports_ip_per_task_no_ip_marathon13(self):
        app = {
            'ipAddress': {},
            'container': {
                'type': 'DOCKER',
                'docker': {
                    'network': 'USER',
                    'portMappings': [
                        {
                            'containerPort': 80,
                            'servicePort': 10000,
                        },
                        {
                            'containerPort': 81,
                            'servicePort': 10001,
                        },
                     ],
                },
            },
        }
        task = {
            "id": "testtaskid",
        }

        result = utils.get_task_ip_and_ports(app, task)
        expected = (None, None)

        self.assertEquals(result, expected)

    def test_get_task_ip_and_ports_ip_per_task_marathon15(self):
        app = {
            'container': {
                'type': 'DOCKER',
                'docker': {
                    'image': 'nginx'
                },
                'portMappings': [
                    {
                        'containerPort': 80,
                        'servicePort': 10000,
                    },
                    {
                        'containerPort': 81,
                        'servicePort': 10001,
                    },
                ]
            },
            'networks': [
                {
                    'mode': 'container',
                    'name': 'dcos'
                }
            ]
        }
        task = {
            "id": "testtaskid",
            "ipAddresses": [{"ipAddress": "1.2.3.4"}]
        }

        result = utils.get_task_ip_and_ports(app, task)
        expected = ("1.2.3.4", [80, 81])
        self.assertEquals(result, expected)

        task_no_ip = {
            "id": "testtaskid",
        }

        result = utils.get_task_ip_and_ports(app, task_no_ip)
        expected = (None, None)
        self.assertEquals(result, expected)

    def test_get_task_ip_and_ports_portmapping_null(self):
        app = {
            'ipAddress': {},
            'container': {
                'type': 'DOCKER',
                'docker': {
                    'network': 'USER',
                    'portMappings': [{
                    }]
                },
            },
        }
        task = {
            "id": "testtaskid",
        }

        result = utils.get_task_ip_and_ports(app, task)
        expected = (None, None)

        self.assertEquals(result, expected)

    def test_get_task_ip_and_ports_port_map(self):
        app = {}
        task = {
            "id": "testtaskid",
            "ports": [234, 345, 567],
            "host": "agent1"
        }

        with patch("utils.resolve_ip", return_value="1.2.3.4"):
            result = utils.get_task_ip_and_ports(app, task)
            expected = ("1.2.3.4", [234, 345, 567])

        self.assertEquals(result, expected)

    def test_get_task_ip_and_ports_port_map_no_ip(self):
        app = {}
        task = {
            "id": "testtaskid",
            "ports": [234, 345, 567],
            "host": "agent1"
        }

        with patch("utils.resolve_ip", return_value=None):
            result = utils.get_task_ip_and_ports(app, task)
            expected = (None, None)

            self.assertEquals(result, expected)


class TestServicePortAssigner(unittest.TestCase):

    def setUp(self):
        self.assigner = ServicePortAssigner()
        self.assigner.set_ports(10000, 10020)

    def test_no_assignment_ports_not_set(self):
        """
        Test that no assignments are made if the port values are not set.
        """
        assigner = ServicePortAssigner()
        app = _get_app(idx=1, num_ports=3, num_tasks=1)

        # No ports set
        self.assertEquals(assigner.get_service_ports(app), [])

    def test_not_ip_per_task(self):
        """
        Test a non-IP-per-task app returns the service ports defined in the
        app data.
        """
        app = _get_app(ip_per_task=False, inc_service_ports=True)
        self.assertEquals(self.assigner.get_service_ports(app),
                          [100, 101, 102])

    def test_ip_per_task_with_ports(self):
        """
        Test an IP-per-task app returns the service ports defined in the
        app data.
        """
        app = _get_app(ip_per_task=True, inc_service_ports=True)
        self.assertEquals(self.assigner.get_service_ports(app),
                          [100, 101, 102])

    def test_ip_per_task_no_clash(self):
        """
        Check that the same ports are assigned are assigned for task-per-IP
        apps and are based on the number of host ports but not the actual
        ports themselves.
        """
        # When assigning a single port for apps with index 1 and 2 there are
        # no clashes.
        app1 = _get_app(idx=1, num_ports=1, num_tasks=1)
        app2 = _get_app(idx=2, num_ports=1, num_tasks=1)

        # Store the ports assigned for app1 and app2
        ports1 = self.assigner.get_service_ports(app1)
        ports2 = self.assigner.get_service_ports(app2)

        # Check we get returned the same ports.
        self.assertEquals(ports2, self.assigner.get_service_ports(app2))
        self.assertEquals(ports1, self.assigner.get_service_ports(app1))

        # Now reset the assigner, and assign in a different order.  Check the
        # ports are still the same.
        self.assigner.reset()
        self.assertEquals(ports2, self.assigner.get_service_ports(app2))
        self.assertEquals(ports1, self.assigner.get_service_ports(app1))

    def test_ip_per_task_clash(self):
        """
        Check that the same ports will not be assigned if there are clashes
        and we assign in a different order.
        """
        # When assigning 5 ports for apps with index 1 and 3 there are
        # clashes.
        app1 = _get_app(idx=1, num_ports=5, num_tasks=1)
        app2 = _get_app(idx=3, num_ports=5, num_tasks=1)

        # Store the ports assigned for app1 and app2
        ports1 = self.assigner.get_service_ports(app1)
        ports2 = self.assigner.get_service_ports(app2)

        # Check we get returned the same ports.
        self.assertEquals(ports2, self.assigner.get_service_ports(app2))
        self.assertEquals(ports1, self.assigner.get_service_ports(app1))

        # Now reset the assigner, and assign in a different order.  Check the
        # ports are not the same.
        self.assigner.reset()
        self.assertNotEquals(ports2, self.assigner.get_service_ports(app2))
        self.assertNotEquals(ports1, self.assigner.get_service_ports(app1))

    def test_ip_per_task_max_clash(self):
        """
        Check that ports are assigned by linear scan when we max out the
        clashes.
        """
        app = _get_app(idx=1, num_ports=10, num_tasks=1)

        # Mock out the hashlib functions so that all hashes return 0.
        sha1 = Mock()
        sha1.hexdigest.return_value = "0" * 64
        with patch("hashlib.sha1", return_value=sha1):
            ports = self.assigner.get_service_ports(app)
        self.assertEquals(ports, list(range(10000, 10010)))

    def test_ip_per_task_exhausted(self):
        """
        Check that ports are returned as None when the ports list is
        exhausted.
        """
        # Create an app with 2 more discovery ports than we are able to
        # allocate.  Check the last two ports are unassigned, and check all
        # ports are allocated from the correct range.
        app = _get_app(idx=1, num_ports=24, num_tasks=1)
        ports = self.assigner.get_service_ports(app)
        self.assertEquals(ports[-3:], [None] * 3)
        self.assertEquals(sorted(ports[:-3]), list(range(10000, 10021)))

    def test_ip_per_task_marathon13(self):
        app = {
            'ipAddress': {},
            'container': {
                'type': 'DOCKER',
                'docker': {
                    'network': 'USER',
                    'portMappings': [
                        {
                            'containerPort': 80,
                            'servicePort': 10000,
                        },
                        {
                            'containerPort': 81,
                            'servicePort': 10001,
                        },
                     ],
                },
            },
            'tasks': [{
                "id": "testtaskid",
                "ipAddresses": [{"ipAddress": "1.2.3.4"}]
            }],
        }
        self.assertEquals(self.assigner.get_service_ports(app),
                          [10000, 10001])

    def test_ip_per_task_marathon15(self):
        app = {
            'container': {
                'type': 'DOCKER',
                'docker': {
                    'image': 'nginx'
                },
                'portMappings': [
                    {
                        'containerPort': 80,
                        'servicePort': 10000,
                    },
                    {
                        'containerPort': 81,
                        'servicePort': 10001,
                    },
                ],
            },
            'networks': [
                {
                    'mode': 'container',
                    'name': 'dcos'
                }
            ],
            'tasks': [{
                "id": "testtaskid",
                "ipAddresses": [{"ipAddress": "1.2.3.4"}]
            }],
        }
        self.assertEquals(self.assigner.get_service_ports(app),
                          [10000, 10001])

    def test_ip_per_task_portMappings_empty(self):
        app = {
            'ipAddress': {
                'networkName': 'testnet',
                'discovery': {
                    'ports': []
                }
            },
            'container': {
                'type': 'DOCKER',
                'docker': {
                    'network': 'USER',
                    'portMappings': [],
                }
            },
            'tasks': [
                {
                    'id': 'testtaskid',
                    'ipAddresses': [{'ipAddress': '1.2.3.4'}],
                    'ports': [],
                    'host': '4.3.2.1'
                }
            ]
        }
        self.assertEquals(self.assigner.get_service_ports(app), [])

    def test_ip_per_task_portMappings_null(self):
        app = {
            'ipAddress': {},
            'container': {
                'type': 'DOCKER',
                'docker': {
                    'network': 'USER',
                    'portMappings': None,
                },
            },
            'tasks': [{
                "id": "testtaskid",
                "ipAddresses": [{"ipAddress": "1.2.3.4"}]
            }],
            "portDefinitions": [
                {
                    'port': 10000,
                },
                {
                    'port': 10001,
                },
            ],
        }
        # Calling cleanup_json because all entrypoints to get_service_ports
        # also call cleanup_json, so None isn't expected at runtime
        self.assertEquals(self.assigner.get_service_ports(cleanup_json(app)),
                          [10000, 10001])

    def test_ip_per_task_portMappings_null_marathon15(self):
        app = {
            'container': {
                'type': 'DOCKER',
                'docker': {
                    'image': 'nginx'
                },
                'portMappings': None
            },
            'networks': [
                {
                    'mode': 'container',
                    'name': 'dcos'
                }
            ],
            'tasks': [{
                "id": "testtaskid",
                "ipAddresses": [{"ipAddress": "1.2.3.4"}]
            }],
        }
        # Calling cleanup_json because all entrypoints to get_service_ports
        # also call cleanup_json, so None isn't expected at runtime
        self.assertEquals(self.assigner.get_service_ports(cleanup_json(app)),
                          [])


def _get_app(idx=1, num_ports=3, num_tasks=1, ip_per_task=True,
             inc_service_ports=False):
    app = {
        "id": "app-%d" % idx,
        "tasks": [_get_task(idx*10 + idx2) for idx2 in range(num_tasks)],
        "portDefinitions": [],
        "ipAddress": None,
    }

    if inc_service_ports:
        app["portDefinitions"] = \
          [{'port': p} for p in list(range(100, 100 + num_ports))]

    if ip_per_task:
        app["ipAddress"] = {
            "discovery": {
                "ports": [
                    {"number": port} for port in range(500, 500 + num_ports)
                ]
            }
        }

    return app


def _get_task(idx):
    return {
        "id": "task-%d" % idx,
        "ipAddresses": [{"ipAddress": "1.2.3.4"}]
    }
