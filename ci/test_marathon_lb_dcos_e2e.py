#!python3

import contextlib
import json
import logging
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from dcos_e2e import cluster
from dcos_e2e import node
from dcos_test_utils import helpers as dcos_helpers
from dcos_test_utils import iam as dcos_iam
from dcos_test_utils import enterprise as dcos_ee_api
from dcos_test_utils import dcos_api
from dcos_test_utils import package

import dcos_installer_tools
import pytest

import test_marathon_lb


DCOS_E2E_BACKEND = 'DCOS_E2E_BACKEND'
DCOS_E2E_CLUSTER_ID = 'DCOS_E2E_CLUSTER_ID'
DCOS_E2E_NODE_TRANSPORT = 'DCOS_E2E_NODE_TRANSPORT'
DCOS_LOGIN_UNAME = 'DCOS_LOGIN_UNAME'
DCOS_LOGIN_PW = 'DCOS_LOGIN_PW'

BACKEND_AWS = 'aws'
BACKEND_DOCKER = 'docker'
BACKEND_VAGRANT = 'vagrant'

MARATHON_LB_IMAGE = os.environ.get('MARATHON_LB_IMAGE',
                                   'marathon-lb:latest')
MARATHON_LB_VERSION = os.environ.get('MARATHON_LB_VERSION',
                                     'dev')

OSS = 'oss'
ENTERPRISE = 'enterprise'
VARIANTS = {OSS: dcos_installer_tools.DCOSVariant.OSS,
            ENTERPRISE: dcos_installer_tools.DCOSVariant.ENTERPRISE}
VARIANT_VALUES = dict((value.value, value) for value in VARIANTS.values())


logging.captureWarnings(True)


# NOTE(jkoelker) Define some helpers that should eventually be upstreamed
class Package(package.Cosmos):
    def render(self, name, options=None, version=None):
        params = {'packageName': name}

        if version:
            params['packageVersion'] = version

        if options:
            params['options'] = options

        self._update_headers('render',
                             request_version=1,
                             response_version=1)
        return self._post('/render', params).json().get('marathonJson')


class Secrets(dcos_helpers.ApiClientSession):
    def __init__(self, default_url: dcos_helpers.Url, session=None):
        super().__init__(default_url)
        if session:
            self.session = session

    def list_stores(self):
        r = self.get('/store')
        r.raise_for_status()
        return r.json()['array']

    def list_secrets(self, store, path='/'):
        params = {'list': True}
        r = self.get(self.secret_uri(store, path), params=params)
        r.raise_for_status()
        return r.json()['array']

    def create_secret(self, path, value, store='default'):
        headers = None
        data = None

        if not isinstance(value, (str, bytes)):
            value = json.dumps(value,
                               sort_keys=True,
                               indent=None,
                               ensure_ascii=False,
                               separators=(',', ':'))

        json_value = {'value': value}

        if isinstance(value, bytes):
            headers = {'Content-Type': 'application/octet-stream'}
            data = value
            json_value = None

        return self.put(self.secret_uri(store, path),
                        json=json_value,
                        data=data,
                        headers=headers)

    def delete_secret(self, path, store='default'):
        return self.delete(self.secret_uri(store, path))

    @staticmethod
    def secret_uri(store, path):
        if not path.startswith('/'):
            path = '/' + path
        return '/secret/{}{}'.format(store, path)


def add_user_to_group(self, user, group):
    return self.put('/groups/{}/users/{}'.format(group, user))


def delete_user_from_group(self, user, group):
    if not self.user_in_group(user, group):
        return

    return self.delete('/groups/{}/users/{}'.format(group, user))


def list_group_users(self, group):
    r = self.get('/groups/{}/users'.format(group))
    r.raise_for_status()
    return r.json()['array']


def user_in_group(self, user, group):
    return user in [a['user']['uid']
                    for a in self.list_group_users(group)]


# NOTE(jkoelker) Monkey patch in our helpers
dcos_api.DcosApiSession.package = property(
        lambda s: Package(default_url=s.default_url.copy(path='package'),
                          session=s.copy().session))
dcos_api.DcosApiSession.secrets = property(
        lambda s: Secrets(
            default_url=s.default_url.copy(path='secrets/v1'),
            session=s.copy().session))
dcos_ee_api.EnterpriseApiSession.secrets = property(
        lambda s: Secrets(
            default_url=s.default_url.copy(path='secrets/v1'),
            session=s.copy().session))
dcos_iam.Iam.add_user_to_group = add_user_to_group
dcos_iam.Iam.delete_user_from_group = delete_user_from_group
dcos_iam.Iam.list_group_users = list_group_users
dcos_iam.Iam.user_in_group = user_in_group


class Cluster(cluster.Cluster):
    _USER_ZKCLI_CMD = (
        '.',
        '/opt/mesosphere/environment.export',
        '&&',
        'zkCli.sh',
        '-server',
        '"zk-1.zk:2181,zk-2.zk:2181,zk-3.zk:2181,zk-4.zk:2181,'
        'zk-5.zk:2181"'
    )
    _USER_OSS_EMAIL = 'albert@bekstil.net'
    _USER_OSS_ZK_PATH = '/dcos/users/{}'.format(_USER_OSS_EMAIL)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._variant = dcos_installer_tools.DCOSVariant.OSS

    @property
    def _any_master(self):
        return next(iter(self.masters))

    def _any_master_run(self, cmd, *args, **kwargs):
        return self._any_master.run(list(cmd), *args, **kwargs)

    @property
    def _oss_user_exists(self):
        cmd = self._USER_ZKCLI_CMD + ('get',
                                      self._USER_OSS_ZK_PATH)
        output = self._any_master_run(cmd, shell=True)
        stdout = output.stdout.decode()

        if stdout.strip().split('\n')[-1] == self._USER_OSS_EMAIL:
            return True

        return False

    def _create_oss_user(self):
        if self._oss_user_exists:
            return

        cmd = self._USER_ZKCLI_CMD + ('create',
                                      self._USER_OSS_ZK_PATH,
                                      self._USER_OSS_EMAIL)
        self._any_master_run(cmd, shell=True)

    def _delete_oss_user(self):
        cmd = self._USER_ZKCLI_CMD + ('delete', self._USER_OSS_ZK_PATH)
        self._any_master_run(cmd, shell=True)

    def _enterprise_session(self):
        cmd = ('cat', '/opt/mesosphere/etc/bootstrap-config.json')
        config_result = self._any_master_run(cmd)
        config = json.loads(config_result.stdout.decode())
        ssl_enabled = config['ssl_enabled']

        scheme = 'https://' if ssl_enabled else 'http://'
        dcos_url = scheme + str(self._any_master.public_ip_address)
        api = dcos_ee_api.EnterpriseApiSession(
            dcos_url=dcos_url,
            masters=[str(n.public_ip_address) for n in self.masters],
            slaves=[str(n.public_ip_address) for n in self.agents],
            public_slaves=[
                str(n.public_ip_address) for n in self.public_agents
            ],
            auth_user=dcos_api.DcosUser(credentials=self.credentials),
        )

        if api.ssl_enabled:
            api.set_ca_cert()
        api.login_default_user()
        api.set_initial_resource_ids()

        return api

    def _oss_session(self):
        api = dcos_api.DcosApiSession(
            dcos_url='http://{}'.format(self._any_master.public_ip_address),
            masters=[str(n.public_ip_address) for n in self.masters],
            slaves=[str(n.public_ip_address) for n in self.agents],
            public_slaves=[
                str(n.public_ip_address) for n in self.public_agents
            ],
            auth_user=dcos_api.DcosUser(credentials=self.credentials),
        )

        api.login_default_user()
        return api

    def _session(self):
        if self.enterprise:
            return self._enterprise_session()

        return self._oss_session()

    @property
    def credentials(self):
        if self.enterprise:
            return {
                'uid': os.environ.get(DCOS_LOGIN_UNAME, 'admin'),
                'password': os.environ.get(DCOS_LOGIN_PW, 'admin')
            }

        return dcos_helpers.CI_CREDENTIALS

    @property
    def enterprise(self):
        return self._variant == dcos_installer_tools.DCOSVariant.ENTERPRISE

    @property
    def oss(self):
        return self._variant == dcos_installer_tools.DCOSVariant.OSS

    @property
    def variant(self):
        return self._variant

    @variant.setter
    def variant(self, value):
        # NOTE(jkoelker) Hack becuase enums from vendored libraries
        #                are technically different
        if hasattr(value, 'value') and value.value in VARIANT_VALUES:
            value = VARIANT_VALUES[value.value]

        if value in VARIANTS:
            value = VARIANTS[value]

        if value not in dcos_installer_tools.DCOSVariant:
            msg = 'Expected one of {} or {} got {}'
            raise ValueError(msg.format(tuple(VARIANTS.keys()),
                                        dcos_installer_tools.DCOSVariant,
                                        value))

        self._variant = value

    def create_user(self):
        if self.enterprise:
            return

        self._create_oss_user()

    def delete_user(self):
        if self.enterprise:
            return

        self._delete_oss_user()

    def create_service_account(self, name, secret, description=None,
                               superuser=False):
        if not self.enterprise:
            return

        if description is None:
            description = '{} service account'.format(name)

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend())

        priv = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())

        pub = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        priv = priv.decode('ascii')
        pub = pub.decode('ascii')

        with self.session as session:
            iam = session.iam
            try:
                iam.create_service(name, pub, description)
            except AssertionError:
                iam.delete_service(name)
                iam.create_service(name, pub, description)

            if superuser:
                iam.add_user_to_group(name, 'superusers')

            login_endpoint = 'https://leader.mesos/{}/auth/login'

            # NOTE(jkoelker) override the login_endpoint to force it to
            #                use `leader.mesos` by default it is set
            #                to the dcos_url the sesion is created with
            sa_creds = iam.make_service_account_credentials(name, priv)
            sa_creds['login_endpoint'] = login_endpoint.format(
                                             iam.default_url.path)
            secret_ret = session.secrets.create_secret(secret, sa_creds)
            if secret_ret.status_code != 201:
                session.secrets.delete_secret(secret, store='default')
                session.secrets.create_secret(secret, sa_creds)

    def delete_service_account(self, name, secret):
        if not self.enterprise:
            return

        with self.session as session:
            iam = session.iam
            iam.delete_user_from_group(name, 'superusers')
            session.secrets.delete_secret(secret, store='default')
            iam.delete_service(name)

    @contextlib.contextmanager
    def service_account(self, name, secret, description=None,
                        superuser=False):
        try:
            yield self.create_service_account(name,
                                              secret,
                                              description,
                                              superuser)
        finally:
            self.delete_service_account(name, secret)

    @property
    @contextlib.contextmanager
    def session(self):
        with self.user:
            yield self._session()

    @property
    @contextlib.contextmanager
    def user(self):
        try:
            yield self.create_user()
        finally:
            self.delete_user()


def get_docker_cluster(cluster_id, transport, **kwargs):
    from dcos_e2e_cli.dcos_docker.commands import _common

    if cluster_id not in _common.existing_cluster_ids():
        return None

    cluster_containers = _common.ClusterContainers(cluster_id, transport)
    cluster = Cluster.from_nodes(
            masters=set(map(cluster_containers.to_node,
                            cluster_containers.masters)),
            agents=set(map(cluster_containers.to_node,
                           cluster_containers.agents)),
            public_agents=set(map(cluster_containers.to_node,
                                  cluster_containers.public_agents)))

    cluster.variant = cluster_containers.dcos_variant

    return cluster


def get_cluster():
    backend = os.environ.get(DCOS_E2E_BACKEND, BACKEND_DOCKER)
    cluster_id = os.environ.get(DCOS_E2E_CLUSTER_ID, 'default')

    if backend == BACKEND_AWS:
        return None

    if backend == BACKEND_VAGRANT:
        return None

    transport = os.environ.get(DCOS_E2E_NODE_TRANSPORT, 'docker-exec')

    if transport == 'ssh':
        transport = node.Transport.SSH
    else:
        transport = node.Transport.DOCKER_EXEC

    return get_docker_cluster(cluster_id, transport)


@pytest.fixture(scope='session')
def dcos_marathon_lb_session():
    '''Fixture to return `cluster.session` after deploying `marathon-lb`'''
    cluster = get_cluster()

    with cluster.session as session:
        options = {
            'marathon-lb': {
                'sysctl-params': ' '.join(
                    ['net.ipv4.tcp_fin_timeout=30',
                     'net.core.somaxconn=10000']),
            }
        }

        if cluster.enterprise:
            options['marathon-lb'].update({
                'secret_name': 'mlb-secret',
                'marathon-uri': 'https://master.mesos:8443',
                'strict-mode': True
            })

        with cluster.service_account('mlb-principal',
                                     'mlb-secret',
                                     superuser=True):
            app = session.package.render('marathon-lb', options=options)
            app['container']['docker']['image'] = MARATHON_LB_IMAGE
            app['labels']['DCOS_PACKAGE_VERSION'] = MARATHON_LB_VERSION

            with session.marathon.deploy_and_cleanup(app):
                yield session


@pytest.fixture(scope='session')
def agent_public_ip(dcos_marathon_lb_session):
    '''Fixture to return the first public agents ip address'''
    return dcos_marathon_lb_session.public_slaves[0]


@pytest.fixture(scope='session')
def dcos_version(dcos_marathon_lb_session):
    '''Fixture to return the first dcos version'''
    return dcos_marathon_lb_session.get_version()


@pytest.fixture(scope='session',
                params=(['backends/' + f
                         for f in os.listdir('backends')] +
                        ['backends_1.9/' + f
                         for f in os.listdir('backends_1.9')]))
def backend_app(request, dcos_version):
    if dcos_version.startswith('1.9.'):
        if not request.param.startswith('backends_1.9/'):
            return pytest.skip('Not a 1.9 backend')
        return test_marathon_lb.get_json(request.param)

    if request.param.startswith('backends_1.9/'):
        return pytest.skip('Not a 1.9 cluster')

    return test_marathon_lb.get_json(request.param)


@pytest.fixture(scope='session')
def app_deployment(dcos_marathon_lb_session, backend_app):
    session = dcos_marathon_lb_session
    with session.marathon.deploy_and_cleanup(backend_app,
                                             check_health=False):
        app_id = backend_app['id']
        backend_app['name'] = app_id[1:] if app_id[0] == '/' else app_id
        yield backend_app


@pytest.fixture(scope='session')
def app_port(app_deployment, agent_public_ip):
    return test_marathon_lb.get_app_port(app_deployment['name'],
                                         agent_public_ip)


def test_port(app_deployment, app_port):
    assert app_port == app_deployment["labels"]["HAPROXY_0_PORT"]


def test_response(app_deployment, app_port, agent_public_ip):
    (response,
     status_code) = test_marathon_lb.get_app_content(app_port,
                                                     agent_public_ip)
    assert status_code == 200
    assert response == app_deployment['name']
