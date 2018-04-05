import json
import logging
import os
import pytest
import re
import requests
import retrying
import shakedown

import dcos

from dcos import marathon

log = logging.getLogger(__name__)


def get_json(file_name):
  """ Retrieves json app definitions for Docker and UCR backends.  
  """
  with open(file_name) as f:
    return json.load(f)


def find_app_port(config, app_name):
  """ Finds the port associated with the app in haproxy_getconfig through regex pattern matching.
  """
  pattern = re.search(r'{0}(.+?)\n  bind .+:\d+'.format(app_name), config)
  return pattern.group()[-5:]


@retrying.retry(stop_max_delay=10000)
def get_app_port(app_name):
  """ Returns the port that the app is configured on.
  """
  request_haproxy_getconfig = requests.get('http://{}:9090/_haproxy_getconfig'.format(os.environ['PUBLIC_AGENT_IP']))
  port = find_app_port(request_haproxy_getconfig.content.decode("utf-8"), app_name)
  return port


@retrying.retry(stop_max_delay=10000)
def get_app_content(app_port):
  """ Returns the content of the app.
  """
  request_app_port = requests.get('http://{}:{}'.format(os.environ['PUBLIC_AGENT_IP'], app_port))
  return (request_app_port.content.decode("utf-8").rstrip(), request_app_port.status_code)


def test_backends():
  """ Tests Marathon-lb against a number of Docker and UCR backends. 
  All backends are defined in the following directories: backends/ & backends_1.9/.
  The test retrieves the port to which the apps are configured against from _haproxy_getconfig. 
  Each app is configured to display its app_id as content if launched healthy. 
  The test then asserts to check whether the text response matches the expected test response.
  """

  if os.environ['DCOS_VERSION'] == '1.9':
    app_defs = [get_json('backends_1.9/' + filename) for filename in os.listdir('backends_1.9/')]
  else:
    app_defs = [get_json('backends/' + filename) for filename in os.listdir('backends/')]

  for app_def in app_defs:
    app_id = app_def['id']
    
    app_name = app_id[1:] if app_id[0] == '/' else app_id
    print(app_name)

    client = marathon.create_client()
    client.add_app(app_def)

    shakedown.deployment_wait(app_id=app_id)
    app = client.get_app(app_id)
    assert app['tasksRunning'] == app_def['instances'], "The number of running tasks is {}, but {} were expected.".format(app["tasksRunning"], app_def['instances'])
    log.info('The number of running tasks for {appname} is {number}'.format(appname=app_name, number=app['tasksRunning']))

    port = get_app_port(app_name)
    expected_port = app_def["labels"]["HAPROXY_0_PORT"]
    port_binding_err_msg = "{} is bound to {}, when it should be bound to {}.".format(app_name, port, expected_port)
    assert port == expected_port, port_binding_err_msg
    log.info('{appname} is bound to port {number}.'.format(appname=app_name, number=port))

    text_response, status_code = get_app_content(port)
    expected_text_response = app_name
    text_response_err_msg = "Text response is {}, when it should be {}.".format(text_response, expected_text_response)
    if status_code == 200:  
      assert text_response == expected_text_response, text_response_err_msg
    log.info('Text response is {content}.'.format(content=text_response))
