#!/usr/bin/env python3

import argparse
import csv
import json
import logging
import math
import socket
import subprocess
import sys
import time
import traceback
from datetime import datetime
from collections import namedtuple

import requests
import six.moves.urllib as urllib

from common import (get_marathon_auth_params, set_logging_args,
                    set_marathon_auth_args, setup_logging, cleanup_json)
from utils import (get_task_ip_and_ports, get_app_port_mappings)
from zdd_exceptions import (
    AppCreateException, AppDeleteException, AppScaleException,
    InvalidArgException, MarathonEndpointException,
    MarathonLbEndpointException, MissingFieldException)


logger = logging.getLogger('zdd')


def query_yes_no(question, default="yes"):
    # Thanks stackoverflow:
    # https://stackoverflow.com/questions/3041986/python-command-line-yes-no-input
    """Ask a yes/no question via input() and return their answer.

    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).

    The "answer" return value is True for "yes" or False for "no".
    """
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")


def marathon_get_request(args, path):
    url = args.marathon + path
    try:
        response = requests.get(url, auth=get_marathon_auth_params(args))
        response.raise_for_status()
    except requests.exceptions.RequestException:
        raise MarathonEndpointException(
            "Error while querying marathon", url, traceback.format_exc())
    return response


def list_marathon_apps(args):
    response = marathon_get_request(args, "/v2/apps")
    return cleanup_json(response.json())['apps']


def fetch_marathon_app(args, app_id):
    response = marathon_get_request(args, "/v2/apps" + app_id)
    return cleanup_json(response.json())['app']


def _get_alias_records(hostname):
    """Return all IPv4 A records for a given hostname
    """
    return socket.gethostbyname_ex(hostname)[2]


def _unparse_url_alias(url, addr):
    """Reassemble a url object into a string but with a new address
    """
    return urllib.parse.urlunparse((url[0],
                                    addr + ":" + str(url.port),
                                    url[2],
                                    url[3],
                                    url[4],
                                    url[5]))


def get_marathon_lb_urls(args):
    """Return a list of urls for all Aliases of the
       marathon_lb url passed in as an argument
    """
    url = urllib.parse.urlparse(args.marathon_lb)
    addrs = _get_alias_records(url.hostname)
    return [_unparse_url_alias(url, addr) for addr in addrs]


def fetch_haproxy_pids(haproxy_url):
    try:
        response = requests.get(haproxy_url + "/_haproxy_getpids")
        response.raise_for_status()
    except requests.exceptions.RequestException:
        logger.exception("Caught exception when retrieving HAProxy"
                         " pids from " + haproxy_url)
        raise

    return response.text.split()


def check_haproxy_reloading(haproxy_url):
    """Return False if haproxy has only one pid, it is not reloading.
       Return True if we catch an exception while making a request to
       haproxy or if more than one pid is returned
    """
    try:
        pids = fetch_haproxy_pids(haproxy_url)
    except requests.exceptions.RequestException:
        # Assume reloading on any error, this should be caught with a timeout
        return True

    if len(pids) > 1:
        logger.info("Waiting for {} pids on {}".format(len(pids), haproxy_url))
        return True

    return False


def any_marathon_lb_reloading(marathon_lb_urls):
    return any([check_haproxy_reloading(url) for url in marathon_lb_urls])


def fetch_haproxy_stats(haproxy_url):
    try:
        response = requests.get(haproxy_url + "/haproxy?stats;csv")
        response.raise_for_status()
    except requests.exceptions.RequestException:
        logger.exception("Caught exception when retrieving HAProxy"
                         " stats from " + haproxy_url)
        raise

    return response.text


def fetch_combined_haproxy_stats(marathon_lb_urls):
    raw = ''.join([fetch_haproxy_stats(url) for url in marathon_lb_urls])
    return parse_haproxy_stats(raw)


def parse_haproxy_stats(csv_data):
    rows = csv_data.splitlines()
    headings = rows.pop(0).lstrip('# ').rstrip(',\n').split(',')
    csv_reader = csv.reader(rows, delimiter=',', quotechar="'")

    Row = namedtuple('Row', headings)

    return [Row(*row[0:-1]) for row in csv_reader if row[0][0] != '#']


def get_deployment_label(app):
    return get_deployment_group(app) + "_" + app['labels']['HAPROXY_0_PORT']


def _if_app_listener(app, listener):
    return (listener.pxname == get_deployment_label(app) and
            listener.svname not in ['BACKEND', 'FRONTEND'])


def fetch_app_listeners(app, marathon_lb_urls):
    haproxy_stats = fetch_combined_haproxy_stats(marathon_lb_urls)
    return [l for l in haproxy_stats if _if_app_listener(app, l)]


def waiting_for_listeners(new_app, old_app, listeners, haproxy_count):
    listener_count = (len(listeners) / haproxy_count)
    return listener_count != new_app['instances'] + old_app['instances']


def get_deployment_target(app):
    if 'HAPROXY_DEPLOYMENT_TARGET_INSTANCES' in app['labels']:
        return int(app['labels']['HAPROXY_DEPLOYMENT_TARGET_INSTANCES'])
    else:
        return app['instances']


def get_new_instance_count(app):
    if 'HAPROXY_DEPLOYMENT_NEW_INSTANCES' in app['labels']:
        return int(app['labels']['HAPROXY_DEPLOYMENT_NEW_INSTANCES'])
    else:
        return 0


def waiting_for_up_listeners(app, listeners, haproxy_count):
    up_listeners = [l for l in listeners if l.status == 'UP']
    up_listener_count = (len(up_listeners) / haproxy_count)

    return up_listener_count < get_deployment_target(app)


def select_draining_listeners(listeners):
    return [l for l in listeners if l.status == 'MAINT']


def select_drained_listeners(listeners):
    draining_listeners = select_draining_listeners(listeners)
    return [l for l in draining_listeners if not _has_pending_requests(l)]


def get_svnames_from_task(app, task):
    prefix = task['host'].replace('.', '_')
    task_ip, _ = get_task_ip_and_ports(app, task)
    if task['host'] == task_ip:
        for port in task['ports']:
            yield('{}_{}'.format(prefix, port))
    else:
        for port in task['ports']:
            yield('{}_{}_{}'.format(prefix, task_ip.replace('.', '_'), port))


def get_svnames_from_tasks(app, tasks):
    svnames = []
    for task in tasks:
        svnames += get_svnames_from_task(app, task)
    return svnames


def _has_pending_requests(listener):
    return int(listener.qcur or 0) > 0 or int(listener.scur or 0) > 0


def is_hybrid_deployment(args, app):
    if (get_new_instance_count(app) != 0 and not args.complete_cur and
            not args.complete_prev):
        return True
    else:
        return False


def find_drained_task_ids(app, listeners, haproxy_count):
    """Return app tasks which have all haproxy listeners down and draining
       of any pending sessions or connections
    """
    tasks = zip(get_svnames_from_tasks(app, app['tasks']), app['tasks'])
    drained_listeners = select_drained_listeners(listeners)

    drained_task_ids = []
    for svname, task in tasks:
        task_listeners = [l for l in drained_listeners if l.svname == svname]
        if len(task_listeners) == haproxy_count:
            drained_task_ids.append(task['id'])

    return drained_task_ids


def find_draining_task_ids(app, listeners, haproxy_count):
    """Return app tasks which have all haproxy listeners draining
    """
    tasks = zip(get_svnames_from_tasks(app, app['tasks']), app['tasks'])
    draining_listeners = select_draining_listeners(listeners)

    draining_task_ids = []
    for svname, task in tasks:
        task_listeners = [l for l in draining_listeners if l.svname == svname]
        if len(task_listeners) == haproxy_count:
            draining_task_ids.append(task['id'])

    return draining_task_ids


def max_wait_not_exceeded(max_wait, timestamp):
    return time.time() - timestamp < max_wait


def find_tasks_to_kill(args, new_app, old_app, timestamp):
    marathon_lb_urls = get_marathon_lb_urls(args)
    haproxy_count = len(marathon_lb_urls)
    try:
        listeners = fetch_app_listeners(new_app, marathon_lb_urls)
    except requests.exceptions.RequestException:
        raise MarathonLbEndpointException(
            "Error while querying Marathon-LB",
            marathon_lb_urls,
            traceback.format_exc())
    while max_wait_not_exceeded(args.max_wait, timestamp):
        time.sleep(args.step_delay)

        logger.info("Existing app running {} instances, "
                    "new app running {} instances"
                    .format(old_app['instances'], new_app['instances']))

        if any_marathon_lb_reloading(marathon_lb_urls):
            continue

        try:
            listeners = fetch_app_listeners(new_app, marathon_lb_urls)
        except requests.exceptions.RequestException:
            # Restart loop if we hit an exception while loading listeners,
            # this may be normal behaviour
            continue

        logger.info("Found {} app listeners across {} HAProxy instances"
                    .format(len(listeners), haproxy_count))

        if waiting_for_listeners(new_app, old_app, listeners, haproxy_count):
            continue

        if waiting_for_up_listeners(new_app, listeners, haproxy_count):
            continue

        if waiting_for_drained_listeners(listeners):
            continue

        return find_drained_task_ids(old_app, listeners, haproxy_count)

    logger.info('Timed out waiting for tasks to fully drain, find any draining'
                ' tasks and continue with deployment...')

    return find_draining_task_ids(old_app, listeners, haproxy_count)


def deployment_in_progress(app):
    return len(app['deployments']) > 0


def execute_pre_kill_hook(args, old_app, tasks_to_kill, new_app):
    if args.pre_kill_hook is not None:
        logger.info("Calling pre-kill hook '{}'".format(args.pre_kill_hook))

        subprocess.check_call([args.pre_kill_hook,
                              json.dumps(old_app),
                              json.dumps(tasks_to_kill),
                              json.dumps(new_app)])


def swap_zdd_apps(args, new_app, old_app):
    func_args = (args, new_app, old_app)
    while True:
        res = _swap_zdd_apps(func_args[0], func_args[1], func_args[2])
        if isinstance(res, bool):
            return res
        func_args = res


def _swap_zdd_apps(args, new_app, old_app):
    old_app = fetch_marathon_app(args, old_app['id'])
    new_app = fetch_marathon_app(args, new_app['id'])

    if deployment_in_progress(new_app):
        time.sleep(args.step_delay)
        return args, new_app, old_app

    tasks_to_kill = find_tasks_to_kill(args, new_app, old_app, time.time())

    if ready_to_delete_old_app(args, new_app, old_app, tasks_to_kill):
        return safe_delete_app(args, old_app, new_app)

    if len(tasks_to_kill) > 0:
        execute_pre_kill_hook(args, old_app, tasks_to_kill, new_app)

        logger.info("There are {} draining listeners, "
                    "about to kill the following tasks:\n  - {}"
                    .format(len(tasks_to_kill),
                            "\n  - ".join(tasks_to_kill)))

        if args.force or query_yes_no("Continue?"):
            logger.info("Scaling down old app by {} instances"
                        .format(len(tasks_to_kill)))
            kill_marathon_tasks(args, tasks_to_kill)
        else:
            return False

    if is_hybrid_deployment(args, new_app):
        if new_app['instances'] < get_new_instance_count(new_app):
            scale_new_app_instances(args, new_app, old_app)
    else:
        if new_app['instances'] < get_deployment_target(new_app):
            scale_new_app_instances(args, new_app, old_app)

    return (args, new_app, old_app)


def ready_to_delete_old_app(args, new_app, old_app, draining_task_ids):
    new_instances = get_new_instance_count(new_app)
    if is_hybrid_deployment(args, new_app):
        return (int(new_app['instances']) == new_instances and
                int(old_app['instances']) == (
                    get_deployment_target(old_app) - new_instances))
    else:
        return (int(new_app['instances']) == get_deployment_target(new_app) and
                len(draining_task_ids) == int(old_app['instances']))


def waiting_for_drained_listeners(listeners):
    return len(select_drained_listeners(listeners)) < 1


def scale_new_app_instances(args, new_app, old_app):
    """Scale the app by 50% of its existing instances until we
       meet or surpass instances deployed for old_app.
       At which point go right to the new_app deployment target
    """
    instances = (math.floor(new_app['instances'] +
                 (new_app['instances'] + 1) / 2))
    if is_hybrid_deployment(args, new_app):
        if instances > get_new_instance_count(new_app):
            instances = get_new_instance_count(new_app)
    else:
        if instances >= old_app['instances']:
            instances = get_deployment_target(new_app)

    logger.info("Scaling new app up to {} instances".format(instances))
    return scale_marathon_app_instances(args, new_app, instances)


def safe_delete_app(args, app, new_app):
    if is_hybrid_deployment(args, new_app):
        logger.info("Not deleting old app, as its hybrid configuration")
        return True
    else:
        logger.info("About to delete old app {}".format(app['id']))
        if args.force or query_yes_no("Continue?"):
            delete_marathon_app(args, app)
            return True
        else:
            return False


def delete_marathon_app(args, app):
    url = args.marathon + '/v2/apps' + app['id']
    try:
        response = requests.delete(url,
                                   auth=get_marathon_auth_params(args))
        response.raise_for_status()
    except requests.exceptions.RequestException:
        raise AppDeleteException(
            "Error while deleting the app", url, traceback.format_exc())
    return response


def kill_marathon_tasks(args, ids):
    data = json.dumps({'ids': ids})
    url = args.marathon + "/v2/tasks/delete?scale=true"
    headers = {'Content-Type': 'application/json'}
    try:
        response = requests.post(url, headers=headers, data=data,
                                 auth=get_marathon_auth_params(args))
        response.raise_for_status()
    except requests.exceptions.RequestException:
        # This is App Scale Down, so raising AppScale Exception
        raise AppScaleException(
            "Error while scaling the app", url, data, traceback.format_exc())
    return response


def scale_marathon_app_instances(args, app, instances):
    url = args.marathon + "/v2/apps" + app['id']
    data = json.dumps({'instances': instances})
    headers = {'Content-Type': 'application/json'}
    try:
        response = requests.put(url, headers=headers, data=data,
                                auth=get_marathon_auth_params(args))
        response.raise_for_status()
    except requests.exceptions.RequestException:
        # This is App Scale Up, so raising AppScale Exception
        raise AppScaleException(
            "Error while scaling the app", url, data, traceback.format_exc())
    return response


def deploy_marathon_app(args, app):
    url = args.marathon + "/v2/apps"
    data = json.dumps(app)
    headers = {'Content-Type': 'application/json'}
    try:
        response = requests.post(url, headers=headers, data=data,
                                 auth=get_marathon_auth_params(args))
        response.raise_for_status()
    except requests.exceptions.RequestException:
        raise AppCreateException(
            "Error while creating the app", url, data, traceback.format_exc())
    return response


def get_service_port(app):
    portMappings = get_app_port_mappings(app)
    if len(portMappings) > 0:
        servicePort = portMappings[0].get('servicePort')
        if servicePort:
            return servicePort
    portDefinitions = app.get('portDefinitions', [])
    if len(portDefinitions) > 0:
        port = ['portDefinitions'][0].get('port')
        if port:
            return int(port)
    ports = app.get('ports', [])
    if len(ports) > 0:
        return int(ports[0])
    raise MissingFieldException("App doesn't contain a service port",
                                'container.portMappings')


def set_service_port(app, servicePort):
    container = app.get('container', {})
    portMappings = container.get('docker', {}).get('portMappings', [])
    if len(portMappings) > 0:
        app['container']['docker']['portMappings'][0]['servicePort'] =\
            int(servicePort)
        return app
    portMappings = container.get('portMappings', [])
    if len(portMappings) > 0:
        app['container']['portMappings'][0]['servicePort'] =\
            int(servicePort)
        return app
    portDefinitions = app.get('portDefinitions', [])
    if len(portDefinitions) > 0:
        app['portDefinitions'][0]['port'] = int(servicePort)
        return app
    app['ports'][0] = int(servicePort)
    return app


def validate_app(app):
    if app['id'] is None:
        raise MissingFieldException("App doesn't contain a valid App ID",
                                    'id')
    if 'labels' not in app:
        raise MissingFieldException("No labels found. Please define the"
                                    " HAPROXY_DEPLOYMENT_GROUP label",
                                    'label')
    if 'HAPROXY_DEPLOYMENT_GROUP' not in app['labels']:
        raise MissingFieldException("Please define the "
                                    "HAPROXY_DEPLOYMENT_GROUP label",
                                    'HAPROXY_DEPLOYMENT_GROUP')
    if 'HAPROXY_DEPLOYMENT_ALT_PORT' not in app['labels']:
        raise MissingFieldException("Please define the "
                                    "HAPROXY_DEPLOYMENT_ALT_PORT label",
                                    'HAPROXY_DEPLOYMENT_ALT_PORT')


def set_app_ids(app, colour):
    app['labels']['HAPROXY_APP_ID'] = app['id']
    app['id'] = app['id'] + '-' + colour

    if app['id'][0] != '/':
        app['id'] = '/' + app['id']

    return app


def set_service_ports(app, servicePort):
    app['labels']['HAPROXY_0_PORT'] = str(get_service_port(app))
    return set_service_port(app, servicePort)


def select_next_port(app):
    alt_port = int(app['labels']['HAPROXY_DEPLOYMENT_ALT_PORT'])
    if 'ports' in app:
        if int(app['ports'][0]) == alt_port:
            return int(app['labels']['HAPROXY_0_PORT'])
    return alt_port


def select_next_colour(app):
    if app.get('labels', {}).get('HAPROXY_DEPLOYMENT_COLOUR') == 'blue':
        return 'green'
    else:
        return 'blue'


def sort_deploys(apps):
    return sorted(apps, key=lambda a: a.get('labels', {})
                  .get('HAPROXY_DEPLOYMENT_STARTED_AT', '0'))


def select_last_deploy(apps):
    return sort_deploys(apps).pop()


def select_last_two_deploys(apps):
    return sort_deploys(apps)[:-3:-1]


def get_deployment_group(app):
    return app.get('labels', {}).get('HAPROXY_DEPLOYMENT_GROUP')


def fetch_previous_deploys(args, app):
    apps = list_marathon_apps(args)
    app_deployment_group = get_deployment_group(app)
    return [a for a in apps if get_deployment_group(a) == app_deployment_group]


def prepare_deploy(args, previous_deploys, app):
    """ Return a blue or a green version of `app` based on preexisting deploys
    """
    if len(previous_deploys) > 0:
        last_deploy = select_last_deploy(previous_deploys)

        next_colour = select_next_colour(last_deploy)
        next_port = select_next_port(last_deploy)
        deployment_target_instances = last_deploy['instances']
        if args.new_instances > deployment_target_instances:
            args.new_instances = deployment_target_instances
        if args.new_instances and args.new_instances > 0:
            if args.initial_instances > args.new_instances:
                app['instances'] = args.new_instances
            else:
                app['instances'] = args.initial_instances
        else:
            if args.initial_instances > deployment_target_instances:
                app['instances'] = deployment_target_instances
            else:
                app['instances'] = args.initial_instances
        app['labels']['HAPROXY_DEPLOYMENT_NEW_INSTANCES'] = str(
            args.new_instances)
    else:
        next_colour = 'blue'
        next_port = get_service_port(app)
        deployment_target_instances = app['instances']
        app['labels']['HAPROXY_DEPLOYMENT_NEW_INSTANCES'] = "0"

    app = set_app_ids(app, next_colour)
    app = set_service_ports(app, next_port)
    app['labels']['HAPROXY_DEPLOYMENT_TARGET_INSTANCES'] = \
        str(deployment_target_instances)
    app['labels']['HAPROXY_DEPLOYMENT_COLOUR'] = next_colour
    app['labels']['HAPROXY_DEPLOYMENT_STARTED_AT'] = datetime.now().isoformat()

    return app


def load_app_json(args):
    with open(args.json) as content_file:
        return cleanup_json(json.load(content_file))


def safe_resume_deploy(args, previous_deploys):
    if args.complete_cur:
        logger.info("Converting all instances to current config")
        new_app, old_app = select_last_two_deploys(previous_deploys)
        logger.info("Current config color is %s" % new_app[
            'labels']['HAPROXY_DEPLOYMENT_COLOUR'])
        logger.info("Considering %s color as existing app"
                    % old_app['labels']['HAPROXY_DEPLOYMENT_COLOUR'] +
                    " and %s color as new app"
                    % new_app['labels']['HAPROXY_DEPLOYMENT_COLOUR'])
        return swap_zdd_apps(args, new_app, old_app)
    elif args.complete_prev:
        logger.info("Converting all instances to previous config")
        old_app, new_app = select_last_two_deploys(previous_deploys)
        logger.info("Previous config color is %s" % new_app[
            'labels']['HAPROXY_DEPLOYMENT_COLOUR'])
        logger.info("Considering %s color as existing app"
                    % old_app['labels']['HAPROXY_DEPLOYMENT_COLOUR'] +
                    " and %s color as new app"
                    % new_app['labels']['HAPROXY_DEPLOYMENT_COLOUR'])
        return swap_zdd_apps(args, new_app, old_app)
    elif args.resume:
        logger.info("Found previous deployment, resuming")
        new_app, old_app = select_last_two_deploys(previous_deploys)
        return swap_zdd_apps(args, new_app, old_app)
    else:
        raise Exception("There appears to be an"
                        " existing deployment in progress")


def do_zdd(args, out=sys.stdout):
    app = load_app_json(args)
    validate_app(app)

    previous_deploys = fetch_previous_deploys(args, app)

    if len(previous_deploys) > 1:
        # There is a stuck deploy or hybrid deploy
        return safe_resume_deploy(args, previous_deploys)

    if args.complete_cur or args.complete_prev:
        raise InvalidArgException("Cannot use --complete-cur, --complete-prev"
                                  " flags when config is not hybrid")

    new_app = prepare_deploy(args, previous_deploys, app)

    logger.info('Final app definition:')
    out.write(json.dumps(new_app, sort_keys=True, indent=2))
    out.write("\n")

    if args.dry_run:
        return True

    if args.force or query_yes_no("Continue with deployment?"):
        deploy_marathon_app(args, new_app)

        if len(previous_deploys) == 0:
            # This was the first deploy, nothing to swap
            return True
        else:
            # This is a standard blue/green deploy, swap new app with old
            old_app = select_last_deploy(previous_deploys)
            return swap_zdd_apps(args, new_app, old_app)


def get_arg_parser():
    parser = argparse.ArgumentParser(
        description="Zero-downtime deployment orchestrator for marathon-lb",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--longhelp",
                        help="Print out configuration details",
                        action="store_true"
                        )
    parser.add_argument("--marathon", "-m",
                        help="[required] Marathon endpoint, eg. -m " +
                             "http://marathon1:8080"
                        )
    parser.add_argument("--marathon-lb", "-l",
                        help="[required] Marathon-lb stats endpoint, eg. -l " +
                             "http://marathon-lb.marathon.mesos:9090"
                        )

    parser.add_argument("--json", "-j",
                        help="[required] App JSON"
                        )
    parser.add_argument("--dry-run", "-d",
                        help="Perform a dry run",
                        action="store_true"
                        )
    parser.add_argument("--force", "-f",
                        help="Perform deployment un-prompted",
                        action="store_true"
                        )
    parser.add_argument("--step-delay", "-s",
                        help="Delay (in seconds) between each successive"
                        " deployment step",
                        type=int, default=5
                        )
    parser.add_argument("--initial-instances", "-i",
                        help="Initial number of app instances to launch."
                        " If this number is greater than total number of"
                        " existing instances, then this will be overridden"
                        " by the latter number",
                        type=int, default=1
                        )
    parser.add_argument("--resume", "-r",
                        help="Resume from a previous deployment",
                        action="store_true"
                        )
    parser.add_argument("--max-wait", "-w",
                        help="Maximum amount of time (in seconds) to wait"
                        " for HAProxy to drain connections",
                        type=int, default=300
                        )
    parser.add_argument("--new-instances", "-n",
                        help="Number of new instances to replace the existing"
                        " instances. This is for having instances of both blue"
                        " and green at the same time",
                        type=int, default=0)
    parser.add_argument("--complete-cur", "-c",
                        help="Change hybrid app entirely to"
                        " current (new) app's instances", action="store_true")
    parser.add_argument("--complete-prev", "-p",
                        help="Change hybrid app entirely to"
                        " previous (old) app's instances", action="store_true")
    parser.add_argument("--pre-kill-hook",
                        help="A path to an executable (such as a script) "
                        "which will be called before killing any tasks marked "
                        "for draining at each step. The script will be called "
                        "with 3 arguments (in JSON): the old app definition, "
                        "the list of tasks which will be killed, "
                        "and the new app definition. An exit "
                        "code of 0 indicates the deploy may continue. "
                        "If the hook returns a non-zero exit code, the deploy "
                        "will stop, and an operator must intervene."
                        )
    parser = set_logging_args(parser)
    parser = set_marathon_auth_args(parser)
    return parser


def set_request_retries():
    s = requests.Session()
    a = requests.adapters.HTTPAdapter(max_retries=3)
    s.mount('http://', a)


def process_arguments():
    # Process arguments
    arg_parser = get_arg_parser()
    args = arg_parser.parse_args()

    if args.longhelp:
        print(__doc__)
        sys.exit()
    # otherwise make sure that a Marathon URL was specified
    else:
        if args.marathon is None:
            arg_parser.error('argument --marathon/-m is required')
        if args.marathon_lb is None:
            arg_parser.error('argument --marathon-lb/-l is required')
        if args.json is None:
            arg_parser.error('argument --json/-j is required')

    return args


if __name__ == '__main__':
    args = process_arguments()
    set_request_retries()
    setup_logging(logger, args.syslog_socket, args.log_format, args.log_level)

    try:
        if do_zdd(args):
            sys.exit(0)
        else:
            sys.exit(1)
    except Exception as e:
        if hasattr(e, 'zdd_exit_status'):
            if hasattr(e, 'error'):
                logger.exception(str(e.error))
            else:
                logger.exception(traceback.print_exc())
            sys.exit(e.zdd_exit_status)
        else:
            # For Unknown Exceptions
            logger.exception(traceback.print_exc())
            sys.exit(2)
