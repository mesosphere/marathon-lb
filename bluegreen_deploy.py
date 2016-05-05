#!/usr/bin/env python3

from common import *
from datetime import datetime
from collections import namedtuple, defaultdict
from itertools import groupby

import argparse
import json
import requests
import csv
import time
import re
import math
import six.moves.urllib as urllib
import socket


logger = logging.getLogger('bluegreen_deploy')


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
    response = requests.get(url, auth=get_marathon_auth_params(args))
    response.raise_for_status()
    return response


def list_marathon_apps(args):
    response = marathon_get_request(args, "/v2/apps")
    return response.json()['apps']


def fetch_marathon_app(args, app_id):
    response = marathon_get_request(args, "/v2/apps" + app_id)
    return response.json()['app']


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
    return int(app['labels']['HAPROXY_DEPLOYMENT_TARGET_INSTANCES'])


def waiting_for_up_listeners(app, listeners, haproxy_count):
    up_listeners = [l for l in listeners if l.status == 'UP']
    up_listener_count = (len(up_listeners) / haproxy_count)

    return up_listener_count < get_deployment_target(app)


def _has_pending_requests(listener):
    return int(listener.qcur or 0) > 0 or int(listener.scur or 0) > 0


def select_drained_listeners(listeners):
    draining_listeners = [l for l in listeners if l.status == 'MAINT']
    return [l for l in draining_listeners if not _has_pending_requests(l)]


def get_svnames_from_task(task):
    prefix = task['host'].replace('.', '_')
    for port in task['ports']:
        yield(prefix + '_{}'.format(port))


def get_svnames_from_tasks(tasks):
    svnames = []
    for task in tasks:
        svnames += get_svnames_from_task(task)
    return svnames


def find_drained_task_ids(app, listeners, haproxy_count):
    """Return app tasks which have all haproxy listeners down and drained
       of any pending sessions or connections
    """
    tasks = zip(get_svnames_from_tasks(app['tasks']), app['tasks'])
    drained_listeners = select_drained_listeners(listeners)

    drained_task_ids = []
    for svname, task in tasks:
        task_listeners = [l for l in drained_listeners if l.svname == svname]
        if len(task_listeners) == haproxy_count:
            drained_task_ids.append(task['id'])

    return drained_task_ids


def max_wait_exceeded(max_wait, timestamp):
    return (time.time() - timestamp > max_wait)


def check_time_and_sleep(args, timestamp):
    if max_wait_exceeded(args.max_wait, timestamp):
        raise TimeoutError('Max wait Time Exceeded')

    return time.sleep(args.step_delay)


def swap_bluegreen_apps(args, new_app, old_app, timestamp):
    while True:
        check_time_and_sleep(args, timestamp)

        old_app = fetch_marathon_app(args, old_app['id'])
        new_app = fetch_marathon_app(args, new_app['id'])

        logger.info("Existing app running {} instances, "
                    "new app running {} instances"
                    .format(old_app['instances'], new_app['instances']))

        marathon_lb_urls = get_marathon_lb_urls(args)
        haproxy_count = len(marathon_lb_urls)

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

        drained_task_ids = \
            find_drained_task_ids(old_app, listeners, haproxy_count)

        if ready_to_delete_old_app(new_app, old_app, drained_task_ids):
            return safe_delete_app(args, old_app)

        logger.info("There are {} drained listeners, "
                    "about to kill & scale for these tasks:\n  - {}"
                    .format(len(drained_task_ids),
                            "\n  - ".join(drained_task_ids)))

        if args.force or query_yes_no("Continue?"):
            scale_new_app_instances(args, new_app, old_app)

            # Kill any drained tasks
            logger.info("Scaling down old app by {} instances"
                        .format(len(drained_task_ids)))

            kill_marathon_tasks(args, drained_task_ids)
            continue
        else:
            return False


def ready_to_delete_old_app(new_app, old_app, drained_task_ids):
    return (int(new_app['instances']) == get_deployment_target(new_app) and
            len(drained_task_ids) == int(old_app['instances']))


def waiting_for_drained_listeners(listeners):
    return len(select_drained_listeners(listeners)) < 1


def scale_new_app_instances(args, new_app, old_app):
    """Scale the app by 150% of its existing instances until we
       meet or surpase old_app instances. At which point go right to
       the new_app deployment target
    """
    instances = (math.floor(new_app['instances'] +
                 (new_app['instances'] + 1) / 2))
    if instances >= old_app['instances']:
        instances = get_deployment_target(new_app)

    logger.info("Scaling new app up to {} instances".format(instances))
    return scale_marathon_app_instances(args, new_app, instances)


def safe_delete_app(args, app):
    logger.info("About to delete old app {}".format(app['id']))
    if args.force or query_yes_no("Continue?"):
        delete_marathon_app(args, app)
        return True
    else:
        return False


def delete_marathon_app(args, app):
    url = args.marathon + '/v2/apps' + app['id']
    response = requests.delete(url,
                               auth=get_marathon_auth_params(args))
    response.raise_for_status()
    return response


def kill_marathon_tasks(args, ids):
    data = json.dumps({'ids': ids})
    url = args.marathon + "/v2/tasks/delete?scale=true"
    headers = {'Content-Type': 'application/json'}
    response = requests.post(url, headers=headers, data=data,
                             auth=get_marathon_auth_params(args))
    response.raise_for_status()
    return response


def scale_marathon_app_instances(args, app, instances):
    url = args.marathon + "/v2/apps" + app['id']
    data = json.dumps({'instances': instances})
    headers = {'Content-Type': 'application/json'}

    response = requests.put(url, headers=headers, data=data,
                            auth=get_marathon_auth_params(args))

    response.raise_for_status()
    return response


def deploy_marathon_app(args, app):
    url = args.marathon + "/v2/apps"
    data = json.dumps(app)
    headers = {'Content-Type': 'application/json'}
    response = requests.post(url, headers=headers, data=data,
                             auth=get_marathon_auth_params(args))
    response.raise_for_status()
    return response


def get_service_port(app):
    try:
        return \
            int(app['container']['docker']['portMappings'][0]['servicePort'])
    except KeyError:
        return int(app['ports'][0])


def set_service_port(app, servicePort):
    try:
        app['container']['docker']['portMappings'][0]['servicePort'] = \
          int(servicePort)
    except KeyError:
        app['ports'][0] = int(servicePort)

    return app


def validate_app(app):
    if app['id'] is None:
        raise Exception("App doesn't contain a valid App ID")
    if 'labels' not in app:
        raise Exception("No labels found. Please define the"
                        "HAPROXY_DEPLOYMENT_GROUP label")
    if 'HAPROXY_DEPLOYMENT_GROUP' not in app['labels']:
        raise Exception("Please define the "
                        "HAPROXY_DEPLOYMENT_GROUP label")
    if 'HAPROXY_DEPLOYMENT_ALT_PORT' not in app['labels']:
        raise Exception("Please define the "
                        "HAPROXY_DEPLOYMENT_ALT_PORT label")


def set_app_ids(app, colour):
    app['labels']['HAPROXY_APP_ID'] = app['id']
    app['id'] = app['id'] + '-' + colour

    if app['id'][0] != '/':
        app['id'] = '/' + app['id']

    return app


def set_service_ports(app, servicePort):
    app['labels']['HAPROXY_0_PORT'] = str(get_service_port(app))
    try:
        app['container']['docker']['portMappings'][0]['servicePort'] = \
          int(servicePort)
        return app
    except KeyError:
        app['ports'][0] = int(servicePort)
        return app


def select_next_port(app):
    alt_port = int(app['labels']['HAPROXY_DEPLOYMENT_ALT_PORT'])
    if int(app['ports'][0]) == alt_port:
        return int(app['labels']['HAPROXY_0_PORT'])
    else:
        return alt_port


def select_next_colour(app):
    if app['labels'].get('HAPROXY_DEPLOYMENT_COLOUR') == 'blue':
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
    """ Return a blue or a green version of `app` based on prexisting deploys
    """
    if len(previous_deploys) > 0:
        last_deploy = select_last_deploy(previous_deploys)

        app['instances'] = args.initial_instances
        next_colour = select_next_colour(last_deploy)
        next_port = select_next_port(last_deploy)
        deployment_target_instances = last_deploy['instances']
    else:
        next_colour = 'blue'
        next_port = get_service_port(app)
        deployment_target_instances = app['instances']

    app = set_app_ids(app, next_colour)
    app = set_service_ports(app, next_port)
    app['labels']['HAPROXY_DEPLOYMENT_TARGET_INSTANCES'] = \
        str(deployment_target_instances)
    app['labels']['HAPROXY_DEPLOYMENT_COLOUR'] = next_colour
    app['labels']['HAPROXY_DEPLOYMENT_STARTED_AT'] = datetime.now().isoformat()

    return app


def load_app_json(args):
    with open(args.json) as content_file:
        return json.load(content_file)


def safe_resume_deploy(args, previous_deploys):
    if args.resume:
        logger.info("Found previous deployment, resuming")
        new_app, old_app = select_last_two_deploys(previous_deploys)
        swap_bluegreen_apps(args, new_app, old_app, time.time())
    else:
        raise Exception("There appears to be an"
                        " existing deployment in progress")


def do_bluegreen_deploy(args, out=sys.stdout):
    app = load_app_json(args)
    validate_app(app)

    previous_deploys = fetch_previous_deploys(args, app)

    if len(previous_deploys) > 1:
        # There is a stuck deploy
        return safe_resume_deploy(args, previous_deploys)

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
            return swap_bluegreen_apps(args, new_app, old_app, time.time())


def get_arg_parser():
    parser = argparse.ArgumentParser(
        description="Marathon HAProxy Load Balancer",
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
                        help="Initial number of app instances to launch",
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
    setup_logging(logger, args.syslog_socket, args.log_format)

    do_bluegreen_deploy(args)
