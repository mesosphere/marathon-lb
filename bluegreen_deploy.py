#!/usr/bin/env python3

from common import *
from datetime import datetime
from io import StringIO

import argparse
import json
import requests
import csv
import time
import re
import math
import socket
import urllib


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


def fetch_marathon_app(args, app_ip):
    response = marathon_get_request(args, "/v2/apps" + app_id)
    return response.json()['app']


def get_hostports_from_backends(hmap, backends, haproxy_instance_count):
    hostports = {}
    regex = re.compile(r"^(\d+)_(\d+)_(\d+)_(\d+)_(\d+)$", re.IGNORECASE)
    counts = {}
    for backend in backends:
        svname = backend[hmap['svname']]
        if svname in counts:
            counts[svname] += 1
        else:
            counts[svname] = 1
        # Are all backends across all instances draining?
        if counts[svname] == haproxy_instance_count:
            m = regex.match(svname)
            host = '.'.join(m.group(1, 2, 3, 4))
            port = m.group(5)
            if host in hostports:
                hostports[host].append(int(port))
            else:
                hostports[host] = [int(port)]
    return hostports


def find_tasks_to_kill(tasks, hostports):
    tasks_to_kill = set()
    for task in tasks:
        if task['host'] in hostports:
            for port in hostports[task['host']]:
                if port in task['ports']:
                    tasks_to_kill.add(task['id'])
    return list(tasks_to_kill)


def check_if_tasks_drained(args, app, existing_app, step_started_at):
    time.sleep(args.step_delay)
    url = args.marathon + "/v2/apps" + existing_app['id']
    response = requests.get(url, auth=get_marathon_auth_params(args))
    response.raise_for_status()
    existing_app = response.json()['app']

    url = args.marathon + "/v2/apps" + app['id']
    response = requests.get(url, auth=get_marathon_auth_params(args))
    response.raise_for_status()
    app = response.json()['app']

    target_instances = \
        int(app['labels']['HAPROXY_DEPLOYMENT_TARGET_INSTANCES'])

    logger.info("Existing app running {} instances, "
                "new app running {} instances"
                .format(existing_app['instances'], app['instances']))

    url = args.marathon_lb
    url = urllib.parse.urlparse(url)
    # Have to find _all_ haproxy stats backends
    addrs = socket.gethostbyname_ex(url.hostname)[2]
    csv_data = ''
    for addr in addrs:
        try:
            nexturl = \
                urllib.parse.urlunparse((url[0],
                                         addr + ":" + str(url.port),
                                         url[2],
                                         url[3],
                                         url[4],
                                         url[5]))
            response = requests.get(nexturl + "/haproxy?stats;csv")
            response.raise_for_status()
            csv_data = csv_data + response.text

            response = requests.get(nexturl + "/_haproxy_getpids")
            response.raise_for_status()
            pids = response.text.split()
            if len(pids) > 1 and time.time() - step_started_at < args.max_wait:
                # HAProxy has not finished reloading
                logger.info("Waiting for {} pids on {}"
                            .format(len(pids), nexturl))
                return check_if_tasks_drained(args,
                                              app,
                                              existing_app,
                                              step_started_at)
        except requests.exceptions.RequestException as e:
            logger.exception("Caught exception when retrieving HAProxy"
                             " stats from " + nexturl)
            return check_if_tasks_drained(args,
                                          app,
                                          existing_app,
                                          step_started_at)

    backends = []
    f = StringIO(csv_data)
    header = None
    haproxy_instance_count = 0
    for row in csv.reader(f, delimiter=',', quotechar="'"):
        if row[0][0] == '#':
            header = row
            haproxy_instance_count += 1
            continue
        if row[0] == app['labels']['HAPROXY_DEPLOYMENT_GROUP'] + "_" + \
                app['labels']['HAPROXY_0_PORT'] and \
                row[1] != "BACKEND" and \
                row[1] != "FRONTEND":
            backends.append(row)

    logger.info("Found {} app backends across {} HAProxy instances"
                .format(len(backends), haproxy_instance_count))
    # Create map of column names to idx
    hmap = {}
    for i in range(0, len(header)):
        hmap[header[i]] = i

    if (len(backends) / haproxy_instance_count) != \
            app['instances'] + existing_app['instances']:
        # HAProxy hasn't updated yet, try again
        return check_if_tasks_drained(args,
                                      app,
                                      existing_app,
                                      step_started_at)

    up_backends = \
        [b for b in backends if b[hmap['status']] == 'UP']
    if (len(up_backends) / haproxy_instance_count) < target_instances:
        # Wait until we're in a healthy state
        return check_if_tasks_drained(args,
                                      app,
                                      existing_app,
                                      step_started_at)

    # Double check that current draining backends are finished serving requests
    draining_backends = \
        [b for b in backends if b[hmap['status']] == 'MAINT']

    if (len(draining_backends) / haproxy_instance_count) < 1:
        # No backends have started draining yet
        return check_if_tasks_drained(args,
                                      app,
                                      existing_app,
                                      step_started_at)

    for backend in draining_backends:
        # Verify that the backends have no sessions or pending connections.
        # This is likely overkill, but we'll do it anyway to be safe.
        if int(backend[hmap['qcur']]) > 0 or int(backend[hmap['scur']]) > 0:
            # Backends are not yet drained.
            return check_if_tasks_drained(args,
                                          app,
                                          existing_app,
                                          step_started_at)

    # If we made it here, all the backends are drained and we can start
    # slaughtering tasks, with prejudice
    hostports = get_hostports_from_backends(hmap,
                                            draining_backends,
                                            haproxy_instance_count)

    tasks_to_kill = find_tasks_to_kill(existing_app['tasks'], hostports)

    logger.info("There are {} drained backends, "
                "about to kill & scale for these tasks:\n{}"
                .format(len(tasks_to_kill), "\n".join(tasks_to_kill)))

    if app['instances'] == target_instances and \
            len(tasks_to_kill) == existing_app['instances']:
        logger.info("About to delete old app {}".format(existing_app['id']))
        if args.force or query_yes_no("Continue?"):
            url = args.marathon + "/v2/apps" + existing_app['id']
            response = requests.delete(url,
                                       auth=get_marathon_auth_params(args))
            response.raise_for_status()
            return True
        else:
            return False

    if args.force or query_yes_no("Continue?"):
        # Scale new app up
        instances = math.floor(app['instances'] + (app['instances'] + 1) / 2)
        if instances >= existing_app['instances']:
            instances = target_instances
        logger.info("Scaling new app up to {} instances".format(instances))
        url = args.marathon + "/v2/apps" + app['id']
        data = json.dumps({'instances': instances})
        headers = {'Content-Type': 'application/json'}
        response = requests.put(url, headers=headers, data=data,
                                auth=get_marathon_auth_params(args))
        response.raise_for_status()

        # Scale old app down
        logger.info("Scaling down old app by {} instances"
                    .format(len(tasks_to_kill)))
        data = json.dumps({'ids': tasks_to_kill})
        url = args.marathon + "/v2/tasks/delete?scale=true"
        response = requests.post(url, headers=headers, data=data,
                                 auth=get_marathon_auth_params(args))
        response.raise_for_status()

        return check_if_tasks_drained(args,
                                      app,
                                      existing_app,
                                      time.time())
    return False


def start_deployment(args, app, existing_app, resuming):
    if not resuming:
        url = args.marathon + "/v2/apps"
        data = json.dumps(app)
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, headers=headers, data=data,
                                 auth=get_marathon_auth_params(args))
        response.raise_for_status()
    if existing_app is not None:
        return check_if_tasks_drained(args,
                                      app,
                                      existing_app,
                                      time.time())
    return False


def get_service_port(app):
    try:
        return app['container']['docker']['portMappings'][0]['servicePort']
    except KeyError:
        return app['ports'][0]


def set_service_port(app, servicePort):
    try:
        app['container']['docker']['portMappings'][0]['servicePort'] \
            = int(servicePort)
    except KeyError:
        app['ports'][0] = int(servicePort)

    return app


def validate_app(app):
    if app['id'] is None:
        raise Exception("App doesn't contain a valid App ID")

    if 'labels' not in app:
        raise Exception("No labels found. Please define the"
                        "HAPROXY_DEPLOYMENT_GROUP label"
                        )
    if 'HAPROXY_DEPLOYMENT_GROUP' not in app['labels']:
        raise Exception("Please define the "
                        "HAPROXY_DEPLOYMENT_GROUP label"
                        )
    if 'HAPROXY_DEPLOYMENT_ALT_PORT' not in app['labels']:
        raise Exception("Please define the "
                        "HAPROXY_DEPLOYMENT_ALT_PORT label"
                        )


def set_app_ids(app, colour):
    app['labels']['HAPROXY_APP_ID'] = app['id']
    app['id'] = app['id'] + '-' + colour

    if app['id'][0] != '/':
        app['id'] = '/' + app['id']

    return app


def set_service_ports(app, servicePort):
    app['labels']['HAPROXY_0_PORT'] = str(get_service_port(app))
    try:
        app['container']['docker']['portMappings'][0]['servicePort'] \
            = int(servicePort)
        return app
    except KeyError:
        app['ports'][0] = int(servicePort)
        return app


def select_next_port(app):
    if int(app['ports'][0]) \
      == int(app['labels']['HAPROXY_DEPLOYMENT_ALT_PORT']):

        return int(app['labels']['HAPROXY_0_PORT'])
    else:
        return int(app['labels']['HAPROXY_DEPLOYMENT_ALT_PORT'])


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
    return sort_deploys(apps)[0:2]


def get_deployment_group(app):
    return app.get('labels', {}).get('HAPROXY_DEPLOYMENT_GROUP')


def select_previous_deploys(apps, deployment_group):
    return [a for a in apps if get_deployment_group(a) == deployment_group]


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


def process_json(args, out=sys.stdout):
    with open(args.json, 'r') as content_file:
        content = content_file.read()

    app = json.loads(content)
    validate_app(app)

    existing_apps = list_marathon_apps(args)
    previous_deploys = \
        select_previous_deploys(existing_apps, get_deployment_group(app))

    if len(previous_deploys) > 1:
        # There is a stuck deploy, oh no!
        if args.resume:
            logger.info("Found previous deployment, resuming")
            old_deploy, current_deploy = \
                select_last_two_deploys(previous_deploys)
            start_deployment(args, current_deploy, old_deploy, True)
        else:
            raise Exception("There appears to be an"
                            " existing deployment in progress")

    app = prepare_deploy(args, previous_deploys, app)

    logger.info('Final app definition:')
    out.write(json.dumps(app, sort_keys=True, indent=2))
    out.write("\n")

    if args.dry_run:
        return

    if args.force or query_yes_no("Continue with deployment?"):

        if len(previous_deploys) == 0:
            # This is the first deployment, no existing_app
            start_deployment(args, app, None, False)

        if len(previous_deploys) == 1:
            # This is a standard blue/green deploy
            existing_app = select_last_deploy(previous_deploys)
            start_deployment(args, app, existing_app, False)


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


if __name__ == '__main__':
    # Process arguments
    arg_parser = get_arg_parser()
    args = arg_parser.parse_args()

    # Print the long help text if flag is set
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

    # Set request retries
    s = requests.Session()
    a = requests.adapters.HTTPAdapter(max_retries=3)
    s.mount('http://', a)

    # Setup logging
    setup_logging(logger, args.syslog_socket, args.log_format)

    process_json(args)
