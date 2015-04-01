#!/usr/bin/env python

import hashlib
import sys
import os
import subprocess
import socket
import argparse
import json

import requests
import paramiko

ADMIN_MESG_LOCATION = "/tmp/admin_message"


def test_login(service, host, user):
    result = {'service': service,
              'status': "green",
              'notes': ''}
    client = paramiko.client.SSHClient()
    try:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, port=22, username=user)
    except paramiko.AuthenticationException:
        result['status'] = 'red'
        result['notes'] = "Can't authenticate to %s" % host
    except paramiko.SSHException:
        result['status'] = 'red'
        result['notes'] = "Can't establish ssh connection to %s" % host
    except socket.error:
        result['status'] = 'red'
        result['notes'] = "Socket error connecting to %s" % host
    return result


def test_download(service, url, sha1):
    result = {'service': service,
              'status': "green",
              'notes': ''}
    try:
        r = requests.get(url, timeout=60)
        if r.status_code != requests.codes.ok:
            result['status'] = "red"
            result['notes'] = "HTTP Status code: %s" % r.status_code
            return result
        if hashlib.sha1(r.text).hexdigest() != sha1:
            result['status'] = "red"
            result['notes'] = "File content doesn't match"
    except requests.exceptions.Timeout:
        result['status'] = "red"
        result['notes'] = "Connection to server timed out"
    except requests.exceptions.ConnectionError:
        result['status'] = "red"
        result['notes'] = "Connection error"
    except requests.exceptions.HTTPError:
        result['status'] = "red"
        result['notes'] = "Invalid HTTP Response"
    except requests.exceptions:
        result['status'] = "red"
        result['notes'] = "Invalid HTTP Response"

    return result


def test_xrootd(service, uri, sha1):
    result = {'service': service,
              'status': "green",
              'notes': ''}
    try:
        status = subprocess.call("./run_xrdcp.sh %s /tmp/xrdcp.test" % uri, shell=True)
    except OSError:
        result['status'] = "red"
        result['notes'] = "xrdcp did not succeed"
        return result
    if status != 0:
        result['status'] = "red"
        result['notes'] = "xrdcp did not succeed"
        return result
    if hashlib.sha1(open("/tmp/xrdcp.test").read()).hexdigest() != sha1:
        result['status'] = "red"
        result['notes'] = "SHA1 hash does not match"
    os.unlink("/tmp/xrdcp.test")

    return result


def run_tests(config={}, site_messages={}):
    """
    Run tests on various services and return a dictionary based on
    test results

    :param config: dictionary with test configuration
    :param site_messages: dictionary with messages/status overrides
                          for sites
    :return: a dictionary with test results
    """
    test_results = []
    if not config:
        return []
    for service, config in config.iteritems():
        result = {'service': service}
        if service in site_messages:
            # if service is in site messages use this instead of
            # test results
            if 'status' in site_messages[service]:
                result['status'] = site_messages[service]['status']
            if 'notes' in site_messages[service]:
                result['notes'] = site_messages[service]['notes']
            test_results.append(result)
            continue
        if config['type'] == 'ssh':
            result.update(test_login(service,
                                     config['host'],
                                     config['user']))
        elif config['type'] == 'http':
            result.update(test_download(service,
                                        config['url'],
                                        config['sha1sum']))
        elif config['type'] == 'xrootd':
            result.update(test_xrootd(service,
                                      config['uri'],
                                      config['sha1sum']))
        test_results.append(result)
    return test_results


def parse_messages(mesg_file=None):
    """
    Read a set of JSON formatted messages and store as dictionary

    :param mesg_file: location of file with JSON formatted messages
    :return: dictionary with messages/statuses
    """
    site_mesg = {}
    if not mesg_file:
        return site_mesg
    buf = open(mesg_file).read()
    site_mesg = json.loads(buf)
    return site_mesg


def parse_group_info(group_file=None):
    """
    Read a set of JSON formatted info on groups for CI Connect

    :param group_file: location of file with JSON formatted messages
    :return: dictionary with messages/statuses
    """
    info = {}
    if not group_file:
        return info
    buf = open(group_file).read()
    info = json.loads(buf)
    return info['groups']


def parse_config(config_file=None):
    """
    Read a set of JSON formatted configs and store as dictionary

    :param config_file: location of file with JSON formatted config
    :return: dictionary with messages/statuses
    """
    config = {}
    if not config_file:
        return config
    buf = open(config_file).read()
    config = json.loads(buf)
    return config


def write_output(output_file=None, results=[], group_info=""):
    """
    Combine test results and group information and
    output JSON to stdout or a file

    :param output_file: path to output file, if None use stdout
    :param results:  list with test results
    :param group_info: dictionary with group information
    :return: None
    """
    combined_output = "{\n"
    combined_output += '"services": {' + "\n"
    for result in results:
        result_str = "\"{0}\": ".format(result['service']) + "{\n"
        result_str += "\"status\": \"{0}\",\n".format(result['status'])
        result_str += "\"notes\": \"{0}\"".format(result['notes']) + "\n},\n"
        combined_output += result_str
    combined_output = combined_output[:-2] + "\n"
    combined_output += "},\n"
    combined_output += "\"groups\" : \n" 
    combined_output += json.dumps(group_info)
    combined_output += "}"
    if output_file is None:
        sys.stdout.write("{0}\n".format(combined_output))
    else:
        try:
            output = open(output_file, 'w')
            output.write(combined_output + "\n")
            output.close()
        except IOError:
            sys.stderr.write("Can't write output to {0}".format(output_file))
            sys.exit(1)
    return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Test a set of services and ' +
                                                 'write test output to a file')
    parser.add_argument('--output',
                        dest='output',
                        default=None,
                        help='Specifies path to the output file')
    parser.add_argument('--group-file',
                        dest='group_file',
                        default=None,
                        required=True,
                        help='Specifies path to the file with' +
                             ' group information in JSON')
    parser.add_argument('--admin-mesg-file',
                        dest='mesg_file',
                        default=None,
                        help='Specifies path to the file with admin messages' +
                             ' in JSON')
    parser.add_argument('--test-config',
                        dest='test_config',
                        default=None,
                        required=True,
                        help='Specifies path to the file with test configuration' +
                             ' in JSON')
    args = parser.parse_args(sys.argv[1:])
    if not os.path.isfile(args.group_file):
        sys.stderr.write("file specified in --group-file must exist " +
                         "got {0}".format(args.group_file))
        sys.exit(1)
    if args.mesg_file and not os.path.isfile(args.mesg_file):
        sys.stderr.write("file specified in --mesg-file must exist " +
                         "got {0}".format(args.group_file))
        sys.exit(1)
    group_info = parse_group_info(args.group_file)
    messages = parse_messages(args.mesg_file)
    test_config = parse_config(args.test_config)
    results = run_tests(test_config, messages)
    write_output(args.output, results, group_info)
    sys.exit(0)
