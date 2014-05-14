#!/usr/bin/env python

import hashlib
import sys
import os
import time
import subprocess

import jinja2
import requests
import paramiko

ADMIN_MESG_LOCATION = "/tmp/admin_message"

def test_login(service, host, user ):
  result = { 'service' : service,
             'status' : "OK", 
             'message' : '' }
  client = paramiko.client.SSHClient()
  try:
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, port=22, username=user)
  except paramiko.AuthenticationException:
    result['status'] = 'FAILED'
    result['message'] = "Can't authenticate to %s" % host
  except paramiko.SSHException:
    result['status'] = 'FAILED'
    result['message'] = "Can't establish ssh connection to %s" % host
  except socket.error:
    result['status'] = 'FAILED'
    result['message'] = "Socket error connecting to %s" % host
  return result

def test_download(service, url, sha1):
  result = { 'service' : service,
             'status' : "OK", 
             'message' : '' }
  try:
    r = requests.get(url, timeout=60)
    if r.status_code != requests.codes.ok:
      result['status'] = "FAILED"
      result['message'] = "HTTP Status code: %s" % r.status_code
      return result
    if hashlib.sha1(r.text).hexdigest() != sha1:
      result['status'] = "FAILED"
      result['message'] = "File content doesn't match"
  except requests.exceptions.Timeout:
    result['status'] = "FAILED"
    result['message'] = "Connection to server timed out"
  except requests.exceptions.ConnectionError:
    result['status'] = "FAILED"
    result['message'] = "Connection error"
  except requests.exceptions.HTTPError:
    result['status'] = "FAILED"
    result['message'] = "Invalid HTTP Response"
  except requests.exceptions:
    result['status'] = "FAILED"
    result['message'] = "Invalid HTTP Response"
    
  return result

def test_xrootd(service, uri, sha1):
  result = { 'service' : service,
             'status' : "OK", 
             'message' : '' } 
  try:
    print "run_xrdcp.sh %s /tmp/xrdcp.test" % uri
    status = subprocess.call("./run_xrdcp.sh %s /tmp/xrdcp.test" % uri, shell=True)
  except OSError:
    result['status'] = "FAILED"
    result['message'] = "xrdcp did not succeed"
    return result
  if status != 0 :
    result['status'] = "FAILED"
    result['message'] = "xrdcp did not succeed"
    return result 
  if hashlib.sha1(open("/tmp/xrdcp.test").read()).hexdigest() != sha1:
    result['status'] = "FAILED"
    result['message'] = "SHA1 hash does not match"
  os.unlink("/tmp/xrdcp.test")

  return result


def run_tests(output_file):
  test_sites = []
  osg_tests = { 'anchor' : 'OSG',
                'set_name' : 'OSG Connect',
                'tests' : { 'http' : ['Stash',
                                      'http://stash.osgconnect.net/keys/cern.ch.pub',
                                      '5b83bedef4c7ba38520d7e1b764f0cbc28527fb9'],
                            'login' : ['SSH Login', 
                                       'login.osgconnect.net',
                                       'sthapa']
                            }}
  test_sites.append(osg_tests)
  atlas_tests = { 'anchor' : 'ATLAS',
                  'set_name' : 'ATLAS Connect',
                  'tests' : { 'http' : ['Faxbox',
                                        'http://faxbox.usatlas.org/keys/cern.ch.pub',
                                        '5b83bedef4c7ba38520d7e1b764f0cbc28527fb9'],
                              'login' : ['SSH Login', 
                                         'login.usatlas.org',
                                         'sthapa'],
                              'xrootd' : ['Xrootd',
                                          'root://faxbox.usatlas.org//user/sthapa/filelist',
                                          'f5127d99e4c75967e1bb992cd7d275554b111d75']}}
  test_sites.append(atlas_tests)

  for site in test_sites:
    site['results'] = []
    for test in site['tests']:
      if test == 'http':
        site['results'].append(test_download(*site['tests'][test]))
      elif test == 'login':
        site['results'].append(test_login(*site['tests'][test]))
      elif test == 'xrootd':
        site['results'].append(test_xrootd(*site['tests'][test]))

  env = jinja2.Environment(loader=jinja2.FileSystemLoader( searchpath="." ))
  template = env.get_template('templates/status.html')
  admin_mesg = None
  if os.path.isfile(ADMIN_MESG_LOCATION):
    admin_mesg = open(ADMIN_MESG_LOCATION).read()
  open(output_file, 'w').write(template.render(test_sets = test_sites,
                               admin_mesg = admin_mesg,
                               time = time.asctime()))
if __name__ == "__main__":
   run_tests(sys.argv[1])
   sys.exit(0)
