#!/usr/bin/env python

import hashlib
import sys
import os
import time

import jinja2
import requests
import paramiko

ADMIN_MESG_LOCATION = "/tmp/admin_message"

def test_login(test_name, host, user ):
  response = [test_name, "OK", ""]
  client = paramiko.client.SSHClient()
  try:
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, port=22, username=user)
  except paramiko.AuthenticationException:
    response = (test_name, "FAILED", "Can't authenticate to %s" % host)
  except paramiko.SSHException:
    response = (test_name, "FAILED", "Can't establish ssh connection to %s" % host)
  except socket.error:
    response = (test_name, "FAILED", "Socket error connecting to %s" % host) 
  return response

def test_download(test_name, url, sha1):
  response = [test_name, "OK", '']
  try:
    r = requests.get(url, timeout=60)
    if r.status_code != requests.codes.ok:
      response[1] = "FAILED"
      response[2] = "HTTP Status code: %s" % r.status_code
      return response
    if hashlib.sha1(r.text).hexdigest() != sha1:
      response = (test_name, "FAILED", "File content doesn't match")
  except requests.exceptions.Timeout:
    response[1] = "FAILED"
    response[2] = "Connection to server timed out"
  except requests.exceptions.ConnectionError:
    response[1] = "FAILED"
    response[2] = "Connection error"
  except requests.exceptions.HTTPError:
    response[1] = "FAILED"
    response[2] = "Invalid HTTP Response"
  except requests.exceptions:
    response[1] = "FAILED"
    response[2] = "Invalid HTTP Response"
    
  return response

def test_xroot(test_name, uri, sha1):
  response = (test_name, "OK", error)

  return response


def run_tests():
  http_results = []
  http_hosts = [['Stash HTTP test', 
                 'http://stash.osgconnect.net/keys/cern.ch.pub', 
                 '5b83bedef4c7ba38520d7e1b764f0cbc28527fb9']]
  ssh_results = []
  ssh_hosts = [['OSG Connect login', 'login.osgconnect.net', 'sthapa'],
               ['ATLAS Connect login', 'login.usatlas.org', 'sthapa']]
  
  #xrdcp_hosts = [['FAXBOX', 'xrootd://faxbox.atlasconnect.net', 'sha1']]
  for host in http_hosts:
    http_results.append(test_download(*host))
  for host in ssh_hosts:
    ssh_results.append(test_login(*host))
  env = jinja2.Environment(loader=jinja2.FileSystemLoader( searchpath="." ))
  template = env.get_template('templates/status.html')
  admin_mesg = None
  if os.path.isfile(ADMIN_MESG_LOCATION):
    admin_mesg = open(ADMIN_MESG_LOCATION).read()
  print template.render(http_results = http_results,
                        ssh_results = ssh_results,
                        xrootd_results = [],
                        admin_mesg = admin_mesg,
                        time = time.asctime())
if __name__ == "__main__":
   run_tests()
   sys.exit(0)
