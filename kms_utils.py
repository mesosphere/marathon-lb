import common
import json
import logging
import os
import subprocess
import time

head_vault_hosts = 'OLD_IFS=${IFS};IFS=\',\' read -r -a VAULT_HOSTS <<< \"$STRING_VAULT_HOST\";IFS=${OLD_IFS};'
source_kms_utils = '. /usr/sbin/kms_utils.sh;'

global vault_token
global vault_accessor
global MAX_PERCENTAGE_EXPIRATION

vault_token = os.getenv('VAULT_TOKEN', '')
vault_accessor = os.getenv('ACCESSOR_TOKEN','')
MAX_PERCENTAGE_EXPIRATION = 0.9

logger = None
def init_log():
    global logger
    logger = common.marathon_lb_logger.getChild('kms_utils.py')

def login():
  global vault_token
  global vault_accessor
  output = exec_with_kms_utils('', 'login', 'echo "{\\\"vaulttoken\\\": \\\"$VAULT_TOKEN\\\",\\\"accessor\\\": \\\"$ACCESSOR_TOKEN\\\"}"')
  resp,_ = output.communicate()
  jsonVal = json.loads(resp.decode("utf-8"))
  vault_accessor = (jsonVal['accessor'])
  vault_token = (jsonVal['vaulttoken'])

def get_cert(cluster, instance, fqdn, o_format, store_path):
  variables = ''.join(['export VAULT_TOKEN=', vault_token, ';'])
  command = ' '.join(['getCert', cluster, instance, fqdn, o_format, store_path]) 
  output = exec_with_kms_utils(variables, command , '')
  resp,_ = output.communicate()
  logger.debug('get_cert for ' + instance + ' returned ' + str(output.returncode) + ' and ' + resp.decode("utf-8"))
  
  return output.returncode == 0

def get_token_info():
  variables = ''.join(['export VAULT_TOKEN=', vault_token, ';', 'export ACCESSOR_TOKEN=', vault_accessor, ';'])
  command = 'token_info'
  output = exec_with_kms_utils(variables, command, '')
  resp,_ = output.communicate()
  respArr = resp.decode("utf-8").split(',')
  jsonValue = json.loads(','.join(respArr[1:]))
  logger.debug('status ' + respArr[0])
  logger.debug(jsonValue)
  
  return jsonValue

def check_token_needs_renewal(force):
  renewal = True
  jsonInfo = get_token_info()
  creationTime = jsonInfo['data']['creation_time']
  ttl = jsonInfo['data']['ttl']
  lastRenewalTime = 0
  
  try: 
    lastRenewalTime = jsonInfo['data']['last_renewal_time']
  except KeyError: pass
  currentTime = int(time.time())
  
  if (lastRenewalTime > 0):
    percentage = (currentTime - lastRenewalTime) / ttl
  else:
    percentage = (currentTime - creationTime) / ttl
  
  logger.debug('Checked token expiration: percentage -> ' + str(percentage))
  
  if (percentage >= MAX_PERCENTAGE_EXPIRATION and percentage < 1):
    logger.info('Token about to expire... need renewal')
    renewal_token(ttl)
  elif (percentage >= 1):
    logger.info('Token expired... need renewal')
    renewal_token(ttl)
  elif force:
    logger.info('Forced renewal')
    renewal_token(ttl)
  else:
    renewal = False

  return renewal

def renewal_token(ttl):
  variables = ''.join(['export VAULT_TOKEN=', vault_token, ';'])
  command = 'token_renewal'
  output = exec_with_kms_utils(variables, command, '')
  resp,_ = output.communicate()
  respArr = resp.decode("utf-8").split(',')
  jsonValue = json.loads(','.join(respArr[1:]))
  logger.debug('status ' + respArr[0])
  logger.debug(jsonValue) 

def exec_with_kms_utils(variables, command, extra_command):
  logger.debug('>>> exec_with_kms_utils: [COMM:'+command+', VARS:'+variables+', EXTRA_COMM:'+extra_command+']')
  output = subprocess.Popen(['bash', '-c', head_vault_hosts + variables + source_kms_utils + command + ';' + extra_command], shell=False, stdout=subprocess.PIPE)
  
  return output

