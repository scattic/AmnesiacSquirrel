# Adapted from Karma's code: https://github.com/KarmaIncarnate

import argparse
import os
import requests
import json
import datetime
import csv
import re
from progressbar import ProgressBar # change to tqdm
import configparser

otx_url     = "https://otx.alienvault.com/api/v1"
otx_api_key = "" # will be loaded from keys.txt

modified_since = None  # Set pulse range to those modified in last x days

total_pulses = 0

#tmp_filename = "otx.csv" # used for debugging 

otx_iocs   = {} # dictionary elements, like this:
                # {
                #    'indicator' : { <details> }
                # }
                # details can be:
                # { 
                #   'type':<type>         # string ; can be 'ipv4' or 'name'
                #   'source':'otx'
                #   'timestamp':<value>   # datetime, eg 2010-05-28T15:36:56.200
                #   'comments':<value>    # string, name of event
                # }

# ------------------------------------------------------------

def otx_get(url, proxies=None, verify=True):
  
  headers = {
    'X-OTX-API-KEY': otx_api_key,
  }

  r = requests.get(url, headers=headers, proxies=proxies, verify=verify)
  if r.status_code == 200:
    return r.text
  else:
    print('Error retrieving AlienVault OTX data.')
    print('Status code was: {}'.format(r.status_code))
    return False

# ------------------------------------------------------------

def get_pulse_generator(proxies=None, verify=True):

  args = []
  global total_pulses, modified_since

  if modified_since:
    args.append('modified_since={}'.format(modified_since.strftime('%Y-%m-%d %H:%M:%S.%f')))

  args.append('limit=10')
  args.append('page=1')
  request_args = '&'.join(args)
  request_args = '?{}'.format(request_args)

  response_data = otx_get('{}/pulses/subscribed{}'.format(otx_url, request_args),proxies=proxies, verify=verify)
  while response_data:  # Loop through pulse data
    all_pulses = json.loads(response_data)
    total_pulses = all_pulses['count']
    if 'results' in all_pulses:
      for pulse in all_pulses['results']:
        yield pulse # returns a generator for this pulse
    response_data = None
    if 'next' in all_pulses:
      if all_pulses['next']:
        response_data = otx_get(all_pulses['next'],proxies=proxies,verify=verify)

# ------------------------------------------------------------
# heavy lifting done here
def get_and_parse():

  #try:
  #  os.remove(tmp_filename)
  #except:
  #  print("will create {}".format(tmp_filename))

  current_pulse = 1
  pbar = ProgressBar().start()

  for pulse in get_pulse_generator():

    pbar.maxval = total_pulses
    pbar.update(current_pulse)

    #print('Loading pulse ID[{}] TITLE[{}]'.format(pulse['id'],pulse['name'].encode("utf-8")))

    #with open(tmp_filename, 'a', newline='') as resultFile:
    for i in pulse['indicators']:
      
      out = ""
      what = ""

      # simplest case (but also not very frequent): a single IP address
      # does not handle slash / notation yet
      if i['type'].find('IPv4')>=0:
        ipregex = re.search("(?P<ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", i['indicator'])
        if ipregex is not None:
          out = ipregex.group('ip')
          what = 'ip'

      # we need to extract the domain name from an URL such as https://www.domain.com/something
      # does not handle subdomains or port numbers yet such as aaa.www.domain.com
      # sometimes this is provided as an IP, in which case we'll match the IP
      elif i['type'].find('URL')>=0:
        nameregex = re.search("\/\/(?P<subdomain>[a-z0-9\-\.]*\.)*(?P<domain>[a-z0-9\-]+\.[a-z]{2,63}){1}:?(?P<port>[0-9]{2,5})?\/",i['indicator'])
        if nameregex is not None:
          if nameregex.group('domain') is not None:
            out = nameregex.group('domain')
            what = 'domain'
          else:
            pd = i['indicator']
            print(f'Error, cannot match domain with format: {pd}')
        else: # let's try to match by IP
          ipregex = re.search("(?P<ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", i['indicator'])
          if ipregex is not None:
            out = ipregex.group('ip')
            what = 'ip'

      # a domain, just a domain
      elif i['type'].find('domain')>=0:
        out = i['indicator']
        what = 'domain'
      
      # sometimes host names can have subdomains
      elif i['type'].find('hostname')>=0:
        nameregex = re.search("(?P<subdomain>[a-z0-9\-\.]*\.)*(?P<domain>[a-z0-9\-]+\.[a-z]{2,63}){1}",i['indicator'])
        if nameregex is not None:
          if nameregex.group('domain') is not None:
            out = nameregex.group('domain')
            what = 'domain'
          else:
            pd = i['indicator']
            print(f'Error, cannot match domain with format: {pd}')   
        else: # maybe it's not a domain with a tld but just a name
          out = i['indicator']
          what = 'domain'

      reference = pulse['references']  
      if not reference:
        reference = pulse['name']
      else:
        reference = pulse['name'] + "," + pulse['references'][0]

      ioc = {
        "type":what,
        "source":"otx",
        "comments":reference[:1024], # max 1024 chars for now
        "timestamp": datetime.datetime.now()
      }
      
      if len(out)>0:
        if not out in otx_iocs:
          otx_iocs[out] = ioc
        
          #wr = csv.writer(resultFile, dialect='excel')
          #wr.writerow([what,out])

    current_pulse = current_pulse + 1
    # if current_pulse > 10: return

  pbar.finish()

# ------------------------------------------------------------

def get_iocs():
  
  global otx_api_key

  cp = configparser.RawConfigParser()   
  cp.read('keys.txt')
  otx_api_key = cp.get('api_keys', 'otx_api_key')
  
  get_and_parse()
  
  return otx_iocs

