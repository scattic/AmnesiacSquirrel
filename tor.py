import requests
import datetime
import re

tor_url     = "https://check.torproject.org/torbulkexitlist"

tor_iocs   = {} # dictionary elements, like this:
                # {
                #    'indicator' : { <details> }
                # }
                # details can be:
                # { 
                #   'type':<type>         # string ; can be 'ipv4' or 'name'
                #   'source':'tor'
                #   'timestamp':<value>   # datetime, eg 2010-05-28T15:36:56.200
                #   'comments':<value>    # string, name of event
                # }

# ------------------------------------------------------------

def tor_get(url, proxies=None, verify=True):
  
  headers = {
  }

  r = requests.get(url, headers=headers, proxies=proxies, verify=verify)
  if r.status_code == 200:
    return r.text
  else:
    print('Error retrieving TOR exit relay list.')
    print('Status code was: {}'.format(r.status_code))
    return False

# ------------------------------------------------------------

def get_iocs():
  
  response_data = tor_get(tor_url).splitlines()
  
  for line in response_data:  # Loop through each row/ip
    
    ipregex = re.search("(?P<ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", line)
    if ipregex is not None:
      out = ipregex.group('ip')
      what = 'ip'  
      ioc = {
        "type":what,
        "source":"tor",
        "comments":"check.torproject.org", 
        "timestamp": datetime.datetime.now()
      }
      if len(out)>0:
        if not out in tor_iocs:
          tor_iocs[out] = ioc

  return tor_iocs

