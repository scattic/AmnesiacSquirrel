import requests
import datetime
import re

url     = "https://talosintelligence.com/documents/ip-blacklist"

iocs   = {} # dictionary elements, like this:
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

def get_data(url, proxies=None, verify=True):
  
  headers = {
  }

  r = requests.get(url, headers=headers, proxies=proxies, verify=verify)
  if r.status_code == 200:
    return r.text
  else:
    print('Error retrieving data.')
    print('Status code was: {}'.format(r.status_code))
    return False

# ------------------------------------------------------------

def get_iocs():
  
  response_data = get_data(url).splitlines()
  
  for line in response_data:  # Loop through each row/ip
    
    ipregex = re.search("(?P<ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", line)
    if ipregex is not None:
      out = ipregex.group('ip')
      what = 'ip'  
      ioc = {
        "type":what,
        "source":"tor",
        "comments":"talos", 
        "timestamp": datetime.datetime.now()
      }
      if len(out)>0:
        if not out in iocs:
          iocs[out] = ioc

  return iocs

