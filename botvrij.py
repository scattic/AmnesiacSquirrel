import requests
import datetime
import re

bv_urls = [ 
  {'url':"https://www.botvrij.eu/data/ioclist.domain", 'type':'domain'},
  {'url':"https://www.botvrij.eu/data/ioclist.hostname", 'type':'domain'},
  {'url':"https://www.botvrij.eu/data/ioclist.ip-dst", 'type':'ip'},
  {'url':"https://www.botvrij.eu/data/ioclist.url", 'type':'url'},
]

bv_iocs   = {} # dictionary elements, like this:
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

def get_data_from_url(url, proxies=None, verify=True):
  
  headers = {}

  r = requests.get(url, headers=headers, proxies=proxies, verify=verify)
  if r.status_code == 200:
    return r.text
  else:
    print('Error retrieving BOTVRIJ.eu data.')
    print('Status code was: {}'.format(r.status_code))
    return False

# ------------------------------------------------------------

def get_iocs():
  
  for url in bv_urls:

    response_data = get_data_from_url(url['url']).splitlines()
  
    for line in response_data:  # Loop through each row/ip

      line_data = line.split(sep="#")
      out = ""

      if "ip" in url['type']:
        ipregex = re.search("(?P<ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", line_data[0])
        if ipregex is not None:
          out = ipregex.group('ip')
          what = 'ip'  
          comments = line_data[1]

      if "domain" in url['type']:
        nameregex = re.search("(?P<domain>[a-z0-9\-\.]{1,63})",line_data[0])
        if nameregex is not None:
          out = nameregex.group('domain')
          what = 'domain'  
          comments = line_data[1]
        
      if len(out)>0:
        if not out in bv_iocs:
          ioc = {
            "type":what,
            "source":"botvrij",
            "comments":comments, 
            "timestamp": datetime.datetime.now()
          }
          bv_iocs[out] = ioc

  return bv_iocs

