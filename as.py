#!/usr/bin/python3

import sqlite3
import datetime
import argparse
import ast

import otx
import botvrij
import plain

sources = { # plain text sources, one IP per line
  "Cisco Talos Bad IP List":"https://talosintelligence.com/documents/ip-blacklist",
  "AlienVault IP Reputation":"https://reputation.alienvault.com/reputation.generic",
  "BinaryDefence":"https://www.binarydefense.com/banlist.txt",
  "Bitcoin-nodes":"https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/bitcoin_nodes_1d.ipset",
  "Blocklist.de":"https://lists.blocklist.de/lists/all.txt",
  "CINSscore":"http://cinsscore.com/list/ci-badguys.txt",
  "Proofpoint EmergingThreats":"http://rules.emergingthreats.net/open/suricata/rules/compromised-ips.txt",
  "SANS Top Bad IPs":"https://isc.sans.edu/feeds/topips.txt",
  "Spys.me Proxy List":"http://spys.me/proxy.txt",
  "Abuse.ch URLhaus":"https://urlhaus.abuse.ch/downloads/text/",
  "Abuse.ch C2 Traker":"https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
  "Tor Exit Nodes":"https://check.torproject.org/torbulkexitlist"
}

dbconn = None # sqlite3 database
dbcurs = None # sqlite3 cursor

# some records statistics, reset for each new source
source_statistics = { 'new_records' : 0, 'updated_records' : 0 }

def print_logo():
  print(" ,;;:;,             ")
  print("   ;;;;;            ")
  print("  ,:;;:;    ,'=.      aMn3$iaC Squ1r^el")
  print("  ;:;:;' .=\" ,'_\  ")
  print("  ':;:;,/  ,__:=@     -- gathering IOCs since 2020")
  print("   ';;:;  =./)_     ")
  print("     `\"=\_  )_\"`    ")
  print("          ``'\"`     ")

def init():
  
  # create db and table struct if missing
  global dbconn, dbcurs
  
  try:
    dbconn = sqlite3.connect('iocs.db')
    dbcurs = dbconn.cursor()
  except:
    print("ERROR: cannot connect to iocs.db. Check file permissions and that sqlite3 is installed.")
    exit(1)
  
  dbcurs.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='tbl_ipv4iocs';")
  rows = dbcurs.fetchall()
  if len(rows)==0:
    print("INFO: table tbl_ipv4iocs not found, will now be created.")
    dbcurs.execute("CREATE TABLE tbl_ipv4iocs(ip_addr text PRIMARY KEY, sources text, added text, last_seen text, comments text);")

  dbcurs.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='tbl_domainiocs';")
  rows = dbcurs.fetchall()
  if len(rows)==0:
    print("INFO: table tbl_domainiocs not found, will now be created.")
    dbcurs.execute("CREATE TABLE tbl_domainiocs(domain text PRIMARY KEY, sources text, added text, last_seen text, comments text);")

  """
  CREATE UNIQUE INDEX "indx_domain" ON "tbl_domainiocs" ("domain");
  CREATE INDEX "indx_ipv4" ON "tbl_ipv4iocs" ("ip_addr");
  """

  dbconn.commit()

  return

# receives a dict of IOCs and updates the database
def db_update(iocs_dict):
  
  global dbconn, dbcurs
  
  source_statistics["new_records"] = 0
  source_statistics["updated_records"] = 0

  for ioc in iocs_dict:

    ioc = str(ioc)
    timestamp = str(iocs_dict[ioc]['timestamp'])
    comments = str(iocs_dict[ioc]['comments'])

    table_name = None
    primary_key = None 

    if iocs_dict[ioc]['type'] == 'ip':
      table_name = "tbl_ipv4iocs"
      primary_key = "ip_addr"

    if iocs_dict[ioc]['type'] == 'domain':
      table_name = "tbl_domainiocs"
      primary_key = "domain"

    dbcurs.execute(f"SELECT sources FROM {table_name} WHERE {primary_key}=?;",(ioc,))
    rows = dbcurs.fetchone()
    
    if not rows == None:
      source = ast.literal_eval(rows[0])
      if not isinstance(source,list):
        source.append(rows[0])
      if not iocs_dict[ioc]['source'] in source:
        source.append(iocs_dict[ioc]['source'])
      source = repr(source)
      dbcurs.execute(f"UPDATE {table_name} SET sources=?, last_seen=?,comments=? WHERE {primary_key}=?;",(source,timestamp,comments,ioc))
      source_statistics["updated_records"] += 1
    
    else:
      source = []
      source.append(iocs_dict[ioc]['source'])
      source = repr(source) 
      dbcurs.execute(f"INSERT INTO {table_name} VALUES(?,?,?,?,?);",(ioc,source,timestamp,timestamp,comments))
      source_statistics["new_records"] += 1
  
  dbconn.commit()
  return 

# print several database statistics
# total IP, total domains (+new last 7 days,  +new last 30 days)
def db_stats():
  return

def db_export(what):
  
  global dbconn, dbcurs
  if 'ipv4' in what:
    sqlcmd = (f"SELECT ip_addr FROM tbl_ipv4iocs;")
    print("IPv4,")
    dbcurs.execute(sqlcmd)
    rows = dbcurs.fetchall()
    for row in rows:
      print(f"{row[0]},")

  if 'domains' in what:
    sqlcmd = (f"SELECT domain FROM tbl_domainiocs;")
    print("DOMAIN,")
    dbcurs.execute(sqlcmd)
    rows = dbcurs.fetchall()
    for row in rows:
      print(f"{row[0]},")  

def main():
  
  init()
  
  # parse cmd line args

  #update = export = days = None

  argparser = argparse.ArgumentParser()
  argparser.add_argument('--last-days', dest='days', default=None, type=int,
                           help='Specify the max range of TI records to retrieve in days (days old) from sources. Does not apply to all sources. If not specified will attempt to retrieve all available.')
  argparser.add_argument('--export', dest='export', default=None, choices=['tagged-ipv4','ipv4','domains'], type=str, 
                           help='Will export the specified data to stdout, formatted as csv. Tagged version also include list of sources and notes if available.')
  argparser.add_argument('--update', dest='update', default='all', choices=['all','otx','botvrij','plain'], type=str,
                           help='Will update db with new records from the specified TI sources. The default action when no args are specified is to update all sources.')
  args = argparser.parse_args()

  # export data from database
  if args.export:
    db_export(args.export)
    return
    
  if args.update:
    print_logo() 
    if args.days:
      print('📅 filtering on changes from last {} days, when possible'.format(args.days))
      otx.modified_since = datetime.datetime.now() - datetime.timedelta(days=args.days)

    if ('all' in args.update) or ('otx' in args.update):
      print("🔎 querying OTX...")
      iocs = otx.get_iocs()
      db_update(iocs)
      print("…… {} new IOCs, {} updated".format(source_statistics['new_records'],source_statistics['updated_records']))


    if ('all' in args.update) or ('botvrij' in args.update):
      print("🔎 querying Botvrij...")
      iocs = botvrij.get_iocs()
      db_update(iocs)
      print("…… {} new IOCs, {} updated".format(source_statistics['new_records'],source_statistics['updated_records']))


    if ('all' in args.update) or ('plain' in args.update):
      for source_name in sources.keys():
        print("🔎 querying {}...".format(source_name))
        iocs = plain.get_iocs(source_name,sources[source_name])
        db_update(iocs)
        print("…… {} new IOCs, {} updated".format(source_statistics['new_records'],source_statistics['updated_records']))

    print("🚪 finished processing. You can now export the results with --export.")  
    return 

main()
