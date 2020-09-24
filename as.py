#!/usr/bin/python3

import otx
import sqlite3
import datetime
import argparse

dbconn = None # sqlite3 database
dbcurs = None # sqlite3 cursor

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

  dbconn.commit()

  return

# receives a dict of IOCs and updates the database
def db_update(iocs_dict):
  global dbconn, dbcurs
  # TODO: table name and primary key
  for ioc in iocs_dict:
    if iocs_dict[ioc]['type'] == 'ip':
      dbcurs.execute(f"SELECT * FROM tbl_ipv4iocs WHERE ip_addr='{ioc}';")
      rows = dbcurs.fetchall()
      source = iocs_dict[ioc]['source']
      timestamp = iocs_dict[ioc]['timestamp']
      comments = iocs_dict[ioc]['comments']
      if len(rows)==1:
        # TODO: we could consider only updating if there are changes, but...
        dbcurs.execute(f"UPDATE tbl_ipv4iocs SET sources='{source}', last_seen='{timestamp}',comments='{comments}' WHERE ip_addr='{ioc}';")
        dbconn.commit()
      else:
        dbcurs.execute(f"INSERT INTO tbl_ipv4iocs VALUES('{ioc}','{source}','{timestamp}','{timestamp}','{comments}');")
        dbconn.commit()
    if iocs_dict[ioc]['type'] == 'domain':
      dbcurs.execute(f"SELECT * FROM tbl_domainiocs WHERE domain='{ioc}';")
      rows = dbcurs.fetchall()
      source = iocs_dict[ioc]['source']
      timestamp = iocs_dict[ioc]['timestamp']
      comments = iocs_dict[ioc]['comments']
      if len(rows)==1:
        # TODO: we could consider only updating if there are changes, but...
        dbcurs.execute(f"UPDATE tbl_domainiocs SET sources='{source}', last_seen='{timestamp}',comments='{comments}' WHERE domain='{ioc}';")
        dbconn.commit()
      else:
        dbcurs.execute(f"INSERT INTO tbl_domainiocs VALUES('{ioc}','{source}','{timestamp}','{timestamp}','{comments}');")
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
  if 'domains' in what:
    sqlcmd = (f"SELECT domain FROM tbl_domainiocs;")
  
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
                           help='Specify the max range of TI records to retrieve in days (days old) from sources. If not specified will attempt to retrieve all available.')
  argparser.add_argument('--export', dest='export', default=None, choices=['ipv4','domains'], type=str, 
                           help='Will export the specified data to stdout, formatted as csv.')
  argparser.add_argument('--update', dest='update', default='all', choices=['all','otx'], type=str,
                           help='Will update db with new records from the specified TI sources. The default action when no args are specified is to update all sources.')
  args = argparser.parse_args()


  # export data from database
  if args.export:
    db_export(args.export)
    return
    
  if args.update:
    print_logo() 
    if args.days:
      print('📅 time is of the essence, especially the last {} days'.format(args.days))
      otx.modified_since = datetime.datetime.now() - datetime.timedelta(days=args.days)
    if ('all' in args.update) or ('otx' in args.update):
      print("🐿️  is going nuts about OTX...")
      iocs = otx.get_iocs()
    # update the database
    print("🌳 sorting nuts and keeping the tasty ones")
    db_update(iocs)
    print("🐿️  is now tired, bye")
    return 

main()