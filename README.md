AmnesiacSquirrel
================

Overview
--------

Collects IP address and domain name IOCs from various OSINT sources, performs deduplication, updates timestamps, 
and remembers sources. Exports those IOCs to CSV for easy import into other analysis platforms.

Supported sources (for the moment):

1. AlienVault OTX: 
  - will extract IPv4 
  - will parse URLs to get IP addresses
  - will add hostname, domain and will parse non-IP URLs
2. Botvrij.eu lists (hostnames, urls, ip addresses, domains).
3. Cisco Talos Bad IP List.
4. AlienVault IP Reputation.
5. BinaryDefence.
6. Bitcoin-nodes.
7. Blocklist.de.
8. CINSscore.
9. Proofpoint EmergingThreats.
10. SANS Top Bad IPs.
11. Spys.me Proxy List.
12. Abuse.ch URLhaus, IP addresses only
13. Abuse.ch C2 Traker.
14. Tor Exit Nodes.

**NOTE**: source API keys must be supplied in a `keys.txt` file with this format, present in the same folder as `as.py`:
```
[api_keys]
otx_api_key = 1234567890
```

Syntax
------
```
usage: as.py [-h] [--last-days DAYS] [--export {ipv4,domains}]
             [--update {all,otx,tor,botvrij}]

optional arguments:
  -h, --help            show this help message and exit
  --last-days DAYS      Specify the max range of TI records to retrieve in
                        days (days old) from sources. Does not apply to all
                        sources. If not specified will attempt to retrieve all
                        available.
  --export {ipv4,domains}
                        Will export the specified data to stdout, formatted as
                        csv.
  --update {all,otx,tor,botvrij}
                        Will update db with new records from the specified TI
                        sources. The default action when no args are specified
                        is to update all sources.
```

SQLite3 tables and db info
--------------------------

`tbl_ipv4iocs`
| ip_addr | sources | added   | last_seen |comments |
|---------|---------|---------|-----------|---------|
|  text   |  text   |   text  |   text    |  text   |

* ip_addr: the IP, also the primary key
* sources: pipe separated list of sources where this indicator has been seen
* last_seen: a timestamp for when the record was last seen in a source
* added: a timestamp for when the record was first added
* comments: other relevant details, such as tags, links made available by the source. Max 1024 chars.

`tbl_domainiocs`
| domain  | sources | added   | last_seen |comments |
|---------|---------|---------|-----------|---------|
|  text   |  text   |   text  |   text    |  text   |


#### Useful stuff
DB Browser for SQLite app from Snap store

#### References
- www.threat-intel.xyz
- https://github.com/threat-hunting/awesome-threat-intelligence
- https://github.com/sroberts/awesome-iocs
- http://iplists.firehol.org -> https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset
- https://bgpranking.circl.lu/
