AmnesiacSquirrel
================

TODO
----
* measure time needed to run each task
* implement ThreatConnect

Overview
--------

Collects IP address and domain name IOCs from various OSINT sources, performs deduplication, updates timestamps, 
and remembers sources. Exports those IOCs to CSV for easy import into other analysis platforms.

Supported sources:
1. AlienVault OTX: 
  - will extract IPv4 
  - will parse URLs to get IP addresses
  - will add hostname, domain and will parse non-IP URLs

SQLite3 tables
--------------

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
https://github.com/threat-hunting/awesome-threat-intelligence
www.threat-intel.xyz
https://github.com/sroberts/awesome-iocs
http://iplists.firehol.org -> https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset
