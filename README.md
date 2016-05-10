Cisc0wn2 - Cisco SNMP Script
============================================

Cisco SNMP enumeration, brute force, config downloader and password cracking script.

Tested and designed to work against Cisco IOS Switches and Routers.

Complete rewrite of my original script hosted here:

https://github.com/nccgroup/cisco-SNMP-enumeration

Released under AGPL see LICENSE for more information

Installing  
=======================
    git clone https://github.com/commonexploits/cisco-SNMP-enumeration.git


How To Use	
=======================
    ./cisc0wn2.sh

Features	
=======================

* Checks SNMP is enabled on the route
* Brute forces the SNMP Read Only and Read Write community strings (can edit which wordlist it uses in script header)
* Enumerates information such as IOS version,  hostname, Arp table, Routing table, interface list and IP addresses using the RO or RW community string.
* If RW community was found it will then download the router config automatically.
* It then searches and displays any enable or telnet passwords in clear text.
* If it finds Cisco type 7 encoded enable or telnet passwords it will auto decode them.
* It will display the Enable secret type 5 password hash.
* Added command line features, can specify single community, list of communites in file and router IP. -h to display help.
* Has a few built-in communites in the script code, if no string or list or strings supplied it will try the built in ones.
* Much faster as no longer uses Metasploit, only checks RW access against RO strings found to save duplicate checks. Uses built in TFTP server.

Requirements   
=======================

* No longer requires Metasploit to function.
* Requires snmpwalk and snmpset

Tested Kali Linux



Screen Shot    
=======================
<img src="http://www.commonexploits.com/tools/cisc0wn/1.png" alt="Screenshot" style="max-width:100%;">

<img src="http://www.commonexploits.com/tools/cisc0wn/2.png" alt="Screenshot" style="max-width:100%;">

Change Log
=======================

* Version 2.0 - Complete new version with code cleanup into functions, no longer requires Metasploit. Command line switches added
