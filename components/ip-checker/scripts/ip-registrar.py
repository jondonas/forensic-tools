#!/usr/bin/python
#The purpose of this script is to gather IP registration information
# about a given IP address.  This information will then be stored in 
# Paladion's ElasticSearch warehouse.
#
# Usage:
#    ip-registrar.py $IPaddress
#
# Test cases:
#   174.94.149.64 - Returns two assignment records
#   31.13.74.36 - Returns RIPE assignment
#   200.3.14.10 - Returns LACNIC assignment
#   202.32.211.142 - Returns JPNIC assignment
#   164.100.78.177 - Returns APNIC assignment
#   196.216.2.6 - Returns AFRINIC assignment
import sys
import json
import urllib2
import httplib
import subprocess
from subprocess import CalledProcessError, STDOUT
import re
import dns.resolver
import dns.reversename
import time
from datetime import datetime
from elasticsearch import Elasticsearch


#Start of program
ipaddr=sys.argv[1]
workspace="/cti/workspace"
whoismatch=0


#Call whois to get information about the IP address registration
# try/except is used to exit gracefully and ignore error if whois command times out
try:
	whois = subprocess.check_output(("timeout --preserve-status 5 whois " + ipaddr).split(), stderr=STDOUT)
except CalledProcessError as ex:
	whois = ex.output

entries=0
netname=[]
netrange=[]
organization=[]
#Pull the 'netrange' out of the whois info
search=re.compile('^netrange:\s*(.*)$|^inetnum:\s*(.*)$|\[network number]\s*(.*)$',re.I+re.M)
results=search.findall(whois)
i=0
for x in results:
        #Since we have 2 regular expressions being matched against, there will be 2 results
        # Parse them into y and z, and use whichever matched.
        w,y,z=x
        if z:
                netrange.append(str(z))
        elif y:
                netrange.append(str(y))
        else:
                netrange.append(str(w))
	i=i+1
        whoismatch=1
entries=i		

#Pull the 'netname' out of the whois info
search=re.compile('^netName:\s*(.*)$|\[network name\]\s*(.*)$',re.I+re.M)
results=search.findall(whois)
for x in results:
	#Since we have 2 regular expressions being matched against, there will be 2 results
	# Parse them into y and z, and use whichever matched.
	y,z=x
	if z:
		netname.append(str(z))
	else:
		netname.append(str(y))
	whoismatch=1


#Pull the 'organization' or 'customer' out of the whois info
search=re.compile('^organization:\s*(.*)$|^descr:\s*(.*)$|^customer:\s*(.*)$|\[organization\]\s*(.*)$|^owner:\s*(.*)$',re.I+re.M)
results=search.findall(whois)
for x in results:
	#Since we have 2 regular expressions being matched against, there will be 2 results
	# Parse them into y and z, and use whichever matched.
	u,v,w,y,z=x
	if z:
		organization.append(str(z))
	elif y:
		organization.append(str(y))
	elif w:
		organization.append(str(w))
	elif v:
		organization.append(str(v))
	else:
		organization.append(str(u))
		

	whoismatch=1


search=re.compile('whois.(lacnic).net|whois.nic.ad.(jp)|www.(ripe).net|www.(apnic).net|(AfriNIC) Whois',re.I+re.M)
results=search.findall(whois)
registrar="arin"
for x in results:
	for y in x:
		if y=="lacnic":
			registrar="lacnic"
		if y=="jp":
			registrar="jpnic"
		if y=="ripe":
			registrar="ripe"
		if y=="apnic":
			registrar="apnic"
		if y=="AfriNIC":
			registrar="afrinic"

i=0
curtime = time.strftime("%m")+'/'+time.strftime("%d")+'/'+time.strftime("%Y")+' '+time.strftime("%X")

while i < entries:
	#Because LACNIC doesn't have the concept of a network "name", 
	# check if the netname is valid.
	try:
		a=netname[i]
	except IndexError:
		a=''
	jsonregistrar={"source": registrar, "netname": a, "netrange": netrange[i], "organization": organization[i] , "datetime": curtime, "ipaddr": ipaddr}
	#Store information in ElasticSearch
	conn = httplib.HTTPConnection("localhost", 9200)
	conn.request("POST", "/cti/ipaddr/?pretty", json.dumps(jsonregistrar))
	response = conn.getresponse()
	print response.status, response.reason
	data = response.read()
	print data
	print json.dumps(jsonregistrar)
	i=i+1


