#!/usr/bin/python
from HTMLParser import HTMLParser
import sys
import json
import urllib2
import httplib
import subprocess
import re
import dns.resolver
import dns.reversename
import time
from datetime import datetime
from elasticsearch import Elasticsearch

#Start of program
ipaddr=sys.argv[1]
apikey='7d92c292f26e53a26cd04c1f8816ed91c158e295759bf633a1fe2ba3e40c5911'
workspace="/cti/workspace"
whoismatch=0

#Use Virustotal API key to gather info on IP address
response = urllib2.urlopen('http://www.virustotal.com/vtapi/v2/ip-address/report?ip='+ipaddr+"&apikey="+apikey)
html = response.read()

jsonvirustotal=json.loads(html)
source={"source": "virustotal", "ipaddr": ipaddr, "datetime": time.strftime("%m")+'/'+time.strftime("%d")+'/'+time.strftime("%Y")+' '+time.strftime("%X")}
jsonoutput=dict(jsonvirustotal.items()+source.items())
#jsonvirustotal.append({"datetime":  time.strftime("%c")})
print jsonoutput

#Store virustotal information into ElasticSearch
conn = httplib.HTTPConnection("localhost", 9200)
conn.request("POST", "/cti/ipaddr/?pretty", json.dumps(jsonoutput))
response = conn.getresponse()
print response.status, response.reason
data = response.read()
print data

#time.sleep(15)
