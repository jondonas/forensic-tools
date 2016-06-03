#!/usr/bin/python
import requests
import sys
import json

ip = sys.argv[1]

payload = {
            "query": {
              "match": {
              "ipaddr": ip}
            }
          }

r = requests.post("http://localhost:9200/cti/ipaddr/_search/exists", data=json.dumps(payload))
print(r.text)
