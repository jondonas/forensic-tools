#!/usr/bin/python
import requests
import sys
import json

ip = sys.argv[1]

payload = {
            "query": {
              "bool": {
                "must": [
                  { "match": { "ipaddr":  ip }},
                  { "match": { "source": "virustotal"   }}
                ]
              }
            },
            "size": 1,
            "sort":
              {
                "datetime": {
                  "order": "desc"
                }
              }
          }

r = requests.post("http://localhost:9200/cti/_search?pretty", data=json.dumps(payload))
print(r.text)
