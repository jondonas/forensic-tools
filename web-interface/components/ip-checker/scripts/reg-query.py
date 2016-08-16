#!/usr/bin/python
import requests
import sys
import json

ip = sys.argv[1]

if sys.argv[2] == '1':
  time = sys.argv[3]
  payload = {
              "query": {
                "bool": {
                  "must": [
                    { "match": { "ipaddr":  ip }},
                    { "match": { "datetime": time }}
                  ],
                  "must_not":
                      { "match": { "source":  "virustotal" }}
                }
              }
            }
else:
  payload = {
              "query":  {
                "bool": {
                  "must":
                    { "match": { "ipaddr":  ip }},
                  "must_not":
                    { "match": { "source":  "virustotal" }}
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
