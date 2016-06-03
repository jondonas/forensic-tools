#!/usr/bin/python
import requests
import json

payload = {
                "size" : 0,
                "aggs" : {
                  "counts" : {
                      "cardinality" : {
                        "field" : "ipaddr"
                      }
                  }
              }
          }

r = requests.post("http://localhost:9200/cti/ipaddr/_search", data=json.dumps(payload))
print(r.text)
