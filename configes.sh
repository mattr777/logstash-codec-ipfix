#!/usr/bin/env bash

curl -XPUT localhost:9200/_template/logstash_ipfix -d '{
    "template" : "logstash-ipfix-*",
    "settings": {
      "index.refresh_interval": "15s"
    },
    "mappings" : {
      "_default_" : {
        "_all" : {"enabled" : false},
        "properties" : {
          "@version": { "index": "analyzed", "type": "integer" },
          "@timestamp": { "index": "analyzed", "type": "date" },
          "netflow": {
            "dynamic": true,
            "type": "object",
            "properties": {
              "version": { "index": "analyzed", "type": "integer" },
              "field1_id": { "index": "not_analyzed", "type": "short" },
              "field2_id": { "index": "not_analyzed", "type": "short" },
              "field3_id": { "index": "not_analyzed", "type": "short" },
              "field4_id": { "index": "not_analyzed", "type": "short" }
            }
          }
        }
      }
    }
  }'


sudo /opt/logstash/bin/plugin install --no-verify logstash-codec-ipfix-0.1.0.gem

sudo tcpreplay -i lo short_template.pcap

/opt/logstash/bin$ sudo ./logstash -f /etc/logstash/conf.d/logstash-ipfix.conf --debug
