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
          "ipfix": {
            "dynamic": true,
            "type": "object",
            "properties": {
              "version": { "index": "not_analyzed", "type": "integer" },
              "sequence_number": { "index": "not_analyzed", "type": "integer" },
              "observation_domain_id": { "index": "not_analyzed", "type": "integer" },
              "set_id": { "index": "not_analyzed", "type": "integer" },
              "template_id": { "index": "not_analyzed", "type": "integer" },
              "field_count": { "index": "not_analyzed", "type": "integer" },
              "field1_id": { "index": "not_analyzed", "type": "integer" },
              "field2_id": { "index": "not_analyzed", "type": "integer" },
              "field3_id": { "index": "not_analyzed", "type": "integer" },
              "field4_id": { "index": "not_analyzed", "type": "integer" }
            }
          }
        }
      }
    }
  }'

sudo /opt/logstash/bin/plugin install --no-verify logstash-codec-ipfix-0.1.0.gem
sudo /opt/logstash/bin/plugin install /home/mrichards/RubymineProjects/logstash-codec-ipfix/logstash-codec-ipfix-0.1.0.gem

sudo tcpreplay -i lo short_template.pcap

/opt/logstash/bin$ sudo ./logstash -f /etc/logstash/conf.d/logstash-ipfix.conf --debug



input {
  udp {
    port => 4739
    codec => ipfix
  }
}

output {
  stdout { codec => rubydebug }
  elasticsearch {
    index => "logstash-ipfix-%{+YYYY.MM.dd}"
    hosts => ["localhost:9200"]
  }
}
