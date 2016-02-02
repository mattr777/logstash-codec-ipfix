#!/usr/bin/env bash

curl -XPUT localhost:9200/_template/logstash_ipfix -d '{
    "template" : "logstash-ipfix3-*",
    "settings": {
      "index.refresh_interval": "5s"
    },
    "mappings" : {
      "logs" : {
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
              "source_ipv4_address": { "index": "not_analyzed", "type": "ip" },
              "destination_ipv4_address": { "index": "not_analyzed", "type": "ip" },
              "source_ipv6_address": { "index": "not_analyzed", "type": "string" },
              "destination_ipv6_address": { "index": "not_analyzed", "type": "string" },
              "ingress_interface": { "index": "not_analyzed", "type": "integer" },
              "packet_delta_count": { "index": "not_analyzed", "type": "long" },
              "octet_delta_count": { "index": "not_analyzed", "type": "long" },
              "flow_start_milliseconds": { "index": "not_analyzed", "type": "long" },
              "flow_end_milliseconds": { "index": "not_analyzed", "type": "long" },
              "source_transport_port": { "index": "not_analyzed", "type": "integer" },
              "destination_transport_port": { "index": "not_analyzed", "type": "integer" },
              "protocol_identifier": { "index": "not_analyzed", "type": "short" },
              "ip_class_of_service": { "index": "not_analyzed", "type": "short" },
              "vlan_id": { "index": "not_analyzed", "type": "integer" },
              "flow_id": { "index": "not_analyzed", "type": "long" },
              "server_indicator": { "index": "not_analyzed", "type": "boolean" },
              "application_id": { "index": "not_analyzed", "type": "integer" },
              "client_site": { "index": "not_analyzed", "type": "integer" },
              "server_site": { "index": "not_analyzed", "type": "integer" }
            }
          }
        }
      }
    }
  }'

curl -XDELETE localhost:9200/_template/logstash_ipfix

sudo /opt/logstash/bin/plugin install /home/mrichards/RubymineProjects/logstash-codec-ipfix/logstash-codec-ipfix-0.1.0.gem

sudo tcpreplay -i lo short_template.pcap

/opt/logstash$ sudo bin/logstash -f /etc/logstash/conf.d/logstash-ipfix.conf --debug



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
