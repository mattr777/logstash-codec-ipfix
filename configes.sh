#!/usr/bin/env bash

curl -XPUT localhost:9200/_template/logstash_ipfix -d '{
    "template" : "logstash-ipfix-*",
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
sudo /opt/logstash/bin/plugin uninstall logstash-codec-ipfix

/opt/logstash$ sudo bin/logstash -f /etc/logstash/conf.d/logstash-ipfix.conf --debug


-----------------------------------------------------------------------------
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
-----------------------------------------------------------------------------
input {
  udp {
    port => 2055
    codec => ipfix {
      definitions => "/opt/logstash/enterprise.yaml"
    }
  }
}

output {
  elasticsearch {
    index => "logstash-ipfix-%{+YYYY.MM.dd}"
    hosts => ["localhost:9200"]
  }
}
-----------------------------------------------------------------------------

[mrichards@localhost dev]$ pwd
/opt/tv/scenarios/dev

sudo /usr/local/bin/devicemultiplier --input=pcaps/tfqueryv10.pcap --dst=192.168.0.51 --num_devices=1 --start_address=192.168.0.52 --rate=10

DeviceMultiplier Version 2.62
--input=pcaps/tfqueryv10.pcap
--dst=192.168.0.51
--num_devices=1
--start_address=192.168.0.52
--rate=10

Number of devices: 1
Export rate per device: 10.000 pkts/sec
Number of plays: Continual
Starting at device 3232235572
Using consecutive sequence numbers.
Not printing 'nosleeps'

Steady rate inter-packet interval: 100000.000 microseconds
