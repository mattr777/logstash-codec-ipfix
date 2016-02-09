#!/usr/bin/env bash

curl -XDELETE localhost:9200/_template/logstash_ipfix

sudo /opt/logstash/bin/plugin install /home/mrichards/RubymineProjects/logstash-codec-ipfix/logstash-codec-ipfix-0.1.0.gem
sudo /opt/logstash/bin/plugin uninstall logstash-codec-ipfix

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
