# Logstash::Codecs::IPFIX

This codec will decode IPFIX version 10 messages for logstash.
It was developed by modifying the logstash-codec-netflow code.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'codecs'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install logstash-codec-ipfix

## Usage with Logstash

To use this codec, include it in a Logstash configuration file such as this:

    input {
      udp {
        port => 2055
        codec => ipfix {
          definitions => "/opt/logstash/enterprise.yaml"
        }
      }
    }

    output {
      stdout { codec => rubydebug }
      elasticsearch {
        index => "logstash-ipfix-%{+YYYY.MM.dd}"
        hosts => ["localhost:9200"]
      }
    }

This codec currently works only with UDP connections. The UDP port must be specified. The
example above uses the standard netflow port of 2055.  Port 4739 is the official port for
IPFIX.

This example also specifies a definitions file for enterprise fields.  This file may be
omitted if only standard IANA fields are used.

For output, this configuration sends results to stdout and to Elasticsearch.  If the output
to stdout is not desired, that line can be deleted.  The output to Elasticsearch goes to
an instance running on the same machine as Logstash and uses an index named
logstash-ipfix- followed by the current date.

Here is an example that does not specify enterprise fields,does not output to stdout, and
uses port 4739:

    input {
      udp {
        port => 4739
        codec => ipfix
      }
    }

    output {
      elasticsearch {
        index => "logstash-ipfix-%{+YYYY.MM.dd}"
        hosts => ["localhost:9200"]
      }
    }

If the configuration is placed in the file /etc/logstash/conf.d/logstash-ipfix.conf, then
logstash can be run with just this configuration in the following manner:

```bash
cd /opt/logstash
sudo bin/logstash -f /etc/logstash/conf.d/logstash-ipfix.conf
```
This assumes that Logstash is installed in /opt/logstash. To turn on debugging, there is
a debug flag for Logstash:
```bash
cd /opt/logstash
sudo bin/logstash -f /etc/logstash/conf.d/logstash-ipfix.conf --debug
```
### Elasticsearch Templates

While Elasticsearch will automatically index the fields exported by this codec, the user
may want to define how the fields are interpreted.  This is done by specifying a
template to Elasticsearch such as this:

```bash
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
```


## Exceptions

IPFIX is documented in RFC 7011: https://tools.ietf.org/html/rfc7011
The standard fields defined by IANA are documented here:
http://www.iana.org/assignments/ipfix/ipfix.xhtml
The fields supported by this codec are defined in the file ipfix.yaml.  This codec does
not yet support support the variable width fields or the more complex fields beyond
primitive types, MAC addresses, and IP addresses.

## Contributing

Bug reports and pull requests are welcome on GitHub at
https://github.com/mattr777/logstash-codec-ipfix


## License

The gem is available as open source under the terms of the [Apache License, Version 2.0](https://opensource.org/licenses/Apache-2.0).

