# encoding: utf-8
require 'logstash/codecs/base'
require 'logstash/codecs/IPFIX/version'
require 'logstash/codecs/IPFIX/util'
require 'logstash/namespace'

class LogStash::Codecs::IPFIX < LogStash::Codecs::Base
  config_name 'ipfix'

  # template cache TTL (minutes)
  config :cache_ttl, :validate => :number, :default => 4000

  # Specify into what field you want the IPFIX data.
  config :target, :validate => :string, :default => "ipfix"

  # Override YAML file containing IPFIX information elements
  # See <http://www.iana.org/assignments/ipfix/ipfix.xhtml> for IANA definitions
  #
  # Each field is defined like so:
  #
  #    ---
  #    id:
  #    - default length in bytes
  #    - :name
  #    id:
  #    - :uintN or :ip4_addr or :ip6_addr or :mac_addr or :string
  #    - :name
  #    id:
  #    - :skip
  #
  # See <https://github.com/logstash-plugins/logstash-codec-netflow/blob/master/lib/logstash/codecs/netflow/netflow.yaml> for the base set.
  config :definitions, :validate => :path

  public
  def initialize(params = {})
    super(params)
    @threadsafe = false
  end

  public
  def register
    @templates = Vash.new()

    # Path to default field definitions
    filename = ::File.expand_path('IPFIX/ipfix.yaml', ::File.dirname(__FILE__))

    begin
      @fields = YAML.load_file(filename)
    rescue Exception => e
      raise "#{self.class.name}: Bad syntax in definitions file #{filename}"
    end

    # Allow the user to augment/override/rename the supported fields
    if @definitions
      raise "#{self.class.name}: definitions file #{@definitions} does not exists" unless File.exists?(@definitions)
      begin
        @fields.merge!(YAML.load_file(@definitions))
      rescue Exception => e
        raise "#{self.class.name}: Bad syntax in definitions file #{@definitions}"
      end
    end
  end # def register

  public
  def decode(payload, &block)
    message_header = IPFIXMessageHeader.read(payload)
    set_header = IPFIXSetHeader.read(payload)
    template_header = IPFIXTemplateRecordHeader.read(payload)
    field1 = IPFIXFieldSpecifier.read(payload)
    field2 = IPFIXFieldSpecifier.read(payload)
    field3 = IPFIXFieldSpecifier.read(payload)
    field4 = IPFIXFieldSpecifier.read(payload)

    event = {
        LogStash::Event::TIMESTAMP => LogStash::Timestamp.at(message_header.export_time.snapshot),
        @target => {}
    }

    event[@target]['version'] = message_header.version_number.snapshot
    event[@target]['sequence_number'] = message_header.sequence_number.snapshot
    event[@target]['observation_domain_id'] = message_header.observation_domain_id.snapshot
    event[@target]['set_id'] = set_header.set_id.snapshot
    event[@target]['template_id'] = template_header.template_id.snapshot
    event[@target]['field_count'] = template_header.field_count.snapshot
    event[@target]['field1_id'] = field1.information_element_id.snapshot
    event[@target]['field2_id'] = field2.information_element_id.snapshot
    event[@target]['field3_id'] = field3.information_element_id.snapshot
    event[@target]['field4_id'] = field4.information_element_id.snapshot


    yield LogStash::Event.new(event)
  end # def decode
end # class LogStash::Codecs::IPFIX

