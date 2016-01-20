# encoding: utf-8
require 'logstash/codecs/base'
require 'logstash/codecs/IPFIX/version'
require 'logstash/codecs/IPFIX/util'
require 'logstash/namespace'

class LogStash::Codecs::IPFIX < LogStash::Codecs::Base
  config_name 'ipfix'
  config :target, :validate => :string, :default => "ipfix"

  public
  def initialize(params = {})
    super(params)
    @threadsafe = false
  end

  public
  def register
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

