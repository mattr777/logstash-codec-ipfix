# encoding: utf-8
require 'logstash/codecs/base'
require 'logstash/codecs/IPFIX/version'
require 'logstash/codecs/IPFIX/util'

class LogStash::Codecs::IPFIX < LogStash::Codecs::Base
  config_name 'ipfix'

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
        LogStash::Event::TIMESTAMP => LogStash::Timestamp.at(message_header.export_time),
        @target => {}
    }

    event[@target]['field1_id'] = field1.information_element_id
    event[@target]['field2_id'] = field2.information_element_id
    event[@target]['field3_id'] = field3.information_element_id
    event[@target]['field4_id'] = field4.information_element_id

    yield LogStash::Event.new(event)
  end # def decode
end # class LogStash::Codecs::IPFIX
