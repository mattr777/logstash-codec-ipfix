# encoding: utf-8
require 'logstash/codecs/base'
require 'logstash/codecs/IPFIX/version'
require 'logstash/codecs/IPFIX/util'
require 'logstash/namespace'
require 'logstash/codecs/IPFIX/util'

class LogStash::Codecs::IPFIX < LogStash::Codecs::Base
  config_name 'ipfix'

  # template cache TTL (minutes)
  config :cache_ttl, :validate => :number, :default => 4000

  # Specify into what field you want the IPFIX data.
  config :target, :validate => :string, :default => 'ipfix'

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

  IPFIX10_FIELDS = %w{ sequence_number observation_domain_id }

  public
  def initialize(params = {})
    super(params)
    @threadsafe = false
  end

  public
  def register
    @templates = Vash.new

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
    message_header = Header.read(payload)

    if message_header.version_number == 10
      flowset = IPFIXSet.read(payload)
      flowset.records.each do |record|
        decode_ipfix10(flowset, record).each{|event| yield(event)}
      end
    else
      @logger.warn("Unsupported IPFIX version v#{header.version}")
    end
  end # def decode

  private
  def decode_ipfix10(flowset, record)
    events = []

    case record.set_id
      when 2
        # Template set
        record.flowset_data.templates.each do |template|
          catch (:field) do
            fields = []
            template.fields.each do |field|
              entry = netflow_field_for(field.field_type, field.field_length)
              throw :field unless entry
              fields += entry
            end
            # We get this far, we have a list of fields
            key = "#{flowset.observation_domain_id}|#{template.template_id}"
            @templates[key, @cache_ttl] = BinData::Struct.new(:endian => :big, :fields => fields)
            # Purge any expired templates
            @templates.cleanup!
          end
        end
      when 3
        # Options template set
        record.flowset_data.templates.each do |template|
          catch (:field) do
            fields = []
            template.option_fields.each do |field|
              entry = netflow_field_for(field.field_type, field.field_length)
              throw :field unless entry
              fields += entry
            end
            # We get this far, we have a list of fields
            key = "#{flowset.observation_domain_id}|#{template.template_id}"
            @templates[key, @cache_ttl] = BinData::Struct.new(:endian => :big, :fields => fields)
            # Purge any expired templates
            @templates.cleanup!
          end
        end
      when 256..65535
        # Data set
        key = "#{flowset.observation_domain_id}|#{record.set_id}"
        template = @templates[key]

        unless template
          @logger.warn("No matching template for set id #{record.set_id}")
          return
        end

        length = record.set_length_in_bytes - 4

        # Template shouldn't be longer than the record and there should
        # be at most 3 padding bytes
        if template.num_bytes > length or ! (length % template.num_bytes).between?(0, 3)
          @logger.warn("Template length doesn't fit cleanly into flowset", :template_id => record.set_id, :template_length => template.num_bytes, :record_length => length)
          return
        end

        array = BinData::Array.new(:type => template, :initial_length => length / template.num_bytes)
        records = array.read(record.flowset_data)

        records.each do |r|
          event = {
              LogStash::Event::TIMESTAMP => LogStash::Timestamp.at(flowset.export_time),
              @target => {}
          }

          IPFIX10_FIELDS.each do |f|
            event[@target][f] = flowset[f].snapshot
          end

          event[@target]['set_id'] = record.set_id.snapshot

          r.each_pair do |k, v|
            event[@target][k.to_s] = v.snapshot
          end

          events << LogStash::Event.new(event)
        end
      else
        @logger.warn("Unsupported set id #{record.set_id}")
    end

    events
  end

  def uint_field(length, default)
    # If length is 4, return :uint32, etc. and use default if length is 0
    ('uint' + (((length > 0) ? length : default) * 8).to_s).to_sym
  end # def uint_field

  def netflow_field_for(type, length)
    if @fields.include?(type)
      field = @fields[type]
      if field.is_a?(Array)

        field[0] = uint_field(length, field[0]) if field[0].is_a?(Integer)

        # Small bit of fixup for skip or string field types where the length
        # is dynamic
        case field[0]
          when :skip
            field += [nil, {:length => length}]
          when :string
            field += [{:length => length, :trim_padding => true}]
        end

        @logger.debug? and @logger.debug('Definition complete', :field => field)

        [field]
      else
        @logger.warn('Definition should be an array', :field => field)
        nil
      end
    else
      @logger.warn('Unsupported field', :type => type, :length => length)
      nil
    end
  end # def netflow_field_for
end # class LogStash::Codecs::IPFIX

