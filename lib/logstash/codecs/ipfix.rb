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
  config :target, :validate => :string, :default => 'ipfix'

  # Add enterprise field definitions
  # See <https://tools.ietf.org/html/rfc7011#section-3.2> for Field Specifier Format
  # See <https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers> for Private Enterprise Numbers
  #
  # Enterprise fields are defined in the YAML file like so:
  #
  # ---
  # 1246:
  #   10:
  #   - :uint32
  #   - :application_id
  #   17:
  #   - :uint32
  #   - :client_site
  #   18:
  #   - :uint32
  #   - :server_site
  #   30:
  #   - :uint8
  #   - :server_indicator
  config :definitions, :validate => :path

  IPFIX10_FIELDS = %w{ export_time sequence_number observation_domain_id }

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
      raise "#{self.class.name}: Bad syntax in definitions file #{filename}: " + e.message
    end

    # Allow the user to supply enterprise fields
    if @definitions
      raise "#{self.class.name}: definitions file #{@definitions} does not exist" unless File.exists?(@definitions)
      begin
        @enterprise_fields = YAML.load_file(@definitions)
        @logger.debug? and @logger.debug('Enterprise fields: ', @enterprise_fields)
      rescue Exception => e
        raise "#{self.class.name}: Bad syntax in definitions file #{@definitions}: " + e.message
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

  # enterprise_field_for(type, length, enterprise_number)
  # if (type & 0x8000) == 0x8000
  #   if @enterprise_fields.include?(type & 0xFFF)

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
              if (field.field_type & 0x8000) == 0x8000
                entry = enterprise_field_for((field.field_type & 0xFFF), field.field_length, field.information_element.enterprise_number)
                throw :field unless entry
                fields += entry
              else
                entry = iana_field_for(field.field_type, field.field_length)
                throw :field unless entry
                fields += entry
              end
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
              entry = iana_field_for(field.field_type, field.field_length)
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
              LogStash::Event::TIMESTAMP => LogStash::Timestamp.at(Time.now.to_i),
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

  def iana_field_for(type, length)
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
        field = []
        field[0] = uint_field(length, 4)
        field[1] = ('unknown_field_'+type.to_s).to_sym

        @logger.debug? and @logger.debug('Definition complete', :field => field)

        [field]
      end
    else
      @logger.warn('Unknown field', :type => type, :length => length)
      field = []
      field[0] = uint_field(length, 4)
      field[1] = ('unknown_field_'+type.to_s).to_sym

      @logger.debug? and @logger.debug('Definition complete', :field => field)

      [field]
    end
  end

  # def iana_field_for

  def enterprise_field_for(type, length, enterprise_number)
    if @enterprise_fields.include?(enterprise_number)
      fields = @enterprise_fields[enterprise_number]
      if fields.include?(type)
        field = fields[type]

        @logger.debug? and @logger.debug('Enterprise definition complete', :field => field)

        [field]
      else
        field = []
        field[0] = uint_field(length, 4)
        field[1] = ('enterprise_field_'+(type & 0xFFF).to_s).to_sym

        @logger.debug? and @logger.debug('Unknown enterprise field definition complete', :field => field)

        [field]
      end
    else
      @logger.warn('Unknown enterprise number', :type => type, :length => length, :enterprise_number => enterprise_number)
      field = []
      field[0] = uint_field(length, 4)
      field[1] = ('enterprise_field_'+type.to_s).to_sym

      @logger.debug? and @logger.debug('Unknown enterprise definition complete', :field => field)

      [field]
    end
  end # def enterprise_field_for
end # class LogStash::Codecs::IPFIX

