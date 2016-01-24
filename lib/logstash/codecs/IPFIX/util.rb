# encoding: utf-8
require 'bindata'
require 'ipaddr'

class IP4Addr < BinData::Primitive
  endian :big
  uint32 :storage

  def set(val)
    ip = IPAddr.new(val)
    if ! ip.ipv4?
      raise ArgumentError, "invalid IPv4 address '#{val}'"
    end
    self.storage = ip.to_i
  end

  def get
    IPAddr.new_ntoh([self.storage].pack('N')).to_s
  end
end

class IP6Addr < BinData::Primitive
  endian  :big
  uint128 :storage

  def set(val)
    ip = IPAddr.new(val)
    if ! ip.ipv6?
      raise ArgumentError, "invalid IPv6 address `#{val}'"
    end
    self.storage = ip.to_i
  end

  def get
    IPAddr.new_ntoh((0..7).map { |i|
      (self.storage >> (112 - 16 * i)) & 0xffff
    }.pack('n8')).to_s
  end
end

class MacAddr < BinData::Primitive
  array :bytes, :type => :uint8, :initial_length => 6

  def set(val)
    ints = val.split(/:/).collect { |int| int.to_i(16) }
    self.bytes = ints
  end

  def get
    self.bytes.collect { |byte| byte.to_s(16) }.join(":")
  end
end

class Header < BinData::Record
  endian :big
  uint16 :version_number
end

class IANAField < BinData::Record
  endian :big
end

class EnterpriseField < BinData::Record
  endian :big
  uint32 :enterprise_number
end

class TemplateFlowset < BinData::Record
  endian :big
  array  :templates, :read_until => lambda { array.num_bytes == set_length_in_bytes - 4 } do
    uint16 :template_id
    uint16 :field_count
    array  :fields, :initial_length => :field_count do
      uint16 :field_type
      uint16 :field_length
      choice :information_element, :selection => lambda { (field_type & 0x8000) == 0x8000 } do
        IANAField false
        EnterpriseField   true
      end
    end
  end
end

class OptionFlowset < BinData::Record
  endian :big
  array  :templates, :read_until => lambda { set_length_in_bytes - 4 - array.num_bytes <= 2 } do
    uint16 :template_id
    uint16 :scope_length
    uint16 :option_length
    array  :scope_fields, :initial_length => lambda { scope_length / 4 } do
      uint16 :field_type
      uint16 :field_length
    end
    array  :option_fields, :initial_length => lambda { option_length / 4 } do
      uint16 :field_type
      uint16 :field_length
    end
  end
  skip   :length => lambda { templates.length.odd? ? 2 : 0 }
end


class IPFIXSet < BinData::Record
  endian :big
  uint16 :version_number
  uint16 :message_length_in_bytes
  uint32 :export_time
  uint32 :sequence_number
  uint32 :observation_domain_id
  array  :records, :read_until => :eof do
    uint16 :set_id
    uint16 :set_length_in_bytes
    choice :flowset_data, :selection => :set_id do
      TemplateFlowset 2
      OptionFlowset   3
      string           :default, :read_length => lambda { set_length_in_bytes - 4 }
    end
  end
end

# https://gist.github.com/joshaven/184837
class Vash < Hash
  def initialize(constructor = {})
    @register ||= {}
    if constructor.is_a?(Hash)
      super()
      merge(constructor)
    else
      super(constructor)
    end
  end

  alias_method :regular_writer, :[]= unless method_defined?(:regular_writer)
  alias_method :regular_reader, :[] unless method_defined?(:regular_reader)

  def [](key)
    sterilize(key)
    clear(key) if expired?(key)
    regular_reader(key)
  end

  def []=(key, *args)
    if args.length == 2
      value, ttl = args[1], args[0]
    elsif args.length == 1
      value, ttl = args[0], 60
    else
      raise ArgumentError, "Wrong number of arguments, expected 2 or 3, received: #{args.length+1}\n"+
          "Example Usage:  volatile_hash[:key]=value OR volatile_hash[:key, ttl]=value"
    end
    sterilize(key)
    ttl(key, ttl)
    regular_writer(key, value)
  end

  def merge(hsh)
    hsh.map {|key,value| self[sterile(key)] = hsh[key]}
    self
  end

  def cleanup!
    now = Time.now.to_i
    @register.map {|k,v| clear(k) if v < now}
  end

  def clear(key)
    sterilize(key)
    @register.delete key
    self.delete key
  end

  private
  def expired?(key)
    Time.now.to_i > @register[key].to_i
  end

  def ttl(key, secs=60)
    @register[key] = Time.now.to_i + secs.to_i
  end

  def sterile(key)
    String === key ? key.chomp('!').chomp('=') : key.to_s.chomp('!').chomp('=').to_sym
  end

  def sterilize(key)
    key = sterile(key)
  end
end

