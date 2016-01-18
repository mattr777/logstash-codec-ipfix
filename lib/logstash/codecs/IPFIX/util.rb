# encoding: utf-8
require 'bindata'
require 'ipaddr'

class IPFIXMessageHeader < BinData::Record
  endian :big
  uint16 :version_number
  uint16 :length_in_bytes
  uint32 :export_time
  uint32 :sequence_number
  uint32 :observation_domain_id
end

class IPFIXSetHeader < BinData::Record
  endian :big
  uint16 :set_id
  uint16 :length_in_bytes
end

class IPFIXTemplateRecordHeader < BinData::Record
  endian :big
  uint16 :template_id
  uint16 :field_count
end

class IPFIXFieldSpecifier < BinData::Record
  endian :big
  uint16 :information_element_id
  uint16 :field_length
end
