require 'spec_helper'

describe Logstash::Codec::IPFIX do
  it 'has a version number' do
    expect(Logstash::Codec::IPFIX::VERSION).not_to be nil
  end

  it 'does something useful' do
    expect(false).to eq(true)
  end
end
