# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'logstash/codecs/IPFIX/version'

Gem::Specification.new do |spec|
  spec.name          = 'logstash-codec-ipfix'
  spec.version       = Logstash::Codec::IPFIX::VERSION
  spec.authors       = ['Matt Richards']
  spec.email         = ['yo@richards777.com']

  spec.summary       = %q{The IPFIX codec decodes IPFIX version 10 flows.}
  spec.description   = %q{This codec was developed using the example of the netflow codec, which decodes v5 and v9 flows.}
  spec.homepage      = "TODO: Put your gem's website or public repo URL here."
  spec.license       = 'MIT'

  # Prevent pushing this gem to RubyGems.org by setting 'allowed_push_host', or
  # delete this section to allow pushing this gem to any host.
  if spec.respond_to?(:metadata)
    spec.metadata['allowed_push_host'] = "TODO: Set to 'http://mygemserver.com'"
  else
    raise 'RubyGems 2.0 or newer is required to protect against public gem pushes.'
  end

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.require_paths = ['lib']

  spec.test_files = spec.files.grep(%r{^(test|spec|features)/})


  # Special flag to let us know this is actually a logstash plugin
  spec.metadata = {'logstash_plugin' => 'true', 'logstash_group' => 'codec'}

  spec.add_development_dependency 'bundler', '~> 1.11'
  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'rspec', '~> 3.0'
  spec.add_runtime_dependency 'logstash-core', '>= 2.1.0', '< 3.0.0'
  spec.add_runtime_dependency 'bindata', '>= 2.1', '< 3.0'
  spec.add_development_dependency 'logstash-devutils', '~> 0.0.18'
end
