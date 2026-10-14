# SmartSwitch for Ruby, agent side. Not published on RubyGems; use it from a clone (ruby -Ilib).
Gem::Specification.new do |s|
  s.name = 'sf-smartswitch'
  s.version = '0.1.0'
  s.summary = 'SmartSwitch agent side for Ruby: verifies the switch log, certificates and heartbeats and decides whether an agent may run.'
  s.license = 'Apache-2.0'
  s.authors = ['SmartTasks Lab']
  s.files = Dir['lib/**/*']
  s.required_ruby_version = '>= 3.2'
  s.metadata['allowed_push_host'] = 'https://example.invalid' # not published: refuse `gem push`
end
