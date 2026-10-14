# frozen_string_literal: true

# ruby bin/conformance.rb DIR: runs spec/conformance/*.json against the Ruby port, as the Python runner does.
require_relative '../lib/smartswitch'

dir = ARGV[0] || File.join(__dir__, '..', '..', '..', 'spec', 'conformance')
load_v = ->(n) { JSON.parse(File.read(File.join(dir, n), encoding: 'UTF-8')) }
c = lambda do |v|
  SmartSwitch.canonical(v)
rescue SmartSwitch::CanonicalError => e
  "<not canonical: #{e.message}>"
end
total = 0
fails = []
check = lambda do |name, got, want|
  total += 1
  g = c.(got)
  w = c.(want)
  fails << "#{name}: got #{g[0, 300]}, want #{w[0, 300]}" unless g == w
end
pick = ->(cs, keys) { cs.slice(*keys) }

load_v.('canonical.json')['cases'].each do |cs|
  text = c.(cs['input'])
  check.("canonical/#{cs['name']}", [text, SmartSwitch.sha256_hex(text)], [cs['canonical'], cs['sha256']])
end

load_v.('ed25519.json')['cases'].each do |cs|
  check.("ed25519/#{cs['name']}", SmartSwitch.verify(cs['public_key'], [cs['message_hex']].pack('H*'), cs['sig']), cs['valid'])
end

v = load_v.('fleets.json')
v['default_thresholds'].each { |cs| check.("fleets/default threshold n=#{cs['n']}", SmartSwitch.default_threshold(cs['n']), cs['k']) }
v['cases'].each do |cs|
  got = begin
    SmartSwitch.validate_fleet(cs['fleet'])
    { 'ok' => true, 'fleet_hash' => SmartSwitch.doc_hash(cs['fleet']), 'threshold' => SmartSwitch::State.genesis(cs['fleet']).threshold }
  rescue SmartSwitch::SwitchError => e
    { 'ok' => false, 'code' => e.code }
  end
  check.("fleets/#{cs['name']}", got, pick.(cs, %w[ok fleet_hash threshold code]))
end

v = load_v.('certificates.json')
v['cases'].each do |cs|
  st = SmartSwitch::State.genesis(v['fleets'][cs['fleet']])
  cs['setup'].each { |s| st = SmartSwitch.apply(st, s['certificate'], s['at_ms']) }
  cert = cs['certificate']
  ph = nil
  if cert.is_a?(Hash) && cert.key?('proposal')
    ph = begin
      SmartSwitch.proposal_hash(cert['proposal'])
    rescue SmartSwitch::CanonicalError
      nil
    end
  end
  check.("certificates/#{cs['name']} (proposal hash)", ph, cs['proposal_hash'])
  got = begin
    if cs['ahead']
      SmartSwitch.verify_certificate(st, cert, cs['at_ms'], ahead: true)
      { 'ok' => true, 'state' => nil }
    else
      { 'ok' => true, 'state' => SmartSwitch.apply(st, cert, cs['at_ms']).summary }
    end
  rescue SmartSwitch::SwitchError => e
    { 'ok' => false, 'code' => e.code }
  end
  check.("certificates/#{cs['name']}", got, pick.(cs, %w[ok state code]))
end

load_v.('logs.json')['cases'].each do |cs|
  check.("logs/#{cs['name']}", SmartSwitch.replay(cs['entries'], cs['pinned']), cs['result'])
end

v = load_v.('agent.json')
v['cases'].each do |cs|
  view = SmartSwitch::AgentView.new(v['fleet'], cs['agent_id'], cs['instance_id'])
  cs['steps'].each_with_index do |s, i|
    got = case s['op']
          when 'log' then view.log(s['entries'])
          when 'heartbeat' then view.heartbeat(s['heartbeat'], s['nonce'], s['at_ms'])
          when 'certificate' then view.certificate(s['certificate'], s['at_ms'])
          else view.status(s['at_ms'])
          end
    check.("agent/#{cs['name']} step #{i} (#{s['op']})", got, s['expect'])
  end
end

fails.each { |f| puts "FAIL #{f}" }
if fails.empty?
  puts "ruby: #{total}/#{total} vectors passed"
else
  puts "ruby: #{fails.size} of #{total} vectors FAILED"
  exit 1
end
