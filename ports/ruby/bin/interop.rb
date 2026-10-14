# frozen_string_literal: true

# The interop agent for ports/conformance/interop.py: ruby bin/interop.rb URL FLEET_FILE AGENT_ID INSTANCE_ID,
# token in SMARTSWITCH_AGENT_TOKEN. Polls every 100 ms and prints "STATUS code" on every change; exits when
# standard input closes or after 60 s.
require_relative '../lib/smartswitch'

abort 'usage: ruby bin/interop.rb URL FLEET_FILE AGENT_ID INSTANCE_ID' unless ARGV.size == 4
url, fleet_file, agent_id, instance_id = ARGV
agent = SmartSwitch::Agent.new(url, ENV['SMARTSWITCH_AGENT_TOKEN'], SmartSwitch.load_fleet(fleet_file), agent_id, instance_id,
                               poll_ms: 100, timeout: 1.0)
done = Queue.new
Thread.new do
  $stdin.read
rescue StandardError
  nil
ensure
  done << true
end
$stdout.sync = true
last = nil
deadline = SmartSwitch.mono_ms + 60_000
while done.empty? && SmartSwitch.mono_ms < deadline
  code = agent.poll_once['code']
  if code != last
    puts "STATUS #{code}"
    $stdout.flush
    last = code
  end
  done.pop(timeout: 0.1) && break
end
