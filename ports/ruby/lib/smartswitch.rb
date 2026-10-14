# frozen_string_literal: true

# SmartSwitch for Ruby, agent side (spec/SEMANTICS.md): canonical JSON, strict Ed25519 verify, fleet
# validation, certificate checks and apply, log replay, the agent view and a networked agent.
#
# Documents are what JSON.parse returns (Hash, Array, Integer, Float, String, true, false, nil); only
# Integer counts as an integer, so 2.5, true and "1" are refused where one is required.
require 'json'
require 'monitor'
require 'digest'
require 'openssl'
require 'securerandom'
require 'set'
require 'net/http'
require 'uri'

module SmartSwitch
  MAX_INT = 2**53 - 1
  MAX_KEYHOLDERS = 64
  MAX_AGENTS = 100_000
  MAX_REASON_BYTES = 1000
  GENESIS_PREV = ('0' * 64).freeze
  VOTE_PREFIX = 'smartswitch-vote-v1:'
  HEARTBEAT_PREFIX = 'smartswitch-heartbeat-v1:'
  ID = /\A[A-Za-z0-9._-]{1,64}\z/
  HEX64 = /\A[0-9a-f]{64}\z/
  HEX128 = /\A[0-9a-f]{128}\z/
  NONCE = /\A[0-9a-f]{32}\z/
  ACTIONS = %w[halt resume suspend reinstate].freeze
  KINDS = %w[genesis certificate event].freeze
  FLEET_FIELDS = %w[type version fleet_id keyholders threshold coordinator_key offline_timeout_ms proposal_max_ttl_ms
                    agents].sort.freeze
  PROPOSAL_FIELDS = %w[type fleet_id fleet_hash seq epoch action target new_public_key reason created_ms expires_ms].sort.freeze
  ENTRY_FIELDS = %w[n ts_ms kind body prev hash].sort.freeze
  HEARTBEAT_FIELDS = %w[type fleet_hash agent_id instance_id nonce log_size head issued_ms sig].sort.freeze
  L = 2**252 + 27_742_317_777_372_353_535_851_937_790_883_648_493
  SPKI_PREFIX = ['302a300506032b6570032100'].pack('H*').freeze

  # A rule was broken; +code+ is the stable SW-* code.
  class SwitchError < StandardError
    attr_reader :code

    def initialize(code, message = '')
      super(message.empty? ? code : "#{code}: #{message}")
      @code = code
    end
  end

  # Raised by Agent#checkpoint when the agent may not run.
  class Halted < StandardError
    attr_reader :code

    def initialize(code)
      super("SmartSwitch: this agent may not run (#{code})")
      @code = code
    end
  end

  # A value with no canonical form (a float, a non-ASCII key, text that is not valid UTF-8, another type).
  class CanonicalError < ArgumentError; end

  # ---------------------------------------------------------------- encodings

  ESCAPES = { '"' => '\\"', '\\' => '\\\\', "\b" => '\\b', "\f" => '\\f', "\n" => '\\n', "\r" => '\\r', "\t" => '\\t' }.freeze

  def self.canon_str(s)
    s = s.dup.force_encoding(Encoding::UTF_8) unless s.encoding == Encoding::UTF_8
    raise CanonicalError, 'canonical JSON strings must be valid UTF-8' unless s.valid_encoding?

    body = s.gsub(/["\\\x00-\x1f]/) { |ch| ESCAPES[ch] || format('\\u%04x', ch.ord) }
    "\"#{body}\""
  end

  # Canonical JSON text (SEMANTICS.md, "Encodings"), UTF-8. Raises CanonicalError.
  def self.canonical(v)
    case v
    when nil then 'null'
    when true then 'true'
    when false then 'false'
    when Integer then v.to_s
    when String then canon_str(v)
    when Array then "[#{v.map { |x| canonical(x) }.join(',')}]"
    when Hash
      v.each_key { |k| raise CanonicalError, 'object keys must be ASCII strings' unless k.is_a?(String) && k.ascii_only? }
      "{#{v.keys.sort.map { |k| "#{canon_str(k)}:#{canonical(v[k])}" }.join(',')}}"
    when Float then raise CanonicalError, 'canonical JSON allows integers only'
    else raise CanonicalError, "canonical JSON cannot encode #{v.class}"
    end
  end

  def self.sha256_hex(bytes) = Digest::SHA256.hexdigest(bytes)

  # sha256 of the canonical form; raises CanonicalError when there is none.
  def self.doc_hash(v) = sha256_hex(canonical(v))

  def self.id?(v) = v.is_a?(String) && ID.match?(v)
  def self.key_hex?(v) = v.is_a?(String) && HEX64.match?(v)
  def self.int_in?(v, lo, hi) = v.is_a?(Integer) && v >= lo && v <= hi
  def self.exactly?(o, fields) = o.is_a?(Hash) && o.keys.sort == fields

  # ---------------------------------------------------------------- Ed25519

  # Strict verify (SEMANTICS.md, "Signatures"): lower-case hex of the right lengths, S < L, then OpenSSL.
  # Any library error is false.
  def self.verify(public_hex, message, sig_hex)
    return false unless key_hex?(public_hex) && sig_hex.is_a?(String) && HEX128.match?(sig_hex)

    sig = [sig_hex].pack('H*')
    return false if sig.byteslice(32, 32).reverse.unpack1('H*').to_i(16) >= L

    key = OpenSSL::PKey.read(SPKI_PREFIX + [public_hex].pack('H*'))
    key.verify(nil, sig, message.b) == true
  rescue StandardError
    false
  end

  # ---------------------------------------------------------------- fleet

  # 2 for up to five keyholders; floor(n/2) + 1 above five.
  def self.default_threshold(n) = n <= 5 ? 2 : n / 2 + 1

  # Returns +doc+ if it is a valid fleet document; raises SwitchError('SW-BAD-FLEET') otherwise.
  def self.validate_fleet(doc)
    bad = ->(m) { raise SwitchError.new('SW-BAD-FLEET', m) }
    bad.("the fleet document must have exactly the fields #{FLEET_FIELDS.join(', ')}") unless exactly?(doc, FLEET_FIELDS)
    bad.('type must be "smartswitch.fleet" and version 1') unless doc['type'] == 'smartswitch.fleet' && int_in?(doc['version'], 1, 1)
    bad.('fleet_id must match [A-Za-z0-9._-]{1,64}') unless id?(doc['fleet_id'])
    khs = doc['keyholders']
    bad.("keyholders must be a list of 3 to #{MAX_KEYHOLDERS}") unless khs.is_a?(Array) && khs.size.between?(3, MAX_KEYHOLDERS)
    ids = Set.new
    keys = Set.new
    khs.each do |kh|
      bad.('each keyholder must be {"id", "public_key"}') unless exactly?(kh, %w[id public_key])
      unless id?(kh['id']) && key_hex?(kh['public_key'])
        bad.('keyholder id must match [A-Za-z0-9._-]{1,64} and public_key be 64 lower-case hex')
      end
      bad.('keyholder ids and public keys must be unique') if ids.include?(kh['id']) || keys.include?(kh['public_key'])
      ids << kh['id']
      keys << kh['public_key']
    end
    n = khs.size
    bad.("threshold must be null or an integer from 2 to #{n - 1}") unless doc['threshold'].nil? || int_in?(doc['threshold'], 2, n - 1)
    unless key_hex?(doc['coordinator_key']) && !keys.include?(doc['coordinator_key'])
      bad.('coordinator_key must be 64 lower-case hex and differ from every keyholder key')
    end
    bad.('offline_timeout_ms must be an integer from 1000 to 3600000') unless int_in?(doc['offline_timeout_ms'], 1000, 3_600_000)
    bad.('proposal_max_ttl_ms must be an integer from 1000 to 86400000') unless int_in?(doc['proposal_max_ttl_ms'], 1000, 86_400_000)
    agents = doc['agents']
    unless agents.nil?
      bad.("agents must be null or a list of at most #{MAX_AGENTS}") unless agents.is_a?(Array) && agents.size <= MAX_AGENTS
      seen = Set.new
      agents.each do |a|
        bad.('each agent must be {"id", "max_instances"}') unless exactly?(a, %w[id max_instances])
        unless id?(a['id']) && int_in?(a['max_instances'], 1, 1000) && !seen.include?(a['id'])
          bad.('agent id must match [A-Za-z0-9._-]{1,64}, be unique, and max_instances be 1 to 1000')
        end
        seen << a['id']
      end
    end
    doc
  end

  def self.fleet_threshold(fleet) = fleet['threshold'] || default_threshold(fleet['keyholders'].size)

  # ---------------------------------------------------------------- proposals and certificates

  def self.check_proposal_format(p)
    bad = ->(m) { raise SwitchError.new('SW-BAD-PROPOSAL', m) }
    bad.("a proposal must have exactly the fields #{PROPOSAL_FIELDS.join(', ')}") unless exactly?(p, PROPOSAL_FIELDS)
    bad.('type must be "smartswitch.proposal"') unless p['type'] == 'smartswitch.proposal'
    bad.('fleet_id or fleet_hash is malformed') unless id?(p['fleet_id']) && key_hex?(p['fleet_hash'])
    bad.('seq must be an integer >= 1 and epoch >= 0') unless int_in?(p['seq'], 1, MAX_INT) && int_in?(p['epoch'], 0, MAX_INT)
    bad.("action must be one of #{ACTIONS.join(', ')}") unless p['action'].is_a?(String) && ACTIONS.include?(p['action'])
    bad.('target must be a string') unless p['target'].is_a?(String)
    if p['action'] == 'reinstate'
      bad.('reinstate needs new_public_key (64 lower-case hex)') unless key_hex?(p['new_public_key'])
    elsif !p['new_public_key'].nil?
      bad.('new_public_key must be null unless the action is reinstate')
    end
    unless p['reason'].is_a?(String) && p['reason'].valid_encoding? && p['reason'].bytesize <= MAX_REASON_BYTES
      bad.("reason must be a string of at most #{MAX_REASON_BYTES} UTF-8 bytes")
    end
    unless int_in?(p['created_ms'], 0, MAX_INT) && int_in?(p['expires_ms'], 0, MAX_INT)
      bad.('created_ms and expires_ms must be integers >= 0')
    end
    bad.('expires_ms must be after created_ms') if p['expires_ms'] <= p['created_ms']
    p
  end

  def self.proposal_hash(p) = doc_hash(p)

  def self.vote_message(proposal_hash) = VOTE_PREFIX + proposal_hash

  def self.check_certificate_format(c)
    bad = ->(m) { raise SwitchError.new('SW-BAD-CERTIFICATE', m) }
    bad.('a certificate must be {"type", "proposal", "votes"}') unless exactly?(c, %w[proposal type votes])
    bad.('type must be "smartswitch.certificate"') unless c['type'] == 'smartswitch.certificate'
    votes = c['votes']
    bad.("votes must be a list of 1 to #{MAX_KEYHOLDERS}") unless votes.is_a?(Array) && votes.size.between?(1, MAX_KEYHOLDERS)
    votes.each do |v|
      unless exactly?(v, %w[keyholder sig]) && v['keyholder'].is_a?(String) && v['sig'].is_a?(String)
        bad.('each vote must be {"keyholder": string, "sig": string}')
      end
    end
    c
  end

  # ---------------------------------------------------------------- state

  # The switch state. Treat as immutable: SmartSwitch.apply returns a new one.
  class State
    attr_reader :fleet_id, :fleet_hash, :coordinator_key, :n, :threshold, :max_ttl_ms, :offline_timeout_ms,
                :keys, :suspended, :seq, :epoch, :halted_all, :halted

    def initialize(**f)
      f.each { |k, v| instance_variable_set("@#{k}", v) }
    end

    def self.genesis(fleet)
      f = SmartSwitch.validate_fleet(fleet)
      new(fleet_id: f['fleet_id'], fleet_hash: SmartSwitch.doc_hash(f), coordinator_key: f['coordinator_key'],
          n: f['keyholders'].size, threshold: SmartSwitch.fleet_threshold(f), max_ttl_ms: f['proposal_max_ttl_ms'],
          offline_timeout_ms: f['offline_timeout_ms'], keys: f['keyholders'].to_h { |k| [k['id'], k['public_key']] }.freeze,
          suspended: Set.new.freeze, seq: 0, epoch: 0, halted_all: false, halted: Set.new.freeze)
    end

    # A copy with some fields changed.
    def with(**changes)
      fields = %i[fleet_id fleet_hash coordinator_key n threshold max_ttl_ms offline_timeout_ms keys suspended seq epoch
                  halted_all halted]
      State.new(**fields.to_h { |k| [k, changes.key?(k) ? changes[k] : instance_variable_get("@#{k}")] })
    end

    def active = @keys.keys.reject { |k| @suspended.include?(k) }.sort

    def may_run?(agent_id) = !@halted_all && !@halted.include?(agent_id)

    # The state as the vectors compare it.
    def summary
      { 'seq' => @seq, 'epoch' => @epoch, 'threshold' => @threshold, 'halted_all' => @halted_all,
        'halted' => @halted.to_a.sort, 'active' => active, 'suspended' => @suspended.to_a.sort,
        'keys' => @keys.sort.to_h }
    end
  end

  # Check +cert+ against +st+ at +at_ms+; returns its proposal or raises SwitchError. Order: SEMANTICS.md,
  # "Certificate checks". +ahead+: any seq above the state's is accepted (an agent receiving it directly).
  def self.verify_certificate(st, cert, at_ms, ahead: false)
    check_certificate_format(cert)
    p = check_proposal_format(cert['proposal'])
    raise SwitchError.new('SW-WRONG-FLEET', 'the proposal is for another fleet') if p['fleet_id'] != st.fleet_id || p['fleet_hash'] != st.fleet_hash
    raise SwitchError.new('SW-STALE-SEQ', "seq #{p['seq']} is not after the current seq #{st.seq}") if p['seq'] <= st.seq
    raise SwitchError.new('SW-SEQ-GAP', "seq #{p['seq']} is not the next seq #{st.seq + 1}") if !ahead && p['seq'] != st.seq + 1
    raise SwitchError.new('SW-WRONG-EPOCH', "epoch #{p['epoch']} is not the current epoch #{st.epoch}") if p['epoch'] != st.epoch
    if p['expires_ms'] - p['created_ms'] > st.max_ttl_ms
      raise SwitchError.new('SW-BAD-PROPOSAL', "the proposal is valid for longer than #{st.max_ttl_ms} ms")
    end
    raise SwitchError.new('SW-EXPIRED', 'the proposal has expired') if at_ms >= p['expires_ms']

    check_target(st, p)
    msg = vote_message(proposal_hash(p))
    seen = Set.new
    cert['votes'].each do |v|
      kh = v['keyholder']
      raise SwitchError.new('SW-UNKNOWN-KEYHOLDER', "#{kh.inspect} is not a keyholder of this fleet") unless st.keys.key?(kh)
      raise SwitchError.new('SW-DUPLICATE-VOTE', "#{kh.inspect} voted twice") if seen.include?(kh)

      seen << kh
      raise SwitchError.new('SW-SUSPENDED-KEYHOLDER', "#{kh.inspect} is suspended") if st.suspended.include?(kh)
      raise SwitchError.new('SW-TARGET-VOTE', 'a keyholder cannot vote on its own suspension') if p['action'] == 'suspend' && kh == p['target']
      raise SwitchError.new('SW-BAD-SIGNATURE', "the signature of #{kh.inspect} does not verify") unless verify(st.keys[kh], msg, v['sig'])
    end
    raise SwitchError.new('SW-NO-QUORUM', "#{seen.size} valid votes, #{st.threshold} needed") if seen.size < st.threshold

    p
  end

  def self.check_target(st, p)
    a = p['action']
    t = p['target']
    case a
    when 'halt', 'resume'
      raise SwitchError.new('SW-BAD-TARGET', 'target must be "*" or an agent id') unless t == '*' || id?(t)
    when 'suspend'
      raise SwitchError.new('SW-BAD-TARGET', 'target must be an active keyholder') if !st.keys.key?(t) || st.suspended.include?(t)
      if st.active.size - 1 < st.threshold
        raise SwitchError.new('SW-QUORUM-IMPOSSIBLE',
                              "suspending this keyholder would leave fewer active keyholders than the threshold #{st.threshold}")
      end
    else
      raise SwitchError.new('SW-BAD-TARGET', 'target must be a suspended keyholder') unless st.suspended.include?(t)

      k = p['new_public_key']
      raise SwitchError.new('SW-BAD-TARGET', 'new_public_key must be a key not used in this fleet') if st.keys.value?(k) || k == st.coordinator_key
    end
  end

  # Verify +cert+ (seq must be state seq + 1) and return the next state; +st+ is unchanged.
  def self.apply(st, cert, at_ms)
    p = verify_certificate(st, cert, at_ms)
    t = p['target']
    nxt = { seq: st.seq + 1 }
    case p['action']
    when 'halt'
      t == '*' ? nxt[:halted_all] = true : nxt[:halted] = (st.halted | [t]).freeze
    when 'resume'
      if t == '*'
        nxt[:halted_all] = false
        nxt[:halted] = Set.new.freeze
      else
        nxt[:halted] = (st.halted - [t]).freeze
      end
    when 'suspend'
      nxt[:suspended] = (st.suspended | [t]).freeze
      nxt[:epoch] = st.epoch + 1
    else
      nxt[:suspended] = (st.suspended - [t]).freeze
      nxt[:keys] = st.keys.merge(t => p['new_public_key']).freeze
      nxt[:epoch] = st.epoch + 1
    end
    st.with(**nxt)
  end

  # ---------------------------------------------------------------- log

  def self.entry_hash(entry) = doc_hash(entry.except('hash'))

  # A verified copy of a log. #append checks entries one by one and applies certificates; on the first bad
  # entry it raises SwitchError and keeps everything before it.
  class Replica
    attr_reader :pinned, :state, :size, :head, :hashes

    # +fleet_hash+: the fleet hash entry 0 must have, or nil to accept any genesis.
    def initialize(fleet_hash = nil)
      @pinned = fleet_hash
      @state = nil
      @size = 0
      @head = GENESIS_PREV
      @hashes = []
    end

    def append(entries)
      entries.each { |e| one(e) }
      @size
    end

    private

    def one(e)
      unless SmartSwitch.exactly?(e, ENTRY_FIELDS) && KINDS.include?(e['kind']) && e['body'].is_a?(Hash) &&
             e['n'].is_a?(Integer) && e['ts_ms'].is_a?(Integer) && e['ts_ms'] >= 0
        raise SwitchError.new('SW-BAD-ENTRY', "entry #{@size} is malformed")
      end
      # ts_ms is the coordinator's unsigned wall clock: it need not increase (SEMANTICS.md, "Log")
      raise SwitchError.new('SW-LOG-ORDER', "entry #{@size}: n is #{e['n']}") if e['n'] != @size

      chained = begin
        e['prev'] == @head && e['hash'] == SmartSwitch.entry_hash(e)
      rescue CanonicalError # no canonical form (a float, invalid text): cannot match
        false
      end
      raise SwitchError.new('SW-LOG-CHAIN', "entry #{@size}: the hash chain is broken") unless chained

      if @size.zero?
        raise SwitchError.new('SW-BAD-ENTRY', 'entry 0 must be the genesis') unless e['kind'] == 'genesis'

        begin
          SmartSwitch.validate_fleet(e['body'])
        rescue SwitchError => err
          raise SwitchError.new('SW-BAD-FLEET', "entry 0: #{err.message}")
        end
        raise SwitchError.new('SW-WRONG-FLEET', 'entry 0 is not the pinned fleet') if @pinned && SmartSwitch.doc_hash(e['body']) != @pinned

        @state = State.genesis(e['body'])
      elsif e['kind'] == 'genesis'
        raise SwitchError.new('SW-BAD-ENTRY', "entry #{@size}: only entry 0 can be a genesis")
      elsif e['kind'] == 'certificate'
        @state = SmartSwitch.apply(@state, e['body'], e['ts_ms'])
      end
      @size += 1
      @head = e['hash']
      @hashes << e['hash']
    end
  end

  # {"ok" => true, "size", "head", "state"} or {"ok" => false, "index", "code"} (the vectors' form).
  def self.replay(entries, fleet_hash = nil)
    r = Replica.new(fleet_hash)
    begin
      r.append(entries)
    rescue SwitchError => e
      return { 'ok' => false, 'index' => r.size, 'code' => e.code }
    end
    return { 'ok' => false, 'index' => 0, 'code' => 'SW-BAD-ENTRY' } if r.size.zero?

    { 'ok' => true, 'size' => r.size, 'head' => r.head, 'state' => r.state.summary }
  end

  # ---------------------------------------------------------------- agent view

  def self.heartbeat_message(hb) = HEARTBEAT_PREFIX + doc_hash(hb.except('sig'))

  # What an agent believes, and whether it may run (SEMANTICS.md, "Agent"), without any I/O. Times for
  # heartbeats and status are the agent's own monotonic milliseconds; the time for a delivered certificate is
  # wall-clock milliseconds. Not thread-safe: Agent serialises access.
  class AgentView
    attr_reader :fleet, :fleet_hash, :agent_id, :instance_id, :replica

    # +fleet+: the fleet document the agent was deployed with (validated by the caller, see SmartSwitch.load_fleet).
    def initialize(fleet, agent_id, instance_id)
      raise ArgumentError, 'agent_id and instance_id must match [A-Za-z0-9._-]{1,64}' unless SmartSwitch.id?(agent_id) && SmartSwitch.id?(instance_id)

      @fleet = fleet
      @fleet_hash = SmartSwitch.doc_hash(fleet)
      @agent_id = agent_id
      @instance_id = instance_id
      @replica = Replica.new(@fleet_hash)
      @last_ok_ms = nil
      @provisional = {} # proposal hash => seq of halts delivered directly that the log has not settled
      @fork = false
    end

    # Entries that continue the local copy, appended one at a time: {ok, size} or {ok, code, size} (entries
    # before the first bad one are kept). A provisional halt ends when the log applies that same proposal, or
    # a later resume of "*" or of this agent; another certificate taking its seq does not end it.
    def log(entries)
      return { 'ok' => false, 'code' => 'SW-BAD-ENTRY', 'size' => @replica.size } unless entries.is_a?(Array)

      entries.each do |e|
        begin
          @replica.append([e])
        rescue SwitchError => err
          return { 'ok' => false, 'code' => err.code, 'size' => @replica.size }
        end
        next unless !@provisional.empty? && e['kind'] == 'certificate'

        p = e['body']['proposal']
        @provisional.delete(SmartSwitch.proposal_hash(p))
        @provisional.select! { |_, q| q >= p['seq'] } if p['action'] == 'resume' && ['*', @agent_id].include?(p['target'])
      end
      { 'ok' => true, 'size' => @replica.size }
    end

    # A heartbeat answering +nonce+, which the agent sent at +at_ms+: {ok, code}.
    def heartbeat(hb, nonce, at_ms)
      code = check_heartbeat(hb, nonce)
      if code.nil?
        size = hb['log_size']
        if @replica.size >= size
          if @replica.hashes[size - 1] != hb['head']
            @fork = true
            code = 'SW-FORK'
          end
        else
          code = 'SW-BEHIND'
        end
      end
      if code.nil?
        @last_ok_ms = @last_ok_ms.nil? ? at_ms : [@last_ok_ms, at_ms].max
        return { 'ok' => true, 'code' => 'SW-OK' }
      end
      { 'ok' => false, 'code' => code }
    end

    # A certificate delivered directly (not through the log), checked at WALL-CLOCK time +at_ms+ (it is
    # compared with expires_ms): {ok, code}. Only a valid halt of this agent or of the whole fleet, newer than
    # the local state, has an effect: a provisional halt (see #log for when it ends).
    def certificate(cert, at_ms)
      st = @replica.state
      return { 'ok' => false, 'code' => 'SW-NO-STATE' } if st.nil?

      begin
        p = SmartSwitch.verify_certificate(st, cert, at_ms, ahead: true)
      rescue SwitchError => e
        return { 'ok' => false, 'code' => e.code }
      end
      return { 'ok' => false, 'code' => 'SW-NOT-APPLICABLE' } if p['action'] != 'halt' || !['*', @agent_id].include?(p['target'])

      @provisional[SmartSwitch.proposal_hash(p)] = p['seq']
      { 'ok' => true, 'code' => 'SW-PROVISIONAL-HALT' }
    end

    # {run, code}: the first matching reason in the order of SEMANTICS.md wins.
    def status(at_ms)
      st = @replica.state
      code = if @fork then 'SW-FORK'
             elsif st&.halted_all then 'SW-HALTED-FLEET'
             elsif st&.halted&.include?(@agent_id) then 'SW-HALTED-AGENT'
             elsif !@provisional.empty? then 'SW-PROVISIONAL-HALT'
             elsif @last_ok_ms.nil? || st.nil? then 'SW-NO-HEARTBEAT'
             elsif at_ms - @last_ok_ms >= st.offline_timeout_ms then 'SW-OFFLINE'
             end
      return { 'run' => true, 'code' => 'SW-RUN' } if code.nil?

      { 'run' => false, 'code' => code }
    end

    private

    def check_heartbeat(hb, nonce)
      unless SmartSwitch.exactly?(hb, HEARTBEAT_FIELDS) && hb['type'] == 'smartswitch.heartbeat' &&
             SmartSwitch.int_in?(hb['log_size'], 1, MAX_INT) && SmartSwitch.key_hex?(hb['head']) &&
             SmartSwitch.int_in?(hb['issued_ms'], 0, MAX_INT)
        return 'SW-BAD-HEARTBEAT'
      end

      msg = begin
        SmartSwitch.heartbeat_message(hb)
      rescue CanonicalError # no canonical form: it cannot carry a valid signature
        return 'SW-BAD-HEARTBEAT'
      end
      return 'SW-BAD-HEARTBEAT' unless SmartSwitch.verify(@fleet['coordinator_key'], msg, hb['sig'])
      return 'SW-WRONG-FLEET' if hb['fleet_hash'] != @fleet_hash
      return 'SW-WRONG-AGENT' if hb['agent_id'] != @agent_id || hb['instance_id'] != @instance_id
      return 'SW-NONCE' unless nonce.is_a?(String) && NONCE.match?(nonce) && hb['nonce'] == nonce

      nil
    end
  end

  # ---------------------------------------------------------------- networked agent

  # The agent's monotonic clock in milliseconds (heartbeats and status).
  def self.mono_ms = Process.clock_gettime(Process::CLOCK_MONOTONIC, :millisecond)

  # Wall-clock milliseconds (delivered certificates: compared with expires_ms).
  def self.wall_ms = Process.clock_gettime(Process::CLOCK_REALTIME, :millisecond)

  # Read and validate a fleet document (raises SwitchError SW-BAD-FLEET, SystemCallError, JSON::ParserError).
  def self.load_fleet(path) = validate_fleet(JSON.parse(File.read(path, encoding: 'UTF-8')))

  # The agent's calls to the coordinator (Net::HTTP, a new connection per request). Any answer other than
  # 2xx raises ClientError.
  class Client
    class ClientError < StandardError; end

    # The largest answer read; a longer one is an error.
    MAX_RESPONSE_BYTES = 32 * 1024 * 1024

    attr_reader :url

    def initialize(url, token = nil, timeout: 2.0)
      raise ArgumentError, 'the coordinator URL must start with http:// or https://' unless url.start_with?('http://', 'https://')

      @url = url.sub(%r{/+\z}, '')
      @uri = URI(@url)
      @token = token
      @timeout = timeout
    end

    def get(path, query)
      req = Net::HTTP::Get.new("#{@uri.path}#{path}?#{URI.encode_www_form(query)}")
      req['Accept'] = 'application/json'
      req['Authorization'] = "Bearer #{@token}" if @token && !@token.empty?
      code = nil
      body = +''
      Net::HTTP.start(@uri.host, @uri.port, use_ssl: @uri.scheme == 'https', open_timeout: @timeout,
                                            read_timeout: @timeout, write_timeout: @timeout) do |h|
        h.request(req) do |res|
          code = res.code.to_i
          res.read_body do |chunk|
            raise ClientError, "the answer is longer than #{MAX_RESPONSE_BYTES} bytes" if body.bytesize + chunk.bytesize > MAX_RESPONSE_BYTES

            body << chunk
          end
        end
      end
      raise ClientError, "HTTP #{code}: #{body[0, 300]}" unless code.between?(200, 299)

      JSON.parse(body.force_encoding('UTF-8'))
    end

    def heartbeat(agent_id, instance_id, nonce)
      get('/v1/heartbeat', { 'agent_id' => agent_id, 'instance_id' => instance_id, 'nonce' => nonce })
    end

    def log(from, limit, agent_id, instance_id)
      get('/v1/log', { 'from' => from, 'limit' => limit, 'agent_id' => agent_id, 'instance_id' => instance_id })
    end
  end

  # The networked agent: a signed heartbeat every +poll_ms+ (in a background thread after #start, or by
  # calling #poll_once yourself), the log fetched and verified when behind. Network errors change nothing;
  # with no valid heartbeat for the fleet's offline_timeout_ms the agent stops by itself (SW-OFFLINE).
  class Agent
    attr_reader :fleet, :view, :poll_ms, :last_error

    def initialize(url, token, fleet, agent_id, instance_id, poll_ms: 1000, timeout: 2.0, &on_change)
      @fleet = SmartSwitch.validate_fleet(fleet)
      @view = AgentView.new(@fleet, agent_id, instance_id)
      @client = Client.new(url, token, timeout: timeout)
      @poll_ms = poll_ms
      @on_change = on_change
      @lock = Monitor.new
      @last = nil
      @last_error = nil
      @thread = nil
      @stop = false
    end

    # One round: heartbeat (and log fetch when behind). Returns the status afterwards.
    def poll_once
      nonce = SecureRandom.hex(16)
      sent = SmartSwitch.mono_ms
      begin
        hb = @client.heartbeat(@view.agent_id, @view.instance_id, nonce)
        r = @lock.synchronize { @view.heartbeat(hb, nonce, sent) }
        if r['code'] == 'SW-BEHIND'
          catch_up(hb['log_size'])
          r = @lock.synchronize { @view.heartbeat(hb, nonce, sent) }
        end
        @last_error = r['ok'] ? nil : r['code']
      rescue StandardError, Timeout::Error, SystemStackError, NoMemoryError => e # any error changes nothing
        @last_error = "#{e.class}: #{e.message}"
      end
      status
    end

    # A certificate that reached this agent some other way than the coordinator.
    def deliver(certificate)
      r = @lock.synchronize { @view.certificate(certificate, SmartSwitch.wall_ms) }
      status
      r
    end

    # {"run" => bool, "code" => String} now (no network).
    def status
      s = nil
      changed = @lock.synchronize do
        s = @view.status(SmartSwitch.mono_ms)
        next false if s == @last

        @last = s
        true
      end
      if changed && @on_change
        begin
          @on_change.call(s)
        rescue StandardError => e
          warn "smartswitch: on_change failed: #{e.message}"
        end
      end
      s
    end

    def may_run? = status['run']

    # Raises Halted when the agent may not run.
    def checkpoint
      s = status
      raise Halted, s['code'] unless s['run']
    end

    # Poll in a background thread every poll_ms.
    def start
      @lock.synchronize do
        return self if @thread

        @stop = false
        @thread = Thread.new do
          until @stop
            begin
              poll_once
            rescue Exception => e # rubocop:disable Lint/RescueException -- the loop must survive anything
              @last_error = "#{e.class}: #{e.message}"
              warn "smartswitch: poll failed: #{@last_error}"
            end
            sleep(@poll_ms / 1000.0)
          end
        end
      end
      self
    end

    def stop
      t = @lock.synchronize do
        @stop = true
        th = @thread
        @thread = nil
        th
      end
      t&.join(5)
    end

    private

    def catch_up(size)
      loop do
        have = @lock.synchronize { @view.replica.size }
        return if have >= size

        body = @client.log(have, 1000, @view.agent_id, @view.instance_id)
        page = body.is_a?(Hash) ? body['entries'] : nil
        raise Client::ClientError, 'the coordinator answered /v1/log without entries' unless page.is_a?(Array)
        return if page.empty?

        r = @lock.synchronize { @view.log(page) }
        raise Client::ClientError, "the coordinator log does not verify (#{r['code']} at entry #{r['size']})" unless r['ok']
      end
    end
  end
end
