<?php
// SmartSwitch for PHP, agent side (spec/SEMANTICS.md): canonical JSON, strict Ed25519 verify, fleet
// validation, certificate checks and apply, log replay, the agent view and a networked agent.
//
// Documents are decoded with SmartTasks\SmartSwitch\decode(): JSON objects become \stdClass (so {} and []
// stay different), integers int, other numbers float. Results this library returns are PHP arrays.
declare(strict_types=1);

namespace SmartTasks\SmartSwitch;

const MAX_INT = 9007199254740991; // 2^53 - 1
const MAX_KEYHOLDERS = 64;
const MAX_AGENTS = 100000;
const MAX_REASON_BYTES = 1000;
const GENESIS_PREV = '0000000000000000000000000000000000000000000000000000000000000000';
const VOTE_PREFIX = 'smartswitch-vote-v1:';
const HEARTBEAT_PREFIX = 'smartswitch-heartbeat-v1:';
const ACTIONS = ['halt', 'resume', 'suspend', 'reinstate'];
const KINDS = ['genesis', 'certificate', 'event'];
const FLEET_FIELDS = ['type', 'version', 'fleet_id', 'keyholders', 'threshold', 'coordinator_key', 'offline_timeout_ms',
    'proposal_max_ttl_ms', 'agents'];
const PROPOSAL_FIELDS = ['type', 'fleet_id', 'fleet_hash', 'seq', 'epoch', 'action', 'target', 'new_public_key', 'reason',
    'created_ms', 'expires_ms'];
const ENTRY_FIELDS = ['n', 'ts_ms', 'kind', 'body', 'prev', 'hash'];
const HEARTBEAT_FIELDS = ['type', 'fleet_hash', 'agent_id', 'instance_id', 'nonce', 'log_size', 'head', 'issued_ms', 'sig'];
// L = 2^252 + 27742317777372353535851937790883648493, big-endian
const ED25519_L_HEX = '1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed';

/** A rule was broken; $swCode is the stable SW-* code. */
final class SwitchError extends \RuntimeException {
    public function __construct(public readonly string $swCode, string $message = '') {
        parent::__construct($message === '' ? $swCode : "$swCode: $message");
    }
}

/** Thrown by Agent::checkpoint() when the agent may not run. */
final class Halted extends \RuntimeException {
    public function __construct(public readonly string $swCode) {
        parent::__construct("SmartSwitch: this agent may not run ($swCode)");
    }
}

// ------------------------------------------------------------------ JSON

/** Decode JSON keeping objects (\stdClass) distinct from lists. Throws \JsonException. */
function decode(string $json): mixed {
    return json_decode($json, false, 512, JSON_THROW_ON_ERROR);
}

/** True when $s is valid UTF-8 text (json_decode only produces such strings). */
function valid_text(string $s): bool { return preg_match('//u', $s) === 1; }

function canon_str(string $s): string {
    if (!valid_text($s)) throw new \InvalidArgumentException('canonical JSON strings must be valid UTF-8');
    static $map = null;
    if ($map === null) {
        $map = ['"' => '\\"', '\\' => '\\\\', "\x08" => '\\b', "\f" => '\\f', "\n" => '\\n', "\r" => '\\r', "\t" => '\\t'];
        for ($c = 0; $c < 0x20; $c++) if (!isset($map[chr($c)])) $map[chr($c)] = sprintf('\\u%04x', $c);
    }
    return '"' . strtr($s, $map) . '"';
}

/** Canonical JSON (SEMANTICS.md, "Encodings"). \stdClass and non-list arrays are objects. Floats, non-ASCII
 *  keys, strings that are not valid UTF-8 and other types throw \InvalidArgumentException. */
function canonical(mixed $v): string {
    if ($v === null) return 'null';
    if ($v === true) return 'true';
    if ($v === false) return 'false';
    if (is_int($v)) return (string) $v;
    if (is_string($v)) return canon_str($v);
    if (is_array($v) && array_is_list($v)) {
        return '[' . implode(',', array_map(__NAMESPACE__ . '\canonical', $v)) . ']';
    }
    if (is_array($v) || $v instanceof \stdClass) {
        $a = is_array($v) ? $v : get_object_vars($v);
        $pairs = [];
        foreach ($a as $k => $x) {
            $k = (string) $k;
            if (preg_match('/[^\x00-\x7f]/', $k)) throw new \InvalidArgumentException('object keys must be ASCII');
            $pairs[$k] = $x;
        }
        $keys = array_map('strval', array_keys($pairs));
        sort($keys, SORT_STRING);
        $parts = [];
        foreach ($keys as $k) $parts[] = canon_str($k) . ':' . canonical($pairs[$k]);
        return '{' . implode(',', $parts) . '}';
    }
    if (is_float($v)) throw new \InvalidArgumentException('canonical JSON allows integers only');
    throw new \InvalidArgumentException('canonical JSON cannot encode ' . get_debug_type($v));
}

function sha256_hex(string $bytes): string { return hash('sha256', $bytes); }

/** sha256 of the canonical form; throws \InvalidArgumentException when there is none. */
function doc_hash(mixed $v): string { return sha256_hex(canonical($v)); }

// ------------------------------------------------------------------ helpers

function is_id(mixed $v): bool { return is_string($v) && preg_match('/\A[A-Za-z0-9._-]{1,64}\z/', $v) === 1; }

function is_key_hex(mixed $v): bool { return is_string($v) && preg_match('/\A[0-9a-f]{64}\z/', $v) === 1; }

function is_nonce(mixed $v): bool { return is_string($v) && preg_match('/\A[0-9a-f]{32}\z/', $v) === 1; }

function int_in(mixed $v, int $lo, int $hi): bool { return is_int($v) && $v >= $lo && $v <= $hi; }

/** True when $o is a JSON object with exactly these field names. */
function exactly(mixed $o, array $fields): bool {
    if (!($o instanceof \stdClass)) return false;
    $k = array_map('strval', array_keys(get_object_vars($o)));
    sort($k, SORT_STRING);
    sort($fields, SORT_STRING);
    return $k === $fields;
}

// ------------------------------------------------------------------ Ed25519

/** Strict verify (SEMANTICS.md, "Signatures"): lower-case hex of the right lengths, S < L, then libsodium.
 *  Any library error is false. */
function verify(mixed $publicHex, string $message, mixed $sigHex): bool {
    if (!is_key_hex($publicHex) || !is_string($sigHex) || preg_match('/\A[0-9a-f]{128}\z/', $sigHex) !== 1) return false;
    $sig = hex2bin($sigHex);
    $sBigEndian = strrev(substr($sig, 32, 32));
    if (strcmp($sBigEndian, hex2bin(ED25519_L_HEX)) >= 0) return false;
    try {
        return sodium_crypto_sign_verify_detached($sig, $message, hex2bin($publicHex));
    } catch (\Throwable) {
        return false;
    }
}

// ------------------------------------------------------------------ fleet

/** 2 for up to five keyholders; floor(n/2) + 1 above five. */
function default_threshold(int $n): int { return $n <= 5 ? 2 : intdiv($n, 2) + 1; }

/** Return the fleet document if valid; throw SwitchError('SW-BAD-FLEET') otherwise. */
function validate_fleet(mixed $doc): \stdClass {
    $bad = fn (string $m) => new SwitchError('SW-BAD-FLEET', $m);
    if (!exactly($doc, FLEET_FIELDS)) throw $bad('the fleet document must have exactly the fields ' . implode(', ', FLEET_FIELDS));
    if ($doc->type !== 'smartswitch.fleet' || $doc->version !== 1) throw $bad('type must be "smartswitch.fleet" and version 1');
    if (!is_id($doc->fleet_id)) throw $bad('fleet_id must match [A-Za-z0-9._-]{1,64}');
    $khs = $doc->keyholders;
    if (!is_array($khs) || count($khs) < 3 || count($khs) > MAX_KEYHOLDERS) throw $bad('keyholders must be a list of 3 to ' . MAX_KEYHOLDERS);
    $ids = [];
    $keys = [];
    foreach ($khs as $kh) {
        if (!exactly($kh, ['id', 'public_key'])) throw $bad('each keyholder must be {"id", "public_key"}');
        if (!is_id($kh->id) || !is_key_hex($kh->public_key)) {
            throw $bad('keyholder id must match [A-Za-z0-9._-]{1,64} and public_key be 64 lower-case hex');
        }
        if (isset($ids[$kh->id]) || isset($keys[$kh->public_key])) throw $bad('keyholder ids and public keys must be unique');
        $ids[$kh->id] = true;
        $keys[$kh->public_key] = true;
    }
    $n = count($khs);
    if ($doc->threshold !== null && !int_in($doc->threshold, 2, $n - 1)) throw $bad('threshold must be null or an integer from 2 to ' . ($n - 1));
    if (!is_key_hex($doc->coordinator_key) || isset($keys[$doc->coordinator_key])) {
        throw $bad('coordinator_key must be 64 lower-case hex and differ from every keyholder key');
    }
    if (!int_in($doc->offline_timeout_ms, 1000, 3600000)) throw $bad('offline_timeout_ms must be an integer from 1000 to 3600000');
    if (!int_in($doc->proposal_max_ttl_ms, 1000, 86400000)) throw $bad('proposal_max_ttl_ms must be an integer from 1000 to 86400000');
    if ($doc->agents !== null) {
        if (!is_array($doc->agents) || count($doc->agents) > MAX_AGENTS) throw $bad('agents must be null or a list of at most ' . MAX_AGENTS);
        $seen = [];
        foreach ($doc->agents as $a) {
            if (!exactly($a, ['id', 'max_instances'])) throw $bad('each agent must be {"id", "max_instances"}');
            if (!is_id($a->id) || !int_in($a->max_instances, 1, 1000) || isset($seen[$a->id])) {
                throw $bad('agent id must match [A-Za-z0-9._-]{1,64}, be unique, and max_instances be 1 to 1000');
            }
            $seen[$a->id] = true;
        }
    }
    return $doc;
}

function fleet_threshold(\stdClass $fleet): int {
    return $fleet->threshold ?? default_threshold(count($fleet->keyholders));
}

// ------------------------------------------------------------------ proposals and certificates

function check_proposal_format(mixed $p): \stdClass {
    $bad = fn (string $m) => new SwitchError('SW-BAD-PROPOSAL', $m);
    if (!exactly($p, PROPOSAL_FIELDS)) throw $bad('a proposal must have exactly the fields ' . implode(', ', PROPOSAL_FIELDS));
    if ($p->type !== 'smartswitch.proposal') throw $bad('type must be "smartswitch.proposal"');
    if (!is_id($p->fleet_id) || !is_key_hex($p->fleet_hash)) throw $bad('fleet_id or fleet_hash is malformed');
    if (!int_in($p->seq, 1, MAX_INT) || !int_in($p->epoch, 0, MAX_INT)) throw $bad('seq must be an integer >= 1 and epoch >= 0');
    if (!in_array($p->action, ACTIONS, true)) throw $bad('action must be one of ' . implode(', ', ACTIONS));
    if (!is_string($p->target)) throw $bad('target must be a string');
    if ($p->action === 'reinstate') {
        if (!is_key_hex($p->new_public_key)) throw $bad('reinstate needs new_public_key (64 lower-case hex)');
    } elseif ($p->new_public_key !== null) {
        throw $bad('new_public_key must be null unless the action is reinstate');
    }
    if (!is_string($p->reason) || !valid_text($p->reason) || strlen($p->reason) > MAX_REASON_BYTES) {
        throw $bad('reason must be a string of at most ' . MAX_REASON_BYTES . ' UTF-8 bytes');
    }
    if (!int_in($p->created_ms, 0, MAX_INT) || !int_in($p->expires_ms, 0, MAX_INT)) throw $bad('created_ms and expires_ms must be integers >= 0');
    if ($p->expires_ms <= $p->created_ms) throw $bad('expires_ms must be after created_ms');
    return $p;
}

function proposal_hash(mixed $p): string { return doc_hash($p); }

function vote_message(string $proposalHash): string { return VOTE_PREFIX . $proposalHash; }

function check_certificate_format(mixed $c): \stdClass {
    $bad = fn (string $m) => new SwitchError('SW-BAD-CERTIFICATE', $m);
    if (!exactly($c, ['type', 'proposal', 'votes'])) throw $bad('a certificate must be {"type", "proposal", "votes"}');
    if ($c->type !== 'smartswitch.certificate') throw $bad('type must be "smartswitch.certificate"');
    if (!is_array($c->votes) || count($c->votes) < 1 || count($c->votes) > MAX_KEYHOLDERS) throw $bad('votes must be a list of 1 to ' . MAX_KEYHOLDERS);
    foreach ($c->votes as $v) {
        if (!exactly($v, ['keyholder', 'sig']) || !is_string($v->keyholder) || !is_string($v->sig)) {
            throw $bad('each vote must be {"keyholder": string, "sig": string}');
        }
    }
    return $c;
}

// ------------------------------------------------------------------ state

/** The switch state. Treat as immutable: apply() returns a new one. Id-keyed arrays may have int keys
 *  for numeric ids (PHP array semantics); every output casts them back to strings. */
final class State {
    public string $fleetId;
    public string $fleetHash;
    public string $coordinatorKey;
    public int $n;
    public int $threshold;
    public int $maxTtlMs;
    public int $offlineTimeoutMs;
    /** @var array<string,string> keyholder id => current public key */
    public array $keys = [];
    /** @var array<string,true> */
    public array $suspended = [];
    public int $seq = 0;
    public int $epoch = 0;
    public bool $haltedAll = false;
    /** @var array<string,true> */
    public array $halted = [];

    public static function genesis(mixed $fleet): self {
        $f = validate_fleet($fleet);
        $s = new self();
        $s->fleetId = $f->fleet_id;
        $s->fleetHash = doc_hash($f);
        $s->coordinatorKey = $f->coordinator_key;
        $s->n = count($f->keyholders);
        $s->threshold = fleet_threshold($f);
        $s->maxTtlMs = $f->proposal_max_ttl_ms;
        $s->offlineTimeoutMs = $f->offline_timeout_ms;
        foreach ($f->keyholders as $kh) $s->keys[$kh->id] = $kh->public_key;
        return $s;
    }

    private static function sortedIds(array $set): array {
        $ids = array_map('strval', array_keys($set));
        sort($ids, SORT_STRING);
        return $ids;
    }

    /** @return list<string> keyholder ids not suspended, sorted */
    public function active(): array {
        return self::sortedIds(array_diff_key($this->keys, $this->suspended));
    }

    public function isHalted(string $agentId): bool { return isset($this->halted[$agentId]); }

    public function mayRun(string $agentId): bool { return !$this->haltedAll && !$this->isHalted($agentId); }

    /** The state as the vectors compare it. */
    public function summary(): array {
        $keys = new \stdClass();
        foreach (self::sortedIds($this->keys) as $id) $keys->{$id} = $this->keys[$id];
        return ['seq' => $this->seq, 'epoch' => $this->epoch, 'threshold' => $this->threshold, 'halted_all' => $this->haltedAll,
            'halted' => self::sortedIds($this->halted), 'active' => $this->active(), 'suspended' => self::sortedIds($this->suspended),
            'keys' => $keys];
    }
}

/** Check $cert against $st at $atMs; return its proposal or throw SwitchError. Order: SEMANTICS.md,
 *  "Certificate checks". $ahead: any seq above the state's is accepted (an agent receiving it directly). */
function verify_certificate(State $st, mixed $cert, int $atMs, bool $ahead = false): \stdClass {
    $c = check_certificate_format($cert);
    $p = check_proposal_format($c->proposal);
    if ($p->fleet_id !== $st->fleetId || $p->fleet_hash !== $st->fleetHash) throw new SwitchError('SW-WRONG-FLEET', 'the proposal is for another fleet');
    if ($p->seq <= $st->seq) throw new SwitchError('SW-STALE-SEQ', "seq {$p->seq} is not after the current seq {$st->seq}");
    if (!$ahead && $p->seq !== $st->seq + 1) throw new SwitchError('SW-SEQ-GAP', "seq {$p->seq} is not the next seq " . ($st->seq + 1));
    if ($p->epoch !== $st->epoch) throw new SwitchError('SW-WRONG-EPOCH', "epoch {$p->epoch} is not the current epoch {$st->epoch}");
    if ($p->expires_ms - $p->created_ms > $st->maxTtlMs) throw new SwitchError('SW-BAD-PROPOSAL', "the proposal is valid for longer than {$st->maxTtlMs} ms");
    if ($atMs >= $p->expires_ms) throw new SwitchError('SW-EXPIRED', 'the proposal has expired');
    check_target($st, $p);
    $msg = vote_message(proposal_hash($p));
    $seen = [];
    foreach ($c->votes as $v) {
        $kh = $v->keyholder;
        if (!array_key_exists($kh, $st->keys)) throw new SwitchError('SW-UNKNOWN-KEYHOLDER', "'$kh' is not a keyholder of this fleet");
        if (isset($seen[$kh])) throw new SwitchError('SW-DUPLICATE-VOTE', "'$kh' voted twice");
        $seen[$kh] = true;
        if (isset($st->suspended[$kh])) throw new SwitchError('SW-SUSPENDED-KEYHOLDER', "'$kh' is suspended");
        if ($p->action === 'suspend' && $kh === $p->target) throw new SwitchError('SW-TARGET-VOTE', 'a keyholder cannot vote on its own suspension');
        if (!verify($st->keys[$kh], $msg, $v->sig)) throw new SwitchError('SW-BAD-SIGNATURE', "the signature of '$kh' does not verify");
    }
    if (count($seen) < $st->threshold) throw new SwitchError('SW-NO-QUORUM', count($seen) . " valid votes, {$st->threshold} needed");
    return $p;
}

function check_target(State $st, \stdClass $p): void {
    $a = $p->action;
    $t = $p->target;
    if ($a === 'halt' || $a === 'resume') {
        if ($t !== '*' && !is_id($t)) throw new SwitchError('SW-BAD-TARGET', 'target must be "*" or an agent id');
    } elseif ($a === 'suspend') {
        if (!array_key_exists($t, $st->keys) || isset($st->suspended[$t])) throw new SwitchError('SW-BAD-TARGET', 'target must be an active keyholder');
        if (count($st->active()) - 1 < $st->threshold) {
            throw new SwitchError('SW-QUORUM-IMPOSSIBLE', "suspending this keyholder would leave fewer active keyholders than the threshold {$st->threshold}");
        }
    } else {
        if (!isset($st->suspended[$t])) throw new SwitchError('SW-BAD-TARGET', 'target must be a suspended keyholder');
        $k = $p->new_public_key;
        if (in_array($k, $st->keys, true) || $k === $st->coordinatorKey) throw new SwitchError('SW-BAD-TARGET', 'new_public_key must be a key not used in this fleet');
    }
}

/** Verify $cert (seq must be state seq + 1) and return the next state; $st is unchanged. */
function apply(State $st, mixed $cert, int $atMs): State {
    $p = verify_certificate($st, $cert, $atMs);
    $t = $p->target;
    $nxt = clone $st;     // arrays are copied by value
    $nxt->seq = $st->seq + 1;
    switch ($p->action) {
        case 'halt':
            if ($t === '*') $nxt->haltedAll = true; else $nxt->halted[$t] = true;
            break;
        case 'resume':
            if ($t === '*') { $nxt->haltedAll = false; $nxt->halted = []; } else unset($nxt->halted[$t]);
            break;
        case 'suspend':
            $nxt->suspended[$t] = true;
            $nxt->epoch = $st->epoch + 1;
            break;
        default:
            unset($nxt->suspended[$t]);
            $nxt->keys[$t] = $p->new_public_key;
            $nxt->epoch = $st->epoch + 1;
    }
    return $nxt;
}

// ------------------------------------------------------------------ log

function entry_hash(\stdClass $e): string {
    $c = clone $e;
    unset($c->hash);
    return doc_hash($c);
}

/** A verified copy of a log. extend() checks entries one by one and applies certificates; on the first bad
 *  entry it throws SwitchError and keeps everything before it. */
final class Replica {
    public ?State $state = null;
    public int $size = 0;
    public string $head = GENESIS_PREV;
    /** @var list<string> every entry's hash */
    public array $hashes = [];

    /** @param ?string $pinned the fleet hash entry 0 must have, or null to accept any genesis */
    public function __construct(public readonly ?string $pinned = null) {}

    public function extend(iterable $entries): int {
        foreach ($entries as $e) $this->one($e);
        return $this->size;
    }

    private function one(mixed $e): void {
        if (!exactly($e, ENTRY_FIELDS) || !in_array($e->kind, KINDS, true) || !($e->body instanceof \stdClass)
            || !is_int($e->n) || !is_int($e->ts_ms) || $e->ts_ms < 0) {
            throw new SwitchError('SW-BAD-ENTRY', "entry {$this->size} is malformed");
        }
        // ts_ms is the coordinator's unsigned wall clock: it need not increase (SEMANTICS.md, "Log")
        if ($e->n !== $this->size) throw new SwitchError('SW-LOG-ORDER', "entry {$this->size}: n is {$e->n}");
        try {
            $chained = $e->prev === $this->head && $e->hash === entry_hash($e);
        } catch (\InvalidArgumentException) {   // no canonical form (a float, invalid text): cannot match
            $chained = false;
        }
        if (!$chained) throw new SwitchError('SW-LOG-CHAIN', "entry {$this->size}: the hash chain is broken");
        if ($this->size === 0) {
            if ($e->kind !== 'genesis') throw new SwitchError('SW-BAD-ENTRY', 'entry 0 must be the genesis');
            try {
                validate_fleet($e->body);
            } catch (SwitchError $err) {
                throw new SwitchError('SW-BAD-FLEET', 'entry 0: ' . $err->getMessage());
            }
            if ($this->pinned !== null && doc_hash($e->body) !== $this->pinned) throw new SwitchError('SW-WRONG-FLEET', 'entry 0 is not the pinned fleet');
            $this->state = State::genesis($e->body);
        } elseif ($e->kind === 'genesis') {
            throw new SwitchError('SW-BAD-ENTRY', "entry {$this->size}: only entry 0 can be a genesis");
        } elseif ($e->kind === 'certificate') {
            $this->state = apply($this->state, $e->body, $e->ts_ms);
        }
        $this->size++;
        $this->head = $e->hash;
        $this->hashes[] = $e->hash;
    }
}

/** ['ok' => true, 'size', 'head', 'state'] or ['ok' => false, 'index', 'code'] (the vectors' form). */
function replay(iterable $entries, ?string $fleetHash = null): array {
    $r = new Replica($fleetHash);
    try {
        $r->extend($entries);
    } catch (SwitchError $e) {
        return ['ok' => false, 'index' => $r->size, 'code' => $e->swCode];
    }
    if ($r->size === 0) return ['ok' => false, 'index' => 0, 'code' => 'SW-BAD-ENTRY'];
    return ['ok' => true, 'size' => $r->size, 'head' => $r->head, 'state' => $r->state->summary()];
}

// ------------------------------------------------------------------ agent view

function heartbeat_message(\stdClass $hb): string {
    $c = clone $hb;
    unset($c->sig);
    return HEARTBEAT_PREFIX . doc_hash($c);
}

/** What an agent believes, and whether it may run (SEMANTICS.md, "Agent"), without any I/O. Times for
 *  heartbeats and status are the agent's own monotonic milliseconds; the time for a delivered certificate
 *  is wall-clock milliseconds. */
final class AgentView {
    public readonly string $fleetHash;
    public readonly Replica $replica;
    private ?int $lastOkMs = null;
    /** @var array<string,int> proposal hash => seq of halts delivered directly that the log has not settled */
    private array $provisional = [];
    private bool $fork = false;

    /** @param \stdClass $fleet the fleet document the agent was deployed with (validated by the caller) */
    public function __construct(public readonly \stdClass $fleet, public readonly string $agentId, public readonly string $instanceId) {
        if (!is_id($agentId) || !is_id($instanceId)) throw new \InvalidArgumentException('agent_id and instance_id must match [A-Za-z0-9._-]{1,64}');
        $this->fleetHash = doc_hash($fleet);
        $this->replica = new Replica($this->fleetHash);
    }

    /** Entries that continue the local copy, appended one at a time: ['ok', 'size'] or ['ok', 'code', 'size']
     *  (entries before the first bad one are kept). A provisional halt ends when the log applies that same
     *  proposal, or a later resume of "*" or of this agent; another certificate taking its seq does not end it. */
    public function log(mixed $entries): array {
        if (!is_array($entries) || !array_is_list($entries)) return ['ok' => false, 'code' => 'SW-BAD-ENTRY', 'size' => $this->replica->size];
        foreach ($entries as $e) {
            try {
                $this->replica->extend([$e]);
            } catch (SwitchError $err) {
                return ['ok' => false, 'code' => $err->swCode, 'size' => $this->replica->size];
            }
            if ($this->provisional && $e->kind === 'certificate') {
                $p = $e->body->proposal;
                unset($this->provisional[proposal_hash($p)]);
                if ($p->action === 'resume' && ($p->target === '*' || $p->target === $this->agentId)) {
                    $this->provisional = array_filter($this->provisional, fn (int $q) => $q >= $p->seq);
                }
            }
        }
        return ['ok' => true, 'size' => $this->replica->size];
    }

    /** A heartbeat answering $nonce, which the agent sent at $atMs: ['ok', 'code']. */
    public function heartbeat(mixed $hb, mixed $nonce, int $atMs): array {
        $code = $this->checkHeartbeat($hb, $nonce);
        if ($code === null) {
            $size = $hb->log_size;
            if ($this->replica->size >= $size) {
                if ($this->replica->hashes[$size - 1] !== $hb->head) {
                    $this->fork = true;
                    $code = 'SW-FORK';
                }
            } else {
                $code = 'SW-BEHIND';
            }
        }
        if ($code === null) {
            $this->lastOkMs = $this->lastOkMs === null ? $atMs : max($this->lastOkMs, $atMs);
            return ['ok' => true, 'code' => 'SW-OK'];
        }
        return ['ok' => false, 'code' => $code];
    }

    private function checkHeartbeat(mixed $hb, mixed $nonce): ?string {
        if (!exactly($hb, HEARTBEAT_FIELDS) || $hb->type !== 'smartswitch.heartbeat' || !int_in($hb->log_size, 1, MAX_INT)
            || !is_key_hex($hb->head) || !int_in($hb->issued_ms, 0, MAX_INT)) {
            return 'SW-BAD-HEARTBEAT';
        }
        try {
            $msg = heartbeat_message($hb);
        } catch (\InvalidArgumentException) {   // no canonical form: it cannot carry a valid signature
            return 'SW-BAD-HEARTBEAT';
        }
        if (!verify($this->fleet->coordinator_key, $msg, $hb->sig)) return 'SW-BAD-HEARTBEAT';
        if ($hb->fleet_hash !== $this->fleetHash) return 'SW-WRONG-FLEET';
        if ($hb->agent_id !== $this->agentId || $hb->instance_id !== $this->instanceId) return 'SW-WRONG-AGENT';
        if (!is_nonce($nonce) || $hb->nonce !== $nonce) return 'SW-NONCE';
        return null;
    }

    /** A certificate delivered directly (not through the log), checked at WALL-CLOCK time $atMs (it is
     *  compared with expires_ms): ['ok', 'code']. Only a valid halt of this agent or of the whole fleet, newer
     *  than the local state, has an effect: a provisional halt (see log() for when it ends). */
    public function certificate(mixed $cert, int $atMs): array {
        $st = $this->replica->state;
        if ($st === null) return ['ok' => false, 'code' => 'SW-NO-STATE'];
        try {
            $p = verify_certificate($st, $cert, $atMs, true);
        } catch (SwitchError $e) {
            return ['ok' => false, 'code' => $e->swCode];
        }
        if ($p->action !== 'halt' || ($p->target !== '*' && $p->target !== $this->agentId)) return ['ok' => false, 'code' => 'SW-NOT-APPLICABLE'];
        $this->provisional[proposal_hash($p)] = $p->seq;
        return ['ok' => true, 'code' => 'SW-PROVISIONAL-HALT'];
    }

    /** ['run', 'code']: the first matching reason in the order of SEMANTICS.md wins. */
    public function status(int $atMs): array {
        $st = $this->replica->state;
        if ($this->fork) $code = 'SW-FORK';
        elseif ($st !== null && $st->haltedAll) $code = 'SW-HALTED-FLEET';
        elseif ($st !== null && $st->isHalted($this->agentId)) $code = 'SW-HALTED-AGENT';
        elseif ($this->provisional) $code = 'SW-PROVISIONAL-HALT';
        elseif ($this->lastOkMs === null || $st === null) $code = 'SW-NO-HEARTBEAT';
        elseif ($atMs - $this->lastOkMs >= $st->offlineTimeoutMs) $code = 'SW-OFFLINE';
        else return ['run' => true, 'code' => 'SW-RUN'];
        return ['run' => false, 'code' => $code];
    }
}

// ------------------------------------------------------------------ networked agent

/** The agent's monotonic clock in milliseconds (heartbeats and status). */
function mono_ms(): int { return intdiv(hrtime(true), 1000000); }

/** Wall-clock milliseconds (delivered certificates: compared with expires_ms). */
function wall_ms(): int { return (int) floor(microtime(true) * 1000); }

/** Read and validate a fleet document (throws SwitchError SW-BAD-FLEET, \RuntimeException, \JsonException). */
function load_fleet(string $path): \stdClass {
    $text = @file_get_contents($path);
    if ($text === false) throw new \RuntimeException("cannot read $path");
    return validate_fleet(decode($text));
}

/** The agent's calls to the coordinator (PHP http stream wrapper, HTTP/1.0: one connection per request).
 *  Any answer other than 2xx throws \RuntimeException. */
final class Client {
    /** The largest answer read; a longer one is an error. */
    public const MAX_RESPONSE_BYTES = 32 * 1024 * 1024;
    public readonly string $url;

    public function __construct(string $url, private readonly ?string $token = null, private readonly float $timeout = 2.0) {
        if (!str_starts_with($url, 'http://') && !str_starts_with($url, 'https://')) {
            throw new \InvalidArgumentException('the coordinator URL must start with http:// or https://');
        }
        $this->url = rtrim($url, '/');
    }

    public function get(string $path, array $query): mixed {
        $hdr = "Accept: application/json\r\n" . ($this->token !== null && $this->token !== '' ? "Authorization: Bearer {$this->token}\r\n" : '');
        $ctx = stream_context_create(['http' => ['method' => 'GET', 'header' => $hdr, 'timeout' => $this->timeout,
            'ignore_errors' => true, 'follow_location' => 0]]);
        $text = @file_get_contents($this->url . $path . '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986), false, $ctx,
            0, self::MAX_RESPONSE_BYTES + 1);
        if ($text === false) throw new \RuntimeException('coordinator unreachable: ' . (error_get_last()['message'] ?? ''));
        if (strlen($text) > self::MAX_RESPONSE_BYTES) throw new \RuntimeException('the answer is longer than ' . self::MAX_RESPONSE_BYTES . ' bytes');
        $status = 0;
        foreach ($http_response_header ?? [] as $h) if (preg_match('#^HTTP/\S+ (\d+)#', $h, $m)) $status = (int) $m[1];
        if ($status < 200 || $status >= 300) throw new \RuntimeException("HTTP $status: " . substr($text, 0, 300));
        return decode($text);
    }

    public function heartbeat(string $agentId, string $instanceId, string $nonce): mixed {
        return $this->get('/v1/heartbeat', ['agent_id' => $agentId, 'instance_id' => $instanceId, 'nonce' => $nonce]);
    }

    public function log(int $from, int $limit, string $agentId, string $instanceId): mixed {
        return $this->get('/v1/log', ['from' => $from, 'limit' => $limit, 'agent_id' => $agentId, 'instance_id' => $instanceId]);
    }
}

/**
 * The networked agent. PHP has no background thread here: call pollOnce() every $pollMs yourself, or
 * use mayRun() / checkpoint(), which poll first when a poll is due. Network errors change nothing; with
 * no valid heartbeat for the fleet's offline_timeout_ms the agent stops by itself (SW-OFFLINE).
 */
final class Agent {
    public readonly \stdClass $fleet;
    public readonly AgentView $view;
    public ?string $lastError = null;
    /** @var ?callable(array): void called with the new status whenever it changes */
    public $onChange = null;
    private Client $client;
    private ?array $last = null;
    private ?int $lastPollMs = null;

    public function __construct(string $url, ?string $token, \stdClass $fleet, string $agentId, string $instanceId,
                                public readonly int $pollMs = 1000, float $timeout = 2.0) {
        $this->fleet = validate_fleet($fleet);
        $this->view = new AgentView($this->fleet, $agentId, $instanceId);
        $this->client = new Client($url, $token, $timeout);
    }

    /** One round: heartbeat (and log fetch when behind). Returns the status afterwards. */
    public function pollOnce(): array {
        $nonce = bin2hex(random_bytes(16));
        $sent = mono_ms();
        $this->lastPollMs = $sent;
        try {
            $hb = $this->client->heartbeat($this->view->agentId, $this->view->instanceId, $nonce);
            $r = $this->view->heartbeat($hb, $nonce, $sent);
            if ($r['code'] === 'SW-BEHIND') {
                $this->catchUp($hb->log_size);
                $r = $this->view->heartbeat($hb, $nonce, $sent);
            }
            $this->lastError = $r['ok'] ? null : $r['code'];
        } catch (\Throwable $e) {   // any error changes nothing (the dead-man rule takes over)
            $this->lastError = get_class($e) . ': ' . $e->getMessage();
        }
        return $this->status();
    }

    private function catchUp(int $size): void {
        while ($this->view->replica->size < $size) {
            $body = $this->client->log($this->view->replica->size, 1000, $this->view->agentId, $this->view->instanceId);
            if (!($body instanceof \stdClass) || !isset($body->entries) || !is_array($body->entries)) {
                throw new \RuntimeException('the coordinator answered /v1/log without entries');
            }
            if (!$body->entries) return;
            $r = $this->view->log($body->entries);
            if (!$r['ok']) throw new \RuntimeException("the coordinator log does not verify ({$r['code']} at entry {$r['size']})");
        }
    }

    /** Poll if the last poll is $pollMs or more ago. */
    public function tick(): void {
        if ($this->lastPollMs === null || mono_ms() - $this->lastPollMs >= $this->pollMs) $this->pollOnce();
    }

    /** A certificate that reached this agent some other way than the coordinator. */
    public function deliver(mixed $certificate): array {
        $r = $this->view->certificate($certificate, wall_ms());
        $this->status();
        return $r;
    }

    /** ['run' => bool, 'code' => string] now (no network). */
    public function status(): array {
        $s = $this->view->status(mono_ms());
        if ($s !== $this->last) {
            $this->last = $s;
            if ($this->onChange !== null) ($this->onChange)($s);
        }
        return $s;
    }

    public function mayRun(): bool {
        $this->tick();
        return $this->status()['run'];
    }

    /** Throws Halted when the agent may not run. */
    public function checkpoint(): void {
        $this->tick();
        $s = $this->status();
        if (!$s['run']) throw new Halted($s['code']);
    }
}
