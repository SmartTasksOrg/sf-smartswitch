//! The SmartSwitch protocol: fleet document, proposals, certificates and the switch state
//! (spec/SEMANTICS.md). Deterministic: no clock, no randomness, no I/O; time comes in as `at_ms`.
use crate::ed25519;
use crate::json::{canonical, Value};
use crate::sha256;
use std::collections::{BTreeMap, BTreeSet};

pub const VOTE_PREFIX: &str = "smartswitch-vote-v1:";
pub const HEARTBEAT_PREFIX: &str = "smartswitch-heartbeat-v1:";
pub const MAX_KEYHOLDERS: usize = 64;
pub const MAX_AGENTS: usize = 100_000;
pub const MAX_REASON_BYTES: usize = 1000;
pub const MAX_INT: i64 = (1 << 53) - 1;

const FLEET_FIELDS: [&str; 9] = [
    "type", "version", "fleet_id", "keyholders", "threshold", "coordinator_key", "offline_timeout_ms",
    "proposal_max_ttl_ms", "agents",
];
const PROPOSAL_FIELDS: [&str; 11] = [
    "type", "fleet_id", "fleet_hash", "seq", "epoch", "action", "target", "new_public_key", "reason",
    "created_ms", "expires_ms",
];

/// A broken rule; `code` is the stable SW-* code of spec/SEMANTICS.md.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwitchError {
    pub code: &'static str,
    pub message: String,
}

impl SwitchError {
    pub fn new(code: &'static str, message: impl Into<String>) -> SwitchError {
        SwitchError { code, message: message.into() }
    }
}

impl std::fmt::Display for SwitchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.message.is_empty() {
            write!(f, "{}", self.code)
        } else {
            write!(f, "{}: {}", self.code, self.message)
        }
    }
}

impl std::error::Error for SwitchError {}

/// sha256(canonical(v)) as lower-case hex; None when `v` has no canonical form (a float).
pub fn doc_hash(v: &Value) -> Option<String> {
    canonical(v).ok().map(|t| sha256::hex(t.as_bytes()))
}

/// An id: 1 to 64 characters from A-Z a-z 0-9 . _ -
pub fn is_id_str(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-')
}

pub fn is_id(v: &Value) -> bool {
    v.as_str().is_some_and(is_id_str)
}

pub fn is_key(v: &Value) -> bool {
    v.as_str().is_some_and(ed25519::is_key_hex)
}

/// An integer (not a bool, not a float) from lo to hi.
pub fn int_in(v: &Value, lo: i64, hi: i64) -> bool {
    matches!(v, Value::Int(i) if lo <= *i && *i <= hi)
}

fn field<'a>(v: &'a Value, k: &str) -> &'a Value {
    v.get(k).unwrap_or(&Value::Null)
}

// ------------------------------------------------------------------ fleet

/// 2 for up to five keyholders; floor(n/2) + 1 above five.
pub fn default_threshold(n: i64) -> i64 {
    if n <= 5 {
        2
    } else {
        n / 2 + 1
    }
}

/// Ok when `doc` is a valid fleet document, else SW-BAD-FLEET.
pub fn validate_fleet(doc: &Value) -> Result<(), SwitchError> {
    let bad = |m: &str| Err(SwitchError::new("SW-BAD-FLEET", m));
    if !doc.has_exactly(&FLEET_FIELDS) {
        return bad("the fleet document must have exactly the fields of spec/SEMANTICS.md");
    }
    if field(doc, "type").as_str() != Some("smartswitch.fleet") || field(doc, "version") != &Value::Int(1) {
        return bad("type must be \"smartswitch.fleet\" and version 1");
    }
    if !is_id(field(doc, "fleet_id")) {
        return bad("fleet_id must match [A-Za-z0-9._-]{1,64}");
    }
    let khs = match field(doc, "keyholders").as_arr() {
        Some(a) if (3..=MAX_KEYHOLDERS).contains(&a.len()) => a,
        _ => return bad("keyholders must be a list of 3 to 64"),
    };
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for kh in khs {
        if !kh.has_exactly(&["id", "public_key"]) {
            return bad("each keyholder must be {\"id\", \"public_key\"}");
        }
        if !is_id(field(kh, "id")) || !is_key(field(kh, "public_key")) {
            return bad("keyholder id must be an id and public_key 64 lower-case hex");
        }
        let id = field(kh, "id").as_str().unwrap();
        let key = field(kh, "public_key").as_str().unwrap();
        if ids.contains(id) || keys.contains(key) {
            return bad("keyholder ids and public keys must be unique");
        }
        ids.insert(id);
        keys.insert(key);
    }
    let n = khs.len() as i64;
    let th = field(doc, "threshold");
    if th != &Value::Null && !int_in(th, 2, n - 1) {
        return bad("threshold must be null or an integer from 2 to n - 1");
    }
    let ck = field(doc, "coordinator_key");
    if !is_key(ck) || keys.contains(ck.as_str().unwrap()) {
        return bad("coordinator_key must be 64 lower-case hex and differ from every keyholder key");
    }
    if !int_in(field(doc, "offline_timeout_ms"), 1000, 3_600_000) {
        return bad("offline_timeout_ms must be an integer from 1000 to 3600000");
    }
    if !int_in(field(doc, "proposal_max_ttl_ms"), 1000, 86_400_000) {
        return bad("proposal_max_ttl_ms must be an integer from 1000 to 86400000");
    }
    match field(doc, "agents") {
        Value::Null => {}
        Value::Arr(agents) if agents.len() <= MAX_AGENTS => {
            let mut seen = BTreeSet::new();
            for a in agents {
                if !a.has_exactly(&["id", "max_instances"]) {
                    return bad("each agent must be {\"id\", \"max_instances\"}");
                }
                let id = field(a, "id");
                if !is_id(id) || !int_in(field(a, "max_instances"), 1, 1000) || seen.contains(id.as_str().unwrap()) {
                    return bad("agent ids must be unique ids and max_instances 1 to 1000");
                }
                seen.insert(id.as_str().unwrap());
            }
        }
        _ => return bad("agents must be null or a list of at most 100000"),
    }
    Ok(())
}

// ------------------------------------------------------------------ proposals and certificates

/// A proposal that passed the format check.
#[derive(Clone, Debug)]
pub struct Proposal {
    pub fleet_id: String,
    pub fleet_hash: String,
    pub seq: i64,
    pub epoch: i64,
    pub action: String,
    pub target: String,
    pub new_public_key: Option<String>,
    pub reason: String,
    pub created_ms: i64,
    pub expires_ms: i64,
}

pub fn check_proposal_format(p: &Value) -> Result<Proposal, SwitchError> {
    let bad = |m: &str| Err(SwitchError::new("SW-BAD-PROPOSAL", m));
    if !p.has_exactly(&PROPOSAL_FIELDS) {
        return bad("a proposal must have exactly the fields of spec/SEMANTICS.md");
    }
    if field(p, "type").as_str() != Some("smartswitch.proposal") {
        return bad("type must be \"smartswitch.proposal\"");
    }
    if !is_id(field(p, "fleet_id")) || !is_key(field(p, "fleet_hash")) {
        return bad("fleet_id or fleet_hash is malformed");
    }
    if !int_in(field(p, "seq"), 1, MAX_INT) || !int_in(field(p, "epoch"), 0, MAX_INT) {
        return bad("seq must be an integer >= 1 and epoch >= 0");
    }
    let action = match field(p, "action").as_str() {
        Some(a @ ("halt" | "resume" | "suspend" | "reinstate")) => a,
        _ => return bad("action must be halt, resume, suspend or reinstate"),
    };
    let Some(target) = field(p, "target").as_str() else {
        return bad("target must be a string");
    };
    let nk = field(p, "new_public_key");
    if action == "reinstate" {
        if !is_key(nk) {
            return bad("reinstate needs new_public_key (64 lower-case hex)");
        }
    } else if nk != &Value::Null {
        return bad("new_public_key must be null unless the action is reinstate");
    }
    let reason = match field(p, "reason").as_str() {
        Some(r) if r.len() <= MAX_REASON_BYTES => r,
        _ => return bad("reason must be a string of at most 1000 UTF-8 bytes"),
    };
    if !int_in(field(p, "created_ms"), 0, MAX_INT) || !int_in(field(p, "expires_ms"), 0, MAX_INT) {
        return bad("created_ms and expires_ms must be integers >= 0");
    }
    let created_ms = field(p, "created_ms").as_int().unwrap();
    let expires_ms = field(p, "expires_ms").as_int().unwrap();
    if expires_ms <= created_ms {
        return bad("expires_ms must be after created_ms");
    }
    Ok(Proposal {
        fleet_id: field(p, "fleet_id").as_str().unwrap().to_string(),
        fleet_hash: field(p, "fleet_hash").as_str().unwrap().to_string(),
        seq: field(p, "seq").as_int().unwrap(),
        epoch: field(p, "epoch").as_int().unwrap(),
        action: action.to_string(),
        target: target.to_string(),
        new_public_key: nk.as_str().map(str::to_string),
        reason: reason.to_string(),
        created_ms,
        expires_ms,
    })
}

/// doc_hash of a proposal (any JSON value; None when it has no canonical form).
pub fn proposal_hash(p: &Value) -> Option<String> {
    doc_hash(p)
}

pub fn vote_message(p_hash: &str) -> Vec<u8> {
    format!("{}{}", VOTE_PREFIX, p_hash).into_bytes()
}

fn check_certificate_format(c: &Value) -> Result<(), SwitchError> {
    let bad = |m: &str| Err(SwitchError::new("SW-BAD-CERTIFICATE", m));
    if !c.has_exactly(&["type", "proposal", "votes"]) {
        return bad("a certificate must be {\"type\", \"proposal\", \"votes\"}");
    }
    if field(c, "type").as_str() != Some("smartswitch.certificate") {
        return bad("type must be \"smartswitch.certificate\"");
    }
    let votes = match field(c, "votes").as_arr() {
        Some(v) if (1..=MAX_KEYHOLDERS).contains(&v.len()) => v,
        _ => return bad("votes must be a list of 1 to 64"),
    };
    for v in votes {
        if !v.has_exactly(&["keyholder", "sig"]) || field(v, "keyholder").as_str().is_none() || field(v, "sig").as_str().is_none() {
            return bad("each vote must be {\"keyholder\": string, \"sig\": string}");
        }
    }
    Ok(())
}

// ------------------------------------------------------------------ state

#[derive(Clone, Debug)]
pub struct State {
    pub fleet_id: String,
    pub fleet_hash: String,
    pub coordinator_key: String,
    pub n: usize,
    pub threshold: i64,
    pub max_ttl_ms: i64,
    pub offline_timeout_ms: i64,
    /// keyholder id -> current public key
    pub keys: BTreeMap<String, String>,
    pub suspended: BTreeSet<String>,
    pub seq: i64,
    pub epoch: i64,
    pub halted_all: bool,
    pub halted: BTreeSet<String>,
    /// agent id -> max_instances, or None without a roster
    pub roster: Option<BTreeMap<String, i64>>,
}

impl State {
    /// The state of a valid fleet before any certificate.
    pub fn genesis(fleet: &Value) -> Result<State, SwitchError> {
        validate_fleet(fleet)?;
        let khs = field(fleet, "keyholders").as_arr().unwrap();
        let n = khs.len();
        let threshold = field(fleet, "threshold").as_int().unwrap_or_else(|| default_threshold(n as i64));
        Ok(State {
            fleet_id: field(fleet, "fleet_id").as_str().unwrap().to_string(),
            fleet_hash: doc_hash(fleet).unwrap(),
            coordinator_key: field(fleet, "coordinator_key").as_str().unwrap().to_string(),
            n,
            threshold,
            max_ttl_ms: field(fleet, "proposal_max_ttl_ms").as_int().unwrap(),
            offline_timeout_ms: field(fleet, "offline_timeout_ms").as_int().unwrap(),
            keys: khs
                .iter()
                .map(|k| (field(k, "id").as_str().unwrap().to_string(), field(k, "public_key").as_str().unwrap().to_string()))
                .collect(),
            suspended: BTreeSet::new(),
            seq: 0,
            epoch: 0,
            halted_all: false,
            halted: BTreeSet::new(),
            roster: field(fleet, "agents").as_arr().map(|a| {
                a.iter()
                    .map(|x| (field(x, "id").as_str().unwrap().to_string(), field(x, "max_instances").as_int().unwrap()))
                    .collect()
            }),
        })
    }

    /// Keyholder ids that are not suspended, sorted.
    pub fn active(&self) -> Vec<String> {
        self.keys.keys().filter(|k| !self.suspended.contains(*k)).cloned().collect()
    }

    pub fn may_run(&self, agent_id: &str) -> bool {
        !self.halted_all && !self.halted.contains(agent_id)
    }

    /// The state as the vectors compare it.
    pub fn summary(&self) -> Value {
        let strs = |it: &mut dyn Iterator<Item = &String>| Value::Arr(it.map(|s| Value::Str(s.clone())).collect());
        Value::obj(vec![
            ("seq", Value::Int(self.seq)),
            ("epoch", Value::Int(self.epoch)),
            ("threshold", Value::Int(self.threshold)),
            ("halted_all", Value::Bool(self.halted_all)),
            ("halted", strs(&mut self.halted.iter())),
            ("active", strs(&mut self.active().iter())),
            ("suspended", strs(&mut self.suspended.iter())),
            ("keys", Value::Obj(self.keys.iter().map(|(k, v)| (k.clone(), Value::Str(v.clone()))).collect())),
        ])
    }
}

/// Check `cert` against `st` at `at_ms` (spec/SEMANTICS.md, "Certificate checks"); the first failing
/// check gives the error. `ahead` accepts any seq above the state's (a certificate delivered directly).
pub fn verify_certificate(st: &State, cert: &Value, at_ms: i64, ahead: bool) -> Result<Proposal, SwitchError> {
    check_certificate_format(cert)?;
    let pv = field(cert, "proposal");
    let p = check_proposal_format(pv)?;
    if p.fleet_id != st.fleet_id || p.fleet_hash != st.fleet_hash {
        return Err(SwitchError::new("SW-WRONG-FLEET", "the proposal is for another fleet"));
    }
    if p.seq <= st.seq {
        return Err(SwitchError::new("SW-STALE-SEQ", format!("seq {} is not after the current seq {}", p.seq, st.seq)));
    }
    if !ahead && p.seq != st.seq + 1 {
        return Err(SwitchError::new("SW-SEQ-GAP", format!("seq {} is not the next seq {}", p.seq, st.seq + 1)));
    }
    if p.epoch != st.epoch {
        return Err(SwitchError::new("SW-WRONG-EPOCH", format!("epoch {} is not the current epoch {}", p.epoch, st.epoch)));
    }
    if p.expires_ms - p.created_ms > st.max_ttl_ms {
        return Err(SwitchError::new("SW-BAD-PROPOSAL", "the proposal is valid for longer than proposal_max_ttl_ms"));
    }
    if at_ms >= p.expires_ms {
        return Err(SwitchError::new("SW-EXPIRED", "the proposal has expired"));
    }
    check_target(st, &p)?;
    let msg = vote_message(&proposal_hash(pv).unwrap());
    let mut seen = BTreeSet::new();
    for v in field(cert, "votes").as_arr().unwrap() {
        let kh = field(v, "keyholder").as_str().unwrap();
        let Some(key) = st.keys.get(kh) else {
            return Err(SwitchError::new("SW-UNKNOWN-KEYHOLDER", format!("{:?} is not a keyholder of this fleet", kh)));
        };
        if !seen.insert(kh) {
            return Err(SwitchError::new("SW-DUPLICATE-VOTE", format!("{:?} voted twice", kh)));
        }
        if st.suspended.contains(kh) {
            return Err(SwitchError::new("SW-SUSPENDED-KEYHOLDER", format!("{:?} is suspended", kh)));
        }
        if p.action == "suspend" && kh == p.target {
            return Err(SwitchError::new("SW-TARGET-VOTE", "a keyholder cannot vote on its own suspension"));
        }
        if !ed25519::verify(key, &msg, field(v, "sig").as_str().unwrap()) {
            return Err(SwitchError::new("SW-BAD-SIGNATURE", format!("the signature of {:?} does not verify", kh)));
        }
    }
    if (seen.len() as i64) < st.threshold {
        return Err(SwitchError::new("SW-NO-QUORUM", format!("{} valid votes, {} needed", seen.len(), st.threshold)));
    }
    Ok(p)
}

fn check_target(st: &State, p: &Proposal) -> Result<(), SwitchError> {
    let t = p.target.as_str();
    match p.action.as_str() {
        "halt" | "resume" => {
            if t != "*" && !is_id_str(t) {
                return Err(SwitchError::new("SW-BAD-TARGET", "target must be \"*\" or an agent id"));
            }
        }
        "suspend" => {
            if !st.keys.contains_key(t) || st.suspended.contains(t) {
                return Err(SwitchError::new("SW-BAD-TARGET", "target must be an active keyholder"));
            }
            if (st.active().len() as i64) - 1 < st.threshold {
                return Err(SwitchError::new("SW-QUORUM-IMPOSSIBLE", "suspending would leave fewer active keyholders than the threshold"));
            }
        }
        _ => {
            if !st.suspended.contains(t) {
                return Err(SwitchError::new("SW-BAD-TARGET", "target must be a suspended keyholder"));
            }
            let k = p.new_public_key.as_deref().unwrap_or("");
            if st.keys.values().any(|v| v == k) || k == st.coordinator_key {
                return Err(SwitchError::new("SW-BAD-TARGET", "new_public_key must be a key not used in this fleet"));
            }
        }
    }
    Ok(())
}

/// Verify `cert` (seq must be st.seq + 1) and return the next state; `st` is not changed.
pub fn apply(st: &State, cert: &Value, at_ms: i64) -> Result<State, SwitchError> {
    let p = verify_certificate(st, cert, at_ms, false)?;
    let mut nxt = st.clone();
    nxt.seq += 1;
    let t = p.target.clone();
    match p.action.as_str() {
        "halt" => {
            if t == "*" {
                nxt.halted_all = true;
            } else {
                nxt.halted.insert(t);
            }
        }
        "resume" => {
            if t == "*" {
                nxt.halted_all = false;
                nxt.halted.clear();
            } else {
                nxt.halted.remove(&t);
            }
        }
        "suspend" => {
            nxt.epoch += 1;
            nxt.suspended.insert(t);
        }
        _ => {
            nxt.epoch += 1;
            nxt.suspended.remove(&t);
            nxt.keys.insert(t, p.new_public_key.unwrap());
        }
    }
    Ok(nxt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    fn fleet(threshold: &str) -> Value {
        let k = |c: char| format!("\"{}\"", c.to_string().repeat(64));
        parse(&format!(
            "{{\"type\":\"smartswitch.fleet\",\"version\":1,\"fleet_id\":\"f\",\"keyholders\":[{{\"id\":\"a\",\"public_key\":{}}},{{\"id\":\"b\",\"public_key\":{}}},{{\"id\":\"c\",\"public_key\":{}}},{{\"id\":\"d\",\"public_key\":{}}}],\"threshold\":{},\"coordinator_key\":{},\"offline_timeout_ms\":30000,\"proposal_max_ttl_ms\":600000,\"agents\":null}}",
            k('a'), k('b'), k('c'), k('d'), threshold, k('e')
        ))
        .unwrap()
    }

    #[test]
    fn default_thresholds() {
        let got: Vec<i64> = (3..=9).map(default_threshold).collect();
        assert_eq!(got, vec![2, 2, 2, 4, 4, 5, 5]);
    }

    #[test]
    fn threshold_must_be_an_integer() {
        assert!(validate_fleet(&fleet("null")).is_ok());
        assert!(validate_fleet(&fleet("3")).is_ok());
        for bad in ["2.5", "true", "\"2\"", "4", "1"] {
            assert_eq!(validate_fleet(&fleet(bad)).unwrap_err().code, "SW-BAD-FLEET", "{}", bad);
        }
        assert_eq!(State::genesis(&fleet("null")).unwrap().threshold, 2);
    }

    #[test]
    fn ids() {
        assert!(is_id_str("a-1._B"));
        assert!(!is_id_str(""));
        assert!(!is_id_str("a b"));
        assert!(!is_id_str(&"x".repeat(65)));
    }
}
