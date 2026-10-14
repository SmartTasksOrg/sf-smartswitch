//! What an agent believes, and whether it may run: the agent-side rules without any I/O
//! (spec/SEMANTICS.md, "Agent"). Times for heartbeats and status are the agent's own monotonic
//! milliseconds; the time for a delivered certificate is wall-clock milliseconds (it is compared with
//! `expires_ms`).
use crate::ed25519;
use crate::json::Value;
use crate::log::Replica;
use crate::protocol::{doc_hash, int_in, is_id_str, is_key, proposal_hash, verify_certificate, HEARTBEAT_PREFIX, MAX_INT};
use std::collections::BTreeMap;

const HEARTBEAT_FIELDS: [&str; 9] =
    ["type", "fleet_hash", "agent_id", "instance_id", "nonce", "log_size", "head", "issued_ms", "sig"];

/// The signed message of a heartbeat: prefix + doc_hash(heartbeat without "sig").
pub fn heartbeat_message(hb: &Value) -> Option<Vec<u8>> {
    let mut m = hb.as_obj()?.clone();
    m.remove("sig");
    Some(format!("{}{}", HEARTBEAT_PREFIX, doc_hash(&Value::Obj(m))?).into_bytes())
}

fn res(ok: bool, code: &str) -> Value {
    Value::obj(vec![("ok", Value::Bool(ok)), ("code", Value::s(code))])
}

#[derive(Clone, Debug)]
pub struct AgentView {
    pub fleet: Value,
    pub fleet_hash: String,
    pub coordinator_key: String,
    pub agent_id: String,
    pub instance_id: String,
    pub replica: Replica,
    pub last_ok_ms: Option<i64>,
    /// Directly delivered halts not yet ended by the log: proposal hash -> seq.
    pub provisional: BTreeMap<String, i64>,
    pub fork: bool,
}

impl AgentView {
    /// `fleet` must be a valid fleet document (see protocol::validate_fleet); the ids must be ids.
    pub fn new(fleet: &Value, agent_id: &str, instance_id: &str) -> Result<AgentView, String> {
        if !is_id_str(agent_id) || !is_id_str(instance_id) {
            return Err("agent_id and instance_id must match [A-Za-z0-9._-]{1,64}".into());
        }
        crate::protocol::validate_fleet(fleet).map_err(|e| e.to_string())?;
        let fleet_hash = doc_hash(fleet).ok_or("the fleet has no canonical form")?;
        Ok(AgentView {
            fleet: fleet.clone(),
            coordinator_key: fleet.get("coordinator_key").and_then(Value::as_str).unwrap_or("").to_string(),
            replica: Replica::new(Some(fleet_hash.clone())),
            fleet_hash,
            agent_id: agent_id.to_string(),
            instance_id: instance_id.to_string(),
            last_ok_ms: None,
            provisional: BTreeMap::new(),
            fork: false,
        })
    }

    /// Entries that continue the local copy, appended one at a time: `{ok: true, size}` or
    /// `{ok: false, code, size}` (entries before the bad one are kept). A provisional halt ends when the
    /// log applies that same proposal, or a resume of "*" or of this agent with a higher seq; another
    /// certificate taking its seq does not end it.
    pub fn log(&mut self, entries: &[Value]) -> Value {
        for e in entries {
            if let Err(err) = self.replica.extend(std::slice::from_ref(e)) {
                return Value::obj(vec![
                    ("ok", Value::Bool(false)),
                    ("code", Value::s(err.code)),
                    ("size", Value::Int(self.replica.size as i64)),
                ]);
            }
            if !self.provisional.is_empty() && e.get("kind").and_then(Value::as_str) == Some("certificate") {
                // The entry was applied, so its proposal is well-formed.
                let p = e.get("body").and_then(|b| b.get("proposal")).unwrap_or(&Value::Null);
                if let Some(ph) = proposal_hash(p) {
                    self.provisional.remove(&ph);
                }
                let target = p.get("target").and_then(Value::as_str);
                if p.get("action").and_then(Value::as_str) == Some("resume")
                    && (target == Some("*") || target == Some(self.agent_id.as_str()))
                {
                    let seq = p.get("seq").and_then(Value::as_int).unwrap_or(0);
                    self.provisional.retain(|_, q| *q >= seq);
                }
            }
        }
        Value::obj(vec![("ok", Value::Bool(true)), ("size", Value::Int(self.replica.size as i64))])
    }

    /// A heartbeat answering `nonce`, which the agent sent at `at_ms`: `{ok, code}`.
    pub fn heartbeat(&mut self, hb: &Value, nonce: &str, at_ms: i64) -> Value {
        let mut code = self.check_heartbeat(hb, nonce);
        if code.is_none() {
            let size = hb.get("log_size").and_then(Value::as_int).unwrap() as usize;
            let r = &self.replica;
            if r.size >= size {
                if Some(r.hashes[size - 1].as_str()) != hb.get("head").and_then(Value::as_str) {
                    self.fork = true;
                    code = Some("SW-FORK");
                }
            } else {
                code = Some("SW-BEHIND");
            }
        }
        match code {
            None => {
                self.last_ok_ms = Some(self.last_ok_ms.map_or(at_ms, |l| l.max(at_ms)));
                res(true, "SW-OK")
            }
            Some(c) => res(false, c),
        }
    }

    fn check_heartbeat(&self, hb: &Value, nonce: &str) -> Option<&'static str> {
        let get = |k: &str| hb.get(k).unwrap_or(&Value::Null);
        if !hb.has_exactly(&HEARTBEAT_FIELDS)
            || get("type").as_str() != Some("smartswitch.heartbeat")
            || !int_in(get("log_size"), 1, MAX_INT)
            || !is_key(get("head"))
            || !int_in(get("issued_ms"), 0, MAX_INT)
        {
            return Some("SW-BAD-HEARTBEAT");
        }
        let signed = match (heartbeat_message(hb), get("sig").as_str()) {
            (Some(msg), Some(sig)) => ed25519::verify(&self.coordinator_key, &msg, sig),
            _ => false,
        };
        if !signed {
            return Some("SW-BAD-HEARTBEAT");
        }
        if get("fleet_hash").as_str() != Some(self.fleet_hash.as_str()) {
            return Some("SW-WRONG-FLEET");
        }
        if get("agent_id").as_str() != Some(self.agent_id.as_str()) || get("instance_id").as_str() != Some(self.instance_id.as_str()) {
            return Some("SW-WRONG-AGENT");
        }
        if !ed25519::is_lower_hex(nonce, 32) || get("nonce").as_str() != Some(nonce) {
            return Some("SW-NONCE");
        }
        None
    }

    /// A certificate delivered directly (not through the log), checked at wall-clock time `at_ms`:
    /// `{ok, code}`. Only a valid halt of this agent or of the whole fleet has an effect: a provisional
    /// halt (see `log` for when it ends).
    pub fn certificate(&mut self, cert: &Value, at_ms: i64) -> Value {
        let Some(st) = &self.replica.state else {
            return res(false, "SW-NO-STATE");
        };
        let p = match verify_certificate(st, cert, at_ms, true) {
            Ok(p) => p,
            Err(e) => return res(false, e.code),
        };
        if p.action != "halt" || (p.target != "*" && p.target != self.agent_id) {
            return res(false, "SW-NOT-APPLICABLE");
        }
        let ph = proposal_hash(cert.get("proposal").unwrap_or(&Value::Null)).unwrap();
        self.provisional.insert(ph, p.seq);
        res(true, "SW-PROVISIONAL-HALT")
    }

    /// The status code at `at_ms`; the first matching reason wins.
    pub fn status_code(&self, at_ms: i64) -> &'static str {
        let st = self.replica.state.as_ref();
        if self.fork {
            "SW-FORK"
        } else if st.is_some_and(|s| s.halted_all) {
            "SW-HALTED-FLEET"
        } else if st.is_some_and(|s| s.halted.contains(&self.agent_id)) {
            "SW-HALTED-AGENT"
        } else if !self.provisional.is_empty() {
            "SW-PROVISIONAL-HALT"
        } else if self.last_ok_ms.is_none() || st.is_none() {
            "SW-NO-HEARTBEAT"
        } else if at_ms - self.last_ok_ms.unwrap() >= st.unwrap().offline_timeout_ms {
            "SW-OFFLINE"
        } else {
            "SW-RUN"
        }
    }

    /// `{run, code}`.
    pub fn status(&self, at_ms: i64) -> Value {
        let code = self.status_code(at_ms);
        Value::obj(vec![("run", Value::Bool(code == "SW-RUN")), ("code", Value::s(code))])
    }
}
