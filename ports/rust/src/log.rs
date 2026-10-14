//! The switch log: a hash-chained list of entries, verified and replayed entry by entry
//! (spec/SEMANTICS.md, "Log").
use crate::json::Value;
use crate::protocol::{apply, doc_hash, validate_fleet, State, SwitchError};

pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const ENTRY_FIELDS: [&str; 6] = ["n", "ts_ms", "kind", "body", "prev", "hash"];

/// doc_hash of the entry without its "hash" field; None when it has no canonical form.
pub fn entry_hash(e: &Value) -> Option<String> {
    let mut m = e.as_obj()?.clone();
    m.remove("hash");
    doc_hash(&Value::Obj(m))
}

/// A verified copy of a log. `extend` checks entries one by one and applies certificates; on the first
/// bad entry it returns the error and keeps everything before it.
#[derive(Clone, Debug)]
pub struct Replica {
    /// None: accept any genesis.
    pub pinned: Option<String>,
    pub state: Option<State>,
    pub size: usize,
    pub head: String,
    /// Every entry's hash, to compare with heartbeats.
    pub hashes: Vec<String>,
}

impl Replica {
    pub fn new(pinned: Option<String>) -> Replica {
        Replica { pinned, state: None, size: 0, head: GENESIS_PREV.to_string(), hashes: vec![] }
    }

    pub fn extend(&mut self, entries: &[Value]) -> Result<usize, SwitchError> {
        for e in entries {
            self.one(e)?;
        }
        Ok(self.size)
    }

    fn one(&mut self, e: &Value) -> Result<(), SwitchError> {
        let i = self.size;
        let get = |k: &str| e.get(k).unwrap_or(&Value::Null);
        let kind = get("kind").as_str().unwrap_or("");
        let shape_ok = e.has_exactly(&ENTRY_FIELDS)
            && matches!(kind, "genesis" | "certificate" | "event")
            && get("body").as_obj().is_some()
            && get("n").as_int().is_some()
            && get("ts_ms").as_int().is_some_and(|t| t >= 0);
        if !shape_ok {
            return Err(SwitchError::new("SW-BAD-ENTRY", format!("entry {} is malformed", i)));
        }
        let n = get("n").as_int().unwrap();
        let ts = get("ts_ms").as_int().unwrap();
        // ts_ms is the coordinator's unsigned wall clock and need not increase (spec/SEMANTICS.md, "Log").
        if n != i as i64 {
            return Err(SwitchError::new("SW-LOG-ORDER", format!("entry {}: n is {}", i, n)));
        }
        let hash = get("hash").as_str();
        if get("prev").as_str() != Some(self.head.as_str()) || hash.is_none() || entry_hash(e).as_deref() != hash {
            return Err(SwitchError::new("SW-LOG-CHAIN", format!("entry {}: the hash chain is broken", i)));
        }
        let body = get("body");
        let next_state = if i == 0 {
            if kind != "genesis" {
                return Err(SwitchError::new("SW-BAD-ENTRY", "entry 0 must be the genesis"));
            }
            if let Err(err) = validate_fleet(body) {
                return Err(SwitchError::new("SW-BAD-FLEET", format!("entry 0: {}", err.message)));
            }
            if let Some(p) = &self.pinned {
                if doc_hash(body).as_deref() != Some(p.as_str()) {
                    return Err(SwitchError::new("SW-WRONG-FLEET", "entry 0 is not the pinned fleet"));
                }
            }
            Some(State::genesis(body)?)
        } else if kind == "genesis" {
            return Err(SwitchError::new("SW-BAD-ENTRY", format!("entry {}: only entry 0 can be a genesis", i)));
        } else if kind == "certificate" {
            Some(apply(self.state.as_ref().unwrap(), body, ts)?)
        } else {
            None
        };
        if let Some(s) = next_state {
            self.state = Some(s);
        }
        let h = hash.unwrap().to_string();
        self.size += 1;
        self.head = h.clone();
        self.hashes.push(h);
        Ok(())
    }
}

/// `{"ok": true, "size", "head", "state"}` or `{"ok": false, "index", "code"}` (the vectors' form).
pub fn replay(entries: &[Value], pinned: Option<&str>) -> Value {
    let mut r = Replica::new(pinned.map(str::to_string));
    if let Err(e) = r.extend(entries) {
        return Value::obj(vec![("ok", Value::Bool(false)), ("index", Value::Int(r.size as i64)), ("code", Value::s(e.code))]);
    }
    if r.size == 0 {
        return Value::obj(vec![("ok", Value::Bool(false)), ("index", Value::Int(0)), ("code", Value::s("SW-BAD-ENTRY"))]);
    }
    Value::obj(vec![
        ("ok", Value::Bool(true)),
        ("size", Value::Int(r.size as i64)),
        ("head", Value::Str(r.head.clone())),
        ("state", r.state.as_ref().unwrap().summary()),
    ])
}
