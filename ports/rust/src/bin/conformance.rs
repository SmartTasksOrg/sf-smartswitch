//! Run the shared vectors (spec/conformance/*.json) against this port:
//!     cargo run --release --bin conformance -- <vectors dir>
//! Prints each failure and a last line "rust: N/N vectors passed"; exit 1 on any failure.
use smartswitch::agentview::AgentView;
use smartswitch::ed25519;
use smartswitch::json::{self, canonical, Value};
use smartswitch::log::replay;
use smartswitch::protocol::{apply, default_threshold, doc_hash, proposal_hash, validate_fleet, verify_certificate, State};
use smartswitch::sha256;

fn load(dir: &str, name: &str) -> Value {
    let path = format!("{}/{}", dir, name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {}", path, e));
    json::parse(&text).unwrap_or_else(|e| panic!("{}: {}", path, e))
}

fn show(v: &Value) -> String {
    let s = canonical(v).unwrap_or_else(|_| format!("{:?}", v));
    s.chars().take(300).collect()
}

fn cases(v: &Value) -> &Vec<Value> {
    v.get("cases").and_then(Value::as_arr).expect("cases")
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or_else(|| panic!("missing string {}", k))
}

fn i(v: &Value, k: &str) -> i64 {
    v.get(k).and_then(Value::as_int).unwrap_or_else(|| panic!("missing integer {}", k))
}

fn null() -> &'static Value {
    &Value::Null
}

/// The keys of `c` among `keys`, as an object (the "want" of a case).
fn pick(c: &Value, keys: &[&str]) -> Value {
    Value::Obj(keys.iter().filter_map(|k| c.get(k).map(|v| (k.to_string(), v.clone()))).collect())
}

fn err(code: &str) -> Value {
    Value::obj(vec![("ok", Value::Bool(false)), ("code", Value::s(code))])
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "../../spec/conformance".into());
    let mut total = 0usize;
    let mut fails: Vec<String> = vec![];
    let mut check = |name: String, got: Value, want: &Value| {
        total += 1;
        if &got != want {
            fails.push(format!("{}: got {}, want {}", name, show(&got), show(want)));
        }
    };

    let v = load(&dir, "canonical.json");
    for c in cases(&v) {
        let got = match canonical(c.get("input").unwrap_or(null())) {
            Ok(t) => Value::Arr(vec![Value::Str(t.clone()), Value::Str(sha256::hex(t.as_bytes()))]),
            Err(e) => Value::Str(format!("error: {}", e)),
        };
        let want = Value::Arr(vec![c.get("canonical").cloned().unwrap_or(Value::Null), c.get("sha256").cloned().unwrap_or(Value::Null)]);
        check(format!("canonical/{}", s(c, "name")), got, &want);
    }

    let v = load(&dir, "ed25519.json");
    for c in cases(&v) {
        let msg = ed25519::hex_decode(s(c, "message_hex")).expect("message_hex");
        let got = ed25519::verify(s(c, "public_key"), &msg, s(c, "sig"));
        check(format!("ed25519/{}", s(c, "name")), Value::Bool(got), c.get("valid").unwrap_or(null()));
    }

    let v = load(&dir, "fleets.json");
    for c in v.get("default_thresholds").and_then(Value::as_arr).expect("default_thresholds") {
        let n = i(c, "n");
        check(format!("fleets/default threshold n={}", n), Value::Int(default_threshold(n)), c.get("k").unwrap_or(null()));
    }
    for c in cases(&v) {
        let fleet = c.get("fleet").unwrap_or(null());
        let got = match validate_fleet(fleet).and_then(|_| State::genesis(fleet)) {
            Ok(st) => Value::obj(vec![
                ("ok", Value::Bool(true)),
                ("fleet_hash", Value::Str(doc_hash(fleet).unwrap())),
                ("threshold", Value::Int(st.threshold)),
            ]),
            Err(e) => err(e.code),
        };
        check(format!("fleets/{}", s(c, "name")), got, &pick(c, &["ok", "fleet_hash", "threshold", "code"]));
    }

    let v = load(&dir, "certificates.json");
    let fleets = v.get("fleets").expect("fleets");
    for c in cases(&v) {
        let name = s(c, "name");
        let mut st = State::genesis(fleets.get(s(c, "fleet")).expect("fleet")).expect("a valid fleet");
        for su in c.get("setup").and_then(Value::as_arr).expect("setup") {
            st = apply(&st, su.get("certificate").unwrap_or(null()), i(su, "at_ms")).expect("setup certificates apply");
        }
        let cert = c.get("certificate").unwrap_or(null());
        let ph = match cert {
            Value::Obj(m) => m.get("proposal").and_then(proposal_hash).map(Value::Str).unwrap_or(Value::Null),
            _ => Value::Null,
        };
        check(format!("certificates/{} (proposal hash)", name), ph, c.get("proposal_hash").unwrap_or(null()));
        let at = i(c, "at_ms");
        let got = if c.get("ahead") == Some(&Value::Bool(true)) {
            match verify_certificate(&st, cert, at, true) {
                Ok(_) => Value::obj(vec![("ok", Value::Bool(true)), ("state", Value::Null)]),
                Err(e) => err(e.code),
            }
        } else {
            match apply(&st, cert, at) {
                Ok(n) => Value::obj(vec![("ok", Value::Bool(true)), ("state", n.summary())]),
                Err(e) => err(e.code),
            }
        };
        check(format!("certificates/{}", name), got, &pick(c, &["ok", "state", "code"]));
    }

    let v = load(&dir, "logs.json");
    for c in cases(&v) {
        let entries = c.get("entries").and_then(Value::as_arr).expect("entries");
        let pinned = c.get("pinned").and_then(Value::as_str);
        check(format!("logs/{}", s(c, "name")), replay(entries, pinned), c.get("result").unwrap_or(null()));
    }

    let v = load(&dir, "agent.json");
    let fleet = v.get("fleet").expect("fleet");
    for c in cases(&v) {
        let mut view = AgentView::new(fleet, s(c, "agent_id"), s(c, "instance_id")).expect("agent view");
        for (k, st) in c.get("steps").and_then(Value::as_arr).expect("steps").iter().enumerate() {
            let op = s(st, "op");
            let got = match op {
                "log" => view.log(st.get("entries").and_then(Value::as_arr).expect("entries")),
                "heartbeat" => view.heartbeat(st.get("heartbeat").unwrap_or(null()), s(st, "nonce"), i(st, "at_ms")),
                "certificate" => view.certificate(st.get("certificate").unwrap_or(null()), i(st, "at_ms")),
                _ => view.status(i(st, "at_ms")),
            };
            check(format!("agent/{} step {} ({})", s(c, "name"), k, op), got, st.get("expect").unwrap_or(null()));
        }
    }

    for f in &fails {
        println!("FAIL {}", f);
    }
    if fails.is_empty() {
        println!("rust: {}/{} vectors passed", total, total);
    } else {
        println!("rust: {} of {} vectors failed", fails.len(), total);
        std::process::exit(1);
    }
}
