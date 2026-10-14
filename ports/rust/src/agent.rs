//! The networked agent: ask the coordinator for a signed heartbeat every `poll_ms`, fetch and verify
//! the log when behind, and stop when told or when cut off (spec/PORTING.md, item 8).
//!
//! The HTTP client speaks plain HTTP/1.1 over `std::net::TcpStream` only (no TLS): put the coordinator
//! behind a local TLS-terminating proxy, or reach it over a trusted network. Every request uses
//! `Connection: close`. Nonces come from `/dev/urandom`, so the networked agent is for Unix systems.
use crate::agentview::AgentView;
use crate::json::{self, Value};
use crate::protocol::validate_fleet;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum Error {
    /// Connection, timeout or malformed response.
    Network(String),
    /// The coordinator answered with an HTTP error status.
    Http(u16, String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Network(m) => write!(f, "network: {}", m),
            Error::Http(s, b) => write!(f, "HTTP {}: {}", s, b),
        }
    }
}

impl std::error::Error for Error {}

/// Percent-encode a query value (RFC 3986 unreserved characters are kept).
pub fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{:02X}", b) })
        .collect()
}

/// A plain-HTTP JSON client for the coordinator's agent endpoints.
#[derive(Clone, Debug)]
pub struct Client {
    host: String,
    port: u16,
    prefix: String,
    token: Option<String>,
    pub timeout: Duration,
}

impl Client {
    /// `url` must start with `http://` (no TLS in this client).
    pub fn new(url: &str, token: Option<&str>, timeout: Duration) -> Result<Client, String> {
        let rest = url.strip_prefix("http://").ok_or("only http:// URLs are supported by this client (no TLS)")?;
        let (hostport, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].trim_end_matches('/')),
            None => (rest, ""),
        };
        // host, host:port, [v6] or [v6]:port
        let (host, port) = if let Some(end) = hostport.strip_prefix('[').and_then(|r| r.find(']')) {
            let port = match &hostport[end + 2..] {
                "" => 80,
                p => p.strip_prefix(':').and_then(|p| p.parse().ok()).ok_or("bad port")?,
            };
            (hostport[..end + 2].to_string(), port)
        } else {
            match hostport.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.parse().map_err(|_| "bad port")?),
                None => (hostport.to_string(), 80),
            }
        };
        if host.is_empty() {
            return Err("the URL has no host".into());
        }
        Ok(Client { host, port, prefix: path.to_string(), token: token.filter(|t| !t.is_empty()).map(str::to_string), timeout })
    }

    /// GET `path` with the query pairs; the parsed JSON body on a 2xx answer.
    pub fn get(&self, path: &str, query: &[(&str, String)]) -> Result<Value, Error> {
        let net = |e: std::io::Error| Error::Network(e.to_string());
        let q: Vec<String> = query.iter().map(|(k, v)| format!("{}={}", enc(k), enc(v))).collect();
        let target = format!("{}{}{}{}", self.prefix, path, if q.is_empty() { "" } else { "?" }, q.join("&"));
        let host = self.host.trim_start_matches('[').trim_end_matches(']');
        let addr = (host, self.port).to_socket_addrs().map_err(net)?.next().ok_or(Error::Network("no address".into()))?;
        let mut s = TcpStream::connect_timeout(&addr, self.timeout).map_err(net)?;
        s.set_read_timeout(Some(self.timeout)).map_err(net)?;
        s.set_write_timeout(Some(self.timeout)).map_err(net)?;
        let mut req = format!(
            "GET {} HTTP/1.1\r\nHost: {}:{}\r\nAccept: application/json\r\nConnection: close\r\n",
            target, self.host, self.port
        );
        if let Some(t) = &self.token {
            req.push_str(&format!("Authorization: Bearer {}\r\n", t));
        }
        req.push_str("\r\n");
        s.write_all(req.as_bytes()).map_err(net)?;
        let deadline = Instant::now() + self.timeout;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        let mut header_end = None;
        let mut want: Option<usize> = None;
        loop {
            if let (Some(h), Some(n)) = (header_end, want) {
                if buf.len() >= h + n {
                    break;
                }
            }
            if Instant::now() > deadline {
                return Err(Error::Network("timed out".into()));
            }
            let k = s.read(&mut chunk).map_err(net)?;
            if k == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..k]);
            if buf.len() > 64 << 20 {
                return Err(Error::Network("response too large".into()));
            }
            if header_end.is_none() {
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    header_end = Some(i + 4);
                    let head = String::from_utf8_lossy(&buf[..i]).to_string();
                    want = head.lines().skip(1).find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        if k.trim().eq_ignore_ascii_case("content-length") {
                            v.trim().parse().ok()
                        } else {
                            None
                        }
                    });
                }
            }
        }
        let h = header_end.ok_or(Error::Network("incomplete response".into()))?;
        let head = String::from_utf8_lossy(&buf[..h]).to_string();
        let status: u16 = head
            .split_whitespace()
            .nth(1)
            .and_then(|x| x.parse().ok())
            .ok_or(Error::Network("bad status line".into()))?;
        let body = match want {
            Some(n) if buf.len() >= h + n => &buf[h..h + n],
            Some(_) => return Err(Error::Network("response shorter than Content-Length".into())),
            None => &buf[h..],
        };
        let text = std::str::from_utf8(body).map_err(|_| Error::Network("response is not UTF-8".into()))?;
        if !(200..300).contains(&status) {
            return Err(Error::Http(status, text.chars().take(300).collect()));
        }
        json::parse(text).map_err(Error::Network)
    }

    pub fn heartbeat(&self, agent_id: &str, instance_id: &str, nonce: &str) -> Result<Value, Error> {
        self.get(
            "/v1/heartbeat",
            &[("agent_id", agent_id.to_string()), ("instance_id", instance_id.to_string()), ("nonce", nonce.to_string())],
        )
    }

    pub fn log(&self, from: usize, limit: usize, agent_id: &str, instance_id: &str) -> Result<Value, Error> {
        self.get(
            "/v1/log",
            &[
                ("from", from.to_string()),
                ("limit", limit.to_string()),
                ("agent_id", agent_id.to_string()),
                ("instance_id", instance_id.to_string()),
            ],
        )
    }
}

/// 16 random bytes from /dev/urandom as 32 lower-case hex characters.
pub fn new_nonce() -> std::io::Result<String> {
    let mut b = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(crate::ed25519::hex_encode(&b))
}

/// The agent may not run; `code` says why (SW-HALTED-FLEET, SW-OFFLINE, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Halted {
    pub code: &'static str,
}

impl std::fmt::Display for Halted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SmartSwitch: this agent may not run ({})", self.code)
    }
}

impl std::error::Error for Halted {}

/// A networked agent. Thread-safe: share it in an `Arc`, call `start` for a background poll loop or
/// call `poll_once` yourself.
pub struct Agent {
    view: Mutex<AgentView>,
    client: Client,
    pub poll_ms: u64,
    epoch: Instant,
    stop: AtomicBool,
    last_error: Mutex<Option<String>>,
}

impl Agent {
    /// `fleet` is the fleet document the agent was deployed with; it is validated here.
    pub fn new(url: &str, token: Option<&str>, fleet: &Value, agent_id: &str, instance_id: &str) -> Result<Agent, String> {
        validate_fleet(fleet).map_err(|e| e.to_string())?;
        Ok(Agent {
            view: Mutex::new(AgentView::new(fleet, agent_id, instance_id)?),
            client: Client::new(url, token, Duration::from_secs(2))?,
            poll_ms: 1000,
            epoch: Instant::now(),
            stop: AtomicBool::new(false),
            last_error: Mutex::new(None),
        })
    }

    /// Read and validate a fleet document from a file.
    pub fn load_fleet(path: &str) -> Result<Value, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {}", path, e))?;
        let v = json::parse(&text)?;
        validate_fleet(&v).map_err(|e| e.to_string())?;
        Ok(v)
    }

    /// This agent's monotonic clock in milliseconds (for heartbeats and status).
    pub fn now_ms(&self) -> i64 {
        self.epoch.elapsed().as_millis() as i64
    }

    pub fn set_timeout(&mut self, t: Duration) {
        self.client.timeout = t;
    }

    fn view(&self) -> std::sync::MutexGuard<'_, AgentView> {
        self.view.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// One round: heartbeat, catch up on the log if behind, check the same heartbeat again.
    /// Any error (network, malformed answer, parser limit, even a panic) changes nothing; the dead-man
    /// rule takes over if errors persist. Returns the status code afterwards.
    pub fn poll_once(&self) -> &'static str {
        let err = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.round())) {
            Ok(r) => r.err(),
            Err(_) => Some("internal error while polling".to_string()),
        };
        *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) = err;
        self.status()
    }

    fn round(&self) -> Result<(), String> {
        let nonce = new_nonce().map_err(|e| e.to_string())?;
        let (agent_id, instance_id) = {
            let v = self.view();
            (v.agent_id.clone(), v.instance_id.clone())
        };
        let sent = self.now_ms();
        let hb = self.client.heartbeat(&agent_id, &instance_id, &nonce).map_err(|e| e.to_string())?;
        let mut r = self.view().heartbeat(&hb, &nonce, sent);
        if r.get("code").and_then(Value::as_str) == Some("SW-BEHIND") {
            let size = hb.get("log_size").and_then(Value::as_int).unwrap_or(0) as usize;
            self.catch_up(size, &agent_id, &instance_id)?;
            r = self.view().heartbeat(&hb, &nonce, sent);
        }
        match r.get("code").and_then(Value::as_str) {
            Some("SW-OK") => Ok(()),
            other => Err(other.unwrap_or("?").to_string()),
        }
    }

    fn catch_up(&self, size: usize, agent_id: &str, instance_id: &str) -> Result<(), String> {
        loop {
            let have = self.view().replica.size;
            if have >= size {
                return Ok(());
            }
            let page = self.client.log(have, 1000, agent_id, instance_id).map_err(|e| e.to_string())?;
            let entries = page.get("entries").and_then(Value::as_arr).ok_or("the log answer has no entries")?;
            if entries.is_empty() {
                return Ok(());
            }
            let r = self.view().log(entries);
            if r.get("ok") != Some(&Value::Bool(true)) {
                return Err(format!(
                    "the coordinator log does not verify ({} at entry {})",
                    r.get("code").and_then(Value::as_str).unwrap_or("?"),
                    r.get("size").and_then(Value::as_int).unwrap_or(-1)
                ));
            }
        }
    }

    /// The last round's problem (a network error or a heartbeat code), if any.
    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Wall-clock milliseconds since the Unix epoch (proposal expiry is wall-clock time).
    pub fn wall_ms() -> i64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
    }

    /// A certificate that reached this agent some other way than the coordinator: `{ok, code}`.
    /// It is checked at wall-clock time, since it is compared with the proposal's `expires_ms`.
    pub fn deliver(&self, cert: &Value) -> Value {
        let at = Self::wall_ms();
        self.view().certificate(cert, at)
    }

    /// The status code now (SW-RUN when the agent may run).
    pub fn status(&self) -> &'static str {
        let at = self.now_ms();
        self.view().status_code(at)
    }

    pub fn may_run(&self) -> bool {
        self.status() == "SW-RUN"
    }

    /// Err(Halted) when the agent may not run.
    pub fn checkpoint(&self) -> Result<(), Halted> {
        match self.status() {
            "SW-RUN" => Ok(()),
            code => Err(Halted { code }),
        }
    }

    /// Poll every `poll_ms` on a background thread until `stop`.
    pub fn start(self: &Arc<Self>) -> std::thread::JoinHandle<()> {
        let me = Arc::clone(self);
        std::thread::spawn(move || {
            while !me.stop.load(Ordering::SeqCst) {
                me.poll_once();
                std::thread::sleep(Duration::from_millis(me.poll_ms));
            }
        })
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn deliver_uses_wall_clock() {
        // Milliseconds since the Unix epoch (after 2020-01-01), not a monotonic clock starting at 0.
        assert!(super::Agent::wall_ms() > 1_577_836_800_000);
    }

    #[test]
    fn nonce_is_32_lower_hex() {
        let n = super::new_nonce().unwrap();
        assert!(crate::ed25519::is_lower_hex(&n, 32));
        assert_ne!(n, super::new_nonce().unwrap());
    }
}
