//! SmartSwitch for Rust: the agent side of the quorum kill switch (spec/SEMANTICS.md).
//!
//! - `json`: JSON reader and canonical writer
//! - `sha256`, `sha512`: hashes (own implementations, no dependencies)
//! - `ed25519`: verify-only Ed25519 written for this port (not independently audited)
//! - `protocol`: fleet validation, certificate checks, state
//! - `log`: log replay
//! - `agentview`: the agent rules without I/O
//! - `agent`: the networked agent (plain HTTP, Unix)
pub mod agent;
pub mod agentview;
pub mod ed25519;
pub mod json;
pub mod log;
pub mod protocol;
pub mod sha256;
pub mod sha512;

pub use agent::{Agent, Halted};
pub use agentview::AgentView;
pub use protocol::{apply, validate_fleet, verify_certificate, State, SwitchError};
