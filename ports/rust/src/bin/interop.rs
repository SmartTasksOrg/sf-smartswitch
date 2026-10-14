//! The interop agent for ports/conformance/interop.py:
//!     interop URL FLEET_FILE AGENT_ID INSTANCE_ID     (token in SMARTSWITCH_AGENT_TOKEN)
//! Polls every 100 ms and prints "STATUS <code>" whenever the status code changes; exits when
//! standard input closes or after 60 s.
use smartswitch::Agent;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!("usage: interop URL FLEET_FILE AGENT_ID INSTANCE_ID");
        std::process::exit(2);
    }
    let token = std::env::var("SMARTSWITCH_AGENT_TOKEN").ok();
    let fleet = Agent::load_fleet(&args[2]).unwrap_or_else(|e| {
        eprintln!("{}", e);
        std::process::exit(2)
    });
    let mut agent = Agent::new(&args[1], token.as_deref(), &fleet, &args[3], &args[4]).unwrap_or_else(|e| {
        eprintln!("{}", e);
        std::process::exit(2)
    });
    agent.set_timeout(Duration::from_secs(1));
    let done = Arc::new(AtomicBool::new(false));
    let d = Arc::clone(&done);
    std::thread::spawn(move || {
        let mut sink = Vec::new();
        let _ = std::io::stdin().read_to_end(&mut sink);
        d.store(true, Ordering::SeqCst);
    });
    let end = Instant::now() + Duration::from_secs(60);
    let mut last = "";
    let mut out = std::io::stdout();
    while !done.load(Ordering::SeqCst) && Instant::now() < end {
        let code = agent.poll_once();
        if code != last {
            let _ = writeln!(out, "STATUS {}", code);
            let _ = out.flush();
            last = code;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
