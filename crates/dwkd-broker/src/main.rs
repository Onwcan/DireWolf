//! `dwkd-broker` — the DireWolf execution broker. **It does, and decides
//! nothing.**
//!
//! # What this process is
//!
//! The executor. It owns the Filesystem Broker, the Exec Broker, the Sandbox
//! Supervisor, Network Egress (the `PROXY_ONLY` CONNECT proxy and `net.http`),
//! Model Egress and artifact capture. It holds file descriptors, PIDs, sockets
//! and containers — and **no long-lived key** ([ADR-0018]).
//!
//! It receives a *per-invocation authorisation* from `dwkd-authority`: one
//! canonical action, an obligation set, and where one was granted, a one-shot
//! secret injection. It performs exactly that.
//!
//! # What this process must never acquire
//!
//! It cannot mint a capability, create or match an approval, widen authority,
//! evaluate policy, read `kernel.db` or the keychain, or write `audit.log`. It
//! has no code for any of those and must never grow any: the boundary is
//! asymmetric on purpose — compromising the broker yields the current
//! invocation, compromising authority yields everything.
//!
//! There is no DWKP endpoint here. The broker is not addressable from the
//! Cognition Plane at all.
//!
//! By contrast, this crate is *expected* to carry the large dependencies
//! authority must not: a container client, an HTTP/TLS stack, content parsers.
//! That is the point of the split.
//!
//! # Status: not implemented
//!
//! M1 is the repository foundation. This crate exists so that the boundary
//! between deciding and doing is a package boundary from the first commit. The
//! filesystem, exec and secret brokers arrive at **M4**; the sandbox and egress
//! proxy at **M5**.
//!
//! [ADR-0018]: ../../../docs/adr/0018-authority-broker-split.md

// Pedantic lints on the security crates, per docs/LANGUAGE_SELECTION.md §7.
#![warn(clippy::pedantic)]

use std::process::ExitCode;

const NAME: &str = "dwkd-broker";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("-V" | "--version") => {
            println!("{NAME} {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("-h" | "--help") => {
            print!("{}", help());
            ExitCode::SUCCESS
        }
        _ => {
            eprint!("{}", help());
            eprintln!();
            eprintln!("{NAME} is not implemented. The filesystem, exec and secret brokers");
            eprintln!("arrive at M4; the sandbox supervisor and egress proxy at M5.");
            eprintln!("See docs/ROADMAP.md and docs/adr/0018-authority-broker-split.md.");
            ExitCode::FAILURE
        }
    }
}

fn help() -> String {
    format!(
        "{NAME} {} - the DireWolf execution broker (does)\n\
         \n\
         Performs filesystem, exec, sandbox and egress operations under a\n\
         per-invocation authorisation from dwkd-authority. Decides nothing.\n\
         Not addressable from the cognition plane.\n\
         \n\
         USAGE:\n    \
             {NAME} [-V | --version] [-h | --help]\n\
         \n\
         STATUS: not implemented; arrives at milestones M4 and M5.\n",
        env!("CARGO_PKG_VERSION")
    )
}

#[cfg(test)]
mod tests {
    use super::{NAME, help};

    #[test]
    fn help_names_the_component_and_its_milestones() {
        let h = help();
        assert!(h.contains(NAME));
        assert!(h.contains("M4") && h.contains("M5"));
        assert!(h.contains("not implemented"));
    }

    /// The broker's defining property, asserted as a test so that a future
    /// change which makes this crate a decider fails something.
    #[test]
    fn help_states_that_the_broker_decides_nothing() {
        assert!(help().contains("Decides nothing"));
    }
}
