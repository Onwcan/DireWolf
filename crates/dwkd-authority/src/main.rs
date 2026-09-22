//! `dwkd-authority` — the DireWolf authority daemon. **It decides.**
//!
//! # What this process is
//!
//! The trusted computing base. It owns the Request Canonicaliser, the Policy
//! Engine, the Capability Broker, the Approval Registry, the Budget Ledger,
//! the Secret Broker and the Audit Log. It holds `kernel.db`, `audit.log`, the
//! capability-token MAC key and secret material ([ADR-0018]).
//!
//! It is the only process the cognition runtime is permitted to address, and
//! the DWKP server is the only way in ([ADR-0000]).
//!
//! # What this process must never acquire
//!
//! No HTTP client, no TLS stack, no container client, and no parser for
//! attacker-chosen content — no HTML extraction, no provider-response JSON, no
//! MIME sniffing. Those live in `dwkd-broker`, in an address space holding no
//! credentials and no key. That division is the reason the dependency-set claim
//! in [ADR-0019] is true rather than aspirational, so adding a dependency here
//! requires a note on that ADR and a reviewer other than the author.
//!
//! # Status: not implemented
//!
//! M1 is the repository foundation. This crate exists so that the boundary
//! between deciding and doing is a package boundary from the first commit
//! rather than something extracted later — retrofitting a privilege boundary is
//! the mistake the whole architecture exists to avoid. The DWKP server, the
//! policy engine and the capability broker arrive at **M3**.
//!
//! M3b added the library half (`dwkd_authority::capability`): the typed
//! capability vocabulary and the `⊑` lattice over it; M3c the policy engine;
//! M3d the durable state behind them — `kernel.db`, leases, admission and the
//! hash-chained audit log. **Nothing in this binary serves any of it**:
//! answering a request needs the socket and peer authentication of M3e. The
//! help text reports the vocabulary's size so that "linked, not running" is
//! something you can see rather than something you have to assume.
//!
//! One operator tool is here, because it is read-only and needs no socket:
//! `verify-audit`, which checks `audit.log`'s hash chain and compares it with
//! `kernel.db`'s record of it. It opens both for reading only.
//!
//! [ADR-0000]: ../../../docs/adr/0000-authority-plane-separation.md
//! [ADR-0018]: ../../../docs/adr/0018-authority-broker-split.md
//! [ADR-0019]: ../../../docs/adr/0019-language-rationale-v2.md

// Pedantic lints on the security crates, per docs/LANGUAGE_SELECTION.md §7.
#![warn(clippy::pedantic)]

use std::path::Path;
use std::process::ExitCode;

use dwkd_authority::capability::Verb;
use dwkd_authority::state::{AUDIT_LOG, KERNEL_DB, verify_audit_against_store, verify_audit_log};

// The policy loader's parser is a dependency of the LIBRARY. The binary
// inherits the manifest edge without using it -- there is no DWKP server yet,
// so nothing here reads a policy file. Acknowledged rather than silenced with
// an `#[allow]`, so the day this binary does load policy the acknowledgement
// becomes a real `use` instead.
use toml as _;
// Likewise the M3d storage and wire dependencies: the library links them, and
// this binary reaches them only through `dwkd_authority::state`.
use dwk_proto as _;
use rusqlite as _;
use sha2 as _;

// Dev-only, and the binary's test target inherits the manifest edge without
// using it. Acknowledged rather than silenced with an `#[allow]`.
#[cfg(test)]
use proptest as _;

const NAME: &str = "dwkd-authority";

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
        Some("verify-audit") => {
            if let Some([dir]) = args.get(1..) {
                verify_audit(Path::new(dir))
            } else {
                eprintln!("usage: {NAME} verify-audit <state-dir>");
                ExitCode::from(2)
            }
        }
        _ => {
            eprint!("{}", help());
            eprintln!();
            eprintln!("{NAME} does not serve DWKP yet: the server and peer authentication arrive");
            eprintln!("at M3e, the brokers at M4, approvals and budgets at M6.");
            eprintln!("See docs/ROADMAP.md and docs/adr/0018-authority-broker-split.md.");
            ExitCode::FAILURE
        }
    }
}

/// Verify `audit.log` in `dir`, alone and against `kernel.db`. Read-only.
fn verify_audit(dir: &Path) -> ExitCode {
    match verify_audit_log(&dir.join(AUDIT_LOG)) {
        Ok(summary) => println!(
            "audit.log: {} records, chain intact, head {}",
            summary.records, summary.head
        ),
        Err(fault) => {
            eprintln!("audit.log: FAILED: {fault}");
            return ExitCode::FAILURE;
        }
    }
    if !dir.join(KERNEL_DB).exists() {
        println!("kernel.db: absent; the log was verified on its own");
        return ExitCode::SUCCESS;
    }
    match verify_audit_against_store(dir) {
        Ok(comparison) => {
            println!(
                "kernel.db: head {}, flushed {}, pending {}",
                comparison.store_head,
                comparison.store_flushed,
                comparison.pending()
            );
            ExitCode::SUCCESS
        }
        Err(fault) => {
            eprintln!("kernel.db: FAILED: {fault}");
            ExitCode::FAILURE
        }
    }
}

fn help() -> String {
    format!(
        "{NAME} {} - the DireWolf authority daemon (decides)\n\
         \n\
         Owns policy, capabilities, approvals, budgets, secrets and audit.\n\
         The only process the cognition runtime may address.\n\
         \n\
         USAGE:\n    \
             {NAME} [-V | --version] [-h | --help]\n    \
             {NAME} verify-audit <state-dir>   read-only audit chain check\n\
         \n\
         STATUS: not implemented; the DWKP server arrives at milestone M3e.\n\
         The capability vocabulary ({verbs} verbs, M3b), the policy engine (M3c) and the\n\
         durable authority state (M3d) are linked; nothing serves them yet.\n",
        env!("CARGO_PKG_VERSION"),
        verbs = Verb::ALL.len()
    )
}

#[cfg(test)]
mod tests {
    use super::{NAME, help};

    #[test]
    fn help_names_the_component_and_its_milestone() {
        let h = help();
        assert!(h.contains(NAME));
        assert!(
            h.contains("M3"),
            "help must name the milestone that implements this"
        );
        assert!(h.contains("not implemented"));
    }
}
