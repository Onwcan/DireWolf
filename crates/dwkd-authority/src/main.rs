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
//! # Status: M3 — the authority serves DWKP; nothing is executed yet
//!
//! `dwkd-authority serve` (M3e) is the DWKP server: a Unix-domain socket whose
//! peers are identified by the kernel (`SO_PEERCRED`), admitted only if the
//! operator listed their uid, given one fresh lease holder per connection, and
//! required to handshake before anything else. Behind it are the library
//! halves — the capability lattice (M3b), the policy engine (M3c) and the
//! durable state (M3d) — which the server calls and never duplicates
//! ([ADR-0041]). **Linux only**: macOS and native Windows have no peer
//! credential this build can read safely, and `serve` refuses there before
//! touching a file.
//!
//! What the authority still does **not** do: execute anything, canonicalise a
//! filesystem resource, answer `ToolInvoke` or `CanonicalPreview` (both
//! reserved until M4), hold approvals (M6) or call a model provider (M7).
//!
//! One operator tool is here too, because it is read-only and needs no socket:
//! `verify-audit`, which checks `audit.log`'s hash chain and compares it with
//! `kernel.db`'s record of it. It opens both for reading only, and it works on
//! every platform.
//!
//! [ADR-0000]: ../../../docs/adr/0000-authority-plane-separation.md
//! [ADR-0018]: ../../../docs/adr/0018-authority-broker-split.md
//! [ADR-0019]: ../../../docs/adr/0019-language-rationale-v2.md
//! [ADR-0041]: ../../../docs/adr/0041-m3e-authenticated-dwkp-transport.md

// Pedantic lints on the security crates, per docs/LANGUAGE_SELECTION.md §7.
#![warn(clippy::pedantic)]

use std::path::Path;
use std::process::ExitCode;

use dwkd_authority::capability::Verb;
use dwkd_authority::server::{self, SERVE_USAGE, ServeError, Stopped};
use dwkd_authority::state::{AUDIT_LOG, KERNEL_DB, verify_audit_against_store, verify_audit_log};

// The library's dependencies, which this binary reaches only through
// `dwkd_authority`: the policy loader's parser, the M3d storage and wire
// crates, and (Linux only) the peer-credential wrapper. Acknowledged rather
// than silenced with an `#[allow]`.
use dwk_proto as _;
use rusqlite as _;
#[cfg(target_os = "linux")]
use rustix as _;
use sha2 as _;
use toml as _;
use unicode_normalization as _;

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
        Some("serve") => serve(args.get(1..).unwrap_or_default()),
        _ => {
            eprint!("{}", help());
            ExitCode::from(2)
        }
    }
}

/// `serve`. Exit codes: 2 a usage error, 3 an unsupported platform, 1 the
/// server did not start, 4 it stopped because the store was poisoned. It does
/// not return otherwise: it serves until the process is killed.
fn serve(args: &[String]) -> ExitCode {
    let config = match server::parse_serve_args(args) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{NAME} serve: {error}");
            eprintln!("usage: {NAME} serve [flags]\n{SERVE_USAGE}");
            return ExitCode::from(2);
        }
    };
    match server::serve(&config) {
        Ok(Stopped::Poisoned(reason)) => {
            eprintln!("{NAME}: stopped serving: the authority store is poisoned: {reason}");
            ExitCode::from(4)
        }
        Err(error @ ServeError::Unsupported(_)) => {
            eprintln!("{NAME} serve: {error}");
            ExitCode::from(3)
        }
        Err(error) => {
            eprintln!("{NAME} serve: {error}");
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
             {NAME} serve [flags]               serve DWKP on a Unix-domain socket (Linux only)\n    \
             {NAME} verify-audit <state-dir>   read-only audit chain check\n\
         \n\
         SERVE FLAGS:\n{SERVE_USAGE}\
         \n\
         STATUS: milestone M3. `serve` answers the six M3 authority requests over DWKP to\n\
         peers whose kernel-reported uid the operator listed: one fresh lease holder per\n\
         connection, handshake first. On macOS and Windows it refuses to start.\n\
         Linked: the capability vocabulary ({verbs} verbs, M3b), the policy engine (M3c)\n\
         and the durable authority state (M3d). Not yet: tool execution, canonical\n\
         resources and CanonicalPreview (M4), approvals (M6), model providers (M7).\n",
        env!("CARGO_PKG_VERSION"),
        verbs = Verb::ALL.len()
    )
}

#[cfg(test)]
mod tests {
    use super::{NAME, help};

    #[test]
    fn help_names_the_component_and_what_it_does_now() {
        let h = help();
        assert!(h.contains(NAME));
        assert!(h.contains("M3"), "help must name the milestone");
        assert!(
            h.contains("serve"),
            "help must describe the server that exists"
        );
        assert!(
            !h.contains("not implemented"),
            "help must not claim the server is missing"
        );
        assert!(
            h.contains("Linux only"),
            "help must state the platform limit"
        );
    }
}
