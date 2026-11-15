//! `direwolf doctor` — foundation diagnostics.
//!
//! # Scope, deliberately narrow
//!
//! This command reports only what it can *verify* from where it runs: build
//! provenance, the host platform tier, and where `DIREWOLF_HOME` resolves to.
//! It connects to no daemon and reads no daemon's state, so it checks none of
//! the security mechanisms the daemons enforce. It names each one instead,
//! and where the daemon that owns it says what holds: an empty report is
//! never a clean bill of health, and a mechanism that exists is never said not
//! to (F-03).
//!
//! The full `doctor` (M17) "verifies facts, not settings"
//! (`docs/OBSERVABILITY.md` §4) — it attempts the write that should fail rather
//! than reading a configuration value that claims it would. This subset keeps
//! that discipline: it never reports a property it has not observed.

use std::fmt::Write as _;
use std::path::PathBuf;

use crate::build_info;
use crate::platform;

/// Security properties the daemons enforce and this command does not check,
/// each with where its owner reports it. The checks themselves -- run against
/// a live deployment -- are the M17 `doctor`'s.
const PENDING: &[(&str, &str)] = &[
    (
        "kernel socket reachable and peer-verified",
        "dwkd-authority: SO_PEERCRED per connection; transport.* in audit.log",
    ),
    (
        "kernel.db not writable by the runtime identity",
        "dwkd-authority: authority.peer_boundary in authority.posture, audit.log",
    ),
    (
        "audit chain verifies",
        "dwkd-authority: verified at every start, or it does not start",
    ),
    (
        "policy profile loads",
        "dwkd-authority: refuses to start otherwise; policy.installed in audit.log",
    ),
    (
        "container runtime present; oci-strict profile applies",
        "per environment: environment.ready or environment.refused in audit.log",
    ),
    (
        "sandbox has no route except the egress proxy",
        "per environment: environment.ready in audit.log",
    ),
    (
        "each daemon's effective security posture",
        "dwkd-broker: event=posture on stderr; dwkd-authority: authority.posture in audit.log",
    ),
];

/// Run the diagnostics. Returns the process exit code.
pub(crate) fn run() -> i32 {
    let mut out = String::new();
    let mut problems: Vec<String> = Vec::new();

    let _ = writeln!(out, "DireWolf {}", build_info::VERSION);
    let _ = writeln!(out, "  commit          {}", build_info::GIT_COMMIT);
    let _ = writeln!(out, "  build profile   {}", build_info::PROFILE);
    let _ = writeln!(out, "  target          {}", build_info::TARGET);

    let tier = platform::detect();
    let _ = writeln!(out, "  platform        {tier} - {}", tier.explain());

    match direwolf_home() {
        Some(home) => {
            let state = if home.is_dir() {
                "exists"
            } else {
                "not created yet"
            };
            let _ = writeln!(out, "  DIREWOLF_HOME   {} ({state})", home.display());
        }
        None => {
            let _ = writeln!(out, "  DIREWOLF_HOME   COULD NOT BE RESOLVED");
            problems.push(
                "Could not determine a home directory. Set DIREWOLF_HOME to an absolute path."
                    .to_owned(),
            );
        }
    }

    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Not checked yet by this command - each is enforced and reported by its daemon:"
    );
    for (what, reported) in PENDING {
        let _ = writeln!(out, "  {what}\n      {reported}");
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "This is the foundation subset of `doctor`. It reports build and host\n\
         facts only. It does not verify any security property: it reads no\n\
         daemon's state. Checking a running deployment is the M17 doctor's;\n\
         see docs/ROADMAP.md and docs/F03_EFFECTIVE_POSTURE.md."
    );

    print!("{out}");

    if problems.is_empty() {
        0
    } else {
        eprintln!();
        for p in &problems {
            eprintln!("problem: {p}");
        }
        1
    }
}

/// Resolve `DIREWOLF_HOME`: the environment variable if set, otherwise
/// `~/.direwolf`.
///
/// Matches the layered configuration in `docs/PRODUCT_SPEC.md` §7. Resolution
/// only — this function creates nothing.
fn direwolf_home() -> Option<PathBuf> {
    if let Some(v) = non_empty_env("DIREWOLF_HOME") {
        return Some(PathBuf::from(v));
    }
    let home = if cfg!(windows) {
        non_empty_env("USERPROFILE")
    } else {
        non_empty_env("HOME")
    }?;
    Some(PathBuf::from(home).join(".direwolf"))
}

fn non_empty_env(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::PENDING;

    #[test]
    fn every_check_not_made_here_names_the_daemon_that_reports_it() {
        assert!(!PENDING.is_empty());
        for (what, reported) in PENDING {
            assert!(!what.is_empty());
            assert!(
                reported.contains("dwkd-") || reported.contains("audit.log"),
                "{what:?} must name where it is reported, got {reported:?}"
            );
        }
        // F-03: the daemons' own posture is among them, by name.
        assert!(
            PENDING
                .iter()
                .any(|(_, reported)| reported.contains("authority.posture")
                    && reported.contains("event=posture"))
        );
    }
}
