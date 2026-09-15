//! `direwolf doctor` — foundation diagnostics.
//!
//! # Scope, deliberately narrow
//!
//! At M1 there is no kernel, no policy engine and no sandbox, so this command
//! reports only what it can *verify*: build provenance, the host platform tier,
//! and where `DIREWOLF_HOME` resolves to. It then names, explicitly, the checks
//! it cannot yet perform and the milestone that will add each one.
//!
//! The full `doctor` (M17) "verifies facts, not settings"
//! (`docs/OBSERVABILITY.md` §4) — it attempts the write that should fail rather
//! than reading a configuration value that claims it would. This M1 subset
//! keeps that discipline: it never reports a property it has not observed.

use std::fmt::Write as _;
use std::path::PathBuf;

use crate::build_info;
use crate::platform;

/// Checks that exist in the architecture but have no implementation to verify
/// yet. Printed so that an empty report is never mistaken for a clean bill of
/// health.
const PENDING: &[(&str, &str)] = &[
    ("kernel socket reachable and peer-verified", "M3"),
    ("kernel.db not writable by the runtime identity", "M3"),
    ("audit chain verifies against its signed checkpoint", "M3"),
    (
        "policy profile loads and every rule has a source location",
        "M3",
    ),
    (
        "container runtime present; oci-strict profile applies",
        "M5",
    ),
    ("sandbox has no route except the egress proxy", "M5"),
    ("runtime and kernel protocol versions match", "M2"),
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
    let _ = writeln!(out, "Not checked yet - no implementation exists to check:");
    for (what, milestone) in PENDING {
        let _ = writeln!(out, "  [{milestone:>3}] {what}");
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "This is the M1 foundation subset of `doctor`. It reports build and host\n\
         facts only. It does not verify any security property, because no security\n\
         mechanism is implemented yet. See docs/ROADMAP.md."
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
    fn every_pending_check_names_an_owning_milestone() {
        assert!(!PENDING.is_empty());
        for (what, milestone) in PENDING {
            assert!(!what.is_empty());
            assert!(
                milestone.starts_with('M') && milestone.len() >= 2,
                "pending check {what:?} must name a milestone like \"M3\", got {milestone:?}"
            );
        }
    }
}
