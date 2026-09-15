//! Integration tests for the `direwolf` binary.
//!
//! These run the real binary as a subprocess, so they test what a contributor
//! actually invokes rather than what the library functions do.

// The workspace denies `panic`/`unwrap` in production paths. A test harness is
// not a production path: panicking IS how a test reports failure. The opt-out
// is crate-wide here and deliberately absent from every non-test crate root.
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use std::process::{Command, Output};

fn direwolf(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_direwolf"))
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to run the direwolf binary: {e}"))
}

#[test]
fn version_prints_a_version_and_exits_zero() {
    let out = direwolf(&["--version"]);
    assert!(out.status.success(), "`direwolf --version` must succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("direwolf "), "got: {stdout:?}");
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "version output must contain the package version; got: {stdout:?}"
    );
}

#[test]
fn help_exits_zero_and_says_what_is_not_implemented() {
    let out = direwolf(&["--help"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("doctor"));
    assert!(
        stdout.contains("not implemented"),
        "help must be honest about the absent command surface; got: {stdout:?}"
    );
}

#[test]
fn doctor_reports_platform_and_names_what_it_cannot_check() {
    let out = direwolf(&["doctor"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "doctor failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("platform"), "got: {stdout}");
    assert!(
        stdout.contains("Not checked yet"),
        "doctor must state what it cannot verify; got: {stdout}"
    );
    assert!(
        stdout.contains("does not verify any security property"),
        "doctor must not imply it has checked security properties; got: {stdout}"
    );
}

#[test]
fn unknown_command_fails_with_a_usage_error() {
    let out = direwolf(&["definitely-not-a-command"]);
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unknown command"));
}

/// M1 must not ship a command whose subsystem does not exist. If any of these
/// starts succeeding, either a milestone landed (update this test) or someone
/// added a stub (do not).
#[test]
fn the_agent_command_surface_is_not_stubbed() {
    for cmd in [
        "run", "chat", "agent", "approve", "memory", "policy", "init",
    ] {
        let out = direwolf(&[cmd]);
        assert_eq!(
            out.status.code(),
            Some(2),
            "`direwolf {cmd}` must not exist before its owning milestone"
        );
    }
}
