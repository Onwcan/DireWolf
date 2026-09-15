//! Build script: records build provenance for `direwolf --version`.
//!
//! It records the git commit the binary was built from, so that a reported
//! version can be tied to a tree.  If git is unavailable — a source tarball, a
//! vendored build — the commit is reported as `unknown` rather than failing the
//! build.  Nothing here affects behaviour; it affects only what the binary can
//! say about itself.

use std::process::Command;

fn main() {
    let commit = git_commit().unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=DIREWOLF_GIT_COMMIT={commit}");

    // `TARGET` and `PROFILE` are set by cargo for build scripts but are not
    // available to the crate itself, so forward them.
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_owned());
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".to_owned());
    println!("cargo:rustc-env=DIREWOLF_TARGET={target}");
    println!("cargo:rustc-env=DIREWOLF_PROFILE={profile}");

    // Rebuild when HEAD moves.  `../..` because this script runs with the
    // crate directory as its working directory.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=build.rs");
}

fn git_commit() -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_owned())
    }
}
