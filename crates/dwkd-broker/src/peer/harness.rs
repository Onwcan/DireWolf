//! F-04's process harness (ADR-0068), compiled into this crate's tests only:
//! the two things the CONNECT proxy's peer cases need that no test can do in
//! one process -- a reader in a pid namespace that cannot see its peer
//! (`unshare --user --map-current-user --pid`, no privilege), and a client
//! running as a second operating-system user (`sudo -n -u $DW_PEER_AS`).
//!
//! It starts nothing a hop, an authorisation or a relay names, and nothing
//! the broker runs; TX021 names it beside the other test files that start a
//! process. It lives outside `egress/` so that the egress code, its tests
//! included, still reads no environment variable (TX042).

#![allow(clippy::expect_used)]

use std::ffi::OsStr;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::process::{Command, Output, Stdio};

/// Set in the copy of a test binary that judges a hidden peer.
const HIDDEN_JUDGE: &str = "DW_BROKER_F04_HIDDEN_JUDGE";

/// A new user namespace (so no privilege is needed) and a new pid namespace,
/// of which the judge is the first process: its peer outside is invisible to
/// it, and the kernel reports that peer's pid as 0.
const HIDDEN_NAMESPACES: [&str; 5] = [
    "--user",
    "--map-current-user",
    "--pid",
    "--fork",
    "--kill-child",
];

/// Whether this process is a hidden judge a test started.
pub(crate) fn is_hidden_judge() -> bool {
    std::env::var_os(HIDDEN_JUDGE).is_some()
}

/// Run this binary's test `name` as a hidden judge, its stdin `peer` -- one
/// end of a socket pair the caller made, whose credentials are the caller's.
/// `None`, said on stderr, where unprivileged user and pid namespaces are not
/// available: NOT EXERCISED, never a pass.
///
/// # Panics
///
/// The test binary cannot be started.
pub(crate) fn judge_hidden(name: &str, peer: OwnedFd) -> Option<Output> {
    let _fork = crate::process::fork_guard();
    let available = Command::new("unshare")
        .args(HIDDEN_NAMESPACES)
        .arg("true")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !available {
        eprintln!(
            "NOT EXERCISED: unprivileged user and pid namespaces are not available here \
             (`unshare --user --pid` failed), so no peer this process cannot see can be made"
        );
        return None;
    }
    let output = Command::new("unshare")
        .args(HIDDEN_NAMESPACES)
        .arg(std::env::current_exe().expect("this test binary"))
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(HIDDEN_JUDGE, "1")
        .stdin(Stdio::from(peer))
        .output()
        .expect("the hidden judge starts");
    Some(output)
}

/// The user `DW_PEER_AS` names, proven by numbers: the uid a process started
/// as it reports must be none of `not` (this process's, the relay's) and not
/// root's. A name is not evidence; two uids are.
///
/// # Panics
///
/// NOT EXERCISED without such a user: a cross-uid property is never passed
/// without one.
pub(crate) fn second_identity(not: &[u32]) -> (String, u32) {
    let user = std::env::var("DW_PEER_AS").unwrap_or_default();
    assert!(
        !user.is_empty(),
        "NOT EXERCISED: set DW_PEER_AS to a second user `sudo -n -u` can switch to (CI uses \
         `nobody`); a cross-uid property is never passed without one"
    );
    let probe = {
        let _fork = crate::process::fork_guard();
        Command::new("sudo")
            .args(["-n", "-u", &user, "id", "-u"])
            .output()
            .expect("sudo runs")
    };
    assert!(
        probe.status.success(),
        "NOT EXERCISED: `sudo -n -u {user}` cannot start a process here: {}",
        String::from_utf8_lossy(&probe.stderr)
    );
    let uid: u32 = String::from_utf8_lossy(&probe.stdout)
        .trim()
        .parse()
        .expect("`id -u` prints a uid");
    eprintln!("second identity: DW_PEER_AS={user} is uid {uid}; not {not:?}");
    assert!(
        uid != 0 && !not.contains(&uid),
        "DW_PEER_AS={user} is uid {uid}: root, or an identity already in use here"
    );
    (user, uid)
}

/// Run `script` with `args` under `python3`, as `user`, from the script's
/// directory; what it printed.
///
/// # Panics
///
/// `sudo` cannot be started.
pub(crate) fn run_as(user: &str, script: &Path, args: &[&OsStr]) -> Output {
    let python = if Path::new("/usr/bin/python3").exists() {
        "/usr/bin/python3"
    } else {
        "python3"
    };
    let _fork = crate::process::fork_guard();
    Command::new("sudo")
        .args(["-n", "-u", user, python])
        .arg(script)
        .args(args)
        .current_dir(script.parent().unwrap_or(Path::new("/")))
        .output()
        .expect("sudo runs the client")
}
