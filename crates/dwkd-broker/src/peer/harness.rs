//! F-04's process harness (ADR-0068), compiled into this crate's tests only:
//! the two things the CONNECT proxy's peer cases need that no test can do in
//! one process -- a reader in a pid namespace that cannot see its peer
//! (`unshare --user --map-current-user --pid`, no privilege), and a client
//! running as a second operating-system user (`sudo -n -u $DW_PEER_AS`).
//! F-05's identity tables (ADR-0069) use the first to judge a real kernel's
//! mapping in an unprivileged user namespace, and ADR-0070's read one such
//! namespace's maps from inside it and from outside (`namespace_views`).
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

/// Set in the copy of a test binary that resolves under a hostile resolver
/// configuration (F-16, ADR-0074): the directory holding it.
const HOSTILE_RESOLVER: &str = "DW_BROKER_F16_HOSTILE_RESOLVER";

/// User, mount and network namespaces of the copy's own: its
/// `/etc/resolv.conf`, `/etc/nsswitch.conf` and `/etc/hosts` are the test's
/// files, bind-mounted, and its loopback is its own, so the test's DNS
/// responder answers it on port 53. Nothing outside them changes.
const RESOLVER_NAMESPACES: [&str; 4] = ["--user", "--map-root-user", "--mount", "--net"];

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

/// The hostile resolver configuration's directory, in the copy a test
/// started -- `None` everywhere else.
pub(crate) fn hostile_resolver_dir() -> Option<std::path::PathBuf> {
    std::env::var_os(HOSTILE_RESOLVER).map(std::path::PathBuf::from)
}

/// Run this binary's test `name` under the hostile resolver configuration
/// in `dir` (`resolv.conf`, `nsswitch.conf`, `hosts`), in namespaces of its
/// own. `None`, said on stderr, where unprivileged user, mount and network
/// namespaces are not available: NOT EXERCISED, never a pass.
///
/// # Panics
///
/// The test binary cannot be started.
pub(crate) fn under_hostile_resolver(name: &str, dir: &Path) -> Option<Output> {
    let _fork = crate::process::fork_guard();
    let available = Command::new("unshare")
        .args(RESOLVER_NAMESPACES)
        .arg("true")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !available {
        eprintln!(
            "NOT EXERCISED: unprivileged user, mount and network namespaces are not \
             available here (`unshare --user --mount --net` failed), so no resolver \
             configuration of the test's own can be made"
        );
        return None;
    }
    let output = Command::new("unshare")
        .args(RESOLVER_NAMESPACES)
        .arg(std::env::current_exe().expect("this test binary"))
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(HOSTILE_RESOLVER, dir)
        .stdin(Stdio::null())
        .output()
        .expect("the copy starts");
    Some(output)
}

/// Inside that copy: its loopback up, and the three files bind-mounted over
/// the host's -- in its own namespaces, so nothing outside them changes. No
/// shell: `ip` and `mount`, each run directly.
///
/// # Errors
///
/// The command that could not run or failed, and what it said.
pub(crate) fn install_hostile_resolver(dir: &Path) -> Result<(), String> {
    let _fork = crate::process::fork_guard();
    let run = |program: &str, args: &[&OsStr]| -> Result<(), String> {
        let output = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| format!("{program}: {e}"))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "{program} {args:?}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    };
    run("ip", &["link", "set", "lo", "up"].map(OsStr::new))?;
    for file in ["resolv.conf", "nsswitch.conf", "hosts"] {
        let from = dir.join(file);
        let onto = Path::new("/etc").join(file);
        run(
            "mount",
            &[OsStr::new("--bind"), from.as_os_str(), onto.as_os_str()],
        )?;
    }
    Ok(())
}

/// A real unprivileged user namespace's uid and gid maps as the process in it
/// prints them (`cat` reading its own `/proc/self/uid_map` and `gid_map`,
/// then holding on its standard input), and `outside(pid)`'s answer, called
/// while that process lives -- the caller reads the host's view of it. No
/// shell, and no file read here (TX015). `None`, said on stderr, where
/// unprivileged user namespaces are not available: NOT EXERCISED, never a
/// pass. ADR-0070's two-vantage comparison rests on the two agreeing.
pub(crate) fn namespace_views<T>(outside: impl FnOnce(u32) -> T) -> Option<((String, String), T)> {
    use std::io::{BufRead as _, BufReader};
    let _fork = crate::process::fork_guard();
    let Ok(mut child) = Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "cat",
            "/proc/self/uid_map",
            "/proc/self/gid_map",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        eprintln!("NOT EXERCISED: `unshare` cannot be started here");
        return None;
    };
    let mut lines = BufReader::new(child.stdout.take().expect("stdout")).lines();
    let (Some(Ok(uid)), Some(Ok(gid))) = (lines.next(), lines.next()) else {
        let _ = child.kill();
        let _ = child.wait();
        eprintln!(
            "NOT EXERCISED: an unprivileged user namespace is not available here \
             (`unshare --user --map-root-user` printed no map)"
        );
        return None;
    };
    let seen = outside(child.id());
    drop(child.stdin.take());
    let _ = child.wait();
    Some(((uid, gid), seen))
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
