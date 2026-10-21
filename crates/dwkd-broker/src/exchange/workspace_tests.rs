//! M5d.4's exchange evidence (ADR-0052 §§6, 10): a directory of the
//! workspace group that does not keep the group's convention changes
//! nothing, and a full filesystem -- a real one, the kernel's own `ENOSPC` --
//! is `NO_SPACE` for every tool that changes a name, with nothing changed
//! and nothing left behind.
//!
//! The full filesystem is a tmpfs of 256 KiB this test mounts for itself in
//! an unprivileged user and mount namespace of its own (`unshare --user
//! --map-root-user --mount`): the bound is the kernel's, it fills no
//! filesystem of the host's, and it is gone with the namespace. Where such a
//! namespace cannot be made it says `NOT EXERCISED`, which the evidence task
//! refuses. It starts `unshare` and `mount` for that, which TX021 and TX022
//! permit in this file alone.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use std::path::Path;

use dwk_proto::brokerp::sandbox::{WORKSPACE_GROUP, WORKSPACE_ROOT_MODE};
use dwk_proto::brokerp::{BrokerRefusal, OutcomeResult};
use dwk_proto::wire::scalar::StatKind;
use rustix::io::Errno;

use super::super::staging::{denied_or, exclusive, room_or_io};
use super::{Scratch, delete_authorisation, identity, refused, run, write_authorisation};

/// One line of M5d.4 evidence for `make sandbox-workspace-evidence`.
fn evidence(case: &str, outcome: &str) {
    println!(
        "WORKSPACE-EVIDENCE {{\"suite\":\"broker-exchange\",\"case\":\"{case}\",\"outcome\":\"{outcome}\"}}"
    );
}

#[test]
fn a_directory_of_the_workspace_group_keeps_its_convention_or_nothing_changes_in_it() {
    let dir = Scratch::new("convention");
    let real = rustix::fs::fstat(dir.dir()).unwrap();
    let with = |gid: u32, mode: u32| {
        let mut st = real;
        st.st_gid = gid;
        st.st_mode = (real.st_mode & !0o7777) | mode;
        exclusive(&st)
    };
    // The convention: set-group-id and the group's to write.
    assert_eq!(with(WORKSPACE_GROUP, WORKSPACE_ROOT_MODE), Ok(()));
    assert_eq!(with(WORKSPACE_GROUP, 0o2775), Ok(()));
    // A workload cleared the bit, or the group's write, or its search.
    for mode in [0o770, 0o2750, 0o2730, 0o2760, 0o0700, 0o0755] {
        assert_eq!(
            with(WORKSPACE_GROUP, mode),
            Err(BrokerRefusal::WorkspaceGroupContract),
            "{mode:o}"
        );
    }
    // World-writable is refused first, as ever (ADR-0044 §3).
    assert_eq!(
        with(WORKSPACE_GROUP, 0o2777),
        Err(BrokerRefusal::SharedDirectory)
    );
    // Another group's directory keeps ADR-0044's rule alone: the broker's
    // M4c write-enabled workspaces are unchanged by M5d.4.
    assert_eq!(with(1000, 0o770), Ok(()));
    assert_eq!(with(1000, 0o755), Ok(()));
    evidence(
        "broker-group-convention-refused",
        "WORKSPACE_GROUP_CONTRACT",
    );
}

#[test]
fn no_room_is_its_own_class_and_nothing_else_is() {
    for errno in [Errno::NOSPC, Errno::DQUOT] {
        assert_eq!(
            denied_or(errno, BrokerRefusal::IoError),
            BrokerRefusal::NoSpace
        );
        assert_eq!(room_or_io(errno), BrokerRefusal::NoSpace);
    }
    assert_eq!(room_or_io(Errno::IO), BrokerRefusal::IoError);
    assert_eq!(room_or_io(Errno::ACCESS), BrokerRefusal::IoError);
    assert_eq!(
        denied_or(Errno::ACCESS, BrokerRefusal::IoError),
        BrokerRefusal::WriteDenied
    );
    assert_eq!(
        denied_or(Errno::IO, BrokerRefusal::IoError),
        BrokerRefusal::IoError
    );
}

/// Set for the child this test starts inside its own namespaces: the
/// directory to mount the full filesystem on.
const CHILD: &str = "DW_M5D4_FULL_FILESYSTEM";
const NAMESPACES: [&str; 5] = [
    "--user",
    "--map-root-user",
    "--mount",
    "--propagation",
    "private",
];

#[test]
fn a_full_filesystem_is_no_space_for_every_change_and_nothing_changes() {
    if let Some(dir) = std::env::var_os(CHILD) {
        full_filesystem(Path::new(&dir));
        return;
    }
    let available = std::process::Command::new("unshare")
        .args(NAMESPACES)
        .arg("true")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !available {
        println!(
            "NOT EXERCISED: no unprivileged user and mount namespace here \
             (`unshare --user --map-root-user --mount` failed), so no filesystem of the test's \
             own can be filled"
        );
        return;
    }
    let scratch = Scratch::new("full");
    let output = std::process::Command::new("unshare")
        .args(NAMESPACES)
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "exchange::tests::workspace::a_full_filesystem_is_no_space_for_every_change_and_nothing_changes",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, &scratch.0)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        text.contains("FULL-FILESYSTEM write=NO_SPACE create=NO_SPACE delete=NO_SPACE"),
        "{text}"
    );
    // The host's own directory never held anything: the tmpfs was the
    // child's, in the child's mount namespace, and went with it.
    assert!(scratch.names().is_empty(), "{:?}", scratch.names());
    evidence("broker-full-filesystem-write", "NO_SPACE");
    evidence("broker-full-filesystem-create", "NO_SPACE");
    evidence("broker-full-filesystem-delete", "NO_SPACE");
    evidence("broker-full-filesystem-nothing-changed", "unchanged");
}

/// Inside the namespaces: mount a 256 KiB tmpfs, fill it to the kernel's
/// `ENOSPC`, and ask for a replacement, a creation and a deletion.
fn full_filesystem(dir: &Path) {
    use std::io::Write as _;
    let mounted = std::process::Command::new("mount")
        .args(["-t", "tmpfs", "-o", "size=256k,mode=0700", "dw-m5d4-full"])
        .arg(dir)
        .status()
        .unwrap();
    assert!(mounted.success(), "mount {mounted:?}");
    let full = Scratch(dir.to_path_buf());
    let target = full.file("f", b"before");
    let before = identity(&target);
    // Fill what is left, a page at a time, until the kernel refuses.
    let mut filler = std::fs::File::create(full.0.join("filler")).unwrap();
    let page = [0x5a_u8; 4096];
    let refused_with = loop {
        if let Err(error) = filler.write_all(&page) {
            break error.raw_os_error();
        }
    };
    drop(filler);
    assert_eq!(refused_with, Some(Errno::NOSPC.raw_os_error()));
    let names = full.names();
    assert_eq!(names, ["f", "filler"]);

    let replaced = run(
        &write_authorisation(&full, "f", Some(before), b"after"),
        vec![full.dir()],
    );
    let created = run(
        &write_authorisation(&full, "n", None, b"new"),
        vec![full.dir()],
    );
    let deleted = run(
        &delete_authorisation(&full, "f", StatKind::RegularFile),
        vec![full.dir()],
    );
    let class = |got: &OutcomeResult| refused(got).as_str();
    // Nothing changed: the target holds what it held, nothing was made, and
    // no staging directory is left behind.
    let unchanged = std::fs::read(&target).unwrap() == b"before"
        && identity(&target) == before
        && full.names() == names;
    println!(
        "FULL-FILESYSTEM write={} create={} delete={} unchanged={unchanged}",
        class(&replaced),
        class(&created),
        class(&deleted)
    );
    assert!(unchanged, "{:?}", full.names());
}
