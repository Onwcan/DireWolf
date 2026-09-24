//! The M4c write permission model on three real identities (ADR-0044 §3).
//!
//! The authority is this process's uid. The broker runs as `DW_BROKER_AS`,
//! started by this harness through `sudo -n -u`; the hostile runtime is
//! `DW_PEER_AS`. `DW_WRITE_GROUP` names a group the broker's user and this
//! process are both members of: the operator's grant for a write-enabled
//! workspace, which the harness applies to the fixture workspace itself and
//! reports exactly (chgrp to the group, mode `2770`).
//!
//! What only this suite can show:
//!
//! * **a directory descriptor is not a right to change its names**: on a
//!   workspace with no grant, the broker's uid — holding the checked parent
//!   directory's descriptor — changes nothing, `WRITE_DENIED`, while it still
//!   stats, lists, searches and reads through the descriptors it is handed;
//! * **the grant is what makes a workspace writable, and it is ambient**: with
//!   it, every operation succeeds and the broker's uid owns what it wrote —
//!   and the same uid can create a file there by path, with no authorisation
//!   at all, which is why ADR-0044 §3 states it as ambient authority the
//!   operator grants deliberately;
//! * **the grant reaches only what it names**: a directory outside it is
//!   `WRITE_DENIED`, a file whose group the broker cannot keep is
//!   `ATTRIBUTES_NOT_PRESERVED` and unchanged, and the runtime's uid, outside
//!   the group, can do nothing there.
//!
//! Without the identities and the group these tests are `#[ignore]`d, and
//! `make filesystem-operations-evidence` fails as NOT EXERCISED rather than
//! passing. The hosted Linux CI job creates the broker user and the group.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use dwk_proto as _;
use proptest as _;
use rusqlite as _;
#[cfg(target_os = "linux")]
use rustix as _;
use sha2 as _;
use toml as _;
use unicode_normalization as _;

#[cfg(target_os = "linux")]
mod broker_support;
mod state_support;
#[cfg(target_os = "linux")]
mod transport_support;

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use dwk_proto::dwkp::{DwkpBody, DwkpMessage};
    use dwk_proto::json::{self, ParseOptions, Value};
    use dwk_proto::wire::scalar::{FsFailureReason, PatchOutcome};
    use sha2::{Digest as _, Sha256};

    use super::broker_support::{Broker, FSOPS_CAPABILITIES, Runtime, Setup, broker_bin};
    use super::state_support::TempDir;
    use super::transport_support::{Server, own_uid};

    fn fsop(case: &str, outcome: &str) {
        println!(
            "FSOP-EVIDENCE {{\"suite\":\"fs-ops-foreign\",\"case\":\"{case}\",\"outcome\":\"{outcome}\"}}"
        );
    }

    // ---- identities ----------------------------------------------------------------

    /// The user `variable` names, proven by the uid a process started as it
    /// reports: not this process's, not root, not any in `others`.
    fn identity(variable: &str, others: &[u32]) -> (String, u32) {
        let user = std::env::var(variable).unwrap_or_default();
        assert!(
            !user.is_empty(),
            "NOT EXERCISED: set {variable} to a user `sudo -n -u` can switch to; a cross-uid \
             property is never passed without one"
        );
        let probe = super::state_support::output(
            Command::new("sudo").args(["-n", "-u", &user, "id", "-u"]),
        )
        .expect("sudo runs");
        assert!(
            probe.status.success(),
            "NOT EXERCISED: `sudo -n -u {user}` cannot start a process here: {}",
            String::from_utf8_lossy(&probe.stderr)
        );
        let uid: u32 = String::from_utf8_lossy(&probe.stdout)
            .trim()
            .parse()
            .unwrap();
        assert_ne!(uid, own_uid(), "{variable} is this process's uid");
        assert_ne!(
            uid, 0,
            "{variable} is root, which is outside the threat model"
        );
        assert!(
            !others.contains(&uid),
            "{variable} shares a uid with another identity"
        );
        (user, uid)
    }

    /// The write group: its gid, proven to hold the broker's user and to be
    /// among this process's own groups, and not to hold the runtime's user.
    fn write_group(broker_user: &str, peer_user: &str) -> (String, u32) {
        let group = std::env::var("DW_WRITE_GROUP").unwrap_or_default();
        assert!(
            !group.is_empty(),
            "NOT EXERCISED: set DW_WRITE_GROUP to a group holding DW_BROKER_AS and this user"
        );
        let entry = std::fs::read_to_string("/etc/group")
            .unwrap()
            .lines()
            .find(|l| l.split(':').next() == Some(group.as_str()))
            .map(str::to_owned)
            .unwrap_or_else(|| panic!("NOT EXERCISED: no group {group} in /etc/group"));
        let fields: Vec<&str> = entry.split(':').collect();
        let gid: u32 = fields[2].parse().unwrap();
        let members: Vec<&str> = fields[3].split(',').collect();
        assert!(
            members.contains(&broker_user),
            "{broker_user} is not in {group}"
        );
        assert!(
            !members.contains(&peer_user),
            "{peer_user} must not be in {group}"
        );
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let groups = status
            .lines()
            .find_map(|l| l.strip_prefix("Groups:"))
            .unwrap_or_default();
        assert!(
            groups.split_whitespace().any(|g| g == gid.to_string()),
            "NOT EXERCISED: this process is not in {group} (gid {gid}); start it in a \
             session that has the group (CI: `sudo -u \"$USER\"` after `usermod -aG`)"
        );
        eprintln!("DW_WRITE_GROUP={group} is gid {gid}; members {members:?}");
        (group, gid)
    }

    struct Identities {
        broker_user: String,
        broker_uid: u32,
        peer_user: String,
        peer_uid: u32,
        gid: u32,
        group: String,
    }

    fn identities() -> Identities {
        let (broker_user, broker_uid) = identity("DW_BROKER_AS", &[]);
        let (peer_user, peer_uid) = identity("DW_PEER_AS", &[broker_uid]);
        let (group, gid) = write_group(&broker_user, &peer_user);
        Identities {
            broker_user,
            broker_uid,
            peer_user,
            peer_uid,
            gid,
            group,
        }
    }

    // ---- the deployment ----------------------------------------------------------------

    /// Traverse-only for other users.
    fn traversable_only(dir: &Path) {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o711)).unwrap();
    }

    fn private(dir: &Path) {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn mode(dir: &Path) -> u32 {
        std::fs::symlink_metadata(dir).unwrap().mode() & 0o7777
    }

    /// Not a three-identity test: it runs everywhere. A fixture is private
    /// until the test that needs another uid inside widens it — here, with the
    /// same helpers the hosted cross-uid tests use — and nothing is widened
    /// for it by the host's umask.
    #[test]
    fn a_fixture_is_private_until_a_cross_uid_test_widens_it_explicitly() {
        let dir = TempDir::new("m4c-widening");
        assert_eq!(mode(dir.path()), 0o700, "private by default");
        traversable_only(dir.path());
        assert_eq!(mode(dir.path()), 0o711, "traverse-only, explicitly");
        private(dir.path());
        assert_eq!(mode(dir.path()), 0o700, "and private again");
    }

    /// The broker binary and the probe client, where other users can run them.
    struct Staging {
        dir: TempDir,
        broker: PathBuf,
        client: PathBuf,
    }

    fn staging() -> Staging {
        let dir = TempDir::new("m4c-staging");
        traversable_only(dir.path());
        let broker = dir.path().join("dwkd-broker");
        std::fs::copy(broker_bin(), &broker).unwrap();
        std::fs::set_permissions(&broker, std::fs::Permissions::from_mode(0o755)).unwrap();
        let client = dir.path().join("broker_foreign_client.py");
        std::fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/authority/broker_foreign_client.py"),
            &client,
        )
        .unwrap();
        std::fs::set_permissions(&client, std::fs::Permissions::from_mode(0o644)).unwrap();
        Staging {
            dir,
            broker,
            client,
        }
    }

    fn broker_socket(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        PathBuf::from(format!("/tmp/dwb-{tag}-{}-{nanos}", std::process::id())).join("broker.sock")
    }

    fn run_as(user: &str, staging: &Staging, args: &[&str]) -> json::Object {
        let python = if Path::new("/usr/bin/python3").exists() {
            "/usr/bin/python3"
        } else {
            "python3"
        };
        let output = super::state_support::output(
            Command::new("sudo")
                .args(["-n", "-u", user, python])
                .arg(&staging.client)
                .args(args)
                .current_dir(staging.dir.path()),
        )
        .expect("sudo runs the client");
        assert!(
            output.status.success(),
            "the client failed as {user}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let line = String::from_utf8(output.stdout).unwrap();
        match json::parse(line.trim().as_bytes(), ParseOptions::dwkp()) {
            Ok(Value::Object(object)) => object,
            other => panic!("not a report: {other:?}\n{line}"),
        }
    }

    fn refused(report: &json::Object) -> bool {
        matches!(report.get("refused"), Some(Value::Bool(true)))
    }

    /// The M4c fixture, closed to everyone but this process: the workspace
    /// `0700`, its parent traverse-only.
    fn separated(tag: &str) -> Setup {
        let setup = Setup::fsops(tag);
        traversable_only(setup.dir.path());
        private(&setup.root);
        private(&setup.outside);
        setup
    }

    /// The authority, told the broker's socket and uid; the broker, as its
    /// own user; a `maintainer` run.
    fn deploy(
        setup: &Setup,
        ids: &Identities,
        stage: &Staging,
        tag: &str,
    ) -> (Broker, Server, Runtime) {
        let socket = broker_socket(tag);
        let broker = Broker::start_as(&ids.broker_user, &stage.broker, &socket, own_uid());
        assert_eq!(
            broker.uid(),
            ids.broker_uid,
            "the broker runs as its own identity"
        );
        let mut args = setup.authority_args(None, &[]);
        args.extend([
            "--broker-socket".to_owned(),
            socket.display().to_string(),
            "--broker-uid".to_owned(),
            ids.broker_uid.to_string(),
        ]);
        let server = Server::start(&args);
        let rt = Runtime::admit_as(&setup.kernel_socket(), 1, "maintainer", FSOPS_CAPABILITIES);
        (broker, server, rt)
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn write(path: &str, content: &[u8]) -> String {
        format!(
            r#"{{"fs_write":{{"path":"{path}","content":"{}"}}}}"#,
            hex(content)
        )
    }

    fn revision(bytes: &[u8]) -> String {
        format!(
            r#"{{"sha256":"{}","length":{}}}"#,
            hex(&Sha256::digest(bytes)),
            bytes.len()
        )
    }

    fn failure(message: &DwkpMessage) -> FsFailureReason {
        match &message.body {
            DwkpBody::ToolFailedV2(failure) => failure.reason,
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    fn done(message: &DwkpMessage) -> &dwk_proto::dwkp::fsops::ToolOutput {
        match &message.body {
            DwkpBody::ToolResultV2(result) => &result.output,
            other => panic!("expected a result, got {other:?}"),
        }
    }

    fn debris(dir: &Path) -> usize {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with(".dwkd-"))
            .count()
    }

    // ---- the cases ---------------------------------------------------------------------

    #[test]
    #[ignore = "needs DW_BROKER_AS, DW_PEER_AS and DW_WRITE_GROUP; run by `make filesystem-operations-evidence`"]
    fn a_held_directory_is_not_a_right_to_change_its_names() {
        let ids = identities();
        let stage = staging();
        let setup = separated("m4c-no-grant");
        let (broker, _server, mut rt) = deploy(&setup, &ids, &stage, "nogrant");
        let root = setup.root.clone();

        // The broker's uid cannot open the workspace by path...
        let by_path = run_as(
            &ids.broker_user,
            &stage,
            &["read-path", &root.join("a.txt").display().to_string()],
        );
        assert!(
            refused(&by_path),
            "the broker uid read the workspace by path"
        );
        // ... and observes through the descriptors it is handed.
        let got = rt.invoke_v2(
            r#"{"fs_list":{"path":"/workspace","max_entries":64}}"#,
            "o-1",
        );
        assert!(done(&got).fs_list.is_some(), "{got:?}\n{}", broker.stderr());
        let got = rt.invoke_v2(r#"{"fs_stat":{"path":"/workspace/a.txt"}}"#, "o-2");
        assert!(done(&got).fs_stat.is_some());
        let got = rt.invoke_v2(
            &format!(
                r#"{{"fs_search":{{"path":"/workspace/a.txt","needle":"{}","max_scan_bytes":64,"max_matches":4}}}}"#,
                hex(b"work")
            ),
            "o-3",
        );
        assert!(done(&got).fs_search.is_some());
        fsop(
            "observe-through-descriptors-cross-uid",
            "list-stat-search-ok",
        );

        // Holding the parent directory's descriptor, it changes no name.
        let before = std::fs::read(root.join("a.txt")).unwrap();
        let cases = [
            ("write-existing", write("/workspace/a.txt", b"x")),
            ("write-vacant", write("/workspace/new.txt", b"x")),
            (
                "move",
                r#"{"fs_move":{"source":"/workspace/a.txt","destination":"/workspace/src/a.txt"}}"#
                    .to_owned(),
            ),
            (
                "delete",
                r#"{"fs_delete":{"path":"/workspace/a.txt"}}"#.to_owned(),
            ),
        ];
        for (n, (case, payload)) in cases.iter().enumerate() {
            let got = rt.invoke_v2(payload, &format!("m-{n}"));
            assert_eq!(
                failure(&got),
                FsFailureReason::WriteDenied,
                "{case}\n{}",
                broker.stderr()
            );
            fsop(&format!("no-grant-{case}"), "WRITE_DENIED");
        }
        assert_eq!(std::fs::read(root.join("a.txt")).unwrap(), before);
        assert!(!root.join("new.txt").exists());
        assert!(!root.join("src/a.txt").exists());
        assert_eq!(debris(&root), 0);
        fsop(
            "descriptor-is-not-a-namespace-grant-cross-uid",
            "WRITE_DENIED-nothing-changed",
        );
    }

    #[test]
    #[ignore = "needs DW_BROKER_AS, DW_PEER_AS and DW_WRITE_GROUP; run by `make filesystem-operations-evidence`"]
    fn a_write_enabled_workspace_is_changed_by_the_broker_uid_and_only_where_granted() {
        let ids = identities();
        let stage = staging();
        let setup = separated("m4c-grant");
        let root = setup.root.clone();
        // A file made before the grant keeps this user's own group.
        let own_group_file = root.join("a.txt");
        // The grant, applied by this harness -- never by the product -- and
        // reported exactly.
        std::fs::create_dir(root.join("gone")).unwrap();
        let granted = [root.clone(), root.join("src"), root.join("gone")];
        for dir in &granted {
            std::os::unix::fs::chown(dir, None, Some(ids.gid)).unwrap();
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o2770)).unwrap();
            let meta = std::fs::metadata(dir).unwrap();
            assert_eq!((meta.gid(), meta.mode() & 0o7777), (ids.gid, 0o2770));
        }
        fsop(
            "permission-grant",
            &format!(
                "group {} gid {} mode 2770 on /workspace /workspace/src /workspace/gone; \
                 /workspace/secret not granted",
                ids.group, ids.gid
            ),
        );
        // A file made after it inherits the group.
        std::fs::write(root.join("g.txt"), b"granted").unwrap();
        std::fs::set_permissions(root.join("g.txt"), std::fs::Permissions::from_mode(0o640))
            .unwrap();
        assert_eq!(
            std::fs::metadata(root.join("g.txt")).unwrap().gid(),
            ids.gid
        );
        let (broker, _server, mut rt) = deploy(&setup, &ids, &stage, "grant");

        // Replace: a new file owned by the broker's uid, the mode and the
        // group kept.
        let got = rt.invoke_v2(&write("/workspace/g.txt", b"replaced"), "w-1");
        assert!(
            done(&got).fs_write.is_some(),
            "{got:?}\n{}",
            broker.stderr()
        );
        let meta = std::fs::metadata(root.join("g.txt")).unwrap();
        assert_eq!(std::fs::read(root.join("g.txt")).unwrap(), b"replaced");
        assert_eq!(
            (meta.uid(), meta.gid(), meta.mode() & 0o7777),
            (ids.broker_uid, ids.gid, 0o640)
        );
        fsop(
            "write-existing-cross-uid",
            "replaced-owner-broker-mode-and-group-kept",
        );

        // Create: the contract mode, the directory's group.
        let got = rt.invoke_v2(&write("/workspace/new.txt", b"hello, world"), "w-2");
        assert!(done(&got).fs_write.as_ref().unwrap().created);
        let meta = std::fs::metadata(root.join("new.txt")).unwrap();
        assert_eq!(
            (meta.uid(), meta.gid(), meta.mode() & 0o7777),
            (ids.broker_uid, ids.gid, 0o660)
        );
        fsop("write-vacant-cross-uid", "created-0660-group-inherited");

        // Patch, move, delete.
        let patch = format!(
            r#"{{"fs_patch":{{"path":"/workspace/new.txt","base":{},"post":{},"edits":[{{"offset":7,"delete":5,"insert":"{}"}}]}}}}"#,
            revision(b"hello, world"),
            revision(b"hello, there"),
            hex(b"there")
        );
        let got = rt.invoke_v2(&patch, "w-3");
        assert_eq!(
            done(&got).fs_patch.as_ref().unwrap().outcome,
            PatchOutcome::Applied
        );
        let got = rt.invoke_v2(
            r#"{"fs_move":{"source":"/workspace/new.txt","destination":"/workspace/src/new.txt"}}"#,
            "w-4",
        );
        assert!(done(&got).fs_move.is_some());
        let got = rt.invoke_v2(r#"{"fs_delete":{"path":"/workspace/src/new.txt"}}"#, "w-5");
        assert!(done(&got).fs_delete.is_some());
        let got = rt.invoke_v2(r#"{"fs_delete":{"path":"/workspace/gone"}}"#, "w-6");
        assert!(
            done(&got).fs_delete.is_some(),
            "{got:?}\n{}",
            broker.stderr()
        );
        assert!(!root.join("src/new.txt").exists() && !root.join("gone").exists());
        fsop("patch-move-delete-cross-uid", "applied-moved-deleted");

        // Only where granted: a directory outside the grant, and a file whose
        // group the broker is not in.
        let secret = std::fs::read(root.join("secret/key")).unwrap();
        let got = rt.invoke_v2(&write("/workspace/secret/key", b"x"), "w-7");
        assert_eq!(failure(&got), FsFailureReason::WriteDenied);
        assert_eq!(std::fs::read(root.join("secret/key")).unwrap(), secret);
        fsop("outside-the-grant-cross-uid", "WRITE_DENIED");
        let before = std::fs::read(&own_group_file).unwrap();
        let got = rt.invoke_v2(&write("/workspace/a.txt", b"x"), "w-8");
        assert_eq!(
            failure(&got),
            FsFailureReason::AttributesNotPreserved,
            "{}",
            broker.stderr()
        );
        assert_eq!(std::fs::read(&own_group_file).unwrap(), before);
        fsop(
            "group-not-keepable-cross-uid",
            "ATTRIBUTES_NOT_PRESERVED-unchanged",
        );
        assert_eq!(debris(&root), 0);
        assert_eq!(debris(&root.join("src")), 0);

        // The grant is ambient: the broker's uid can change a name there by
        // path, with no authorisation. Stated, not hidden (ADR-0044 §3).
        let ambient = run_as(
            &ids.broker_user,
            &stage,
            &[
                "create-path",
                &root.join("ambient.txt").display().to_string(),
            ],
        );
        assert!(
            !refused(&ambient),
            "the grant was expected to be ambient: {ambient:?}"
        );
        fsop("grant-is-ambient", "broker-uid-creates-by-path");

        // The runtime's uid, outside the group, can do nothing there.
        let runtime = run_as(
            &ids.peer_user,
            &stage,
            &[
                "create-path",
                &root.join("runtime.txt").display().to_string(),
            ],
        );
        assert!(
            refused(&runtime),
            "the runtime uid changed a name in the workspace"
        );
        // Nor rename or remove one: the permission model excludes it as a
        // concurrent writer of names (ADR-0044 §3).
        let path = |name: &str| root.join(name).display().to_string();
        std::fs::write(root.join("victim.txt"), b"keep").unwrap();
        let renamed = run_as(
            &ids.peer_user,
            &stage,
            &["rename-path", &path("victim.txt"), &path("moved.txt")],
        );
        assert!(refused(&renamed), "the runtime uid renamed a name");
        let removed = run_as(
            &ids.peer_user,
            &stage,
            &["remove-path", &path("victim.txt")],
        );
        assert!(refused(&removed), "the runtime uid removed a name");
        assert_eq!(std::fs::read(root.join("victim.txt")).unwrap(), b"keep");
        std::fs::remove_file(root.join("victim.txt")).unwrap();
        let runtime_read = run_as(
            &ids.peer_user,
            &stage,
            &["read-path", &root.join("g.txt").display().to_string()],
        );
        assert!(refused(&runtime_read));
        assert_ne!(ids.peer_uid, ids.broker_uid);
        fsop("runtime-uid-outside-the-grant", "refused");
    }
}
