//! M4c end to end (ADR-0044): the eight filesystem tools, version 2 of the
//! tool messages, through the released `dwkd-authority` and `dwkd-broker`
//! and this process as the runtime, speaking DWKP.
//!
//! Locally all three share one uid, stated to both daemons with their
//! development flags: what these tests prove is the plan, the gates, the
//! protocol, the atomic operations and every refusal — not uid separation,
//! which is `fs_ops_foreign.rs`'s, on the hosted job.
//!
//! "The broker was not contacted" is measured from the broker's own event
//! lines: it writes one `connection` event for every connection the kernel
//! attributes to the authority, before it reads a byte.

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
    use std::collections::BTreeMap;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::Path;

    use dwk_proto::dwkp::fsops::{
        CanonicalPreviewResultV2, ToolDenialV2, ToolFailureV2, ToolPlan, ToolRefusalV2,
        ToolResultV2,
    };
    use dwk_proto::dwkp::{DwkpBody, DwkpMessage};
    use dwk_proto::wire::scalar::{
        ActionRole, DecisionEffect, EntryKind, FsDecisionReason, FsFailureReason, FsRefusalReason,
        FsTool, FsVerb, ObjectState, PatchOutcome, StatKind,
    };
    use sha2::{Digest as _, Sha256};

    use super::broker_support::{FSOPS_CAPABILITIES, Runtime, Setup};
    use super::state_support::raw;

    const SUITE: &str = "fs-ops";

    /// One line of structured evidence for `make filesystem-operations-evidence`.
    fn fsop(case: &str, outcome: &str, broker_contacts: usize) {
        println!(
            "FSOP-EVIDENCE {{\"suite\":\"{SUITE}\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\
             \"broker_contacts\":{broker_contacts}}}"
        );
    }

    // ---- the version-2 calls, as the runtime writes them ---------------------

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn sha(bytes: &[u8]) -> String {
        hex(&Sha256::digest(bytes))
    }

    fn read(path: &str, max: u32) -> String {
        format!(r#"{{"fs_read":{{"path":"{path}","max_bytes":{max}}}}}"#)
    }

    fn list(path: &str, max: u32) -> String {
        format!(r#"{{"fs_list":{{"path":"{path}","max_entries":{max}}}}}"#)
    }

    fn search(path: &str, needle: &[u8], scan: u32, matches: u32) -> String {
        format!(
            r#"{{"fs_search":{{"path":"{path}","needle":"{}","max_scan_bytes":{scan},"max_matches":{matches}}}}}"#,
            hex(needle)
        )
    }

    fn stat(path: &str) -> String {
        format!(r#"{{"fs_stat":{{"path":"{path}"}}}}"#)
    }

    fn write(path: &str, content: &[u8]) -> String {
        format!(
            r#"{{"fs_write":{{"path":"{path}","content":"{}"}}}}"#,
            hex(content)
        )
    }

    fn revision(bytes: &[u8]) -> String {
        format!(r#"{{"sha256":"{}","length":{}}}"#, sha(bytes), bytes.len())
    }

    fn patch(path: &str, base: &[u8], post: &[u8], edits: &[(u32, u32, &[u8])]) -> String {
        let edits: Vec<String> = edits
            .iter()
            .map(|(offset, delete, insert)| {
                format!(
                    r#"{{"offset":{offset},"delete":{delete},"insert":"{}"}}"#,
                    hex(insert)
                )
            })
            .collect();
        format!(
            r#"{{"fs_patch":{{"path":"{path}","base":{},"post":{},"edits":[{}]}}}}"#,
            revision(base),
            revision(post),
            edits.join(",")
        )
    }

    fn moved(source: &str, destination: &str) -> String {
        format!(r#"{{"fs_move":{{"source":"{source}","destination":"{destination}"}}}}"#)
    }

    fn delete(path: &str) -> String {
        format!(r#"{{"fs_delete":{{"path":"{path}"}}}}"#)
    }

    // ---- the answers ---------------------------------------------------------

    fn result(message: &DwkpMessage) -> &ToolResultV2 {
        match &message.body {
            DwkpBody::ToolResultV2(result) => result,
            other => panic!("expected a version-2 result, got {other:?}"),
        }
    }

    fn denial(message: &DwkpMessage) -> &ToolDenialV2 {
        match &message.body {
            DwkpBody::ToolDeniedV2(denial) => denial,
            other => panic!("expected a version-2 denial, got {other:?}"),
        }
    }

    fn refusal(message: &DwkpMessage) -> FsRefusalReason {
        match &message.body {
            DwkpBody::ToolRefusedV2(ToolRefusalV2 { reason, .. }) => *reason,
            other => panic!("expected a version-2 refusal, got {other:?}"),
        }
    }

    fn failure(message: &DwkpMessage) -> &ToolFailureV2 {
        match &message.body {
            DwkpBody::ToolFailedV2(failure) => failure,
            other => panic!("expected a version-2 failure, got {other:?}"),
        }
    }

    fn previewed(message: &DwkpMessage) -> &CanonicalPreviewResultV2 {
        match &message.body {
            DwkpBody::ToolPreviewedV2(preview) => preview,
            other => panic!("expected a version-2 preview, got {other:?}"),
        }
    }

    /// Every action of a plan: `(role, verb, path, object, effect, reason)`.
    fn actions(
        plan: &ToolPlan,
    ) -> Vec<(
        ActionRole,
        FsVerb,
        String,
        ObjectState,
        DecisionEffect,
        FsDecisionReason,
    )> {
        plan.actions
            .iter()
            .map(|a| {
                (
                    a.role,
                    a.verb,
                    a.canonical_path.as_str().to_owned(),
                    a.object,
                    a.decision.effect,
                    a.decision.reason,
                )
            })
            .collect()
    }

    // ---- the store and the tree -----------------------------------------------

    /// Every invocation row: `(tool, retry_class, state, completion, failure)`.
    type Row = (String, String, String, Option<String>, Option<String>);

    fn rows(state: &Path) -> Vec<Row> {
        let conn = raw(state);
        let mut statement = conn
            .prepare(
                "SELECT tool, retry_class, state, completion, failure FROM tool_invocation \
                 ORDER BY intent_ms, invocation_id",
            )
            .unwrap();
        statement
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    /// `(operation, state)` for every staging record, in order.
    fn staging_rows(state: &Path) -> Vec<(String, String)> {
        let conn = raw(state);
        let mut statement = conn
            .prepare(
                "SELECT operation, state FROM tool_staging ORDER BY recorded_ms, invocation_id",
            )
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn keys(state: &Path) -> i64 {
        raw(state)
            .query_row("SELECT count(*) FROM tool_idempotency", [], |row| {
                row.get(0)
            })
            .unwrap()
    }

    /// Everything under `root`, not following links: each path's kind, inode,
    /// mode and content (or link target).
    fn snapshot(root: &Path) -> BTreeMap<Vec<u8>, (u64, u32, Vec<u8>)> {
        let mut all = BTreeMap::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                let meta = std::fs::symlink_metadata(&path).unwrap();
                let body = if meta.file_type().is_symlink() {
                    std::fs::read_link(&path)
                        .unwrap()
                        .as_os_str()
                        .as_bytes()
                        .to_vec()
                } else if meta.is_dir() {
                    stack.push(path.clone());
                    Vec::new()
                } else {
                    std::fs::read(&path).unwrap()
                };
                all.insert(
                    path.as_os_str().as_bytes().to_vec(),
                    (meta.ino(), meta.mode(), body),
                );
            }
        }
        all
    }

    fn start(
        tag: &str,
    ) -> (
        Setup,
        super::broker_support::Broker,
        super::transport_support::Server,
        Runtime,
    ) {
        let setup = Setup::fsops(tag);
        let (broker, server) = setup.start_both();
        let rt = Runtime::admit_as(&setup.kernel_socket(), 1, "maintainer", FSOPS_CAPABILITIES);
        (setup, broker, server, rt)
    }

    // ---- each tool, end to end -------------------------------------------------

    #[test]
    fn every_tool_performs_through_the_real_broker_and_is_recorded() {
        let (setup, broker, _server, mut rt) = start("m4c-e2e");
        let root = setup.root.clone();

        // fs.stat: a file and a directory, from the object's own O_PATH
        // descriptor.
        let got = rt.invoke_v2(&stat("/workspace/a.txt"), "stat-1");
        let r = result(&got);
        assert_eq!(r.plan.tool, FsTool::FsStat);
        assert_eq!(
            actions(&r.plan),
            [(
                ActionRole::Target,
                FsVerb::FsStat,
                "/workspace/a.txt".to_owned(),
                ObjectState::Existing,
                DecisionEffect::Allow,
                FsDecisionReason::AllowedByRule
            )]
        );
        let s = r.output.fs_stat.as_ref().unwrap();
        assert_eq!(
            (s.kind, s.size.get(), s.link_count.get(), s.executable),
            (StatKind::RegularFile, 17, 1, false)
        );
        let got = rt.invoke_v2(&stat("/workspace/src"), "stat-2");
        let s = result(&got).output.fs_stat.clone().unwrap();
        assert_eq!((s.kind, s.executable), (StatKind::Directory, false));
        fsop("fs.stat", "metadata-from-descriptor", 2);

        // fs.list: byte order, kinds from the directory, the symlink listed
        // and never followed.
        let got = rt.invoke_v2(&list("/workspace", 512), "list-1");
        let l = result(&got).output.fs_list.clone().unwrap();
        let names: Vec<(String, EntryKind)> = l
            .entries
            .iter()
            .map(|e| (e.name.as_str().to_owned(), e.kind))
            .collect();
        assert_eq!(
            names,
            [
                ("a.txt".to_owned(), EntryKind::RegularFile),
                ("bytes.bin".to_owned(), EntryKind::RegularFile),
                ("capped".to_owned(), EntryKind::Directory),
                ("empty".to_owned(), EntryKind::RegularFile),
                ("empty-dir".to_owned(), EntryKind::Directory),
                ("link".to_owned(), EntryKind::Symlink),
                ("secret".to_owned(), EntryKind::Directory),
                ("src".to_owned(), EntryKind::Directory),
            ]
        );
        assert_eq!(l.unaddressable.get(), 0);
        assert!(l.complete);
        fsop("fs.list", "sorted-non-recursive", 1);

        // fs.search: offsets only.
        let got = rt.invoke_v2(&search("/workspace/a.txt", b"o", 1024, 16), "search-1");
        let found = result(&got).output.fs_search.clone().unwrap();
        let offsets: Vec<u64> = found.offsets.iter().map(|o| o.get()).collect();
        assert_eq!(offsets, [4, 8]);
        assert_eq!(found.scanned.get(), 17);
        assert!(found.eof_observed && !found.matches_truncated);
        fsop("fs.search", "offsets-only", 1);

        // fs.read through version 2: the same bytes as version 1.
        let got = rt.invoke_v2(&read("/workspace/bytes.bin", 4096), "read-1");
        let bytes = result(&got).output.fs_read.clone().unwrap();
        assert_eq!(
            bytes.content.to_bytes(),
            super::broker_support::every_byte()
        );

        // fs.write, existing: replaced atomically, the mode kept.
        std::fs::set_permissions(root.join("a.txt"), std::fs::Permissions::from_mode(0o640))
            .unwrap();
        let before = std::fs::metadata(root.join("a.txt")).unwrap().ino();
        let got = rt.invoke_v2(&write("/workspace/a.txt", b"replaced content"), "write-1");
        let r = result(&got);
        assert_eq!(actions(&r.plan).len(), 1);
        let w = r.output.fs_write.as_ref().unwrap();
        assert!(!w.created);
        assert_eq!(w.length.get(), 16);
        assert_eq!(w.sha256.as_str(), sha(b"replaced content"));
        assert_eq!(
            std::fs::read(root.join("a.txt")).unwrap(),
            b"replaced content"
        );
        let meta = std::fs::metadata(root.join("a.txt")).unwrap();
        assert_ne!(meta.ino(), before, "a new file, never written in place");
        assert_eq!(meta.mode() & 0o7777, 0o640, "the permission bits kept");
        fsop("fs.write-existing", "replaced-atomically", 1);

        // fs.write, vacant: a compound plan, and the contract mode.
        let got = rt.invoke_v2(&write("/workspace/new.txt", b"hello, world"), "write-2");
        let r = result(&got);
        assert_eq!(
            actions(&r.plan)
                .iter()
                .map(|a| (a.1, a.3))
                .collect::<Vec<_>>(),
            [
                (FsVerb::FsWrite, ObjectState::Vacant),
                (FsVerb::FsCreate, ObjectState::Vacant)
            ]
        );
        assert!(r.output.fs_write.as_ref().unwrap().created);
        let meta = std::fs::metadata(root.join("new.txt")).unwrap();
        assert_eq!(meta.mode() & 0o7777, 0o660, "never executable");
        fsop("fs.write-vacant", "created-noreplace", 1);

        // fs.patch: applied, then recognised as applied, then a conflict.
        let edit = patch(
            "/workspace/new.txt",
            b"hello, world",
            b"hello, there",
            &[(7, 5, b"there")],
        );
        let got = rt.invoke_v2(&edit, "patch-1");
        let p = result(&got).output.fs_patch.clone().unwrap();
        assert_eq!(p.outcome, PatchOutcome::Applied);
        assert_eq!(
            std::fs::read(root.join("new.txt")).unwrap(),
            b"hello, there"
        );
        let r = result(&got);
        assert_eq!(
            actions(&r.plan)
                .iter()
                .map(|a| (a.1, a.2.clone()))
                .collect::<Vec<_>>(),
            [
                (FsVerb::FsRead, "/workspace/new.txt".to_owned()),
                (FsVerb::FsWrite, "/workspace/new.txt".to_owned())
            ]
        );
        let got = rt.invoke_v2(&edit, "patch-2");
        let p = result(&got).output.fs_patch.clone().unwrap();
        assert_eq!(p.outcome, PatchOutcome::AlreadyApplied);
        std::fs::write(root.join("new.txt"), b"a third thing").unwrap();
        let got = rt.invoke_v2(&edit, "patch-3");
        assert_eq!(failure(&got).reason, FsFailureReason::Conflict);
        assert_eq!(
            std::fs::read(root.join("new.txt")).unwrap(),
            b"a third thing"
        );
        fsop("fs.patch", "applied-already-applied-conflict", 3);

        // fs.move: to a vacant name.
        let id = std::fs::metadata(root.join("new.txt")).unwrap().ino();
        let got = rt.invoke_v2(
            &moved("/workspace/new.txt", "/workspace/src/moved.txt"),
            "move-1",
        );
        let r = result(&got);
        assert_eq!(
            actions(&r.plan)
                .iter()
                .map(|a| (a.0, a.1, a.2.clone()))
                .collect::<Vec<_>>(),
            [
                (
                    ActionRole::Source,
                    FsVerb::FsDelete,
                    "/workspace/new.txt".to_owned()
                ),
                (
                    ActionRole::Destination,
                    FsVerb::FsCreate,
                    "/workspace/src/moved.txt".to_owned()
                )
            ]
        );
        assert!(!root.join("new.txt").exists());
        assert_eq!(
            std::fs::metadata(root.join("src/moved.txt")).unwrap().ino(),
            id
        );
        fsop("fs.move", "renamed-noreplace", 1);

        // fs.delete: a file and an empty directory.
        let got = rt.invoke_v2(&delete("/workspace/src/moved.txt"), "delete-1");
        assert!(result(&got).output.fs_delete.is_some());
        assert!(!root.join("src/moved.txt").exists());
        let got = rt.invoke_v2(&delete("/workspace/empty-dir"), "delete-2");
        assert!(result(&got).output.fs_delete.is_some());
        assert!(!root.join("empty-dir").exists());
        fsop("fs.delete", "removed-after-proof", 2);

        // Nothing left behind by the broker.
        let debris: Vec<String> = std::fs::read_dir(&root)
            .unwrap()
            .chain(std::fs::read_dir(root.join("src")).unwrap())
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| n.starts_with(".dwkd-"))
            .collect();
        assert!(debris.is_empty(), "{debris:?}");

        // Every invocation recorded, with its fixed retry class.
        let state = setup.state();
        let got: Vec<(String, String, String, Option<String>)> = rows(&state)
            .into_iter()
            .map(|(tool, class, state, completion, failure)| {
                (tool, class, state, completion.or(failure))
            })
            .collect();
        let want = [
            ("fs.stat", "RETRY_SAFE", "COMPLETED", "STATED"),
            ("fs.stat", "RETRY_SAFE", "COMPLETED", "STATED"),
            ("fs.list", "RETRY_SAFE", "COMPLETED", "LISTED"),
            ("fs.search", "RETRY_SAFE", "COMPLETED", "SEARCHED"),
            ("fs.read", "RETRY_SAFE", "COMPLETED", "READ"),
            ("fs.write", "RETRY_SAFE", "COMPLETED", "REPLACED"),
            ("fs.write", "RETRY_SAFE", "COMPLETED", "CREATED"),
            ("fs.patch", "RETRY_SAFE", "COMPLETED", "APPLIED"),
            ("fs.patch", "RETRY_SAFE", "COMPLETED", "ALREADY_APPLIED"),
            ("fs.patch", "RETRY_SAFE", "FAILED", "CONFLICT"),
            ("fs.move", "NON_RETRYABLE", "COMPLETED", "MOVED"),
            ("fs.delete", "NON_RETRYABLE", "COMPLETED", "DELETED"),
            ("fs.delete", "NON_RETRYABLE", "COMPLETED", "DELETED"),
        ];
        let want: Vec<(String, String, String, Option<String>)> = want
            .iter()
            .map(|(a, b, c, d)| {
                (
                    (*a).to_owned(),
                    (*b).to_owned(),
                    (*c).to_owned(),
                    Some((*d).to_owned()),
                )
            })
            .collect();
        assert_eq!(got, want);
        assert_eq!(keys(&state), 13, "every key bound to its one invocation");

        // Every intent precedes its outcome, and the audit log holds no
        // content: not the written bytes, not the patch, not their hex.
        let audit = setup.audit();
        let intents = audit
            .iter()
            .filter(|r| r.event() == "tool.intent_recorded")
            .count();
        assert_eq!(intents, 13);
        let text = std::fs::read(setup.state().join("audit.log")).unwrap();
        for secret in [
            &b"replaced content"[..],
            b"hello, world",
            hex(b"replaced content").as_bytes(),
            hex(b"there").as_bytes(),
        ] {
            assert!(
                !text.windows(secret.len()).any(|w| w == secret),
                "the audit log holds content"
            );
        }
        assert_eq!(
            broker.count("executed") - broker.reclaims(),
            12,
            "{}",
            broker.stderr()
        );
        assert_eq!(broker.count("refused"), 1, "the conflict");
        assert_eq!(broker.count("indeterminate"), 0);
        fsop("audit-holds-no-content", "digests-and-counts-only", 13);

        // Every write, patch and delete recorded its one staging directory
        // with its intent, and every record settled: nothing was left, and
        // the one refusal's record was settled by a reclamation that found
        // nothing there (ADR-0044 §10).
        let staging = staging_rows(&state);
        assert_eq!(staging.len(), 7, "{staging:?}");
        assert!(staging.iter().all(|(_, s)| s == "CLEARED"), "{staging:?}");
        assert_eq!(broker.reclaims(), 1, "only the refusal left a record open");

        // Read-family results raise the run's taint before they are
        // delivered; acknowledgements of changes carry no workspace content
        // and raise none.
        for record in audit.iter().filter(|r| r.event() == "tool.completed") {
            let tool = record.text("tool").unwrap_or_default().to_owned();
            let taint = record.text("taint");
            if ["fs.read", "fs.list", "fs.search", "fs.stat"].contains(&tool.as_str()) {
                assert_eq!(taint, Some("LOCAL_UNVERIFIED"), "{tool}");
            } else {
                assert_eq!(taint, None, "{tool}");
            }
        }
        fsop("taint-read-family-only", "raised-for-results-not-acks", 13);
    }

    // ---- previews: the same plan, no effect -------------------------------------

    #[test]
    fn a_preview_names_the_invocations_plan_and_changes_nothing() {
        let (setup, broker, _server, mut rt) = start("m4c-preview");
        let root = setup.root.clone();
        std::fs::write(root.join("p.txt"), b"hello, world").unwrap();
        std::fs::write(root.join("m.txt"), b"to move").unwrap();
        std::fs::write(root.join("d.txt"), b"to delete").unwrap();
        let calls = [
            stat("/workspace/a.txt"),
            list("/workspace/src", 16),
            search("/workspace/a.txt", b"work", 64, 4),
            read("/workspace/a.txt", 64),
            write("/workspace/a.txt", b"previewed"),
            write("/workspace/fresh.txt", b"previewed"),
            patch(
                "/workspace/p.txt",
                b"hello, world",
                b"hello, there",
                &[(7, 5, b"there")],
            ),
            moved("/workspace/m.txt", "/workspace/src/m.txt"),
            delete("/workspace/d.txt"),
        ];
        let before = snapshot(&root);
        let mut previews = Vec::new();
        for call in &calls {
            let got = rt.preview_v2(call);
            previews.push(previewed(&got).plan.clone());
        }
        assert_eq!(snapshot(&root), before, "a preview changed the workspace");
        assert_eq!(
            broker.count("connection"),
            0,
            "a preview contacted the broker"
        );
        assert!(
            rows(&setup.state()).is_empty(),
            "a preview recorded an intent"
        );
        assert_eq!(keys(&setup.state()), 0, "a preview bound a key");
        fsop("preview-zero-effect", "no-broker-no-intent-no-key", 0);

        // The differential: each invocation decides exactly the plan its
        // preview named.
        for (n, (call, preview)) in calls.iter().zip(&previews).enumerate() {
            let got = rt.invoke_v2(call, &format!("diff-{n}"));
            assert_eq!(&result(&got).plan, preview, "{call}");
        }
        fsop("preview-invoke-differential", "same-plan", calls.len());
    }

    // ---- compound plans, denials, obligations ------------------------------------

    #[test]
    fn a_compound_plan_proceeds_only_if_every_action_is_allowed() {
        let (setup, broker, _server, mut rt) = start("m4c-compound");
        let root = setup.root.clone();
        for dir in ["nocreate", "locked", "artifacts", "approval"] {
            std::fs::create_dir(root.join(dir)).unwrap();
            std::fs::write(root.join(dir).join("e.txt"), b"existing").unwrap();
        }
        let before = snapshot(&root);

        // Creating where creation is denied: fs.write allowed, fs.create not.
        let got = rt.invoke_v2(&write("/workspace/nocreate/new.txt", b"x"), "c-1");
        let d = denial(&got);
        assert_eq!(d.plan.effect, DecisionEffect::Deny);
        let a = actions(&d.plan);
        assert_eq!((a[0].1, a[0].4), (FsVerb::FsWrite, DecisionEffect::Allow));
        assert_eq!(
            (a[1].1, a[1].4, a[1].5),
            (
                FsVerb::FsCreate,
                DecisionEffect::Deny,
                FsDecisionReason::DeniedByRule
            )
        );
        assert_eq!(
            d.plan.actions.as_slice()[1].decision.rule_id.as_str(),
            "deny-create-in-nocreate"
        );

        // A move whose destination may not be created: the source stays.
        let got = rt.invoke_v2(
            &moved("/workspace/a.txt", "/workspace/nocreate/a.txt"),
            "c-2",
        );
        let a = actions(&denial(&got).plan);
        assert_eq!(
            a[0].4,
            DecisionEffect::Allow,
            "the source's fs.delete is allowed"
        );
        assert_eq!(
            a[1].4,
            DecisionEffect::Deny,
            "the destination's fs.create is not"
        );

        // A rule's denial, an approval nothing can give, an obligation
        // nothing can enforce.
        let got = rt.invoke_v2(&write("/workspace/locked/e.txt", b"x"), "c-3");
        assert_eq!(
            actions(&denial(&got).plan)[0].5,
            FsDecisionReason::DeniedByRule
        );
        let got = rt.invoke_v2(&delete("/workspace/approval/e.txt"), "c-4");
        let a = &denial(&got).plan.actions.as_slice()[0];
        assert_eq!(a.decision.reason, FsDecisionReason::DeniedByRule);
        assert_eq!(a.decision.rule_id.as_str(), "approve-deletes");
        let got = rt.invoke_v2(&write("/workspace/artifacts/e.txt", b"x"), "c-5");
        let a = &denial(&got).plan.actions.as_slice()[0];
        assert_eq!(a.decision.reason, FsDecisionReason::ObligationUnenforceable);
        assert_eq!(a.decision.rule_id.as_str(), "artifact-captured-writes");
        fsop("obligation-unenforceable", "denied", 0);

        // The capability gate: a run holding fs.write but not fs.create.
        let mut narrow = Runtime::admit_as(
            &setup.kernel_socket(),
            2,
            "maintainer",
            &["fs.write:/workspace", "fs.read:/workspace"],
        );
        let got = narrow.invoke_v2(&write("/workspace/other.txt", b"x"), "c-6");
        let a = actions(&denial(&got).plan);
        assert_eq!(a[0].5, FsDecisionReason::AllowedByRule);
        assert_eq!(a[1].5, FsDecisionReason::NoCapability);

        assert_eq!(
            snapshot(&root),
            before,
            "a denied plan changed the workspace"
        );
        assert_eq!(
            broker.count("connection"),
            0,
            "a denied plan reached the broker"
        );
        assert!(rows(&setup.state()).is_empty());
        assert_eq!(keys(&setup.state()), 0, "a denial binds no key");
        fsop("compound-denial", "all-or-nothing", 0);

        // What is allowed still is: a replacement in nocreate/ needs no
        // fs.create.
        let got = rt.invoke_v2(&write("/workspace/nocreate/e.txt", b"allowed"), "c-7");
        assert!(!result(&got).output.fs_write.as_ref().unwrap().created);
        assert_eq!(broker.count("executed"), 1);
    }

    // ---- idempotency keys ------------------------------------------------------

    #[test]
    fn a_patch_past_its_inline_bound_is_refused_before_anything_is_recorded() {
        use dwk_proto::limits::MAX_PATCH_INSERT_BYTES_TOTAL as MAX;
        let (setup, broker, _server, mut rt) = start("m4c-patch-bound");
        let root = setup.root.clone();
        std::fs::write(root.join("p.txt"), b"a").unwrap();
        // The smallest patch past the bound: one byte more than it inserted,
        // across two edits so that neither is over its own type's bound —
        // the frame it travels in is well under 1 MiB and decodes.
        let first = vec![b'x'; MAX];
        let post = [first.as_slice(), b"a", b"y"].concat();
        let over = patch(
            "/workspace/p.txt",
            b"a",
            &post,
            &[(0, 0, first.as_slice()), (1, 0, b"y")],
        );
        let got = rt.invoke_v2(&over, "too-large");
        assert_eq!(refusal(&got), FsRefusalReason::PatchTooLarge);
        assert!(rows(&setup.state()).is_empty(), "no intent was recorded");
        assert_eq!(keys(&setup.state()), 0, "no key was bound");
        assert_eq!(
            broker.count("connection"),
            0,
            "the broker was not contacted"
        );
        assert_eq!(std::fs::read(root.join("p.txt")).unwrap(), b"a");
        fsop(
            "patch-inline-bound-exceeded",
            "PATCH_TOO_LARGE-before-intent",
            0,
        );
        // Exactly the bound: a patch like any other.
        let first = &first[..MAX - 1];
        let post = [first, b"a", b"y"].concat();
        let exact = patch(
            "/workspace/p.txt",
            b"a",
            &post,
            &[(0, 0, first), (1, 0, b"y")],
        );
        let got = rt.invoke_v2(&exact, "exact");
        assert_eq!(
            result(&got).output.fs_patch.clone().unwrap().outcome,
            PatchOutcome::Applied
        );
        assert_eq!(std::fs::read(root.join("p.txt")).unwrap(), post);
        fsop("patch-inline-bound-exact", "applied", 1);
    }

    #[test]
    fn a_key_names_one_invocation_and_is_never_performed_twice() {
        let (setup, broker, _server, mut rt) = start("m4c-key");
        let root = setup.root.clone();
        std::fs::write(root.join("one"), b"1").unwrap();
        std::fs::write(root.join("two"), b"2").unwrap();
        let got = rt.invoke_v2(&delete("/workspace/one"), "the-key");
        assert!(result(&got).output.fs_delete.is_some());
        // The same key again -- another object, even -- is refused before
        // anything is resolved, opened or sent.
        let got = rt.invoke_v2(&delete("/workspace/two"), "the-key");
        assert_eq!(refusal(&got), FsRefusalReason::IdempotencyKeyReused);
        let got = rt.invoke_v2(&delete("/workspace/one"), "the-key");
        assert_eq!(refusal(&got), FsRefusalReason::IdempotencyKeyReused);
        assert!(root.join("two").exists());
        assert_eq!(broker.count("connection"), 1);
        assert_eq!(rows(&setup.state()).len(), 1);
        // Scoped to the caller's session: another session's run may use it.
        let mut other =
            Runtime::admit_as(&setup.kernel_socket(), 2, "maintainer", FSOPS_CAPABILITIES);
        let got = other.invoke_v2(&delete("/workspace/two"), "the-key");
        assert!(result(&got).output.fs_delete.is_some());
        fsop("idempotency-key", "one-invocation-per-key", 2);

        // A version-2 invocation without a key, and a preview with one, are
        // not requests at all.
        let text = rt.v2_json("direwolf.tool.invoke", &stat("/workspace/a.txt"), None);
        rt.client.body(text.as_bytes()).unwrap();
        let answer = rt.client.recv(super::transport_support::PROMPT).message();
        assert!(
            matches!(answer.body, DwkpBody::ProtocolError(_)),
            "{answer:?}"
        );
    }

    // ---- hard links, symlinks ----------------------------------------------------

    #[test]
    fn hard_links_are_judged_per_operation() {
        let (setup, broker, _server, mut rt) = start("m4c-links");
        let root = setup.root.clone();
        std::fs::write(root.join("h1"), b"hello, world").unwrap();
        std::fs::hard_link(root.join("h1"), root.join("h2")).unwrap();
        // Changing content would reach every name: refused.
        let got = rt.invoke_v2(&write("/workspace/h1", b"x"), "l-1");
        assert_eq!(refusal(&got), FsRefusalReason::MultiplyLinked);
        let got = rt.invoke_v2(
            &patch(
                "/workspace/h1",
                b"hello, world",
                b"hello, there",
                &[(7, 5, b"there")],
            ),
            "l-2",
        );
        assert_eq!(refusal(&got), FsRefusalReason::MultiplyLinked);
        assert_eq!(broker.count("connection"), 0);
        // Observing, renaming or removing one name reaches only that name.
        let got = rt.invoke_v2(&stat("/workspace/h1"), "l-3");
        assert_eq!(
            result(&got)
                .output
                .fs_stat
                .clone()
                .unwrap()
                .link_count
                .get(),
            2
        );
        let got = rt.invoke_v2(&moved("/workspace/h1", "/workspace/h3"), "l-4");
        assert!(result(&got).output.fs_move.is_some());
        let got = rt.invoke_v2(&delete("/workspace/h3"), "l-5");
        assert!(result(&got).output.fs_delete.is_some());
        assert_eq!(std::fs::read(root.join("h2")).unwrap(), b"hello, world");
        assert_eq!(std::fs::metadata(root.join("h2")).unwrap().nlink(), 1);
        fsop("hardlink-write-patch", "MULTIPLY_LINKED", 0);
        fsop("hardlink-move-delete", "one-name-only", 2);
    }

    #[test]
    fn no_tool_follows_a_symlink_anywhere_on_its_paths() {
        let (setup, broker, _server, mut rt) = start("m4c-symlinks");
        let root = setup.root.clone();
        std::os::unix::fs::symlink(&setup.outside, root.join("dirlink")).unwrap();
        let outside = snapshot(&setup.outside);
        let calls = [
            stat("/workspace/link"),
            read("/workspace/link", 64),
            search("/workspace/link", b"SECRET", 64, 4),
            list("/workspace/dirlink", 16),
            write("/workspace/link", b"x"),
            write("/workspace/dirlink/new", b"x"),
            patch("/workspace/link", b"OUTSIDE-SECRET", b"x", &[(0, 14, b"x")]),
            moved("/workspace/link", "/workspace/moved"),
            moved("/workspace/a.txt", "/workspace/dirlink/a.txt"),
            delete("/workspace/link"),
            delete("/workspace/dirlink/secret"),
        ];
        for (n, call) in calls.iter().enumerate() {
            let got = rt.invoke_v2(call, &format!("s-{n}"));
            assert_eq!(refusal(&got), FsRefusalReason::Symlink, "{call}");
        }
        assert_eq!(snapshot(&setup.outside), outside);
        assert!(root.join("a.txt").exists());
        assert_eq!(broker.count("connection"), 0);
        fsop("symlink-containment", "SYMLINK-every-tool", 0);
    }

    // ---- fs.list: bounded, byte order, honest about names --------------------------

    #[test]
    fn a_listing_counts_the_names_no_canonical_path_can_name() {
        let (setup, _broker, _server, mut rt) = start("m4c-names");
        let dir = setup.root.join("names");
        std::fs::create_dir(&dir).unwrap();
        for name in [
            &b"b"[..],
            b"a",
            b"C",
            b"\xff\xfe",        // not UTF-8
            b"e\xcc\x81",       // NFD: not the canonical spelling
            b"\xc3\xa9",        // NFC, but canonically equal to the NFD one beside it
            b"x\x07y",          // a control character
            b"\xe2\x80\xaeabc", // a bidi override
        ] {
            std::fs::write(dir.join(OsStr::from_bytes(name)), b"").unwrap();
        }
        let got = rt.invoke_v2(&list("/workspace/names", 512), "n-1");
        let l = result(&got).output.fs_list.clone().unwrap();
        let names: Vec<&str> = l.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["C", "a", "b"], "byte order, addressable names only");
        assert_eq!(l.unaddressable.get(), 5, "counted, never rewritten");
        assert!(l.complete);
        // The first two in byte order, and it says it stopped.
        let got = rt.invoke_v2(&list("/workspace/names", 2), "n-2");
        let l = result(&got).output.fs_list.clone().unwrap();
        let names: Vec<&str> = l.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["C", "a"]);
        assert!(!l.complete);
        // A listing is not recursive, and a file is not a directory.
        let got = rt.invoke_v2(&list("/workspace/a.txt", 2), "n-3");
        assert_eq!(refusal(&got), FsRefusalReason::WrongKind);
        fsop("fs.list-unaddressable", "counted-not-emitted", 2);
    }

    #[test]
    fn a_search_is_bounded_and_says_so() {
        let (setup, _broker, _server, mut rt) = start("m4c-search");
        std::fs::write(setup.root.join("s.txt"), b"abababab--ab").unwrap();
        let offsets = |got: &DwkpMessage| {
            let f = result(got).output.fs_search.clone().unwrap();
            (
                f.offsets.iter().map(|o| o.get()).collect::<Vec<_>>(),
                f.scanned.get(),
                f.eof_observed,
                f.matches_truncated,
            )
        };
        let got = rt.invoke_v2(&search("/workspace/s.txt", b"abab", 1024, 16), "q-1");
        assert_eq!(
            offsets(&got),
            (vec![0, 2, 4], 12, true, false),
            "overlapping"
        );
        let got = rt.invoke_v2(&search("/workspace/s.txt", b"ab", 1024, 2), "q-2");
        assert_eq!(offsets(&got), (vec![0, 2], 6, false, true), "truncated");
        let got = rt.invoke_v2(&search("/workspace/s.txt", b"ab", 5, 16), "q-3");
        assert_eq!(offsets(&got), (vec![0, 2], 5, false, false), "scan-bounded");
        fsop("fs.search-bounds", "offsets-scanned-truncated", 3);
    }

    // ---- fs.create scopes -----------------------------------------------------

    #[test]
    fn a_create_scope_means_what_the_resolver_found_and_covers_by_component() {
        // (A scope ambiguous under normalisation cannot be requested at all:
        // capability text is ASCII on the wire. The resolver's refusal of an
        // ambiguous declared path is M4a's evidence.)
        let setup = Setup::fsops("m4c-scopes");
        let (broker, _server) = setup.start_both();
        let requested = [
            "fs.write:/workspace",
            "fs.create:/workspace/out.txt", // vacant: the name it will have
            "fs.create:/workspace/src",     // existing: a subtree
            "fs.create:/workspace/missing/x", // vacant, no parent: unstable
            "fs.read:/workspace/vacant.txt", // a read of nothing covers nothing
        ];
        let mut rt = Runtime::admit_as(&setup.kernel_socket(), 3, "maintainer", &requested);
        let granted: Vec<&str> = rt
            .grant
            .granted
            .iter()
            .map(|g| g.capability.as_str())
            .collect();
        for scope in ["fs.create:/workspace/out.txt", "fs.create:/workspace/src"] {
            assert!(
                granted.contains(&scope),
                "{scope} was not minted: {granted:?}"
            );
        }
        let withheld: Vec<&str> = rt
            .grant
            .withheld
            .iter()
            .map(|w| w.capability.as_str())
            .collect();
        for scope in [
            "fs.create:/workspace/missing/x",
            "fs.read:/workspace/vacant.txt",
        ] {
            assert!(
                withheld.contains(&scope),
                "{scope} was minted: {withheld:?}"
            );
        }
        let create = |got: &DwkpMessage| {
            let plan = &previewed(got).plan;
            actions(plan)
                .into_iter()
                .find(|a| a.1 == FsVerb::FsCreate)
                .map(|a| a.5)
        };
        // Exact, descendant; sibling and prefix-but-not-component are not.
        for (path, want) in [
            ("/workspace/out.txt", Some(FsDecisionReason::AllowedByRule)),
            (
                "/workspace/src/new.rs",
                Some(FsDecisionReason::AllowedByRule),
            ),
            ("/workspace/out.txtX", Some(FsDecisionReason::NoCapability)),
            ("/workspace/srcX", Some(FsDecisionReason::NoCapability)),
            // An existing target needs no fs.create at all.
            ("/workspace/a.txt", None),
        ] {
            let got = rt.preview_v2(&write(path, b"x"));
            assert_eq!(create(&got), want, "{path}");
        }
        // Outside the workspace by spelling: not a path at all.
        let got = rt.preview_v2(&write("/workspaceX/a", b"x"));
        assert_eq!(refusal(&got), FsRefusalReason::PathOutsideWorkspace);
        assert_eq!(broker.count("connection"), 0);
        fsop(
            "fs.create-scope-semantics",
            "exact-descendant-vacant-existing",
            0,
        );
    }

    // ---- versions --------------------------------------------------------------

    #[test]
    fn a_version_one_request_is_answered_in_version_one() {
        let (_setup, _broker, _server, mut rt) = start("m4c-v1");
        let got = rt.invoke("/workspace/a.txt", 64);
        assert_eq!(got.header.schema_version.get(), 1);
        assert!(matches!(got.body, DwkpBody::ToolResult(_)), "{got:?}");
        let got = rt.invoke_v2(&read("/workspace/a.txt", 64), "v-1");
        assert_eq!(got.header.schema_version.get(), 2);
        assert!(matches!(got.body, DwkpBody::ToolResultV2(_)), "{got:?}");
        fsop("public-versioning", "answered-in-request-version", 2);
    }

    /// A read allowed only with an obligation this build cannot enforce.
    const AUDITED_READS: &str = r#"schema_version = 1

[meta]
name = "m4c"

[[rule]]
id = "audited-reads"
effect = "ALLOW"
when.verb = ["fs.read", "fs.list", "fs.stat"]
when.path_under = "${WORKSPACE}"
obligations = ["audit_level=full"]

[[rule]]
id = "default"
effect = "DENY"
reason = "NO_MATCHING_RULE"
"#;

    #[test]
    fn an_unenforceable_obligation_denies_in_both_versions() {
        // A runtime choosing the older version is not a way round a condition.
        let setup = Setup::fsops_with("m4c-obligation-v1", AUDITED_READS);
        let (broker, _server) = setup.start_both();
        let mut rt = Runtime::admit_as(&setup.kernel_socket(), 1, "maintainer", FSOPS_CAPABILITIES);
        let got = rt.invoke("/workspace/a.txt", 64);
        let DwkpBody::ToolDenied(denied) = &got.body else {
            panic!("version 1 was not denied: {got:?}")
        };
        assert_eq!(denied.decision.effect, DecisionEffect::Deny);
        assert_eq!(
            denied.decision.reason,
            dwk_proto::wire::scalar::ToolDecisionReason::DeniedByRule
        );
        assert_eq!(
            denied.decision.policy_result,
            dwk_proto::wire::scalar::GateResult::NotSatisfied
        );
        assert_eq!(denied.decision.rule_id.as_str(), "audited-reads");
        let got = rt.invoke_v2(&read("/workspace/a.txt", 64), "o-1");
        let a = &denial(&got).plan.actions.as_slice()[0];
        assert_eq!(a.decision.reason, FsDecisionReason::ObligationUnenforceable);
        assert_eq!(broker.count("connection"), 0);
        fsop("obligation-both-versions", "denied-v1-and-v2", 0);
    }

    // ---- resources ----------------------------------------------------------------

    fn fds(pid: u32) -> usize {
        std::fs::read_dir(format!("/proc/{pid}/fd"))
            .map(Iterator::count)
            .unwrap_or(usize::MAX)
    }

    #[test]
    fn no_descriptor_outlives_its_invocation() {
        let (setup, broker, server, mut rt) = start("m4c-leaks");
        let root = setup.root.clone();
        // Warm both daemons up, then measure.
        let _ = rt.invoke_v2(&stat("/workspace/a.txt"), "warm");
        std::thread::sleep(std::time::Duration::from_millis(100));
        let (authority_before, broker_before) = (fds(server.pid), broker.open_fds());
        for n in 0..25 {
            let name = format!("/workspace/f{n}");
            let _ = result(&rt.invoke_v2(&write(&name, b"content"), &format!("w{n}")));
            let _ = result(&rt.invoke_v2(&write(&name, b"changed"), &format!("r{n}")));
            let _ = result(&rt.invoke_v2(&list("/workspace", 8), &format!("l{n}")));
            let _ = result(&rt.invoke_v2(
                &moved(&name, &format!("/workspace/src/f{n}")),
                &format!("m{n}"),
            ));
            let _ =
                result(&rt.invoke_v2(&delete(&format!("/workspace/src/f{n}")), &format!("d{n}")));
            // Refusals and denials too.
            let _ = refusal(&rt.invoke_v2(&stat("/workspace/missing"), &format!("x{n}")));
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert_eq!(
            fds(server.pid),
            authority_before,
            "the authority kept a descriptor"
        );
        assert_eq!(
            broker.open_fds(),
            broker_before,
            "the broker kept a descriptor"
        );
        assert!(!root.join("f0").exists());
        fsop("resource-leaks", "fds-stable-150-ops", 125);
    }
}
