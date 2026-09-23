//! M4a through the authority's public API ([ADR-0042]): an operator binds a
//! workspace to a filesystem root, a run in that workspace resolves declared
//! paths beneath it, the policy context gains `${WORKSPACE}`, and nothing on the
//! wire changes.
//!
//! Real files, a real `kernel.db`, the production resolver. The resolver's own
//! adversarial evidence — symlinks, magic links, mounts, races — is its unit
//! suite (`src/resource/fs/linux/tests.rs`); this file is the state layer's
//! half: provenance, lifecycle and the wire boundary.
//!
//! [ADR-0042]: ../../../docs/adr/0042-m4a-canonical-filesystem-resolution.md

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use dwk_proto as _;
use proptest as _;
#[cfg(target_os = "linux")]
use rustix as _;
use sha2 as _;
use toml as _;
use unicode_normalization as _;

mod state_support;

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, symlink};
    use std::path::{Path, PathBuf};

    use dwk_proto::dwkp::DwkpBody;
    use dwk_proto::wire::id::{RunId, SessionId};
    use dwk_proto::wire::scalar::RefusalReason;
    use dwkd_authority::capability::{Capability, DeclaredPath, Scope, UnresolvedScope, parse};
    use dwkd_authority::policy::{
        CanonicalAction, Effect, Environment, PolicyContext, ProfileName, Reason, compose,
        evaluate, load,
    };
    use dwkd_authority::resource::fs::{Access, Expect, ResolveError, ResourceKind, RootError};
    use dwkd_authority::state::{
        Admission, CallerContext, KERNEL_SCHEMA_VERSION, Reply, ResolutionRefused, WithheldCause,
        WorkspaceId, WorkspaceSensitivity, verify_audit_log,
    };

    use super::state_support::{
        Harness, admit_simple, audit_records, id, query_msg, raw, release_run_msg, run_id, session,
        text,
    };

    fn evidence(case: &str, outcome: &str) {
        println!(
            "FS-EVIDENCE {{\"category\":\"state\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\"count\":1}}"
        );
    }

    fn declared(path: &str) -> DeclaredPath {
        DeclaredPath::new(path).expect("a declared path")
    }

    fn host(path: &Path) -> &str {
        path.to_str().expect("a UTF-8 scratch path")
    }

    fn workspace(name: &str) -> WorkspaceId {
        WorkspaceId::new(name).expect("a workspace id")
    }

    /// A workspace directory on disk, with a few files.
    fn tree(h: &Harness, name: &str) -> PathBuf {
        let root = h.dir.path().join(name);
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/main.rs"), b"fn main() {}").unwrap();
        fs::write(root.join("marker"), name.as_bytes()).unwrap();
        root
    }

    fn admitted(reply: Reply<Admission>) -> Admission {
        match reply {
            Reply::Done(admission) => admission,
            Reply::Refused(reason) => panic!("admission refused: {reason:?}"),
        }
    }

    /// A workspace bound to a root, a session bound to the workspace, a lease
    /// and an admitted run.
    struct Bound {
        caller: CallerContext,
        session: SessionId,
        epoch: dwk_proto::wire::scalar::Epoch,
        run: RunId,
        root: PathBuf,
    }

    fn bound_run(h: &mut Harness, name: &str, n: u64) -> Bound {
        let root = tree(h, name);
        let id = workspace(name);
        let session = session(n);
        {
            let mut operator = h.authority().operator();
            operator
                .install_workspace(&id, WorkspaceSensitivity::Private)
                .unwrap();
            operator.install_workspace_root(&id, host(&root)).unwrap();
            operator.bind_session_workspace(&session, &id).unwrap();
        }
        let caller = h.connect(1000);
        let epoch = h.lease(&caller, &session);
        let admission = admitted(
            h.authority()
                .admit_run(
                    &caller,
                    &admit_simple(&session, epoch, "k1", &["model.call:*"]),
                )
                .unwrap(),
        );
        Bound {
            caller,
            session,
            epoch,
            run: admission.run_id().clone(),
            root,
        }
    }

    #[test]
    fn an_operator_binds_a_workspace_to_a_measured_root_once() {
        let mut h = Harness::new("ws-install");
        let root = tree(&h, "proj");
        let other = tree(&h, "other");
        let link = h.dir.path().join("proj-link");
        let missing = h.dir.path().join("missing");
        symlink(&root, &link).unwrap();
        let id = workspace("proj");
        let mut operator = h.authority().operator();
        operator
            .install_workspace(&id, WorkspaceSensitivity::Public)
            .unwrap();
        operator.install_workspace_root(&id, host(&root)).unwrap();
        // Idempotent for the same measurement, refused for any other root.
        operator.install_workspace_root(&id, host(&root)).unwrap();
        let rebind = operator.install_workspace_root(&id, host(&other));
        assert!(
            format!("{:?}", rebind.as_ref().err()).contains("already bound"),
            "{rebind:?}"
        );
        evidence("root-rebind-refused", "refused:already-bound");
        // Unknown workspace, and paths that cannot be pinned.
        let unknown = operator.install_workspace_root(&workspace("nope"), host(&root));
        assert!(format!("{unknown:?}").contains("no workspace"));
        for (path, code) in [
            ("relative/path".to_owned(), "ROOT_NOT_ABSOLUTE"),
            (host(&missing).to_owned(), "ROOT_MISSING"),
            (host(&link).to_owned(), "ROOT_SYMLINK"),
            (
                host(&root.join("marker")).to_owned(),
                "ROOT_NOT_A_DIRECTORY",
            ),
        ] {
            let result = operator.install_workspace_root(&workspace("other"), &path);
            // `other` is not installed as a workspace, so the root is refused
            // before the workspace is even looked at: the path is measured
            // first, and only a pinnable path reaches the store.
            assert!(format!("{result:?}").contains(code), "{path}: {result:?}");
            evidence(&format!("root-install-{}", code.to_lowercase()), code);
        }

        // One audit record, carrying the measured identity.
        let records = audit_records(&h.state(), "config.workspace_root_installed");
        assert_eq!(records.len(), 1, "the idempotent re-install wrote nothing");
        let meta = fs::metadata(&root).unwrap();
        assert_eq!(text(&records[0], "workspace_id"), Some("proj"));
        assert_eq!(text(&records[0], "host_path"), Some(host(&root)));
        assert_eq!(
            text(&records[0], "root_device"),
            Some(meta.dev().to_string().as_str())
        );
        assert_eq!(
            text(&records[0], "root_inode"),
            Some(meta.ino().to_string().as_str())
        );
        evidence("root-installed-and-audited", "recorded");

        // The binding is immutable in the store itself.
        let conn = raw(&h.state());
        assert!(
            conn.execute("UPDATE workspace_root SET host_path = '/elsewhere'", [])
                .is_err()
        );
        assert!(conn.execute("DELETE FROM workspace_root", []).is_err());
        evidence("root-binding-immutable", "refused:trigger");
    }

    #[test]
    fn a_run_resolves_beneath_its_workspace_root() {
        let mut h = Harness::new("ws-resolve");
        let b = bound_run(&mut h, "proj", 1);
        let file = h
            .authority()
            .resolve_for_run(
                &b.run,
                &declared("/workspace/src/main.rs"),
                Access::Observe,
                Expect::RegularFile,
            )
            .unwrap();
        let meta = fs::metadata(b.root.join("src/main.rs")).unwrap();
        assert_eq!(file.identity().device(), meta.dev());
        assert_eq!(file.identity().inode(), meta.ino());
        assert_eq!(file.canonical_path().to_string(), "/workspace/src/main.rs");
        assert_eq!(file.kind(), ResourceKind::RegularFile);
        evidence("run-resolves", "resolved");

        // A refusal carries the resolver's class, not the path.
        symlink(b.root.join("src"), b.root.join("link")).unwrap();
        let refused = h.authority().resolve_for_run(
            &b.run,
            &declared("/workspace/link/main.rs"),
            Access::Observe,
            Expect::Any,
        );
        assert_eq!(
            refused.err(),
            Some(ResolutionRefused::Resolve(ResolveError::Symlink {
                depth: 1
            }))
        );
        evidence("run-refuses-symlink", "refused:SYMLINK");

        // `${WORKSPACE}` is filled for this run, and only it.
        let context = h.authority().policy_context_of(&b.run).unwrap();
        let anchor = context
            .anchors()
            .workspace
            .clone()
            .expect("the anchor is filled");
        assert_eq!(anchor.to_string(), "/workspace");
        assert!(context.anchors().home.is_none());
        assert!(context.anchors().direwolf_home.is_none());
        evidence("workspace-anchor-filled", "resolved:/workspace");

        // Capability integration: resolved paths compare component-wise.
        let read_all = parse("fs.read:*").unwrap().resolve().unwrap();
        let cap = |path| {
            Capability::new(
                read_all.verb(),
                Scope::Path(path),
                read_all.constraints().clone(),
            )
            .unwrap()
        };
        let src = h
            .authority()
            .resolve_for_run(
                &b.run,
                &declared("/workspace/src"),
                Access::Observe,
                Expect::Directory,
            )
            .unwrap();
        let (whole, under, leaf) = (
            cap(anchor.clone()),
            cap(src.canonical_path().clone()),
            cap(file.canonical_path().clone()),
        );
        assert!(whole.contains(&under) && under.contains(&leaf) && whole.contains(&leaf));
        assert!(!leaf.contains(&under));
        evidence("capability-over-resolved-paths", "contained");

        // Policy integration, in process, with every fact of the action
        // supplied: `path_under = "${WORKSPACE}/src"` matches the resolved path.
        let policy = compose(
            &ProfileName::new("m4a").unwrap(),
            &[load(
                "m4a.toml",
                "schema_version = 1\n\n[meta]\nname = \"m4a\"\n\n\
                 [[rule]]\nid = \"allow-src\"\neffect = \"ALLOW\"\n\
                 when.verb = \"fs.read\"\nwhen.path_under = \"${WORKSPACE}/src\"\n\n\
                 [[rule]]\nid = \"default\"\neffect = \"DENY\"\nreason = \"NO_MATCHING_RULE\"\n",
            )
            .unwrap()],
        )
        .unwrap();
        let action = CanonicalAction::new(leaf, Environment::Sandbox);
        let decision = evaluate(&policy, &action, &context);
        assert_eq!(decision.effect(), Effect::Allow, "{decision:?}");
        let blind = PolicyContext::new(context.origin(), context.taint());
        let unanchored = evaluate(&policy, &action, &blind);
        assert_eq!(unanchored.effect(), Effect::Deny);
        assert_eq!(unanchored.reason(), Reason::UnresolvedCanonicalInput);
        evidence(
            "policy-path-under-workspace",
            "allow-with-anchor-deny-without",
        );
    }

    #[test]
    fn a_replaced_root_redirects_nothing() {
        let mut h = Harness::new("ws-replace");
        let b = bound_run(&mut h, "proj", 1);
        let pinned = h.authority().pin_run_workspace(&b.run).unwrap();
        let marker_a = fs::metadata(b.root.join("marker")).unwrap().ino();

        // Move the workspace away and put another directory at its path.
        let moved = b.root.with_file_name("proj-moved");
        fs::rename(&b.root, &moved).unwrap();
        fs::create_dir(&b.root).unwrap();
        fs::write(b.root.join("marker"), b"imposter").unwrap();

        let held = pinned
            .resolve(
                &declared("/workspace/marker"),
                Access::Observe,
                Expect::RegularFile,
            )
            .unwrap();
        assert_eq!(
            held.identity().inode(),
            marker_a,
            "the pinned root still means A"
        );
        evidence("pinned-root-survives-replacement", "resolved:a");

        let again = h.authority().resolve_for_run(
            &b.run,
            &declared("/workspace/marker"),
            Access::Observe,
            Expect::RegularFile,
        );
        assert_eq!(
            again.err(),
            Some(ResolutionRefused::Root(RootError::Replaced))
        );
        evidence("replaced-root-refused", "refused:ROOT_REPLACED");
    }

    #[test]
    fn a_run_without_a_bound_root_resolves_nothing() {
        let mut h = Harness::new("ws-none");
        // A workspace with no root.
        let bare = workspace("bare");
        let s1 = session(1);
        {
            let mut operator = h.authority().operator();
            operator
                .install_workspace(&bare, WorkspaceSensitivity::Public)
                .unwrap();
            operator.bind_session_workspace(&s1, &bare).unwrap();
        }
        let caller = h.connect(1000);
        let e1 = h.lease(&caller, &s1);
        let run = admitted(
            h.authority()
                .admit_run(&caller, &admit_simple(&s1, e1, "k1", &["model.call:*"]))
                .unwrap(),
        );
        let refused = h.authority().resolve_for_run(
            run.run_id(),
            &declared("/workspace"),
            Access::Observe,
            Expect::Any,
        );
        assert_eq!(refused.err(), Some(ResolutionRefused::NoWorkspaceRoot));
        let context = h.authority().policy_context_of(run.run_id()).unwrap();
        assert!(context.anchors().workspace.is_none());
        evidence("no-root-no-anchor", "refused:NO_WORKSPACE_ROOT");

        // A session bound to no workspace at all.
        let s2 = session(2);
        let e2 = h.lease(&caller, &s2);
        let loose = admitted(
            h.authority()
                .admit_run(&caller, &admit_simple(&s2, e2, "k2", &["model.call:*"]))
                .unwrap(),
        );
        let refused = h.authority().resolve_for_run(
            loose.run_id(),
            &declared("/workspace"),
            Access::Observe,
            Expect::Any,
        );
        assert_eq!(refused.err(), Some(ResolutionRefused::NoWorkspace));
        evidence("no-workspace", "refused:NO_WORKSPACE");

        // An ended run, and a run the kernel never admitted.
        let released = h
            .authority()
            .dispatch(&caller, &release_run_msg(&s2, loose.run_id(), e2))
            .unwrap();
        assert!(matches!(released, DwkpBody::Ack(_)));
        let ended = h.authority().resolve_for_run(
            loose.run_id(),
            &declared("/workspace"),
            Access::Observe,
            Expect::Any,
        );
        assert_eq!(ended.err(), Some(ResolutionRefused::RunNotActive));
        let unknown = run_id(999);
        let unknown = h.authority().resolve_for_run(
            &unknown,
            &declared("/workspace"),
            Access::Observe,
            Expect::Any,
        );
        assert_eq!(unknown.err(), Some(ResolutionRefused::UnknownRun));
        evidence("ended-run-refused", "refused:RUN_NOT_ACTIVE");
    }

    #[test]
    fn the_wire_is_unchanged_by_a_bound_root() {
        let mut h = Harness::new("ws-wire");
        let b = bound_run(&mut h, "proj", 1);

        // Admission still does not mint filesystem authority in M4a.
        let admission = admitted(
            h.authority()
                .admit_run(
                    &b.caller,
                    &admit_simple(
                        &b.session,
                        b.epoch,
                        "k2",
                        &["fs.read:/workspace", "model.call:*"],
                    ),
                )
                .unwrap(),
        );
        assert!(admission.withheld().iter().any(|w| w.requested().as_str()
            == "fs.read:/workspace"
            && w.cause() == WithheldCause::NeedsCanonicalization(UnresolvedScope::CanonicalPath)));
        evidence(
            "admission-still-withholds-fs",
            "withheld:UNRESOLVED_RESOURCE",
        );

        // A proposal naming a resolvable path is still not a canonical action.
        let answer = h
            .authority()
            .dispatch(
                &b.caller,
                &query_msg(
                    &b.session,
                    &b.run,
                    b.epoch,
                    Some("fs.read:/workspace/src/main.rs"),
                ),
            )
            .unwrap();
        let DwkpBody::AuthorityRefused(refusal) = answer else {
            panic!("a proposal is refused: {answer:?}")
        };
        assert_eq!(refusal.reason, RefusalReason::NoCanonicalAction);
        evidence(
            "query-still-no-canonical-action",
            "refused:NO_CANONICAL_ACTION",
        );

        // The reserved operations are still unknown to the decoder.
        for schema in ["direwolf.tool.invoke", "direwolf.canonical.preview"] {
            let message = format!(
                r#"{{"v":1,"id":"{}","type":"request","schema":"{schema}","schema_version":1,"ts":"2026-09-21T10:00:00.000Z","payload":{{}}}}"#,
                id("msg", 77)
            );
            assert!(
                dwk_proto::dwkp::decode_body(message.as_bytes()).is_err(),
                "{schema}"
            );
        }
        evidence(
            "reserved-operations-still-reserved",
            "refused:UNKNOWN_OPERATION",
        );
    }

    #[test]
    fn an_m3_store_migrates_and_its_audit_chain_still_verifies() {
        let mut h = Harness::new("ws-migrate");
        let id = workspace("proj");
        h.authority()
            .operator()
            .install_workspace(&id, WorkspaceSensitivity::Public)
            .unwrap();
        h.stop();
        // Make it exactly an M3 (schema 1) store: schema 2 is schema 1 plus
        // the workspace-root table and its two triggers.
        {
            let conn = raw(&h.state());
            conn.execute_batch("DROP TABLE workspace_root; PRAGMA user_version = 1;")
                .unwrap();
        }
        h.try_restart().expect("an M3 store migrates");
        assert_eq!(h.report.schema_version, KERNEL_SCHEMA_VERSION);
        let migrated = audit_records(&h.state(), "store.migrated");
        assert_eq!(migrated.len(), 1);
        assert_eq!(
            super::state_support::int(&migrated[0], "from_schema_version"),
            Some(1)
        );
        assert_eq!(
            super::state_support::int(&migrated[0], "to_schema_version"),
            Some(KERNEL_SCHEMA_VERSION)
        );
        verify_audit_log(&h.state().join("audit.log"))
            .expect("the chain verifies across the migration");
        // The migrated store takes a root binding.
        let root = tree(&h, "proj");
        h.authority()
            .operator()
            .install_workspace_root(&id, host(&root))
            .unwrap();
        evidence("m3-store-migrates", "migrated:1-to-2");
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn off_linux_no_workspace_root_can_be_bound() {
    let mut h = state_support::Harness::new("ws-unsupported");
    let id = dwkd_authority::state::WorkspaceId::new("proj").unwrap();
    let mut operator = h.authority().operator();
    operator
        .install_workspace(&id, dwkd_authority::state::WorkspaceSensitivity::Public)
        .unwrap();
    let result = operator.install_workspace_root(&id, "/srv/proj");
    assert!(
        format!("{result:?}").contains("UNSUPPORTED_PLATFORM"),
        "{result:?}"
    );
}
