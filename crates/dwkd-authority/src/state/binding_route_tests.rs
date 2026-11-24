//! M6.1 (ADR-0079, Proposed): the approval binding built from what the real
//! authority holds -- a run admitted over the in-process dispatcher, its
//! record in the store (the subject the kernel reported, its agent profile
//! and revision), its session's workspace and that root's recorded identity,
//! the real filesystem resolver's identity for a file beneath it, the fs
//! route's own capability derivation, and the policy engine's decision.
//!
//! Nothing here asks, stores or spends anything. The binding is computed and
//! compared; every route still denies a `REQUIRE_APPROVAL` as before, and the
//! store and the audit log are unchanged by building one.

use std::os::unix::fs::MetadataExt as _;

use dwk_proto::wire::scalar::{ActionRole, FsVerb, ObjectState};

use super::*;
use crate::capability::DeclaredPath;
use crate::policy::{CanonicalAction, Decision, Effect, Environment, compose, evaluate, load};
use crate::resource::fs::{Access, Expect, FileIdentity, PinnedRoot};
use crate::state::binding::{
    ApprovalBinding, BindingError, BindingInput, BoundArguments, BoundCredentials,
    BoundEnvironment, BoundResource, BoundScope, RunContext,
};
use crate::state::plan::{ActionSpec, required_capability};

/// The run's context, read from its record by the binding's own loader.
pub(super) fn context(fx: &mut Fixture, run: &RunId) -> Result<RunContext, BindingError> {
    fx.authority()
        .transact(|work| RunContext::load(work, run))
        .unwrap()
}

/// The fs route's capability for a write of `bytes` to `canonical`: the
/// production derivation (`plan::required_capability`), on the host, as the
/// route decides it.
fn write_action(canonical: &crate::resource::CanonicalPath, bytes: u64) -> CanonicalAction {
    let spec = ActionSpec {
        role: ActionRole::Target,
        verb: FsVerb::FsWrite,
        canonical: canonical.clone(),
        object: ObjectState::Existing,
        byte_count: bytes,
    };
    CanonicalAction::new(required_capability(&spec).unwrap(), Environment::Host)
        .with_byte_count(bytes)
}

/// The real policy engine's `REQUIRE_APPROVAL` for a write.
fn approve_writes(action: &CanonicalAction) -> Decision {
    let profile = load(
        "m6-1.toml",
        "schema_version = 1\n[meta]\nname = \"m6-1\"\n\n[[rule]]\nid = \"approve-writes\"\n\
         effect = \"REQUIRE_APPROVAL\"\nreason = \"SENSITIVE_PATH\"\nwhen.verb = \"fs.write\"\n\
         approval.scope = \"exact_action\"\napproval.ttl = \"10m\"\napproval.max_uses = 1\n\n\
         [[rule]]\nid = \"default\"\neffect = \"DENY\"\nreason = \"NO_MATCHING_RULE\"\n",
    )
    .unwrap();
    let name = profile.name().clone();
    let policy = compose(&name, &[profile]).unwrap();
    let decision = evaluate(&policy, action, &crate::policy::testing::interactive());
    assert_eq!(decision.effect(), Effect::RequireApproval);
    decision
}

/// The workspace root's host directory, and the real resolver pinned on it.
fn pinned(fx: &Fixture) -> (std::path::PathBuf, PinnedRoot) {
    let root = fx.scratch.path().join("ws");
    let (pinned, _) = PinnedRoot::install(root.to_str().unwrap()).unwrap();
    (root, pinned)
}

/// What the resolver opens at `/workspace/<name>`: its canonical path and
/// identity.
fn resolve(pinned: &PinnedRoot, name: &str) -> (crate::resource::CanonicalPath, FileIdentity) {
    let declared = DeclaredPath::new(&format!("/workspace/{name}")).unwrap();
    let resolved = pinned
        .resolve(&declared, Access::Modify, Expect::RegularFile)
        .unwrap();
    (resolved.canonical_path().clone(), resolved.identity())
}

/// A write's binding for `run`, of `content` to the file the resolver found.
pub(super) fn write_binding(
    run: &RunContext,
    canonical: &crate::resource::CanonicalPath,
    identity: FileIdentity,
    content: &[u8],
) -> ApprovalBinding {
    let action = write_action(canonical, u64::try_from(content.len()).unwrap());
    let decision = approve_writes(&action);
    ApprovalBinding::new(&BindingInput {
        action: &action,
        decision: &decision,
        // The rule imposes none; the route keeps every one of none.
        obligations_kept: decision.obligations().is_empty(),
        run,
        environment: &BoundEnvironment::host(),
        resource: &BoundResource::file(identity),
        arguments: &BoundArguments::fs_content(content).unwrap(),
        credentials: &BoundCredentials::none(),
        scope: &BoundScope::exact_action(),
    })
    .unwrap()
}

fn canonical_text(binding: &ApprovalBinding) -> String {
    String::from_utf8(binding.canonical_bytes().to_vec()).unwrap()
}

#[test]
fn m6_1_a_binding_is_built_from_the_runs_own_record_and_the_resolvers_identity() {
    let mut fx = fixture();
    let run = fx.run("b1", &["fs.read:*"]);
    let (root, pinned) = pinned(&fx);
    std::fs::write(root.join("notes.txt"), b"hello\n").unwrap();
    let (canonical, identity) = resolve(&pinned, "notes.txt");
    let events_before = fx.events();

    let context = context(&mut fx, &run).unwrap();
    let binding = write_binding(&context, &canonical, identity, b"hello\n");
    let text = canonical_text(&binding);

    // Every run-level member is the run's record, not a value the test chose.
    let root_meta = std::fs::metadata(&root).unwrap();
    let file_meta = std::fs::metadata(root.join("notes.txt")).unwrap();
    assert!(text.contains(r#""requester":"uid:1000""#), "{text}");
    assert!(
        text.contains(r#""agent":{"profile":"operator","revision":"1"}"#),
        "{text}"
    );
    assert!(text.contains(r#""id":"ws","root":{"birth":"#), "{text}");
    assert!(
        text.contains(&format!(
            r#""device":"{}","inode":"{}"}}}}"#,
            root_meta.dev(),
            root_meta.ino()
        )),
        "the workspace root as recorded: {text}"
    );
    assert!(
        text.contains(&format!(
            r#""resource_identity":{{"device":"{}","inode":"{}","kind":"file"}}"#,
            file_meta.dev(),
            file_meta.ino()
        )),
        "the file the resolver opened: {text}"
    );
    assert!(text.contains(r#""taint_level":"NONE""#), "{text}");
    assert!(
        text.contains(r#""environment_profile":{"kind":"host"}"#),
        "{text}"
    );

    // Building one changed nothing the authority records.
    assert_eq!(fx.events(), events_before, "no audit record");
    assert_eq!(
        fx.count("SELECT count(*) FROM sqlite_master WHERE name LIKE '%approv%'"),
        0,
        "no approval table exists"
    );
}

#[test]
fn m6_1_a_file_replaced_at_the_same_path_is_another_binding() {
    let mut fx = fixture();
    let run = fx.run("b1", &["fs.read:*"]);
    let (root, pinned) = pinned(&fx);
    std::fs::write(root.join("notes.txt"), b"hello\n").unwrap();
    let (canonical, before) = resolve(&pinned, "notes.txt");
    let context = context(&mut fx, &run).unwrap();
    let approved = write_binding(&context, &canonical, before, b"hello\n");

    // Replaced, not rewritten: a new file renamed over the old one, so both
    // inodes existed at once and cannot be one.
    std::fs::write(root.join("notes.txt.new"), b"hello\n").unwrap();
    std::fs::rename(root.join("notes.txt.new"), root.join("notes.txt")).unwrap();
    let (same_path, after) = resolve(&pinned, "notes.txt");
    assert_eq!(same_path, canonical, "the same canonical path");
    assert_ne!(after, before, "another object");
    let replaced = write_binding(&context, &same_path, after, b"hello\n");
    assert_ne!(approved, replaced);
    assert_ne!(approved.binding_hash(), replaced.binding_hash());

    // The same object, unchanged, is the same binding.
    assert_eq!(
        write_binding(&context, &same_path, after, b"hello\n"),
        replaced
    );
}

#[test]
fn m6_1_a_run_that_is_not_active_has_no_binding_context() {
    let mut fx = fixture();
    let unknown = RunId::from_uuid(uuid(999_999)).unwrap();
    assert_eq!(
        context(&mut fx, &unknown),
        Err(BindingError::RunUnavailable)
    );
}

#[test]
fn m6_1_the_binding_carries_no_run_so_two_runs_of_one_principal_bind_alike() {
    // One principal, one profile, two runs: the binding carries no run id
    // (ADR-0079 §9), so two runs of the same principal and profile at the
    // same taint bind the same action identically -- run scoping is the
    // registry's guard, not the hash's.
    let mut fx = fixture();
    let first = fx.run("b1", &["fs.read:*"]);
    let second = fx.run("b2", &["fs.read:*"]);
    let (root, pinned) = pinned(&fx);
    std::fs::write(root.join("notes.txt"), b"hello\n").unwrap();
    let (canonical, identity) = resolve(&pinned, "notes.txt");
    let one = context(&mut fx, &first).unwrap();
    let two = context(&mut fx, &second).unwrap();
    assert_eq!(one, two);
    assert_eq!(
        write_binding(&one, &canonical, identity, b"hello\n"),
        write_binding(&two, &canonical, identity, b"hello\n")
    );
}
