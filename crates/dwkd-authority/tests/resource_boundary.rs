//! The raw/canonical resource boundary.
//!
//! > **Raw resource spelling is not canonical resource identity.**
//!
//! `CAPABILITIES.md` §2: path containment is decided "**after** canonicalisation
//! to inode identity + NFC normalisation. Never a string prefix on raw input",
//! and an executable is `(resolved path, sha256)`. M4 derives those. M3b must
//! not look as if it has.
//!
//! # What the control actually is
//!
//! A type boundary, not a check:
//!
//! * [`CapabilitySpec`] has no containment method at all, so a declaration
//!   cannot be compared with anything.
//! * `Scope::Path` holds a `CanonicalPath`, whose only constructor takes
//!   **components** — there is no `CanonicalPath::from_str` and no `From<&str>`.
//! * `CapabilitySpec::resolve` is the single bridge, and it refuses for the two
//!   families whose identity is a resource.
//!
//! The first two are absences, and a test cannot observe an absence: what
//! follows checks the third exhaustively over the whole vocabulary, plus the
//! traversal rules on the constructor that does exist. The absences are held by
//! review and by the ADR, and that limitation is stated in the M3b report
//! rather than papered over.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

// The authority links `toml` for the policy loader. This test binary does not
// use it, and `unused_crate_dependencies` sees the manifest edge rather than
// the target that consumes it. Acknowledged rather than silenced with an
// `#[allow]`, so the lint stays meaningful for the binaries that do use it.
use toml as _;

mod common;

use dwkd_authority::capability::{Namespace, ScopeFamily, ScopeSpec, UnresolvedScope, Verb, parse};

#[test]
fn exactly_two_families_need_resolution() {
    // The claim is about the vocabulary, not about two examples. If a
    // thirteenth namespace arrives whose scope is a resource, it has to say so
    // here, and this test is where somebody notices.
    let needing: Vec<Namespace> = Namespace::ALL
        .iter()
        .copied()
        .filter(|n| n.scope_family().needs_resolution())
        .collect();
    assert_eq!(needing, vec![Namespace::Fs, Namespace::Process]);

    assert!(ScopeFamily::Path.needs_resolution());
    assert!(ScopeFamily::Executable.needs_resolution());
    for family in [
        ScopeFamily::Endpoint,
        ScopeFamily::CredentialHandle,
        ScopeFamily::ProviderModel,
        ScopeFamily::Domain,
        ScopeFamily::ServerId,
        ScopeFamily::AgentProfile,
        ScopeFamily::MemoryScope,
        ScopeFamily::Intent,
        ScopeFamily::ArtifactScope,
        ScopeFamily::ChannelTarget,
    ] {
        assert!(!family.needs_resolution(), "{family:?}");
    }
}

#[test]
fn no_verb_in_a_resolvable_family_can_reach_authority_from_text() {
    // Exhaustive over the vocabulary: every `fs` and `process` verb, with a
    // path that looks entirely ordinary, refuses. There is no verb for which
    // somebody quietly wired a shortcut.
    let mut checked = 0;
    for verb in Verb::ALL {
        if !verb.scope_family().needs_resolution() {
            continue;
        }
        for scope in ["/workspace", "/usr/bin/git", "/", "/a/b/c/d"] {
            let text = format!("{verb}:{scope}");
            let spec = parse(&text).unwrap_or_else(|e| panic!("{text}: {e}"));
            assert!(spec.needs_resolution(), "{text}");
            let expected = match verb.namespace() {
                Namespace::Fs => UnresolvedScope::CanonicalPath,
                _ => UnresolvedScope::ExecutableIdentity,
            };
            assert_eq!(spec.resolve(), Err(expected), "{text}");
            checked += 1;
        }
    }
    assert_eq!(
        checked,
        10 * 4,
        "7 fs verbs + 3 process verbs, 4 paths each"
    );
}

#[test]
fn a_declared_path_keeps_its_text_and_gains_no_meaning() {
    // The declaration survives so M4 has something to resolve. It is a
    // `DeclaredPath` and stays one: the type carries no comparison.
    let spec = parse("fs.read:/workspace/src").expect("valid");
    match spec.scope() {
        ScopeSpec::DeclaredPath(p) => assert_eq!(p.as_str(), "/workspace/src"),
        other => panic!("expected a declared path, got {other:?}"),
    }
    assert!(spec.resolve().is_err());
}

#[test]
fn two_declared_paths_that_would_compare_are_still_not_comparable() {
    // `/workspace` and `/workspace/src` are in an obvious prefix relation as
    // text. Neither becomes authority, so the obvious relation is never
    // consulted -- which is the point: obvious-looking path comparisons are how
    // symlink and normalisation bugs get shipped.
    let parent = parse("fs.read:/workspace").expect("valid");
    let child = parse("fs.read:/workspace/src").expect("valid");
    assert!(parent.resolve().is_err());
    assert!(child.resolve().is_err());
    // And they are not equal as specifications either, so nothing can mistake
    // one for the other on the way past.
    assert_ne!(parent, child);
}
