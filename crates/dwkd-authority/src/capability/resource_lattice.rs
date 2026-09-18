//! The `fs` and `process` half of the lattice, tested here rather than in
//! `tests/`.
//!
//! These are the only tests that need a canonical identity, and since
//! [ADR-0037]'s closeout a canonical identity cannot be constructed outside
//! `crate::resource` — including by an integration test, which links the
//! library compiled without `cfg(test)`. So they are unit tests. That is not a
//! workaround: a type whose construction is private is tested where its
//! construction is reachable.
//!
//! Everything here uses **synthetic** identities. It shows the comparison is
//! right *given* an identity, and shows nothing about deriving one from a real
//! resource — which is M4's, and does not exist.
//!
//! [ADR-0037]: ../../../../../docs/adr/0037-capability-specifications-and-canonical-authority-identities.md

use super::{
    Capability, CapabilitySet, ConstraintSet, Narrowing, Scope, Verb, attenuate,
    verb::{Action, Namespace},
};
use crate::resource::synthetic;

/// A verb, or `None`. The lib's tests avoid `expect` for the same reason the
/// lib does: a lint that is switched off in the tests is a lint with a hole.
fn verb(namespace: Namespace, action: Action) -> Option<Verb> {
    Verb::new(namespace, action)
}

/// An unconstrained capability over a synthetic canonical path.
fn path_cap(namespace: Namespace, action: Action, components: &[&str]) -> Option<Capability> {
    let scope = Scope::Path(synthetic::path(components)?);
    Capability::new(
        verb(namespace, action)?,
        scope,
        ConstraintSet::unconstrained(),
    )
    .ok()
}

/// An unconstrained `fs.read` over a synthetic canonical path.
fn read(components: &[&str]) -> Option<Capability> {
    path_cap(Namespace::Fs, Action::Read, components)
}

/// An unconstrained `process.exec` over a synthetic executable identity.
fn exec(components: &[&str], fill: u8) -> Option<Capability> {
    let scope = Scope::Executable(synthetic::executable(components, fill)?);
    Capability::new(
        verb(Namespace::Process, Action::Exec)?,
        scope,
        ConstraintSet::unconstrained(),
    )
    .ok()
}

/// `parent.contains(child)`, or `None` if either could not be built.
fn covers(parent: Option<&Capability>, child: Option<&Capability>) -> Option<bool> {
    Some(parent?.contains(child?))
}

#[test]
fn a_path_capability_contains_its_descendants() {
    let parent = read(&["workspace"]);
    assert_eq!(
        covers(parent.as_ref(), read(&["workspace"]).as_ref()),
        Some(true)
    );
    assert_eq!(
        covers(parent.as_ref(), read(&["workspace", "src"]).as_ref()),
        Some(true)
    );
    assert_eq!(
        covers(
            parent.as_ref(),
            read(&["workspace", "src", "main.rs"]).as_ref()
        ),
        Some(true)
    );
}

#[test]
fn a_path_capability_does_not_contain_a_string_prefix_neighbour() {
    // `/workspace` must not cover `/workspaceX`, and `starts_with` says it
    // does. This is the escalation the component-wise design makes
    // unrepresentable, asserted at the capability level rather than only at the
    // path level.
    let parent = read(&["workspace"]);
    for sibling in [
        vec!["workspaceX"],
        vec!["workspace-other"],
        vec!["workspace2", "src"],
        vec!["etc"],
    ] {
        assert_eq!(
            covers(parent.as_ref(), read(&sibling).as_ref()),
            Some(false),
            "{sibling:?}"
        );
    }
}

#[test]
fn a_deeper_path_capability_does_not_contain_its_ancestor() {
    assert_eq!(
        covers(
            read(&["workspace", "src"]).as_ref(),
            read(&["workspace"]).as_ref()
        ),
        Some(false)
    );
}

#[test]
fn containment_never_crosses_a_verb_even_over_the_same_path() {
    // `fs.read:/workspace` covers no `fs.write` at all, whatever the path.
    let reader = read(&["workspace"]);
    let writer = path_cap(Namespace::Fs, Action::Write, &["workspace"]);
    assert_eq!(covers(reader.as_ref(), writer.as_ref()), Some(false));
    assert_eq!(covers(writer.as_ref(), reader.as_ref()), Some(false));
}

#[test]
fn a_universal_fs_scope_covers_every_path_and_no_path_covers_it() {
    let universal = verb(Namespace::Fs, Action::Read)
        .and_then(|v| Capability::new(v, Scope::Universal, ConstraintSet::unconstrained()).ok());
    assert_eq!(
        covers(
            universal.as_ref(),
            read(&["anything", "at", "all"]).as_ref()
        ),
        Some(true)
    );
    assert_eq!(
        covers(read(&["workspace"]).as_ref(), universal.as_ref()),
        Some(false)
    );
}

#[test]
fn an_executable_capability_covers_itself_and_nothing_else() {
    let git = exec(&["usr", "bin", "git"], 0xAA);
    assert_eq!(
        covers(git.as_ref(), exec(&["usr", "bin", "git"], 0xAA).as_ref()),
        Some(true)
    );
    // A package update: same path, different program.
    assert_eq!(
        covers(git.as_ref(), exec(&["usr", "bin", "git"], 0xBB).as_ref()),
        Some(false)
    );
    // Same bytes, different place.
    assert_eq!(
        covers(git.as_ref(), exec(&["opt", "git"], 0xAA).as_ref()),
        Some(false)
    );
}

#[test]
fn an_executable_directory_does_not_contain_the_executables_under_it() {
    // `process.exec` scopes are identities, not prefixes. Treating a directory
    // as one would turn it into an allowlist nobody wrote.
    assert_eq!(
        covers(
            exec(&["usr", "bin"], 0xAA).as_ref(),
            exec(&["usr", "bin", "git"], 0xAA).as_ref()
        ),
        Some(false)
    );
}

#[test]
fn a_path_capability_renders_its_resolved_identity() {
    assert_eq!(
        read(&["workspace", "src"]).map(|c| c.to_canonical_string()),
        Some("fs.read:/workspace/src".to_owned())
    );
    let rendered = exec(&["usr", "bin", "git"], 0x5A).map(|c| c.to_canonical_string());
    // The executable's authority form carries the hash, which is deliberately
    // not a request spelling: a resolved identity is something the authority
    // holds, never something a caller may ask for.
    assert_eq!(
        rendered,
        Some(format!("process.exec:/usr/bin/git@{}", "5a".repeat(32)))
    );
}

#[test]
fn a_set_of_paths_is_minimised_without_losing_authority() {
    let (Some(wide), Some(narrow)) = (read(&["workspace"]), read(&["workspace", "src"])) else {
        unreachable!("valid components")
    };
    let forwards = CapabilitySet::from_capabilities([wide.clone(), narrow.clone()]);
    let backwards = CapabilitySet::from_capabilities([narrow.clone(), wide.clone()]);
    assert_eq!(forwards, backwards);
    assert_eq!(forwards.len(), 1);
    assert!(forwards.covers(&narrow), "minimising removes no authority");
}

#[test]
fn two_sibling_paths_do_not_synthesise_their_parent() {
    // The no-synthesis property over paths: holding `/workspace/src` and
    // `/workspace/tests` is not holding `/workspace`, which contains files
    // neither capability names.
    let (Some(src), Some(tests), Some(parent)) = (
        read(&["workspace", "src"]),
        read(&["workspace", "tests"]),
        read(&["workspace"]),
    ) else {
        unreachable!("valid components")
    };
    let held = CapabilitySet::from_capabilities([src, tests]);
    assert!(!held.covers(&parent));
    // And each half is still covered, which is what makes the union look
    // reachable to a careless implementation.
    let Some(under_src) = read(&["workspace", "src", "a.rs"]) else {
        unreachable!("valid components")
    };
    assert!(held.covers(&under_src));
}

#[test]
fn two_executables_do_not_synthesise_a_universal_one() {
    let (Some(git), Some(python), Some(any)) = (
        exec(&["usr", "bin", "git"], 1),
        exec(&["usr", "bin", "python"], 2),
        verb(Namespace::Process, Action::Exec).and_then(|v| {
            Capability::new(v, Scope::Universal, ConstraintSet::unconstrained()).ok()
        }),
    ) else {
        unreachable!("valid components")
    };
    let held = CapabilitySet::from_capabilities([git, python]);
    assert!(!held.covers(&any));
}

#[test]
fn attenuating_a_path_capability_narrows_and_never_widens() {
    let (Some(parent), Some(child_scope), Some(wider_scope)) = (
        read(&["workspace"]),
        synthetic::path(&["workspace", "src"]),
        synthetic::path(&[]),
    ) else {
        unreachable!("valid components")
    };
    let narrowed = attenuate(&parent, &Narrowing::to_scope(Scope::Path(child_scope)));
    assert!(narrowed.is_ok());
    if let Ok(child) = &narrowed {
        assert!(parent.contains(child));
    }
    // The root is every path there is; narrowing to it is widening.
    assert!(attenuate(&parent, &Narrowing::to_scope(Scope::Path(wider_scope))).is_err());
    // And so is the universal scope.
    assert!(attenuate(&parent, &Narrowing::to_scope(Scope::Universal)).is_err());
}

#[test]
fn a_chain_of_path_narrowings_stays_under_its_root() {
    let Some(root) = read(&["workspace"]) else {
        unreachable!("valid components")
    };
    let mut current = root.clone();
    for step in [
        vec!["workspace", "src"],
        vec!["workspace", "src", "auth"],
        vec!["workspace", "src", "auth", "mod.rs"],
    ] {
        let Some(scope) = synthetic::path(&step) else {
            unreachable!("valid components")
        };
        match attenuate(&current, &Narrowing::to_scope(Scope::Path(scope))) {
            Ok(next) => {
                assert!(current.contains(&next), "{step:?} must narrow");
                assert!(root.contains(&next), "and stay under the root");
                current = next;
            }
            Err(_) => unreachable!("each step is a descendant"),
        }
    }
    assert!(root.contains(&current));
    assert!(!current.contains(&root));
}

#[test]
fn a_path_capability_still_obeys_both_missing_constraint_rules() {
    // The constraint rules are scope-independent, and `constraints.rs` covers
    // them over `*`. This checks they hold over a resolved path too, because
    // that is the combination a real `fs.write` grant will have.
    let Some(verb) = verb(Namespace::Fs, Action::Write) else {
        unreachable!("fs.write exists")
    };
    let Some(path) = synthetic::path(&["workspace"]) else {
        unreachable!("valid components")
    };
    let build = |bytes: Option<u64>| {
        let mut c = ConstraintSet::unconstrained();
        c.max_bytes = bytes;
        Capability::new(verb, Scope::Path(path.clone()), c).ok()
    };
    let (Some(limited), Some(unlimited), Some(tighter)) =
        (build(Some(100)), build(None), build(Some(10)))
    else {
        unreachable!("valid capability")
    };
    // Rule A: the parent was unconstrained, so a child may add a limit.
    assert!(unlimited.contains(&limited));
    // Rule B: the parent had a limit, so a child without one is WIDER.
    assert!(!limited.contains(&unlimited));
    assert!(limited.contains(&tighter));
    assert!(!tighter.contains(&limited));
}
