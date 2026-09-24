//! How a declared capability becomes authority-comparable in the state layer
//! (M4b, [ADR-0043] §8). Two paths, kept apart on purpose:
//!
//! 1. **A NEW declaration** — a term of an admission's mint expression: the
//!    agent profile, every active skill, the request, the mode ceiling. Every
//!    concrete path an `fs.read`, `fs.list`, `fs.stat`, `fs.write`,
//!    `fs.create` or `fs.delete` declaration names is resolved by the
//!    production resolver beneath the session's pinned workspace root
//!    ([`resolve_paths`], outside any transaction), and the declaration becomes
//!    comparable only through that answer ([`declared`]). **The filesystem
//!    supplies the meaning**: a path that crosses a symlink, a magic link or a
//!    mount, is ambiguous under normalisation, or lies beneath a root that was
//!    replaced, covers nothing and is granted to no one. `fs.read:*` names no
//!    object and needs no resolution.
//! 2. **A TRUSTED STORED grant** — a canonical path the authority itself
//!    resolved, minted and wrote to `kernel.db`, re-read after a restart or for
//!    a replay ([`rehydrate`]). It is not a declaration and is not resolved
//!    again: its stored canonical text is read back and must render to
//!    exactly itself. A replay therefore never re-resolves and never re-mints.
//!
//! No production code turns declared text into a `CanonicalPath` for a new
//! declaration any other way: the grammar-only reader is named for the second
//! path, and only this module may name it (TX017).
//!
//! # Existing and vacant scopes (M4c, ADR-0044 §6)
//!
//! A scope is a subtree: `fs.create:/workspace/out` covers `/workspace/out`
//! and every name beneath it, compared component by component, never
//! `/workspace/outX`. Whether the scope's own path must **exist** depends on
//! the verb:
//!
//! | verb | the scope path must |
//! |---|---|
//! | `fs.read`, `fs.list`, `fs.stat`, `fs.delete` | exist: a scope naming nothing covers nothing |
//! | `fs.write`, `fs.create` | exist, **or** be vacant beneath an existing parent |
//!
//! A vacant scope is proved vacant the way a creating invocation's target is
//! ([`crate::resource::fs::VacantResource`]): its parent resolves as a
//! directory, its name is one canonical component, nothing is there, and no
//! entry is canonically equivalent to it. So a grant to create `out.txt` means
//! the one spelling that `out.txt` will have when it is created, and a scope
//! whose meaning is unstable — an ambiguous name, a missing parent — covers
//! nothing (fail closed).
//!
//! `fs.exec_bit` and `process` stay `UNRESOLVED_RESOURCE` until M4d and later
//! define what their targets mean.
//!
//! [ADR-0043]: ../../../../../docs/adr/0043-m4b-private-broker-channel-and-brokered-fs-read.md

use std::collections::BTreeMap;

use crate::capability::{
    Action, Capability, CapabilitySpec, DeclaredPath, Namespace, ScopeSpec, UnresolvedScope, Verb,
};
use crate::resource::fs::{Access, Expect, PinnedRoot, ResolveError, RootError, Target};
use crate::resource::{CanonicalPath, FileIdentity};

use super::config::RootBinding;
use super::tool;

/// What a verb's scope path must be for the verb to be resolved at all: the
/// filesystem verbs M4c gives a canonical meaning, and whether a vacant name
/// is meaningful for each. `None` for every other verb — `fs.exec_bit` and
/// `process` among them — which stays unresolved.
#[must_use]
pub(super) fn scope_rule(verb: Verb) -> Option<VacantScope> {
    if verb.namespace() != Namespace::Fs {
        return None;
    }
    match verb.action() {
        Action::Read | Action::List | Action::Stat | Action::Delete => Some(VacantScope::Refused),
        Action::Write | Action::Create => Some(VacantScope::Accepted),
        _ => None,
    }
}

/// Whether a scope may name a path that does not exist yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VacantScope {
    /// Only an existing object: the verb acts on what is there.
    Refused,
    /// An existing object or a vacant name beneath an existing directory: the
    /// verb can bring the object into being.
    Accepted,
}

/// The concrete path a resolvable filesystem declaration names, if it names
/// one: the declarations that need the resolver. `fs.read:*` names none.
pub(super) fn concrete_path(spec: &CapabilitySpec) -> Option<&DeclaredPath> {
    match spec.scope() {
        ScopeSpec::DeclaredPath(declared) if scope_rule(spec.verb()).is_some() => Some(declared),
        _ => None,
    }
}

/// What the resolver found at a declared path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Found {
    /// An object, with this identity.
    Existing(FileIdentity),
    /// Nothing, beneath the directory with this identity.
    Vacant(FileIdentity),
}

/// Why a declared path has no canonical meaning for this admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Unresolved {
    /// The session is bound to no workspace, so `/workspace` means nothing.
    NoWorkspace,
    /// The session's workspace has no bound root.
    NoWorkspaceRoot,
    /// The bound root could not be pinned — above all, it was replaced.
    Root(RootError),
    /// The path did not resolve beneath the pinned root.
    Resolve(ResolveError),
    /// The path was not among those resolved for this attempt (the terms
    /// changed between resolution and minting): it covers nothing.
    NotAttempted,
    /// Nothing exists at the path, and the verb acts only on what exists.
    Vacant,
}

impl Unresolved {
    /// The audit spelling: the same classes a tool refusal carries.
    pub(super) fn class(&self) -> &'static str {
        match self {
            Self::NoWorkspace | Self::NoWorkspaceRoot => "WORKSPACE_UNBOUND",
            Self::Root(error) => tool::root_refusal(*error).as_str(),
            Self::Resolve(error) => tool::resolve_refusal(*error).as_str(),
            Self::NotAttempted => "NOT_ATTEMPTED",
            Self::Vacant => "NOT_FOUND",
        }
    }
}

/// What the resolver said, beneath one root binding, about each concrete
/// filesystem path one admission names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Resolutions {
    /// The binding they were resolved beneath; `None` when there was none.
    binding: Option<RootBinding>,
    answers: BTreeMap<String, Result<(CanonicalPath, Found), Unresolved>>,
}

impl Resolutions {
    /// Nothing to resolve.
    pub(super) fn empty() -> Self {
        Self {
            binding: None,
            answers: BTreeMap::new(),
        }
    }

    /// No root to resolve beneath: every path is unresolved for `why`.
    pub(super) fn unavailable(paths: &[DeclaredPath], why: &Unresolved) -> Self {
        Self {
            binding: None,
            answers: paths
                .iter()
                .map(|p| (p.as_str().to_owned(), Err(why.clone())))
                .collect(),
        }
    }

    /// The binding these answers were resolved beneath.
    pub(super) const fn binding(&self) -> Option<&RootBinding> {
        self.binding.as_ref()
    }

    /// Whether every one of `paths` has an answer here.
    pub(super) fn covers(&self, paths: &[DeclaredPath]) -> bool {
        paths.iter().all(|p| self.answers.contains_key(p.as_str()))
    }

    /// The canonical path the resolver derived for `path`, for a verb that
    /// accepts or refuses a vacant scope, or why none.
    pub(super) fn get(
        &self,
        path: &DeclaredPath,
        vacant: VacantScope,
    ) -> Result<&CanonicalPath, Unresolved> {
        match self.answer(path)? {
            (_, Found::Vacant(_)) if vacant == VacantScope::Refused => Err(Unresolved::Vacant),
            (canonical, _) => Ok(canonical),
        }
    }

    /// The canonical path and what was found at `path`, or why nothing
    /// could be: for the admission's audit record.
    pub(super) fn answer(
        &self,
        path: &DeclaredPath,
    ) -> Result<(&CanonicalPath, Found), Unresolved> {
        match self.answers.get(path.as_str()) {
            Some(Ok((canonical, found))) => Ok((canonical, *found)),
            Some(Err(why)) => Err(why.clone()),
            None => Err(Unresolved::NotAttempted),
        }
    }
}

/// Resolve every one of `paths` beneath `binding` with the production
/// resolver an invocation uses, as an observation of a directory or a regular
/// file — and, for a path some declaration may name vacant, with
/// [`PinnedRoot::resolve_target`], which also proves a vacant name vacant
/// beneath its directory. Call with no SQLite transaction open. Each resolved
/// object's descriptors close here: an admission keeps a name and an
/// identity, never a handle.
pub(super) fn resolve_paths(
    binding: &RootBinding,
    paths: &[(DeclaredPath, VacantScope)],
) -> Resolutions {
    let mut answers = BTreeMap::new();
    match PinnedRoot::reopen(&binding.host_path, &binding.fingerprint) {
        Err(error) => {
            for (path, _) in paths {
                answers.insert(path.as_str().to_owned(), Err(Unresolved::Root(error)));
            }
        }
        Ok(root) => {
            for (path, vacant) in paths {
                let found = match vacant {
                    VacantScope::Accepted => {
                        root.resolve_target(path, Access::Observe, Expect::Any)
                    }
                    VacantScope::Refused => root
                        .resolve(path, Access::Observe, Expect::Any)
                        .map(Target::Existing),
                };
                let answer = found
                    .map(|target| match target {
                        Target::Existing(resolved) => (
                            resolved.canonical_path().clone(),
                            Found::Existing(resolved.identity()),
                        ),
                        Target::Vacant(vacant) => (
                            vacant.canonical_path().clone(),
                            Found::Vacant(vacant.parent_identity()),
                        ),
                    })
                    .map_err(Unresolved::Resolve);
                answers.insert(path.as_str().to_owned(), answer);
            }
        }
    }
    Resolutions {
        binding: Some(binding.clone()),
        answers,
    }
}

/// A NEW declaration in authority-comparable form, or which identity is
/// missing. A concrete filesystem path is comparable only through the
/// resolver's answer in `resolutions`, and only where that answer is one the
/// verb can act on; everything else as the capability core resolves it.
pub(super) fn declared(
    spec: &CapabilitySpec,
    resolutions: &Resolutions,
) -> Result<Capability, UnresolvedScope> {
    match (concrete_path(spec), scope_rule(spec.verb())) {
        (Some(path), Some(vacant)) => {
            let canonical = resolutions
                .get(path, vacant)
                .map_err(|_| UnresolvedScope::CanonicalPath)?;
            spec.resolve_path(canonical.clone())
        }
        _ => spec.resolve(),
    }
}

/// A grant the authority itself resolved, minted and stored, re-read. Trusted:
/// its stored canonical text is read back by the grammar (nothing on disk is
/// consulted) and the caller requires it to render to exactly itself. Never
/// for a new declaration.
pub(super) fn rehydrate(spec: &CapabilitySpec) -> Result<Capability, UnresolvedScope> {
    match concrete_path(spec) {
        Some(path) => {
            let canonical = crate::resource::fs::stored_canonical_path(path)
                .map_err(|_| UnresolvedScope::CanonicalPath)?;
            spec.resolve_path(canonical)
        }
        None => spec.resolve(),
    }
}

#[cfg(test)]
mod tests {
    use super::{Resolutions, Unresolved, declared, rehydrate};
    use crate::capability::{DeclaredPath, UnresolvedScope, parse};

    fn spec(text: &str) -> crate::capability::CapabilitySpec {
        let Ok(spec) = parse(text) else {
            unreachable!("{text} parses")
        };
        spec
    }

    #[test]
    fn a_new_concrete_declaration_is_nothing_without_the_resolvers_answer() {
        // No resolution at all: a concrete fs.read path covers nothing,
        // however canonical its spelling.
        for text in [
            "fs.read:/workspace",
            "fs.read:/workspace/src",
            "fs.read:/workspace/src?max_bytes=4096",
        ] {
            assert_eq!(
                declared(&spec(text), &Resolutions::empty()).map(|c| c.to_canonical_string()),
                Err(UnresolvedScope::CanonicalPath),
                "{text}"
            );
        }
        let Some(path) = DeclaredPath::new("/workspace/src") else {
            unreachable!("a path")
        };
        let refused = Resolutions::unavailable(&[path], &Unresolved::NoWorkspaceRoot);
        assert_eq!(
            declared(&spec("fs.read:/workspace/src"), &refused).map(|c| c.to_canonical_string()),
            Err(UnresolvedScope::CanonicalPath)
        );
        // The wildcard names no object and needs no answer.
        assert_eq!(
            declared(&spec("fs.read:*"), &Resolutions::empty()).map(|c| c.to_canonical_string()),
            Ok("fs.read:*".to_owned())
        );
    }

    #[test]
    fn a_stored_grant_rehydrates_to_exactly_its_text() {
        for text in [
            "fs.read:/workspace",
            "fs.read:/workspace/src?max_bytes=4096",
            "fs.read:/workspace?max_bytes=1&no_symlink_targets=true",
            "fs.read:*",
        ] {
            assert_eq!(
                rehydrate(&spec(text)).map(|c| c.to_canonical_string()),
                Ok(text.to_owned())
            );
        }
        for text in ["fs.read:/etc", "fs.read:/workspace/../etc"] {
            assert_eq!(
                rehydrate(&spec(text)).map(|c| c.to_canonical_string()),
                Err(UnresolvedScope::CanonicalPath),
                "{text}"
            );
        }
    }

    #[test]
    fn no_new_filesystem_declaration_means_anything_without_the_resolver() {
        // M4c resolves six fs verbs; none of them is comparable by its
        // spelling, and fs.exec_bit is not resolved at all.
        for text in [
            "fs.write:/workspace",
            "fs.create:/workspace",
            "fs.delete:/workspace",
            "fs.list:/workspace",
            "fs.stat:/workspace",
            "fs.exec_bit:/workspace",
        ] {
            assert_eq!(
                declared(&spec(text), &Resolutions::empty()).map(|c| c.to_canonical_string()),
                Err(UnresolvedScope::CanonicalPath),
                "{text}"
            );
        }
        assert_eq!(super::concrete_path(&spec("fs.exec_bit:/workspace")), None);
        assert_eq!(
            declared(&spec("process.exec:/usr/bin/git"), &Resolutions::empty())
                .map(|c| c.to_canonical_string()),
            Err(UnresolvedScope::ExecutableIdentity)
        );
    }
}
