//! How a declared capability becomes authority-comparable in the state layer
//! (M4b, [ADR-0043] §8). Two paths, kept apart on purpose:
//!
//! 1. **A NEW declaration** — a term of an admission's mint expression: the
//!    agent profile, every active skill, the request, the mode ceiling. Every
//!    concrete `fs.read` path it names is resolved by the production M4a
//!    resolver beneath the session's pinned workspace root ([`resolve_paths`],
//!    outside any transaction), and the declaration becomes comparable only
//!    through that answer ([`declared`]). **The filesystem supplies the
//!    meaning**: a path that does not exist, crosses a symlink, a magic link
//!    or a mount, is ambiguous under normalisation, or lies beneath a root that
//!    was replaced, covers nothing and is granted to no one. `fs.read:*` names
//!    no object and needs no resolution.
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
//! Every other `fs` verb and `process` stay `UNRESOLVED_RESOURCE` until M4c and
//! M4d define what their targets mean.
//!
//! [ADR-0043]: ../../../../../docs/adr/0043-m4b-private-broker-channel-and-brokered-fs-read.md

use std::collections::BTreeMap;

use crate::capability::{
    Action, Capability, CapabilitySpec, DeclaredPath, Namespace, ScopeSpec, UnresolvedScope, Verb,
};
use crate::resource::fs::{Access, Expect, PinnedRoot, ResolveError, RootError};
use crate::resource::{CanonicalPath, FileIdentity};

use super::config::RootBinding;
use super::tool;

/// Whether `verb` is `fs.read`: the one filesystem verb M4b resolves.
#[must_use]
pub(super) fn is_fs_read(verb: Verb) -> bool {
    verb.namespace() == Namespace::Fs && verb.action() == Action::Read
}

/// The concrete path an `fs.read` declaration names, if it names one: the
/// declarations that need the resolver. `fs.read:*` names none.
pub(super) fn concrete_read_path(spec: &CapabilitySpec) -> Option<&DeclaredPath> {
    match spec.scope() {
        ScopeSpec::DeclaredPath(declared) if is_fs_read(spec.verb()) => Some(declared),
        _ => None,
    }
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
}

impl Unresolved {
    /// The audit spelling: the same classes a tool refusal carries.
    pub(super) fn class(&self) -> &'static str {
        match self {
            Self::NoWorkspace | Self::NoWorkspaceRoot => "WORKSPACE_UNBOUND",
            Self::Root(error) => tool::root_refusal(*error).as_str(),
            Self::Resolve(error) => tool::resolve_refusal(*error).as_str(),
            Self::NotAttempted => "NOT_ATTEMPTED",
        }
    }
}

/// What the M4a resolver said, beneath one root binding, about each concrete
/// `fs.read` path one admission names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Resolutions {
    /// The binding they were resolved beneath; `None` when there was none.
    binding: Option<RootBinding>,
    answers: BTreeMap<String, Result<(CanonicalPath, FileIdentity), Unresolved>>,
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

    /// The canonical path the resolver derived for `path`, or why none.
    pub(super) fn get(&self, path: &DeclaredPath) -> Result<&CanonicalPath, Unresolved> {
        self.answer(path).map(|(canonical, _)| canonical)
    }

    /// The canonical path and identity of the object `path` resolved to, or
    /// why none: for the admission's audit record.
    pub(super) fn answer(
        &self,
        path: &DeclaredPath,
    ) -> Result<(&CanonicalPath, FileIdentity), Unresolved> {
        match self.answers.get(path.as_str()) {
            Some(Ok((canonical, identity))) => Ok((canonical, *identity)),
            Some(Err(why)) => Err(why.clone()),
            None => Err(Unresolved::NotAttempted),
        }
    }
}

/// Resolve every one of `paths` beneath `binding` with the production M4a
/// resolver — the same [`PinnedRoot::resolve`] an invocation uses — as an
/// observation of a directory or a regular file. Call with no SQLite
/// transaction open. Each resolved object's descriptors close here: an
/// admission keeps a name and an identity, never a handle.
pub(super) fn resolve_paths(binding: &RootBinding, paths: &[DeclaredPath]) -> Resolutions {
    let mut answers = BTreeMap::new();
    match PinnedRoot::reopen(&binding.host_path, &binding.fingerprint) {
        Err(error) => {
            for path in paths {
                answers.insert(path.as_str().to_owned(), Err(Unresolved::Root(error)));
            }
        }
        Ok(root) => {
            for path in paths {
                let answer = root
                    .resolve(path, Access::Observe, Expect::Any)
                    .map(|resolved| (resolved.canonical_path().clone(), resolved.identity()))
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
/// missing. A concrete `fs.read` path is comparable only through the
/// resolver's answer in `resolutions`; everything else as the capability core
/// resolves it.
pub(super) fn declared(
    spec: &CapabilitySpec,
    resolutions: &Resolutions,
) -> Result<Capability, UnresolvedScope> {
    match concrete_read_path(spec) {
        Some(path) => {
            let canonical = resolutions
                .get(path)
                .map_err(|_| UnresolvedScope::CanonicalPath)?;
            spec.resolve_path(canonical.clone())
        }
        None => spec.resolve(),
    }
}

/// A grant the authority itself resolved, minted and stored, re-read. Trusted:
/// its stored canonical text is read back by the grammar (nothing on disk is
/// consulted) and the caller requires it to render to exactly itself. Never
/// for a new declaration.
pub(super) fn rehydrate(spec: &CapabilitySpec) -> Result<Capability, UnresolvedScope> {
    match concrete_read_path(spec) {
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
    fn every_other_fs_verb_and_process_stay_unresolved() {
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
        assert_eq!(
            declared(&spec("process.exec:/usr/bin/git"), &Resolutions::empty())
                .map(|c| c.to_canonical_string()),
            Err(UnresolvedScope::ExecutableIdentity)
        );
    }
}
