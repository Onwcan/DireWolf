//! Test-only helpers for building actions and contexts.
//!
//! `#[cfg(test)]`, like `crate::resource::synthetic` and for the same reason:
//! these build canonical `fs` and `process` identities, and since
//! [ADR-0037](../../../../../docs/adr/0037-capability-specifications-and-canonical-authority-identities.md)
//! only `crate::resource` may create one. An integration test links the
//! library compiled without `cfg(test)`, so it cannot reach this module
//! either — which is why the policy fixture suites are unit tests.
//!
//! Every identity here is **synthetic**. It shows the policy semantics over
//! the shape M4 will produce; it shows nothing about deriving one from a real
//! resource.

use crate::capability::{Capability, ConstraintSet, Namespace, Scope, Verb, parse};
use crate::resource::synthetic;

use super::action::{CanonicalAction, Environment};
use super::context::{Origin, PathAnchors, PolicyContext, TaintLevel};

/// The verb named by `namespace.action`.
pub(crate) fn verb(text: &str) -> Verb {
    let Some((namespace, action)) = text.split_once('.') else {
        unreachable!("{text} is not a verb")
    };
    let Some(namespace) = Namespace::parse(namespace) else {
        unreachable!("{text} names no namespace")
    };
    let Some(verb) = Verb::parse_action(namespace, action) else {
        unreachable!("{text} names no verb")
    };
    verb
}

/// A capability over the universal scope, with no constraints.
pub(crate) fn universal_capability(verb_text: &str) -> Capability {
    let Ok(capability) = Capability::new(
        verb(verb_text),
        Scope::Universal,
        ConstraintSet::unconstrained(),
    ) else {
        unreachable!("the universal scope fits every verb")
    };
    capability
}

/// A capability over a synthetic canonical path.
pub(crate) fn path_capability(verb_text: &str, components: &[&str]) -> Capability {
    let Some(path) = synthetic::path(components) else {
        unreachable!("{components:?} are valid components")
    };
    let Ok(capability) = Capability::new(
        verb(verb_text),
        Scope::Path(path),
        ConstraintSet::unconstrained(),
    ) else {
        unreachable!("a path scope fits an fs verb")
    };
    capability
}

/// A capability over a synthetic executable identity.
pub(crate) fn executable_capability(verb_text: &str, components: &[&str], fill: u8) -> Capability {
    let Some(executable) = synthetic::executable(components, fill) else {
        unreachable!("{components:?} are valid components")
    };
    let Ok(capability) = Capability::new(
        verb(verb_text),
        Scope::Executable(executable),
        ConstraintSet::unconstrained(),
    ) else {
        unreachable!("an executable scope fits a process verb")
    };
    capability
}

/// A capability over a syntactic scope, parsed from capability text.
///
/// The ten families that are their own identity resolve without touching a
/// resource, so this goes through the real parser and the real bridge.
pub(crate) fn syntactic_capability(text: &str) -> Capability {
    let Ok(spec) = parse(text) else {
        unreachable!("{text} must parse")
    };
    let Ok(capability) = spec.resolve() else {
        unreachable!("{text} names a family that needs no resolution")
    };
    capability
}

/// An action in a sandbox.
pub(crate) fn sandboxed(capability: Capability) -> CanonicalAction {
    CanonicalAction::new(capability, Environment::Sandbox)
}

/// An action on the host.
pub(crate) fn on_host(capability: Capability) -> CanonicalAction {
    CanonicalAction::new(capability, Environment::Host)
}

/// The anchors the shipped profiles name, resolved to synthetic roots.
///
/// `${WORKSPACE}` is `/workspace`, `~` is `/home/agent`, and DireWolf's own
/// three are under `/opt/direwolf`. Invented, and standing in for what M3d
/// will pin from kernel-owned state.
pub(crate) fn anchors() -> PathAnchors {
    let build = |components: &[&str]| match synthetic::path(components) {
        Some(path) => path,
        None => unreachable!("{components:?} are valid components"),
    };
    PathAnchors {
        workspace: Some(build(&["workspace"])),
        direwolf_home: Some(build(&["opt", "direwolf", "state"])),
        direwolf_config: Some(build(&["opt", "direwolf", "config"])),
        direwolf_install: Some(build(&["opt", "direwolf", "bin"])),
        home: Some(build(&["home", "agent"])),
    }
}

/// An interactive, untainted run with the anchors resolved.
pub(crate) fn interactive() -> PolicyContext {
    PolicyContext::new(Origin::Interactive, TaintLevel::None).with_anchors(anchors())
}

/// A scheduled run: nobody is watching.
pub(crate) fn scheduled() -> PolicyContext {
    PolicyContext::new(Origin::Scheduled, TaintLevel::None).with_anchors(anchors())
}
