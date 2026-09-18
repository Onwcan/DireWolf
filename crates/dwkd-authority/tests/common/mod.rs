//! Builders shared by the capability tests.
//!
//! Assembling a `Capability` by hand is six lines, and a test that spends six
//! lines on setup hides what it is asserting.
//!
//! **There is no canonical-path or executable-identity builder here**, and its
//! absence is the point. Since ADR-0037's closeout those identities can only be
//! constructed inside `crate::resource`, and an integration test links the
//! library compiled without `cfg(test)` — so this file *cannot* make one, which
//! is exactly the guarantee production code gets. The `fs` and `process` half
//! of the lattice is tested in `src/capability/resource_lattice.rs`, where the
//! synthetic constructors are reachable and test-only.

#![allow(dead_code)]

// Acknowledge the dev-dependency in every test binary that pulls this in, so
// `unused_crate_dependencies` stays meaningful for the ones that do use it.
use proptest as _;

use dwkd_authority::capability::{
    Action, Capability, ChannelTarget, ConstraintSet, Endpoint, HostPattern, Label, Namespace,
    Pattern, PortSpec, ProviderModel, Scope, SyntacticScope, Verb,
};

/// A verb, or panic — test code, where an unbuildable verb is a typo.
pub(crate) fn verb(namespace: Namespace, action: Action) -> Verb {
    Verb::new(namespace, action).expect("verb pair exists")
}

/// `fs.read`, the verb most of the path tests use.
pub(crate) fn fs_read() -> Verb {
    verb(Namespace::Fs, Action::Read)
}

/// `fs.write`.
pub(crate) fn fs_write() -> Verb {
    verb(Namespace::Fs, Action::Write)
}

/// `network.https`.
pub(crate) fn net_https() -> Verb {
    verb(Namespace::Network, Action::Https)
}

/// `process.exec`.
pub(crate) fn proc_exec() -> Verb {
    verb(Namespace::Process, Action::Exec)
}

/// `model.call`.
pub(crate) fn model_call() -> Verb {
    verb(Namespace::Model, Action::Call)
}

/// `agent.spawn`.
pub(crate) fn agent_spawn() -> Verb {
    verb(Namespace::Agent, Action::Spawn)
}

/// A host-pattern endpoint with no port.
pub(crate) fn host(pattern: &str) -> Scope {
    Scope::Syntactic(SyntacticScope::Endpoint(Endpoint::new(
        HostPattern::parse(pattern).expect("valid host pattern"),
        PortSpec::Any,
    )))
}

/// A host-pattern endpoint on a port.
pub(crate) fn host_port(pattern: &str, port: u16) -> Scope {
    Scope::Syntactic(SyntacticScope::Endpoint(Endpoint::new(
        HostPattern::parse(pattern).expect("valid host pattern"),
        PortSpec::Port(port),
    )))
}

/// A `browser` domain scope.
pub(crate) fn domain(pattern: &str) -> Scope {
    Scope::Syntactic(SyntacticScope::Domain(
        HostPattern::parse(pattern).expect("valid host pattern"),
    ))
}

/// A `model.call` scope.
pub(crate) fn provider_model(text: &str) -> Scope {
    Scope::Syntactic(SyntacticScope::ProviderModel(
        ProviderModel::parse(text).expect("valid provider/model"),
    ))
}

/// An `agent` profile pattern scope.
pub(crate) fn agent_pattern(text: &str) -> Scope {
    Scope::Syntactic(SyntacticScope::AgentProfile(
        Pattern::parse(text).expect("valid pattern"),
    ))
}

/// A `secret.use` handle scope.
pub(crate) fn handle(text: &str) -> Scope {
    Scope::Syntactic(SyntacticScope::CredentialHandle(
        Label::new(text).expect("valid label"),
    ))
}

/// A `channel.send` target scope.
pub(crate) fn channel(text: &str) -> Scope {
    Scope::Syntactic(SyntacticScope::ChannelTarget(
        ChannelTarget::parse(text).expect("valid channel target"),
    ))
}

/// Assemble a capability, or panic — a mismatched verb and scope in a test is a
/// typo, and the production error for it has its own named test.
pub(crate) fn cap(verb: Verb, scope: Scope, constraints: ConstraintSet) -> Capability {
    Capability::new(verb, scope, constraints).expect("well-formed capability")
}

/// Assemble an unconstrained capability.
pub(crate) fn plain(verb: Verb, scope: Scope) -> Capability {
    cap(verb, scope, ConstraintSet::unconstrained())
}

/// Parse capability text and resolve it, for the ten families that need no
/// resolver. Panics for `fs` and `process`, which is correct: those have no
/// authority form in M3b and a test that wanted one is asking for the thing
/// this milestone refuses to fake.
pub(crate) fn resolved(text: &str) -> Capability {
    dwkd_authority::capability::parse(text)
        .expect("valid capability text")
        .resolve()
        .expect("a family that needs no resolver")
}

/// Constraints, built by mutating the default. Reads better than eight fields
/// of `None` at every call site.
pub(crate) fn constraints(build: impl FnOnce(&mut ConstraintSet)) -> ConstraintSet {
    let mut set = ConstraintSet::unconstrained();
    build(&mut set);
    set
}
