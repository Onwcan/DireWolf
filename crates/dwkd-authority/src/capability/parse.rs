//! The one production parser for capability text.
//!
//! ```text
//! capability := verb ":" scope [ "?" constraints ]
//! verb       := namespace "." action
//! scope      := "*" | typed-scope
//! constraints:= name "=" value ( "&" name "=" value )*
//! ```
//!
//! Strict, whole-input, and deterministic. Every rejection is a named variant
//! of [`CapabilityError`]; nothing is trimmed, nothing is case-folded, nothing
//! is guessed, and trailing input is never ignored — a parser that accepts a
//! prefix is a parser two implementations will disagree about.
//!
//! What comes out is a [`CapabilitySpec`]: an *interpreted request*. It is not
//! a grant. Granting needs the agent profile, the active skills, the parent
//! run's authority and the profile ceiling, and M3b has none of them.

use super::constraint::{
    ArgvAllowlist, ConstraintSet, MethodSet, NoSymlinkTargets, PrivacyClass, parse_u16_strict,
    parse_u32_strict, parse_u64_strict,
};
use super::error::{CapabilityError, ConstraintName, ScopeError, ValueError};
use super::scope::{
    ChannelTarget, DeclaredPath, Endpoint, HostPattern, Label, Pattern, ProviderModel, ScopeFamily,
    ScopeSpec, SyntacticScope,
};
use super::spec::CapabilitySpec;
use super::verb::{Namespace, Verb};

/// The longest capability text accepted.
///
/// [ADR-0036] bounds the DWKP field at 512 characters. Matching it here means
/// a capability that crossed the wire cannot be rejected for length *after*
/// being accepted by the protocol, and a capability from a future policy file
/// is held to the same bound.
///
/// [ADR-0036]: ../../../../../docs/adr/0036-m3-authority-operations-and-the-capability-wire-form.md
pub const MAX_CAPABILITY_CHARS: usize = 512;

/// Parse capability text into an interpreted specification.
///
/// # Errors
///
/// A named [`CapabilityError`] for every rejection. See the module
/// documentation for the grammar.
pub fn parse(text: &str) -> Result<CapabilitySpec, CapabilityError> {
    if text.is_empty() {
        return Err(CapabilityError::Empty);
    }
    if text.chars().count() > MAX_CAPABILITY_CHARS {
        return Err(CapabilityError::TooLong);
    }

    // Split the constraints off first: the scope may contain `:` and `.`, but
    // never `?`, which is what makes a single split unambiguous.
    let (head, constraint_text) = match text.split_once('?') {
        None => (text, None),
        Some((head, rest)) => {
            if rest.contains('?') {
                return Err(CapabilityError::RepeatedConstraintSeparator);
            }
            if rest.is_empty() {
                return Err(CapabilityError::EmptyConstraints);
            }
            (head, Some(rest))
        }
    };

    // The *first* colon ends the verb. A scope may carry more of them --
    // `network.https:host:443`, `channel.send:telegram:<chat_id>` -- and both
    // are handled by the family that owns them.
    let (verb_text, scope_text) = head.split_once(':').ok_or(CapabilityError::MissingScope)?;
    let verb = parse_verb(verb_text)?;
    let scope = parse_scope(verb, scope_text)?;
    let constraints = match constraint_text {
        None => ConstraintSet::unconstrained(),
        Some(text) => parse_constraints(verb, text)?,
    };

    Ok(CapabilitySpec::new(verb, scope, constraints))
}

fn parse_verb(text: &str) -> Result<Verb, CapabilityError> {
    let (namespace_text, action_text) =
        text.split_once('.').ok_or(CapabilityError::MissingAction)?;
    if namespace_text.is_empty() {
        return Err(CapabilityError::EmptyNamespace);
    }
    if action_text.is_empty() {
        return Err(CapabilityError::EmptyAction);
    }
    // An action may not itself contain a `.`: `fs.read.extra` names nothing.
    if action_text.contains('.') {
        return Err(CapabilityError::UnknownAction {
            namespace: Namespace::parse(namespace_text).ok_or(CapabilityError::UnknownNamespace)?,
        });
    }
    let namespace = Namespace::parse(namespace_text).ok_or(CapabilityError::UnknownNamespace)?;
    Verb::parse_action(namespace, action_text).ok_or(CapabilityError::UnknownAction { namespace })
}

fn parse_scope(verb: Verb, text: &str) -> Result<ScopeSpec, CapabilityError> {
    if text.is_empty() {
        return Err(CapabilityError::EmptyScope);
    }
    if text == "*" {
        return Ok(ScopeSpec::Universal);
    }
    let syntactic = |s: SyntacticScope| Ok(ScopeSpec::Syntactic(s));
    let name = |text: &str| {
        Label::new(text).ok_or(CapabilityError::InvalidScope(ScopeError::MalformedName))
    };
    match verb.scope_family() {
        // The two families whose identity is a resource, not a spelling. The
        // declared text is kept verbatim and quarantined by its type.
        ScopeFamily::Path => Ok(ScopeSpec::DeclaredPath(
            DeclaredPath::new(text)
                .ok_or(CapabilityError::InvalidScope(ScopeError::MalformedPath))?,
        )),
        ScopeFamily::Executable => Ok(ScopeSpec::DeclaredExecutable(
            DeclaredPath::new(text)
                .ok_or(CapabilityError::InvalidScope(ScopeError::MalformedPath))?,
        )),
        ScopeFamily::Endpoint => syntactic(SyntacticScope::Endpoint(Endpoint::parse(text)?)),
        ScopeFamily::CredentialHandle => syntactic(SyntacticScope::CredentialHandle(name(text)?)),
        ScopeFamily::ProviderModel => {
            syntactic(SyntacticScope::ProviderModel(ProviderModel::parse(text)?))
        }
        ScopeFamily::Domain => syntactic(SyntacticScope::Domain(HostPattern::parse(text)?)),
        ScopeFamily::ServerId => syntactic(SyntacticScope::ServerId(name(text)?)),
        ScopeFamily::AgentProfile => syntactic(SyntacticScope::AgentProfile(Pattern::parse(text)?)),
        ScopeFamily::MemoryScope => syntactic(SyntacticScope::MemoryScope(name(text)?)),
        ScopeFamily::Intent => syntactic(SyntacticScope::Intent(Pattern::parse(text)?)),
        ScopeFamily::ArtifactScope => syntactic(SyntacticScope::ArtifactScope(name(text)?)),
        ScopeFamily::ChannelTarget => {
            syntactic(SyntacticScope::ChannelTarget(ChannelTarget::parse(text)?))
        }
    }
}

fn parse_constraints(verb: Verb, text: &str) -> Result<ConstraintSet, CapabilityError> {
    let mut set = ConstraintSet::unconstrained();
    let mut seen: Vec<ConstraintName> = Vec::new();

    for item in text.split('&') {
        if item.is_empty() {
            return Err(CapabilityError::MalformedConstraint);
        }
        let (name_text, value) = item
            .split_once('=')
            .ok_or(CapabilityError::MalformedConstraint)?;
        if name_text.is_empty() {
            return Err(CapabilityError::EmptyConstraintName);
        }
        if value.is_empty() {
            return Err(CapabilityError::EmptyConstraintValue);
        }
        let name = ConstraintName::parse(name_text).ok_or(CapabilityError::UnknownConstraint)?;
        if seen.contains(&name) {
            return Err(CapabilityError::DuplicateConstraint { name });
        }
        seen.push(name);
        if !name.applies_to(verb) {
            return Err(CapabilityError::ConstraintNotApplicable { name, verb });
        }
        apply(&mut set, name, value)
            .map_err(|reason| CapabilityError::InvalidConstraintValue { name, reason })?;
    }
    Ok(set)
}

fn apply(set: &mut ConstraintSet, name: ConstraintName, value: &str) -> Result<(), ValueError> {
    match name {
        ConstraintName::MaxBytes => set.max_bytes = Some(parse_u64_strict(value)?),
        ConstraintName::NoSymlinkTargets => {
            set.no_symlink_targets = Some(NoSymlinkTargets::parse(value)?);
        }
        ConstraintName::Methods => set.methods = Some(MethodSet::parse(value)?),
        ConstraintName::MaxRequests => set.max_requests = Some(parse_u32_strict(value)?),
        ConstraintName::ArgvAllowlist => set.argv_allowlist = Some(ArgvAllowlist::parse(value)?),
        ConstraintName::PrivacyClass => {
            set.privacy_class =
                Some(PrivacyClass::parse(value).ok_or(ValueError::UnknownPrivacyClass)?);
        }
        ConstraintName::Depth => set.depth = Some(parse_u16_strict(value)?),
        ConstraintName::Fanout => set.fanout = Some(parse_u16_strict(value)?),
    }
    Ok(())
}
