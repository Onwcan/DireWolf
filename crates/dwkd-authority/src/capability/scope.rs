//! Scopes: what a capability is *about*, and what "narrower" means for each.
//!
//! [`CAPABILITIES.md`] §2 calls the per-family containment relation "the heart
//! of the system". Two families make it more than a parsing exercise:
//!
//! > Canonical path — `b` is a path-prefix of `a` **after** canonicalisation to
//! > inode identity + NFC normalisation. **Never a string prefix on raw input.**
//! >
//! > Executable identity — `(resolved path, sha256)`.
//!
//! Neither identity can be derived without touching the filesystem, and doing
//! that safely — `openat2`, symlink refusal, TOCTOU-free re-checks, executable
//! hashing — is M4's entire first half. So this module splits the idea in two:
//!
//! * [`ScopeSpec`] is what a *declaration* says. `fs.read:/workspace` parses to
//!   a [`DeclaredPath`], which is text somebody sent.
//! * [`Scope`] is what authority is compared *with*. Its `fs` variant holds a
//!   [`CanonicalPath`], which this module cannot construct at all: the
//!   constructors live in [`crate::resource`] and are visible only there.
//!
//! There is no conversion from the first to the second for those two families,
//! in either direction, and containment is defined only on [`Scope`]. Passing
//! an unresolved path into an authority comparison is therefore not a mistake a
//! reviewer has to catch; it is a program that does not exist.
//!
//! The other ten families are their own identity: a host pattern means exactly
//! what it says, and comparing two of them needs nothing but the two of them.
//!
//! [`CAPABILITIES.md`]: ../../../../../docs/CAPABILITIES.md

use core::fmt;

use super::error::ScopeError;
// The two identities this module compares and never creates. Their
// constructors are private to `crate::resource` (ADR-0037): the lattice holds
// them, M4's canonicaliser makes them, and nothing in between can forge one.
use crate::resource::{CanonicalPath, ExecutableIdentity};

/// Which shape of scope a namespace takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScopeFamily {
    /// `fs` — a canonical path prefix. Needs M4 resolution.
    Path,
    /// `process` — `(resolved path, sha256)`. Needs M4 resolution.
    Executable,
    /// `network` — host pattern plus optional port.
    Endpoint,
    /// `secret` — a credential handle.
    CredentialHandle,
    /// `model` — `provider/model-pattern`.
    ProviderModel,
    /// `browser` — a domain pattern.
    Domain,
    /// `mcp` — a server id.
    ServerId,
    /// `agent` — an agent profile pattern.
    AgentProfile,
    /// `memory` — a memory scope name.
    MemoryScope,
    /// `scheduler` — an intent pattern.
    Intent,
    /// `artifact` — an artifact scope name.
    ArtifactScope,
    /// `channel` — `channel:destination`.
    ChannelTarget,
}

impl ScopeFamily {
    /// Whether this family's authority identity is a resource the authority
    /// must resolve before it can be compared. True for exactly two families,
    /// and M4 is what makes them resolvable.
    #[must_use]
    pub const fn needs_resolution(self) -> bool {
        matches!(self, Self::Path | Self::Executable)
    }
}

// ---------------------------------------------------------------------------
// Resolution-free families: their syntax *is* their identity.
// ---------------------------------------------------------------------------

/// A scope whose authority identity is its own syntax, so M3b can compare two
/// of them with nothing but the two of them.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SyntacticScope {
    /// `network` — a host pattern and a port.
    Endpoint(Endpoint),
    /// `secret` — a credential handle, matched exactly.
    CredentialHandle(Label),
    /// `model` — `provider/model-pattern`.
    ProviderModel(ProviderModel),
    /// `browser` — a domain pattern, with the same label rules as a host.
    Domain(HostPattern),
    /// `mcp` — a server id, matched exactly.
    ServerId(Label),
    /// `agent` — an agent profile pattern.
    AgentProfile(Pattern),
    /// `memory` — a memory scope name, matched exactly.
    MemoryScope(Label),
    /// `scheduler` — an intent pattern.
    Intent(Pattern),
    /// `artifact` — an artifact scope name, matched exactly.
    ArtifactScope(Label),
    /// `channel` — a channel and a destination, both matched exactly.
    ChannelTarget(ChannelTarget),
}

impl SyntacticScope {
    /// Which family this is.
    #[must_use]
    pub const fn family(&self) -> ScopeFamily {
        match self {
            Self::Endpoint(_) => ScopeFamily::Endpoint,
            Self::CredentialHandle(_) => ScopeFamily::CredentialHandle,
            Self::ProviderModel(_) => ScopeFamily::ProviderModel,
            Self::Domain(_) => ScopeFamily::Domain,
            Self::ServerId(_) => ScopeFamily::ServerId,
            Self::AgentProfile(_) => ScopeFamily::AgentProfile,
            Self::MemoryScope(_) => ScopeFamily::MemoryScope,
            Self::Intent(_) => ScopeFamily::Intent,
            Self::ArtifactScope(_) => ScopeFamily::ArtifactScope,
            Self::ChannelTarget(_) => ScopeFamily::ChannelTarget,
        }
    }

    /// Whether `self` covers `other`. Cross-family is always false: it cannot
    /// arise once verbs match, and answering "no" is the fail-closed answer to
    /// a question that should not have been asked.
    #[must_use]
    pub fn contains(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Endpoint(a), Self::Endpoint(b)) => a.contains(b),
            (Self::ProviderModel(a), Self::ProviderModel(b)) => a.contains(b),
            (Self::Domain(a), Self::Domain(b)) => a.contains(b),
            (Self::AgentProfile(a), Self::AgentProfile(b)) | (Self::Intent(a), Self::Intent(b)) => {
                a.contains(b)
            }
            // Exact-match families. `CAPABILITIES.md` defines no wildcard
            // relation for a credential handle, an MCP server id, a memory
            // scope or an artifact scope, so equality is the whole relation --
            // the fail-closed reading of an unspecified one.
            (Self::CredentialHandle(a), Self::CredentialHandle(b))
            | (Self::ServerId(a), Self::ServerId(b))
            | (Self::MemoryScope(a), Self::MemoryScope(b))
            | (Self::ArtifactScope(a), Self::ArtifactScope(b)) => a == b,
            (Self::ChannelTarget(a), Self::ChannelTarget(b)) => a == b,
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Declared scope: what a request said.
// ---------------------------------------------------------------------------

/// A scope exactly as declared, before any resource is resolved.
///
/// This is the parse result, and it is deliberately **not** comparable. There
/// is no `contains` here and no conversion into [`Scope`] for the two families
/// that need M4.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScopeSpec {
    /// `*` — every scope, for this verb only.
    Universal,
    /// A family whose syntax is its identity.
    Syntactic(SyntacticScope),
    /// `fs` — a path as written. **Not** an inode, not canonical, not
    /// comparable.
    DeclaredPath(DeclaredPath),
    /// `process` — an executable as written. **Not** an identity: the same text
    /// can name different binaries a second apart.
    DeclaredExecutable(DeclaredPath),
}

impl ScopeSpec {
    /// Which family this is.
    #[must_use]
    pub const fn family(&self) -> Option<ScopeFamily> {
        match self {
            // `*` belongs to whatever verb carries it.
            Self::Universal => None,
            Self::Syntactic(s) => Some(s.family()),
            Self::DeclaredPath(_) => Some(ScopeFamily::Path),
            Self::DeclaredExecutable(_) => Some(ScopeFamily::Executable),
        }
    }
}

// ---------------------------------------------------------------------------
// Authority scope: what comparisons are made with.
// ---------------------------------------------------------------------------

/// A scope in authority-comparable form.
///
/// Every variant is an identity the authority is willing to reason about. The
/// two that needed resolving hold resolved values, and the types that carry
/// them ([`CanonicalPath`], [`ExecutableIdentity`]) cannot be built from a path
/// string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    /// `*` — every scope, for this verb only.
    Universal,
    /// A family whose syntax is its identity.
    Syntactic(SyntacticScope),
    /// A canonical filesystem path, as M4 will produce it.
    Path(CanonicalPath),
    /// A resolved executable and its hash, as M4 will produce it.
    Executable(ExecutableIdentity),
}

impl Scope {
    /// Which family this is; `None` for the universal scope, which has no
    /// family of its own.
    #[must_use]
    pub const fn family(&self) -> Option<ScopeFamily> {
        match self {
            Self::Universal => None,
            Self::Syntactic(s) => Some(s.family()),
            Self::Path(_) => Some(ScopeFamily::Path),
            Self::Executable(_) => Some(ScopeFamily::Executable),
        }
    }

    /// Whether this scope is compatible with a verb's family. `*` is
    /// compatible with every verb; everything else must match.
    #[must_use]
    pub fn fits(&self, family: ScopeFamily) -> bool {
        self.family().is_none_or(|f| f == family)
    }

    /// Whether `self` covers `other`.
    ///
    /// `*` covers everything **for the same verb**; the verb check is
    /// [`super::Capability::contains`]'s, and a scope comparison never crosses
    /// verbs. Nothing but `*` covers `*`: a universal child under a specific
    /// parent is the escalation this whole file exists to refuse.
    #[must_use]
    pub fn contains(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Universal, _) => true,
            (Self::Syntactic(a), Self::Syntactic(b)) => a.contains(b),
            (Self::Path(a), Self::Path(b)) => a.contains(b),
            (Self::Executable(a), Self::Executable(b)) => a == b,
            // Everything else, and there are two kinds of it: a `*` child under
            // a specific parent, which is the escalation this refuses, and a
            // cross-family pair, which cannot arise once verbs match. Both
            // answer no.
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Paths.
// ---------------------------------------------------------------------------

/// A path as declared in a capability string.
///
/// Held verbatim. It is a claim about a resource, not a resource: the same text
/// can resolve to different inodes at different moments, through a symlink, a
/// bind mount, a race, or a Unicode spelling this build does not normalise.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeclaredPath(String);

impl DeclaredPath {
    /// The longest declared path the parser accepts. The DWKP capability field
    /// is already bounded at 512 characters; this bounds the component alone.
    pub const MAX_CHARS: usize = 384;

    /// Accept a declared path. Absolute, non-empty, no NUL, no `?` (which ends
    /// the scope), within bounds.
    ///
    /// This deliberately does **not** reject `..` or a symlink-looking path:
    /// rejecting them here would imply the result is safe, and it is not. The
    /// value is quarantined by its type instead.
    #[must_use]
    pub fn new(text: &str) -> Option<Self> {
        let ok = !text.is_empty()
            && text.starts_with('/')
            && text.chars().count() <= Self::MAX_CHARS
            && !text.contains('\0')
            && !text.contains('?');
        ok.then(|| Self(text.to_owned()))
    }

    /// The declared text, for display and for handing to M4's resolver.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Hosts and endpoints.
// ---------------------------------------------------------------------------

/// One DNS label.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostLabel(String);

impl HostLabel {
    /// The longest label, per RFC 1035.
    pub const MAX_BYTES: usize = 63;

    /// A label: lowercase alphanumerics and hyphens, not starting or ending
    /// with a hyphen.
    ///
    /// **Uppercase is refused rather than folded.** DNS is case-insensitive, so
    /// folding would be defensible — but a capability system with two spellings
    /// of one scope has two canonical forms, and refusing is the narrower of
    /// the two fail-closed readings. The cost is that `API.example.com` must be
    /// written `api.example.com`; the benefit is that no comparison anywhere
    /// depends on a normalisation step being remembered.
    #[must_use]
    pub fn new(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        let ok = !bytes.is_empty()
            && bytes.len() <= Self::MAX_BYTES
            && !text.starts_with('-')
            && !text.ends_with('-')
            && text
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        ok.then(|| Self(text.to_owned()))
    }

    /// The label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A host or domain pattern.
///
/// Wildcards are one leading `*` and nothing else — there is no glob engine
/// here, because a glob engine is a language, and a language in an authority
/// comparison is a place for surprises.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostPattern {
    /// `api.example.com` — covers itself only.
    Exact(Vec<HostLabel>),
    /// `*.example.com` — covers any host with at least one label in front of
    /// the suffix. **Not** the suffix itself: `*.example.com` does not cover
    /// `example.com`, because `CAPABILITIES.md` says it covers
    /// `api.example.com` and says nothing about the apex.
    Wildcard(Vec<HostLabel>),
}

impl HostPattern {
    /// The most labels a host may have.
    pub const MAX_LABELS: usize = 16;

    /// Parse a host or domain pattern.
    ///
    /// # Errors
    ///
    /// [`ScopeError::WildcardInTldPosition`] when a wildcard leaves fewer than
    /// two labels, so `*.com` is refused. [`ScopeError::MalformedHost`]
    /// otherwise — an empty label, an uppercase letter, an interior `*`, or a
    /// bracketed IPv6 literal, which has no defined containment relation and is
    /// therefore refused rather than guessed at.
    pub fn parse(text: &str) -> Result<Self, ScopeError> {
        let (wildcard, rest) = match text.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, text),
        };
        if rest.is_empty() || rest.contains('*') {
            return Err(ScopeError::MalformedHost);
        }
        let mut labels = Vec::new();
        for part in rest.split('.') {
            labels.push(HostLabel::new(part).ok_or(ScopeError::MalformedHost)?);
            if labels.len() > Self::MAX_LABELS {
                return Err(ScopeError::MalformedHost);
            }
        }
        if wildcard {
            // A wildcard must leave a registrable name behind it. `*.com`
            // would be authority over a top-level domain.
            if labels.len() < 2 {
                return Err(ScopeError::WildcardInTldPosition);
            }
            Ok(Self::Wildcard(labels))
        } else {
            Ok(Self::Exact(labels))
        }
    }

    /// Whether `self` covers `other`, respecting label boundaries.
    ///
    /// The bug this avoids is `ends_with("example.com")`, which would make
    /// `*.example.com` cover `evil-example.com`. Suffix comparison is over
    /// labels, never over characters.
    #[must_use]
    pub fn contains(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Exact(a), Self::Exact(b)) => a == b,
            (Self::Exact(_), Self::Wildcard(_)) => false,
            (Self::Wildcard(suffix), Self::Exact(host)) => {
                host.len() > suffix.len() && ends_with_labels(host, suffix)
            }
            // `*.example.com` covers `*.api.example.com`: every host the child
            // matches has `.example.com` behind it too. Equal suffixes are the
            // same pattern.
            (Self::Wildcard(suffix), Self::Wildcard(inner)) => {
                inner.len() >= suffix.len() && ends_with_labels(inner, suffix)
            }
        }
    }
}

fn ends_with_labels(host: &[HostLabel], suffix: &[HostLabel]) -> bool {
    let Some(start) = host.len().checked_sub(suffix.len()) else {
        return false;
    };
    host.iter().skip(start).eq(suffix.iter())
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (prefix, labels) = match self {
            Self::Exact(labels) => ("", labels),
            Self::Wildcard(labels) => ("*.", labels),
        };
        f.write_str(prefix)?;
        for (index, label) in labels.iter().enumerate() {
            if index > 0 {
                f.write_str(".")?;
            }
            f.write_str(label.as_str())?;
        }
        Ok(())
    }
}

/// A port, or the absence of one.
///
/// An absent port is *unconstrained*, and behaves exactly as a missing
/// constraint does: a parent without one covers a child with one, and a parent
/// with one does not cover a child without. Dropping the distinction would let
/// `network.tcp:host:22` widen to every port on that host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PortSpec {
    /// No port was named: any port.
    Any,
    /// Exactly this port.
    Port(u16),
}

impl PortSpec {
    /// Whether `self` covers `other`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        match (self, other) {
            (Self::Any, _) => true,
            (Self::Port(_), Self::Any) => false,
            (Self::Port(a), Self::Port(b)) => a == b,
        }
    }
}

/// A network endpoint: a host pattern and a port.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Endpoint {
    host: HostPattern,
    port: PortSpec,
}

impl Endpoint {
    /// Pair a host pattern with a port.
    #[must_use]
    pub const fn new(host: HostPattern, port: PortSpec) -> Self {
        Self { host, port }
    }

    /// The host pattern.
    #[must_use]
    pub const fn host(&self) -> &HostPattern {
        &self.host
    }

    /// The port.
    #[must_use]
    pub const fn port(&self) -> PortSpec {
        self.port
    }

    /// Parse `host` or `host:port`.
    ///
    /// # Errors
    ///
    /// [`ScopeError::MalformedPort`] for a port outside 1–65535, with a leading
    /// zero, or for anything with more than one colon — which is how an IPv6
    /// literal arrives, and IPv6 has no containment relation defined here.
    pub fn parse(text: &str) -> Result<Self, ScopeError> {
        match text.split_once(':') {
            None => Ok(Self::new(HostPattern::parse(text)?, PortSpec::Any)),
            Some((host, port)) => {
                if port.contains(':') {
                    return Err(ScopeError::MalformedPort);
                }
                let number = parse_u16_strict(port).ok_or(ScopeError::MalformedPort)?;
                if number == 0 {
                    return Err(ScopeError::MalformedPort);
                }
                Ok(Self::new(HostPattern::parse(host)?, PortSpec::Port(number)))
            }
        }
    }

    /// Whether `self` covers `other`.
    #[must_use]
    pub fn contains(&self, other: &Self) -> bool {
        self.host.contains(&other.host) && self.port.contains(other.port)
    }
}

/// Strict decimal `u16`: digits only, no sign, no leading zero, no overflow.
fn parse_u16_strict(text: &str) -> Option<u16> {
    if text.is_empty() || !text.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if text.len() > 1 && text.starts_with('0') {
        return None;
    }
    text.parse().ok()
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.port {
            PortSpec::Any => write!(f, "{}", self.host),
            PortSpec::Port(p) => write!(f, "{}:{p}", self.host),
        }
    }
}

// ---------------------------------------------------------------------------
// Names and patterns.
// ---------------------------------------------------------------------------

/// An opaque name matched exactly: a credential handle, an MCP server id, a
/// memory scope, an artifact scope, a channel or a destination.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Label(String);

impl Label {
    /// The longest name.
    pub const MAX_CHARS: usize = 128;

    /// A name: printable ASCII from a deliberately small set, no wildcard.
    ///
    /// `<` and `>` are permitted because `CAPABILITIES.md` writes a channel
    /// destination as `telegram:<chat_id>`. They are ordinary characters here;
    /// nothing substitutes anything.
    #[must_use]
    pub fn new(text: &str) -> Option<Self> {
        let ok = !text.is_empty()
            && text.chars().count() <= Self::MAX_CHARS
            && text.chars().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '<' | '>' | '@' | '+')
            });
        ok.then(|| Self(text.to_owned()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A name, optionally with a trailing `*`.
///
/// `CAPABILITIES.md`: "Glob containment, wildcards only at the trailing
/// position." So this is a literal or a prefix, and there is nothing else to
/// learn about it.
///
/// An empty prefix — a bare `*` — is representable, because `anthropic/*` needs
/// it: the wildcard is over the *model*, not over the scope. It is not a second
/// spelling of the universal scope, because a scope that is exactly `*` is
/// intercepted before a pattern is ever parsed. So `model.call:*` is universal,
/// `model.call:anthropic/*` is every model from one provider, and the two are
/// different capabilities with different spellings.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Pattern {
    /// `researcher` — covers itself only.
    Literal(String),
    /// `research*`, or `*` — covers any name starting with the prefix, which
    /// for the empty prefix is every name.
    Prefix(String),
}

impl Pattern {
    /// The longest pattern.
    pub const MAX_CHARS: usize = 128;

    /// Parse a literal or a trailing-wildcard pattern.
    ///
    /// # Errors
    ///
    /// [`ScopeError::MalformedPattern`] for an interior or leading `*`, an
    /// empty literal, or a character outside the accepted set.
    pub fn parse(text: &str) -> Result<Self, ScopeError> {
        let (body, wildcard) = match text.strip_suffix('*') {
            Some(body) => (body, true),
            None => (text, false),
        };
        // A literal must name something; a prefix may be empty, which is the
        // bare `*` that `provider/*` is written with.
        let ok = (wildcard || !body.is_empty())
            && body.chars().count() <= Self::MAX_CHARS
            && !body.contains('*')
            && body
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'));
        if !ok {
            return Err(ScopeError::MalformedPattern);
        }
        Ok(if wildcard {
            Self::Prefix(body.to_owned())
        } else {
            Self::Literal(body.to_owned())
        })
    }

    /// Whether `self` covers `other`.
    #[must_use]
    pub fn contains(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Literal(a), Self::Literal(b)) => a == b,
            (Self::Literal(_), Self::Prefix(_)) => false,
            (Self::Prefix(p), Self::Literal(l)) => l.starts_with(p),
            (Self::Prefix(p), Self::Prefix(q)) => q.starts_with(p),
        }
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Literal(body) => f.write_str(body),
            Self::Prefix(body) => write!(f, "{body}*"),
        }
    }
}

/// A provider and a model pattern: `anthropic/*`, `anthropic/claude-x`.
///
/// The provider is always exact. A wildcard provider would be `*` — the
/// universal scope — and a pattern like `*/claude-x` would grant authority over
/// a model name wherever it appears, which is not a distinction anybody wants
/// to make.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderModel {
    provider: Label,
    model: Pattern,
}

impl ProviderModel {
    /// Pair a provider with a model pattern.
    #[must_use]
    pub const fn new(provider: Label, model: Pattern) -> Self {
        Self { provider, model }
    }

    /// The provider.
    #[must_use]
    pub const fn provider(&self) -> &Label {
        &self.provider
    }

    /// The model pattern.
    #[must_use]
    pub const fn model(&self) -> &Pattern {
        &self.model
    }

    /// Parse `provider/model-pattern`.
    ///
    /// # Errors
    ///
    /// [`ScopeError::MalformedProviderModel`] when the separator is missing or
    /// repeated, or when the provider is not an exact name.
    pub fn parse(text: &str) -> Result<Self, ScopeError> {
        let (provider, model) = text
            .split_once('/')
            .ok_or(ScopeError::MalformedProviderModel)?;
        if model.contains('/') {
            return Err(ScopeError::MalformedProviderModel);
        }
        let provider = Label::new(provider).ok_or(ScopeError::MalformedProviderModel)?;
        if provider.as_str().contains('*') {
            return Err(ScopeError::MalformedProviderModel);
        }
        Ok(Self::new(provider, Pattern::parse(model)?))
    }

    /// Whether `self` covers `other`.
    #[must_use]
    pub fn contains(&self, other: &Self) -> bool {
        self.provider == other.provider && self.model.contains(&other.model)
    }
}

impl fmt::Display for ProviderModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.provider, self.model)
    }
}

/// A channel and a destination: `telegram:<chat_id>`.
///
/// Both exact. `CAPABILITIES.md` defines no wildcard over destinations, and a
/// wildcard destination would be authority to message anyone on a channel —
/// which, if it is ever wanted, should be an explicit decision rather than a
/// side effect of a parser being generous.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChannelTarget {
    channel: Label,
    destination: Label,
}

impl ChannelTarget {
    /// Pair a channel with a destination.
    #[must_use]
    pub const fn new(channel: Label, destination: Label) -> Self {
        Self {
            channel,
            destination,
        }
    }

    /// The channel.
    #[must_use]
    pub const fn channel(&self) -> &Label {
        &self.channel
    }

    /// The destination.
    #[must_use]
    pub const fn destination(&self) -> &Label {
        &self.destination
    }

    /// Parse `channel:destination`.
    ///
    /// # Errors
    ///
    /// [`ScopeError::MalformedChannelTarget`] when the separator is missing or
    /// either half is not a name.
    pub fn parse(text: &str) -> Result<Self, ScopeError> {
        let (channel, destination) = text
            .split_once(':')
            .ok_or(ScopeError::MalformedChannelTarget)?;
        let channel = Label::new(channel).ok_or(ScopeError::MalformedChannelTarget)?;
        let destination = Label::new(destination).ok_or(ScopeError::MalformedChannelTarget)?;
        Ok(Self::new(channel, destination))
    }
}

impl fmt::Display for ChannelTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.channel, self.destination)
    }
}

// ---------------------------------------------------------------------------
// Display for the two scope enums.
// ---------------------------------------------------------------------------

impl fmt::Display for SyntacticScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Endpoint(e) => write!(f, "{e}"),
            Self::CredentialHandle(l)
            | Self::ServerId(l)
            | Self::MemoryScope(l)
            | Self::ArtifactScope(l) => write!(f, "{l}"),
            Self::ProviderModel(p) => write!(f, "{p}"),
            Self::Domain(h) => write!(f, "{h}"),
            Self::AgentProfile(p) | Self::Intent(p) => write!(f, "{p}"),
            Self::ChannelTarget(c) => write!(f, "{c}"),
        }
    }
}

impl fmt::Display for ScopeSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Universal => f.write_str("*"),
            Self::Syntactic(s) => write!(f, "{s}"),
            Self::DeclaredPath(p) | Self::DeclaredExecutable(p) => f.write_str(p.as_str()),
        }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Universal => f.write_str("*"),
            Self::Syntactic(s) => write!(f, "{s}"),
            Self::Path(p) => write!(f, "{p}"),
            Self::Executable(e) => write!(f, "{e}"),
        }
    }
}
