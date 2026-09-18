//! The eight constraints, closed.
//!
//! [`CAPABILITIES.md`] §2 is unusually explicit about why this is a fixed set
//! rather than a map:
//!
//! > A closed enum with eight hand-written containment rules and eight named
//! > tests is strictly safer than a general typed lattice defended by property
//! > tests. An open `HashMap<Key, Value>` is precisely the shape exhaustive
//! > matching cannot protect, so the generality was the risk, not the
//! > mitigation.
//!
//! [`ConstraintSet`] is therefore a struct with eight optional fields, not a
//! collection. Every operation over it destructures all eight by name with no
//! `..` rest pattern, so adding a ninth is a compile error at every site that
//! has to decide what the ninth means — which is the whole benefit the language
//! choice was bought for.
//!
//! [`CAPABILITIES.md`]: ../../../../../docs/CAPABILITIES.md

use core::fmt;

use super::error::{ConstraintName, ValueError};
use super::verb::{Action, Namespace, Verb};

// ---------------------------------------------------------------------------
// Privacy class.
// ---------------------------------------------------------------------------

/// How far a model call's content may travel.
///
/// `CAPABILITIES.md`: stricter is narrower, `LOCAL_ONLY ⊑ VENDOR_OK ⊑ ANY`.
/// The order is a property of the values, not of their spellings — comparing
/// these as strings would put `ANY` before `LOCAL_ONLY` and invert the lattice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PrivacyClass {
    /// Never leaves the machine. Narrowest.
    LocalOnly,
    /// May reach a contracted vendor.
    VendorOk,
    /// No restriction. Widest.
    Any,
}

impl PrivacyClass {
    /// Every class, narrowest first.
    pub const ALL: &'static [Self] = &[Self::LocalOnly, Self::VendorOk, Self::Any];

    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalOnly => "LOCAL_ONLY",
            Self::VendorOk => "VENDOR_OK",
            Self::Any => "ANY",
        }
    }

    /// Parse exactly; no case folding.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.as_str() == text)
    }

    /// Whether `self` is no wider than `parent`. Derived from the declaration
    /// order above, which is the lattice order.
    #[must_use]
    pub fn narrower_or_equal(self, parent: Self) -> bool {
        self <= parent
    }
}

impl fmt::Display for PrivacyClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// HTTP methods.
// ---------------------------------------------------------------------------

/// An HTTP method.
///
/// **Closed.** `CAPABILITIES.md` writes `methods=GET,POST` and defines no
/// extension-method syntax, so an unrecognised method is refused rather than
/// carried as text. The limitation is real: a capability for `PROPFIND` cannot
/// be expressed today, and adding one is a variant here plus a note on the
/// document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Method {
    /// `GET`.
    Get,
    /// `HEAD`.
    Head,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
    /// `PATCH`.
    Patch,
    /// `DELETE`.
    Delete,
    /// `OPTIONS`.
    Options,
}

impl Method {
    /// Every method, in canonical order. Canonical output follows this order,
    /// so `POST,GET` and `GET,POST` render identically.
    pub const ALL: &'static [Self] = &[
        Self::Get,
        Self::Head,
        Self::Post,
        Self::Put,
        Self::Patch,
        Self::Delete,
        Self::Options,
    ];

    /// The wire spelling. Uppercase, and the only accepted spelling: `get` is
    /// refused rather than folded, so one method has one written form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Options => "OPTIONS",
        }
    }

    /// Parse exactly.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|m| m.as_str() == text)
    }

    /// This method's bit in a [`MethodSet`]. Explicit constants rather than
    /// shifts: the values are part of nothing observable, and a typo in a shift
    /// is harder to see than a typo in a literal.
    const fn bit(self) -> u8 {
        match self {
            Self::Get => 0b0000_0001,
            Self::Head => 0b0000_0010,
            Self::Post => 0b0000_0100,
            Self::Put => 0b0000_1000,
            Self::Patch => 0b0001_0000,
            Self::Delete => 0b0010_0000,
            Self::Options => 0b0100_0000,
        }
    }
}

/// A non-empty set of HTTP methods.
///
/// Stored as a bitset, so membership has one representation and canonical
/// output has one order however the input was written. An empty set is not
/// representable: `methods=` with nothing after it would read as "no methods
/// permitted", which is a denial dressed as a grant, and refusing it is the
/// fail-closed reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MethodSet(u8);

impl MethodSet {
    /// A set from methods. `None` if empty.
    #[must_use]
    pub fn new(methods: &[Method]) -> Option<Self> {
        let bits = methods.iter().fold(0u8, |acc, m| acc | m.bit());
        (bits != 0).then_some(Self(bits))
    }

    /// Whether a method is in the set.
    #[must_use]
    pub const fn has(self, method: Method) -> bool {
        self.0 & method.bit() != 0
    }

    /// The methods, in canonical order.
    #[must_use]
    pub fn methods(self) -> Vec<Method> {
        Method::ALL
            .iter()
            .copied()
            .filter(|m| self.has(*m))
            .collect()
    }

    /// Whether `self` is a subset of `parent` — the narrower relation for a
    /// set constraint.
    #[must_use]
    pub const fn narrower_or_equal(self, parent: Self) -> bool {
        self.0 & !parent.0 == 0
    }

    /// Parse `GET,POST`.
    ///
    /// # Errors
    ///
    /// [`ValueError::EmptySetMember`] for `GET,,POST` or a trailing comma,
    /// [`ValueError::DuplicateSetMember`] for `GET,GET` — a duplicate is a
    /// second spelling of one set, and two spellings of one value is what
    /// canonical form exists to prevent — and [`ValueError::UnknownMethod`]
    /// otherwise.
    pub fn parse(text: &str) -> Result<Self, ValueError> {
        let mut bits = 0u8;
        for part in text.split(',') {
            if part.is_empty() {
                return Err(ValueError::EmptySetMember);
            }
            let method = Method::parse(part).ok_or(ValueError::UnknownMethod)?;
            if bits & method.bit() != 0 {
                return Err(ValueError::DuplicateSetMember);
            }
            bits |= method.bit();
        }
        // `split(',')` always yields at least one part, and an empty part
        // returns above, so at least one bit is set by the time we get here.
        Ok(Self(bits))
    }
}

impl fmt::Display for MethodSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for method in Method::ALL.iter().copied().filter(|m| self.has(*m)) {
            if !first {
                f.write_str(",")?;
            }
            f.write_str(method.as_str())?;
            first = false;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// argv allowlist.
// ---------------------------------------------------------------------------

/// One entry of an `argv_allowlist`.
///
/// A capability-level token and nothing more. This is **not** a command parser:
/// there is no quoting, no splitting, no shell, and no interpretation of a
/// token as a path or a glob. How typed process arguments bind to these tokens
/// is M4's and M5's question, and answering it here would mean inventing a
/// command model before there is a command.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArgvToken(String);

impl ArgvToken {
    /// The longest token.
    pub const MAX_CHARS: usize = 64;

    /// A token: alphanumerics, `_`, `.` and `-`.
    ///
    /// `*`, `/` and `=` are refused. `*` would suggest a glob this does not
    /// implement; the other two would suggest a path or an assignment being
    /// understood. Narrow and documented beats broad and ambiguous.
    #[must_use]
    pub fn new(text: &str) -> Option<Self> {
        let ok = !text.is_empty()
            && text.chars().count() <= Self::MAX_CHARS
            && text
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
        ok.then(|| Self(text.to_owned()))
    }

    /// The token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A non-empty, sorted, duplicate-free set of argv tokens.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArgvAllowlist(Vec<ArgvToken>);

impl ArgvAllowlist {
    /// The most tokens one allowlist may carry.
    pub const MAX_TOKENS: usize = 64;

    /// A set from tokens, sorted and checked for duplicates. `None` if empty,
    /// over the bound, or containing a repeat.
    #[must_use]
    pub fn new(mut tokens: Vec<ArgvToken>) -> Option<Self> {
        if tokens.is_empty() || tokens.len() > Self::MAX_TOKENS {
            return None;
        }
        tokens.sort();
        let before = tokens.len();
        tokens.dedup();
        (tokens.len() == before).then_some(Self(tokens))
    }

    /// The tokens, in canonical order.
    #[must_use]
    pub fn tokens(&self) -> &[ArgvToken] {
        &self.0
    }

    /// Whether `self` is a subset of `parent`.
    #[must_use]
    pub fn narrower_or_equal(&self, parent: &Self) -> bool {
        self.0.iter().all(|t| parent.0.contains(t))
    }

    /// Parse `status,diff,log`.
    ///
    /// # Errors
    ///
    /// [`ValueError::EmptySetMember`], [`ValueError::DuplicateSetMember`] or
    /// [`ValueError::MalformedArgvToken`].
    pub fn parse(text: &str) -> Result<Self, ValueError> {
        let mut tokens = Vec::new();
        for part in text.split(',') {
            if part.is_empty() {
                return Err(ValueError::EmptySetMember);
            }
            let token = ArgvToken::new(part).ok_or(ValueError::MalformedArgvToken)?;
            if tokens.contains(&token) {
                return Err(ValueError::DuplicateSetMember);
            }
            tokens.push(token);
        }
        Self::new(tokens).ok_or(ValueError::MalformedArgvToken)
    }
}

impl fmt::Display for ArgvAllowlist {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, token) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str(",")?;
            }
            f.write_str(token.as_str())?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// no_symlink_targets.
// ---------------------------------------------------------------------------

/// The `no_symlink_targets` flag.
///
/// A unit type rather than a `bool`, because `CAPABILITIES.md` defines exactly
/// one direction — "`true` narrower than absent" — and says nothing about
/// `false`. A `false` would mean the same as absent, giving one meaning two
/// spellings and canonical form two answers; refusing it is the narrower
/// reading and the one that keeps the missing-constraint rules total.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NoSymlinkTargets;

impl NoSymlinkTargets {
    /// Parse. Only `true` is a value.
    ///
    /// # Errors
    ///
    /// [`ValueError::MalformedBoolean`] for `false`, `1`, `TRUE` or anything
    /// else.
    pub fn parse(text: &str) -> Result<Self, ValueError> {
        if text == "true" {
            Ok(Self)
        } else {
            Err(ValueError::MalformedBoolean)
        }
    }
}

impl fmt::Display for NoSymlinkTargets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("true")
    }
}

// ---------------------------------------------------------------------------
// The set.
// ---------------------------------------------------------------------------

/// The eight constraints a capability may carry, each present or absent.
///
/// A struct, not a map. Absence means *unconstrained*, and the two rules that
/// follow from that are the security core of the whole module — see
/// [`ConstraintSet::narrower_or_equal`].
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConstraintSet {
    /// `max_bytes` — fs verbs. Narrower is smaller.
    pub max_bytes: Option<u64>,
    /// `no_symlink_targets` — fs verbs. Present is narrower than absent.
    pub no_symlink_targets: Option<NoSymlinkTargets>,
    /// `methods` — network verbs. Narrower is a subset.
    pub methods: Option<MethodSet>,
    /// `max_requests` — network verbs. Narrower is smaller.
    pub max_requests: Option<u32>,
    /// `argv_allowlist` — `process.exec`. Narrower is a subset.
    pub argv_allowlist: Option<ArgvAllowlist>,
    /// `privacy_class` — `model.call`. Narrower is stricter.
    pub privacy_class: Option<PrivacyClass>,
    /// `depth` — `agent.spawn`. Narrower is smaller.
    pub depth: Option<u16>,
    /// `fanout` — `agent.spawn`. Narrower is smaller.
    pub fanout: Option<u16>,
}

impl ConstraintSet {
    /// No constraints: unconstrained in every dimension.
    #[must_use]
    pub fn unconstrained() -> Self {
        Self::default()
    }

    /// Whether any constraint is present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Whether `self` is no wider than `parent`, in every dimension.
    ///
    /// The two rules `CAPABILITIES.md` §3 singles out as "easy to get wrong,
    /// and therefore property-tested", both of which fall out of one `match`:
    ///
    /// * **A missing constraint on the parent is unconstrained**, so a child
    ///   may add one. `(None, Some)` is narrower — legal.
    /// * **A missing constraint on the child is unconstrained**, and therefore
    ///   *wider*. `(Some, None)` is illegal. Getting this one backwards is a
    ///   silent privilege escalation, which is why it is spelled out per
    ///   constraint below rather than folded into a helper that could be
    ///   written wrong once and be wrong eight times.
    #[must_use]
    pub fn narrower_or_equal(&self, parent: &Self) -> bool {
        // Destructured with no `..`: a ninth constraint stops the build here,
        // which is the point of a closed set.
        let Self {
            max_bytes,
            no_symlink_targets,
            methods,
            max_requests,
            argv_allowlist,
            privacy_class,
            depth,
            fanout,
        } = self;
        let Self {
            max_bytes: p_max_bytes,
            no_symlink_targets: p_no_symlink_targets,
            methods: p_methods,
            max_requests: p_max_requests,
            argv_allowlist: p_argv_allowlist,
            privacy_class: p_privacy_class,
            depth: p_depth,
            fanout: p_fanout,
        } = parent;

        narrower(max_bytes.as_ref(), p_max_bytes.as_ref(), |c, p| c <= p)
            // Present-or-absent: the child must have it if the parent does,
            // and the only value is `true`, so equality is the relation.
            && narrower(
                no_symlink_targets.as_ref(),
                p_no_symlink_targets.as_ref(),
                |c, p| c == p,
            )
            && narrower(methods.as_ref(), p_methods.as_ref(), |c, p| {
                c.narrower_or_equal(*p)
            })
            && narrower(max_requests.as_ref(), p_max_requests.as_ref(), |c, p| c <= p)
            && narrower(
                argv_allowlist.as_ref(),
                p_argv_allowlist.as_ref(),
                ArgvAllowlist::narrower_or_equal,
            )
            && narrower(privacy_class.as_ref(), p_privacy_class.as_ref(), |c, p| {
                c.narrower_or_equal(*p)
            })
            && narrower(depth.as_ref(), p_depth.as_ref(), |c, p| c <= p)
            && narrower(fanout.as_ref(), p_fanout.as_ref(), |c, p| c <= p)
    }

    /// Which constraints are present, in canonical order.
    #[must_use]
    pub fn present(&self) -> Vec<ConstraintName> {
        ConstraintName::ALL
            .iter()
            .copied()
            .filter(|name| self.has(*name))
            .collect()
    }

    /// Whether a named constraint is present.
    #[must_use]
    pub fn has(&self, name: ConstraintName) -> bool {
        match name {
            ConstraintName::MaxBytes => self.max_bytes.is_some(),
            ConstraintName::NoSymlinkTargets => self.no_symlink_targets.is_some(),
            ConstraintName::Methods => self.methods.is_some(),
            ConstraintName::MaxRequests => self.max_requests.is_some(),
            ConstraintName::ArgvAllowlist => self.argv_allowlist.is_some(),
            ConstraintName::PrivacyClass => self.privacy_class.is_some(),
            ConstraintName::Depth => self.depth.is_some(),
            ConstraintName::Fanout => self.fanout.is_some(),
        }
    }

    /// Overlay `other`'s present constraints onto `self`, leaving the rest.
    ///
    /// Used by attenuation to build a candidate; it is not itself a safety
    /// check, and the candidate is verified against its parent afterwards.
    #[must_use]
    pub fn overlay(&self, other: &Self) -> Self {
        Self {
            max_bytes: other.max_bytes.or(self.max_bytes),
            no_symlink_targets: other.no_symlink_targets.or(self.no_symlink_targets),
            methods: other.methods.or(self.methods),
            max_requests: other.max_requests.or(self.max_requests),
            argv_allowlist: other
                .argv_allowlist
                .clone()
                .or_else(|| self.argv_allowlist.clone()),
            privacy_class: other.privacy_class.or(self.privacy_class),
            depth: other.depth.or(self.depth),
            fanout: other.fanout.or(self.fanout),
        }
    }
}

/// One dimension of [`ConstraintSet::narrower_or_equal`].
///
/// `(None, None)` unconstrained both sides — fine. `(Some, None)` the child
/// narrows where the parent did not — fine. `(None, Some)` the child is
/// unconstrained where the parent was not — **wider, and refused**.
fn narrower<T>(child: Option<&T>, parent: Option<&T>, ok: impl Fn(&T, &T) -> bool) -> bool {
    match (child, parent) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(c), Some(p)) => ok(c, p),
    }
}

impl fmt::Display for ConstraintSet {
    /// Canonical form: the eight in declaration order, `&`-joined, omitting
    /// what is absent. Order is fixed by the type, so two equal sets written
    /// differently render identically.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let mut sep = |f: &mut fmt::Formatter<'_>| -> fmt::Result {
            if !first {
                f.write_str("&")?;
            }
            first = false;
            Ok(())
        };
        if let Some(v) = self.max_bytes {
            sep(f)?;
            write!(f, "max_bytes={v}")?;
        }
        if let Some(v) = self.no_symlink_targets {
            sep(f)?;
            write!(f, "no_symlink_targets={v}")?;
        }
        if let Some(v) = self.methods {
            sep(f)?;
            write!(f, "methods={v}")?;
        }
        if let Some(v) = self.max_requests {
            sep(f)?;
            write!(f, "max_requests={v}")?;
        }
        if let Some(v) = &self.argv_allowlist {
            sep(f)?;
            write!(f, "argv_allowlist={v}")?;
        }
        if let Some(v) = self.privacy_class {
            sep(f)?;
            write!(f, "privacy_class={v}")?;
        }
        if let Some(v) = self.depth {
            sep(f)?;
            write!(f, "depth={v}")?;
        }
        if let Some(v) = self.fanout {
            sep(f)?;
            write!(f, "fanout={v}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Applicability.
// ---------------------------------------------------------------------------

impl ConstraintName {
    /// Whether this constraint may attach to this verb, per `CAPABILITIES.md`
    /// §2's "Applies to" column.
    ///
    /// An otherwise-valid constraint on an unrelated verb is refused rather
    /// than ignored. Ignoring it would let a request carry a limit that looks
    /// like a narrowing and is not — `model.call:*?max_bytes=10` would read as
    /// constrained and be unconstrained.
    #[must_use]
    pub fn applies_to(self, verb: Verb) -> bool {
        match self {
            // "fs verbs" — every action in the namespace.
            Self::MaxBytes | Self::NoSymlinkTargets => verb.namespace() == Namespace::Fs,
            // "network verbs" — every action in the namespace.
            Self::Methods | Self::MaxRequests => verb.namespace() == Namespace::Network,
            // Named verbs, not namespaces: `process.inspect` takes no argv
            // allowlist, because it runs nothing.
            Self::ArgvAllowlist => {
                verb.namespace() == Namespace::Process && verb.action() == Action::Exec
            }
            Self::PrivacyClass => {
                verb.namespace() == Namespace::Model && verb.action() == Action::Call
            }
            Self::Depth | Self::Fanout => {
                verb.namespace() == Namespace::Agent && verb.action() == Action::Spawn
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Strict integers.
// ---------------------------------------------------------------------------

/// Decimal `u64`: digits only, no sign, no leading zero, no overflow.
///
/// Rejecting a leading zero keeps one number to one spelling, which canonical
/// form needs. Rejecting overflow rather than saturating keeps a limit of
/// `999999999999999999999999999` from quietly becoming `u64::MAX` — a truncated
/// limit is a wider limit.
pub(crate) fn parse_u64_strict(text: &str) -> Result<u64, ValueError> {
    if text.is_empty() || !text.chars().all(|c| c.is_ascii_digit()) {
        return Err(ValueError::MalformedInteger);
    }
    if text.len() > 1 && text.starts_with('0') {
        return Err(ValueError::LeadingZero);
    }
    text.parse().map_err(|_| ValueError::IntegerOverflow)
}

/// As [`parse_u64_strict`], narrowed to `u32` with a checked conversion.
pub(crate) fn parse_u32_strict(text: &str) -> Result<u32, ValueError> {
    u32::try_from(parse_u64_strict(text)?).map_err(|_| ValueError::IntegerOverflow)
}

/// As [`parse_u64_strict`], narrowed to `u16` with a checked conversion.
pub(crate) fn parse_u16_strict(text: &str) -> Result<u16, ValueError> {
    u16::try_from(parse_u64_strict(text)?).map_err(|_| ValueError::IntegerOverflow)
}
