//! [`PolicyContext`] — the facts about the *run* that policy decides on.
//!
//! # Everything here is kernel-owned
//!
//! [ADR-0028] is the load-bearing document, and its principle is one sentence:
//!
//! > Anything the kernel reads from the runtime and then decides on is
//! > authority the runtime holds.
//!
//! `taint_level`, `origin`, `privacy_class` and workspace sensitivity were all
//! runtime-writable once, and a compromised runtime could set `taint = NONE`
//! after reading a hostile page or `origin = interactive` for an unattended
//! job. So they live in `kernel.db` and are derived kernel-side.
//!
//! **This module has no `kernel.db`, and never will.** What it has is this
//! type, which is deliberately *not* reachable from the wire: no DWKP message
//! carries these fields, there is no constructor from runtime JSON, and there
//! is no generic map constructor at all. Tests build one directly. For a live
//! decision, `crate::state` builds one — in one place — from the run's
//! kernel-owned row (M3d, ADR-0039 §10). Where a value's real producer does
//! not exist yet (origin other than `api`, a rise in taint), that row holds
//! the restrictive derivation, so those values are kernel-owned but not yet
//! end-to-end proven, and saying otherwise would be claiming a control that
//! does not exist yet.
//!
//! # Two things a caller may never state
//!
//! [`StandingGrantState`] has one variant, and [`PolicyContext`] has no
//! `would_require_approval` field at all. Both absences are explained where
//! they are — they are the two ways an unattended denial could be talked out
//! of firing.
//!
//! [ADR-0028]: ../../../../../docs/adr/0028-policy-input-ownership.md

use core::fmt;

use crate::capability::{CanonicalPath, PrivacyClass};

/// What started the run.
///
/// The vocabulary of [`DATA_MODEL.md`] §3:
/// `origin ∈ {interactive, scheduled, channel, subagent, api}`. Unattended
/// runs are governed more strictly, which is the whole point of
/// [`Origin::attended`].
///
/// [`DATA_MODEL.md`]: ../../../../../docs/DATA_MODEL.md
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    /// A human asked, and is there.
    Interactive,
    /// A scheduler started it. Nobody is there.
    Scheduled,
    /// A message on a channel started it.
    Channel,
    /// A parent run spawned it.
    Subagent,
    /// A programmatic caller started it.
    Api,
}

impl Origin {
    /// Every origin, in declaration order.
    pub const ALL: [Self; 5] = [
        Self::Interactive,
        Self::Scheduled,
        Self::Channel,
        Self::Subagent,
        Self::Api,
    ];

    /// The TOML and audit spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Interactive => "interactive",
            Self::Scheduled => "scheduled",
            Self::Channel => "channel",
            Self::Subagent => "subagent",
            Self::Api => "api",
        }
    }

    /// Parse the TOML spelling, exactly. No case folding: `Scheduled` is not
    /// `scheduled`, and quietly accepting it would mean a rule matching a
    /// value no kernel ever produces.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|o| o.as_str() == text)
    }

    /// Whether a human could be asked right now.
    ///
    /// Only `interactive` is attended. A `subagent` run has a human somewhere
    /// above it, but not one watching *this* run, and an approval prompt that
    /// nobody sees is an approval that times out or gets clicked blind. The
    /// fail-closed reading is that everything else is unattended.
    #[must_use]
    pub const fn attended(self) -> bool {
        matches!(self, Self::Interactive)
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How much of what the run holds came from somewhere it chose to reach.
///
/// The three tiers of [`CONTEXT.md`] §4, and the reason there are three rather
/// than two is written out there: a boolean taint makes every run tainted by
/// turn two, and a control users disable is not a control. A cloned repository
/// is `LOCAL_UNVERIFIED`; a page the agent followed a link to is
/// `EXTERNAL_UNTRUSTED`.
///
/// [`CONTEXT.md`]: ../../../../../docs/CONTEXT.md
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TaintLevel {
    /// Operator input and system-trusted content.
    None,
    /// Workspace files and local repositories — content the operator pointed
    /// the agent at.
    LocalUnverified,
    /// Fetched pages, MCP results, downloads, email — content the agent chose
    /// to reach.
    ExternalUntrusted,
}

impl TaintLevel {
    /// Every tier, cleanest first.
    pub const ALL: [Self; 3] = [Self::None, Self::LocalUnverified, Self::ExternalUntrusted];

    /// The TOML and audit spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::LocalUnverified => "LOCAL_UNVERIFIED",
            Self::ExternalUntrusted => "EXTERNAL_UNTRUSTED",
        }
    }

    /// Parse the TOML spelling, exactly.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == text)
    }
}

impl fmt::Display for TaintLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a standing grant covers this action.
///
/// **One variant, and that is the security property.** `unless.standing_grant`
/// is part of the policy format, so the loader parses it; but the approval
/// registry, the grant predicate and the `require_untainted_run` condition are
/// all M6 ([`APPROVALS.md`] §4). Through M5 there is nothing that could hold a
/// grant, and there is therefore no value a caller can construct that says one
/// exists.
///
/// The alternative — a `bool` on the context — is the unattended bypass
/// written out in full: a compromised or merely buggy caller sets
/// `standing_grant: true` and `deny-approval-needed-when-unattended` stops
/// firing. A single-variant enum makes that unrepresentable rather than
/// merely wrong.
///
/// M6 adds the variants. Every `match` on this type will stop compiling that
/// day, which is the intended way to find every site that has to decide what a
/// real grant means.
///
/// [`APPROVALS.md`]: ../../../../../docs/APPROVALS.md
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StandingGrantState {
    /// No approval registry exists, so no grant can be held. Never satisfies
    /// `unless.standing_grant`.
    Unavailable,
}

impl StandingGrantState {
    /// Whether a grant covers the action, which through M5 is never.
    #[must_use]
    pub const fn is_held(self) -> bool {
        match self {
            Self::Unavailable => false,
        }
    }
}

impl fmt::Display for StandingGrantState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("unavailable until M6"),
        }
    }
}

/// A kernel configuration flag a rule may negate on.
///
/// `unless.config = "security.allow_host_execution"` in
/// [`POLICY.md`] §3's `deny-host-exec-unless-opted-in`. **Closed**: an unknown
/// key is a load error, because a rule negating on a key nothing sets is a
/// denial that silently never fires.
///
/// [`POLICY.md`]: ../../../../../docs/POLICY.md
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConfigKey {
    /// `security.allow_host_execution` — whether the operator has opted in to
    /// execution outside a sandbox.
    SecurityAllowHostExecution,
}

impl ConfigKey {
    /// Every key.
    pub const ALL: [Self; 1] = [Self::SecurityAllowHostExecution];

    /// The TOML spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SecurityAllowHostExecution => "security.allow_host_execution",
        }
    }

    /// Parse the TOML spelling, exactly.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == text)
    }
}

impl fmt::Display for ConfigKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The kernel configuration flags policy may read.
///
/// Operator-owned, not runtime-owned: this is the configuration file the
/// authority reads at startup, in a directory the runtime cannot write
/// ([ADR-0000](../../../../../docs/adr/0000-authority-plane-separation.md)).
/// A named field per key rather than a map, so a rule cannot negate on a key
/// nothing defines and a new key is a compile error at every site.
///
/// [`Default`] is every flag off, which is the fail-closed direction: host
/// execution is denied unless someone deliberately turned it on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct ConfigFlags {
    /// `security.allow_host_execution`.
    pub security_allow_host_execution: bool,
}

impl ConfigFlags {
    /// Whether a key is set.
    #[must_use]
    pub const fn is_set(self, key: ConfigKey) -> bool {
        match key {
            ConfigKey::SecurityAllowHostExecution => self.security_allow_host_execution,
        }
    }
}

/// A symbolic root a rule-side path may hang from.
///
/// [`POLICY.md`] §3 writes `${WORKSPACE}`, `${DIREWOLF_HOME}`,
/// `${DIREWOLF_CONFIG}`, `${DIREWOLF_INSTALL}` and `~/.ssh`. **These are
/// closed symbols, not environment variables.** Nothing here reads
/// `std::env`, expands a word, looks up a home directory or consults a shell.
/// The policy engine must not be able to ask the process environment what
/// `${WORKSPACE}` means, because the process environment is not the thing that
/// pinned the workspace root — [`PathAnchors`] is, and M4's canonicaliser
/// fills it from kernel-owned state (M3d leaves every anchor unresolved).
///
/// [`POLICY.md`]: ../../../../../docs/POLICY.md
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PathAnchor {
    /// `${WORKSPACE}` — the run's workspace root, pinned by `(dev, ino)` at
    /// admission and held as an open fd for the life of the run
    /// ([`POLICY.md`] §3).
    Workspace,
    /// `${DIREWOLF_HOME}` — DireWolf's own state directory.
    DirewolfHome,
    /// `${DIREWOLF_CONFIG}` — DireWolf's configuration directory, which holds
    /// the policy files themselves.
    DirewolfConfig,
    /// `${DIREWOLF_INSTALL}` — where the binaries live.
    DirewolfInstall,
    /// `~` — the operating user's home directory, for `~/.ssh` and its
    /// neighbours.
    Home,
    /// No symbol: the rule wrote an absolute path such as
    /// `/var/run/docker.sock`.
    Absolute,
}

impl PathAnchor {
    /// Every anchor that has a `${...}` or `~` spelling.
    pub const SYMBOLIC: [Self; 5] = [
        Self::Workspace,
        Self::DirewolfHome,
        Self::DirewolfConfig,
        Self::DirewolfInstall,
        Self::Home,
    ];

    /// The spelling a rule writes, or `None` for [`PathAnchor::Absolute`],
    /// which is spelled by the leading `/` of the path itself.
    #[must_use]
    pub const fn as_str(self) -> Option<&'static str> {
        match self {
            Self::Workspace => Some("${WORKSPACE}"),
            Self::DirewolfHome => Some("${DIREWOLF_HOME}"),
            Self::DirewolfConfig => Some("${DIREWOLF_CONFIG}"),
            Self::DirewolfInstall => Some("${DIREWOLF_INSTALL}"),
            Self::Home => Some("~"),
            Self::Absolute => None,
        }
    }
}

impl fmt::Display for PathAnchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str().unwrap_or("/"))
    }
}

/// What each symbolic anchor resolves to, as canonical paths.
///
/// Every field is `Option` because M3c cannot produce a [`CanonicalPath`] —
/// only `crate::resource` may, and M4's canonicaliser will live there
/// ([ADR-0037]). A default-constructed [`PathAnchors`] therefore has none, and
/// a rule needing one it does not hold is refused at *evaluation* with
/// [`Reason::UnresolvedPathAnchor`](super::Reason::UnresolvedPathAnchor) —
/// a denial with a rule id and a source line, not a predicate that quietly
/// reads as false. A deny rule that stops firing because its anchor is missing
/// is the exact failure the strict loader exists to prevent, arriving one layer
/// later.
///
/// [ADR-0037]: ../../../../../docs/adr/0037-capability-specifications-and-canonical-authority-identities.md
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathAnchors {
    /// `${WORKSPACE}`.
    pub workspace: Option<CanonicalPath>,
    /// `${DIREWOLF_HOME}`.
    pub direwolf_home: Option<CanonicalPath>,
    /// `${DIREWOLF_CONFIG}`.
    pub direwolf_config: Option<CanonicalPath>,
    /// `${DIREWOLF_INSTALL}`.
    pub direwolf_install: Option<CanonicalPath>,
    /// `~`.
    pub home: Option<CanonicalPath>,
}

impl PathAnchors {
    /// None of them. The default for a context nobody has filled in.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            workspace: None,
            direwolf_home: None,
            direwolf_config: None,
            direwolf_install: None,
            home: None,
        }
    }

    /// What an anchor resolves to, or `None` if this context does not hold it.
    ///
    /// [`PathAnchor::Absolute`] resolves to the filesystem root, which is not a
    /// value this type holds — it is the empty component prefix, and the
    /// matcher treats it as such. Returning `None` for it would conflate
    /// "rooted at `/`" with "missing".
    #[must_use]
    pub const fn get(&self, anchor: PathAnchor) -> Option<&CanonicalPath> {
        match anchor {
            PathAnchor::Workspace => self.workspace.as_ref(),
            PathAnchor::DirewolfHome => self.direwolf_home.as_ref(),
            PathAnchor::DirewolfConfig => self.direwolf_config.as_ref(),
            PathAnchor::DirewolfInstall => self.direwolf_install.as_ref(),
            PathAnchor::Home => self.home.as_ref(),
            PathAnchor::Absolute => None,
        }
    }
}

/// The run-level facts policy decides on.
///
/// Every field is kernel-owned ([ADR-0028]). There is **no**
/// `would_require_approval` here: see [`super::eval`] for why it is the
/// evaluator's own fact rather than an input.
///
/// [ADR-0028]: ../../../../../docs/adr/0028-policy-input-ownership.md
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyContext {
    origin: Origin,
    taint: TaintLevel,
    privacy: PrivacyClass,
    standing_grant: StandingGrantState,
    config: ConfigFlags,
    anchors: PathAnchors,
}

impl PolicyContext {
    /// A context for a run of this origin and taint.
    ///
    /// Privacy defaults to the strictest class, configuration to every flag
    /// off, and the anchors to none — all three being the fail-closed
    /// direction, so that a caller which forgets to narrow something has not
    /// thereby widened it.
    ///
    /// [`StandingGrantState`] is not a parameter. It has one value.
    #[must_use]
    pub fn new(origin: Origin, taint: TaintLevel) -> Self {
        Self {
            origin,
            taint,
            privacy: PrivacyClass::LocalOnly,
            standing_grant: StandingGrantState::Unavailable,
            config: ConfigFlags::default(),
            anchors: PathAnchors::empty(),
        }
    }

    /// The run's privacy class.
    #[must_use]
    pub const fn with_privacy(mut self, privacy: PrivacyClass) -> Self {
        self.privacy = privacy;
        self
    }

    /// The operator's configuration flags.
    #[must_use]
    pub const fn with_config(mut self, config: ConfigFlags) -> Self {
        self.config = config;
        self
    }

    /// What the symbolic path anchors resolve to.
    #[must_use]
    pub fn with_anchors(mut self, anchors: PathAnchors) -> Self {
        self.anchors = anchors;
        self
    }

    /// What started the run.
    #[must_use]
    pub const fn origin(&self) -> Origin {
        self.origin
    }

    /// The run's taint tier.
    #[must_use]
    pub const fn taint(&self) -> TaintLevel {
        self.taint
    }

    /// The run's privacy class.
    #[must_use]
    pub const fn privacy(&self) -> PrivacyClass {
        self.privacy
    }

    /// Whether a standing grant is held, which through M5 is never.
    #[must_use]
    pub const fn standing_grant(&self) -> StandingGrantState {
        self.standing_grant
    }

    /// The operator's configuration flags.
    #[must_use]
    pub const fn config(&self) -> ConfigFlags {
        self.config
    }

    /// What the symbolic path anchors resolve to.
    #[must_use]
    pub const fn anchors(&self) -> &PathAnchors {
        &self.anchors
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ConfigFlags, ConfigKey, Origin, PathAnchor, PathAnchors, PolicyContext, StandingGrantState,
        TaintLevel,
    };
    use crate::capability::PrivacyClass;

    #[test]
    fn the_origin_vocabulary_is_the_documented_one() {
        // DATA_MODEL.md section 3: origin in {interactive, scheduled, channel,
        // subagent, api}.
        let spellings: Vec<&str> = Origin::ALL.iter().map(|o| o.as_str()).collect();
        assert_eq!(
            spellings,
            ["interactive", "scheduled", "channel", "subagent", "api"]
        );
        for origin in Origin::ALL {
            assert_eq!(Origin::parse(origin.as_str()), Some(origin));
        }
    }

    #[test]
    fn only_an_interactive_run_is_attended() {
        assert!(Origin::Interactive.attended());
        for origin in Origin::ALL
            .into_iter()
            .filter(|o| *o != Origin::Interactive)
        {
            assert!(!origin.attended(), "{origin} has no human watching it");
        }
    }

    #[test]
    fn the_taint_vocabulary_is_the_documented_one() {
        // CONTEXT.md section 4, three tiers rather than a boolean.
        let spellings: Vec<&str> = TaintLevel::ALL.iter().map(|t| t.as_str()).collect();
        assert_eq!(
            spellings,
            ["NONE", "LOCAL_UNVERIFIED", "EXTERNAL_UNTRUSTED"]
        );
        for taint in TaintLevel::ALL {
            assert_eq!(TaintLevel::parse(taint.as_str()), Some(taint));
        }
    }

    #[test]
    fn no_vocabulary_is_case_folded_or_guessed() {
        for bad in ["Interactive", "SCHEDULED", "cron", "", " api"] {
            assert!(Origin::parse(bad).is_none(), "{bad}");
        }
        for bad in ["none", "External_Untrusted", "TAINTED", "", "UNTRUSTED"] {
            assert!(TaintLevel::parse(bad).is_none(), "{bad}");
        }
        for bad in [
            "security.allow_host_exec",
            "SECURITY.ALLOW_HOST_EXECUTION",
            "",
        ] {
            assert!(ConfigKey::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn a_standing_grant_is_never_held_and_has_no_other_value() {
        assert!(!StandingGrantState::Unavailable.is_held());
        // The type has exactly one inhabitant, so there is no value a caller
        // could pass that claims a grant exists. If this stops compiling, M6
        // has arrived and every `unless.standing_grant` site needs revisiting.
        let states = [StandingGrantState::Unavailable];
        assert!(states.iter().all(|s| !s.is_held()));
    }

    #[test]
    fn configuration_defaults_to_off() {
        let flags = ConfigFlags::default();
        assert!(!flags.is_set(ConfigKey::SecurityAllowHostExecution));
        for key in ConfigKey::ALL {
            assert!(!flags.is_set(key), "{key} must default off");
        }
    }

    #[test]
    fn a_fresh_context_is_the_strictest_one() {
        let context = PolicyContext::new(Origin::Scheduled, TaintLevel::ExternalUntrusted);
        assert_eq!(context.privacy(), PrivacyClass::LocalOnly);
        assert!(!context.config().security_allow_host_execution);
        assert_eq!(context.anchors(), &PathAnchors::empty());
        assert!(!context.standing_grant().is_held());
    }

    #[test]
    fn an_absolute_anchor_is_not_a_missing_one() {
        let anchors = PathAnchors::empty();
        assert!(anchors.get(PathAnchor::Absolute).is_none());
        for anchor in PathAnchor::SYMBOLIC {
            assert!(anchors.get(anchor).is_none(), "{anchor} starts unset");
            assert!(anchor.as_str().is_some(), "{anchor} has a spelling");
        }
        assert_eq!(PathAnchor::Absolute.as_str(), None);
    }
}
