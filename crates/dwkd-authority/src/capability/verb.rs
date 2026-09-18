//! The closed verb vocabulary: `namespace.action`.
//!
//! [`CAPABILITIES.md`] §2 lists twelve namespaces and their actions. They are
//! sum types rather than strings for the reason the language decision was
//! bought for: adding a thirteenth namespace or a new action makes every match
//! site that must handle it a compile error, and no amount of review achieves
//! that over `&str`.
//!
//! Nothing here normalises case. `FS.READ` is not `fs.read`; it is rejected.
//! A capability system whose vocabulary has two spellings has two vocabularies.
//!
//! [`CAPABILITIES.md`]: ../../../../../docs/CAPABILITIES.md

use core::fmt;

use super::scope::ScopeFamily;

/// A capability namespace — the first half of a verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Namespace {
    /// Filesystem.
    Fs,
    /// Process execution and inspection.
    Process,
    /// Network egress.
    Network,
    /// Credential use.
    Secret,
    /// Model inference.
    Model,
    /// Browser automation.
    Browser,
    /// Model Context Protocol servers.
    Mcp,
    /// Subagents.
    Agent,
    /// Long-term memory.
    Memory,
    /// Scheduled intents.
    Scheduler,
    /// Kernel-owned artifacts.
    Artifact,
    /// Outbound channel messages.
    Channel,
}

/// An action — the second half of a verb. Actions are namespaced: [`Action::Read`]
/// means nothing on its own, and [`Verb`] is the unit that has meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    /// `fs.read`, `memory.read`, `artifact.read`.
    Read,
    /// `fs.write`.
    Write,
    /// `fs.create`, `scheduler.create`, `artifact.create`.
    Create,
    /// `fs.delete`, `scheduler.delete`.
    Delete,
    /// `fs.list`.
    List,
    /// `fs.stat`.
    Stat,
    /// `fs.exec_bit`.
    ExecBit,
    /// `process.exec`.
    Exec,
    /// `process.signal`.
    Signal,
    /// `process.inspect`.
    Inspect,
    /// `network.http`.
    Http,
    /// `network.https`.
    Https,
    /// `network.tcp`.
    Tcp,
    /// `network.dns`.
    Dns,
    /// `secret.use`, `browser.use`, `mcp.use`.
    Use,
    /// `model.call`.
    Call,
    /// `browser.download`.
    Download,
    /// `browser.upload`.
    Upload,
    /// `browser.credential_entry`.
    CredentialEntry,
    /// `agent.spawn`.
    Spawn,
    /// `agent.message`.
    Message,
    /// `agent.cancel`.
    Cancel,
    /// `memory.propose`.
    Propose,
    /// `memory.promote`.
    Promote,
    /// `scheduler.modify`.
    Modify,
    /// `artifact.export`.
    Export,
    /// `channel.send`.
    Send,
}

/// A complete verb. The only way to build one is [`Verb::new`], which accepts
/// exactly the pairs `CAPABILITIES.md` §2 lists — a known action belonging to
/// another namespace is as invalid as an unknown one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Verb {
    namespace: Namespace,
    action: Action,
}

impl Namespace {
    /// Every namespace, in canonical order.
    pub const ALL: &'static [Self] = &[
        Self::Fs,
        Self::Process,
        Self::Network,
        Self::Secret,
        Self::Model,
        Self::Browser,
        Self::Mcp,
        Self::Agent,
        Self::Memory,
        Self::Scheduler,
        Self::Artifact,
        Self::Channel,
    ];

    /// The wire spelling. Lowercase, and the only accepted spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fs => "fs",
            Self::Process => "process",
            Self::Network => "network",
            Self::Secret => "secret",
            Self::Model => "model",
            Self::Browser => "browser",
            Self::Mcp => "mcp",
            Self::Agent => "agent",
            Self::Memory => "memory",
            Self::Scheduler => "scheduler",
            Self::Artifact => "artifact",
            Self::Channel => "channel",
        }
    }

    /// Parse exactly. No case folding, no trimming, no aliases.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|n| n.as_str() == text)
    }

    /// Which scope family this namespace's scopes belong to.
    #[must_use]
    pub const fn scope_family(self) -> ScopeFamily {
        match self {
            Self::Fs => ScopeFamily::Path,
            Self::Process => ScopeFamily::Executable,
            Self::Network => ScopeFamily::Endpoint,
            Self::Secret => ScopeFamily::CredentialHandle,
            Self::Model => ScopeFamily::ProviderModel,
            Self::Browser => ScopeFamily::Domain,
            Self::Mcp => ScopeFamily::ServerId,
            Self::Agent => ScopeFamily::AgentProfile,
            Self::Memory => ScopeFamily::MemoryScope,
            Self::Scheduler => ScopeFamily::Intent,
            Self::Artifact => ScopeFamily::ArtifactScope,
            Self::Channel => ScopeFamily::ChannelTarget,
        }
    }
}

impl Action {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Create => "create",
            Self::Delete => "delete",
            Self::List => "list",
            Self::Stat => "stat",
            Self::ExecBit => "exec_bit",
            Self::Exec => "exec",
            Self::Signal => "signal",
            Self::Inspect => "inspect",
            Self::Http => "http",
            Self::Https => "https",
            Self::Tcp => "tcp",
            Self::Dns => "dns",
            Self::Use => "use",
            Self::Call => "call",
            Self::Download => "download",
            Self::Upload => "upload",
            Self::CredentialEntry => "credential_entry",
            Self::Spawn => "spawn",
            Self::Message => "message",
            Self::Cancel => "cancel",
            Self::Propose => "propose",
            Self::Promote => "promote",
            Self::Modify => "modify",
            Self::Export => "export",
            Self::Send => "send",
        }
    }
}

impl Verb {
    /// Every verb the architecture defines, in canonical order. The source of
    /// truth for what a namespace may be paired with.
    pub const ALL: &'static [Self] = &[
        Self::of(Namespace::Fs, Action::Read),
        Self::of(Namespace::Fs, Action::Write),
        Self::of(Namespace::Fs, Action::Create),
        Self::of(Namespace::Fs, Action::Delete),
        Self::of(Namespace::Fs, Action::List),
        Self::of(Namespace::Fs, Action::Stat),
        Self::of(Namespace::Fs, Action::ExecBit),
        Self::of(Namespace::Process, Action::Exec),
        Self::of(Namespace::Process, Action::Signal),
        Self::of(Namespace::Process, Action::Inspect),
        Self::of(Namespace::Network, Action::Http),
        Self::of(Namespace::Network, Action::Https),
        Self::of(Namespace::Network, Action::Tcp),
        Self::of(Namespace::Network, Action::Dns),
        Self::of(Namespace::Secret, Action::Use),
        Self::of(Namespace::Model, Action::Call),
        Self::of(Namespace::Browser, Action::Use),
        Self::of(Namespace::Browser, Action::Download),
        Self::of(Namespace::Browser, Action::Upload),
        Self::of(Namespace::Browser, Action::CredentialEntry),
        Self::of(Namespace::Mcp, Action::Use),
        Self::of(Namespace::Agent, Action::Spawn),
        Self::of(Namespace::Agent, Action::Message),
        Self::of(Namespace::Agent, Action::Cancel),
        Self::of(Namespace::Memory, Action::Read),
        Self::of(Namespace::Memory, Action::Propose),
        Self::of(Namespace::Memory, Action::Promote),
        Self::of(Namespace::Scheduler, Action::Create),
        Self::of(Namespace::Scheduler, Action::Modify),
        Self::of(Namespace::Scheduler, Action::Delete),
        Self::of(Namespace::Artifact, Action::Read),
        Self::of(Namespace::Artifact, Action::Create),
        Self::of(Namespace::Artifact, Action::Export),
        Self::of(Namespace::Channel, Action::Send),
    ];

    /// Build a pair without checking it. Private: [`Verb::ALL`] is the only
    /// caller, and it is the definition of which pairs exist.
    const fn of(namespace: Namespace, action: Action) -> Self {
        Self { namespace, action }
    }

    /// The verb named by a namespace and an action, if the architecture defines
    /// that pair. `fs.spawn` is rejected as firmly as `fs.teleport`: both name
    /// an authority nothing can grant.
    #[must_use]
    pub fn new(namespace: Namespace, action: Action) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|v| v.namespace == namespace && v.action == action)
    }

    /// Parse the actions a namespace defines, exactly.
    #[must_use]
    pub fn parse_action(namespace: Namespace, text: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|v| v.namespace == namespace && v.action.as_str() == text)
    }

    /// The namespace half.
    #[must_use]
    pub const fn namespace(self) -> Namespace {
        self.namespace
    }

    /// The action half.
    #[must_use]
    pub const fn action(self) -> Action {
        self.action
    }

    /// Which scope family this verb's scopes belong to.
    #[must_use]
    pub const fn scope_family(self) -> ScopeFamily {
        self.namespace.scope_family()
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for Verb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.namespace.as_str(), self.action.as_str())
    }
}
