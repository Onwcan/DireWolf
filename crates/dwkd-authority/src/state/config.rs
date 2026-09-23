//! Kernel-owned configuration records: agent profiles, skills, workspaces.
//!
//! # These are not runtime authority paths
//!
//! Everything here is written through [`OperatorBootstrap`](super::OperatorBootstrap),
//! an **in-process** API for the operator's own tooling and for tests. No DWKP
//! operation reaches it, none will, and there is no message that installs,
//! edits or selects a profile, a skill or a workspace ([`PROTOCOL.md`] §2: "no
//! operation that … sets a policy input"). A runtime names a profile and skills
//! in `AdmitRun`; the kernel resolves those names against these records, and a
//! name it does not hold is resolved to the most restrictive meaning available.
//!
//! # Revisions, not edits
//!
//! Agent profiles and skills are append-only: installing a changed definition
//! records a new revision, and the previous one stays, so an admission can
//! always be explained against the exact revision it was minted from. A
//! workspace's sensitivity can only become stricter; loosening it means a new
//! workspace. A session's workspace binding is fixed for the session's life,
//! and a workspace's filesystem root (M4a) is bound once: another root is
//! another workspace.
//!
//! [`PROTOCOL.md`]: ../../../../../docs/PROTOCOL.md

use core::fmt;

use dwk_proto::wire::scalar::{AgentProfileName, SkillName};
use rusqlite::{Connection, OptionalExtension as _};

use crate::capability::{self, CapabilitySpec, PrivacyClass};
use crate::resource::fs::{BirthTime, RootFingerprint};

use super::audit::{AuditEvent, Fields};
use super::digest::{self, DomainHash, Sha256Hash};
use super::error::AuthorityError;

/// Most capabilities one profile or skill may declare — the wire's own bound
/// on a run's authority, so a declaration can never be larger than what a
/// grant could carry.
pub const MAX_DECLARED_CAPABILITIES: usize = dwk_proto::dwkp::messages::MAX_CAPABILITIES;

/// Most baseline skills a profile may mandate.
pub const MAX_BASELINE_SKILLS: usize = dwk_proto::dwkp::messages::MAX_SKILLS;

/// An agent profile, as the operator defines it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentProfileSpec {
    /// The name `AdmitRun` uses.
    pub name: AgentProfileName,
    /// The profile's capability **ceiling** — never a grant. Capability text,
    /// re-parsed by the kernel at every admission.
    pub declared: Vec<String>,
    /// Skills the kernel activates for **every** run of this profile, whether
    /// or not the runtime names them. Skills only narrow, so a runtime that
    /// omits one cannot widen anything: the kernel adds it back.
    pub baseline_skills: Vec<SkillName>,
    /// The privacy class a run starts from, before workspace sensitivity
    /// narrows it.
    pub privacy_default: PrivacyClass,
}

/// How far a skill is trusted. Assigned by the kernel's registry — here, the
/// operator — and **never** read from a skill's manifest ([`SKILLS.md`] §3).
///
/// [`SKILLS.md`]: ../../../../../docs/SKILLS.md
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SkillTrust {
    /// Shipped with DireWolf and signed.
    SystemTrusted,
    /// Reviewed and approved by the operator.
    UserTrusted,
    /// Installed, not reviewed.
    CommunityUnverified,
    /// Written by an agent.
    GeneratedUntrusted,
    /// Failed validation. Contributes nothing to any intersection.
    Quarantined,
}

impl SkillTrust {
    /// Every level.
    pub const ALL: [Self; 5] = [
        Self::SystemTrusted,
        Self::UserTrusted,
        Self::CommunityUnverified,
        Self::GeneratedUntrusted,
        Self::Quarantined,
    ];

    /// The stored spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SystemTrusted => "SYSTEM_TRUSTED",
            Self::UserTrusted => "USER_TRUSTED",
            Self::CommunityUnverified => "COMMUNITY_UNVERIFIED",
            Self::GeneratedUntrusted => "GENERATED_UNTRUSTED",
            Self::Quarantined => "QUARANTINED",
        }
    }

    /// Parse the stored spelling, exactly.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == text)
    }

    /// Whether a skill at this level contributes its declared set to the
    /// intersection. A quarantined skill contributes the **empty** set: its
    /// declaration is not believed, and "no constraint" would be the one
    /// reading that could widen.
    #[must_use]
    pub const fn contributes_declaration(self) -> bool {
        !matches!(self, Self::Quarantined)
    }
}

/// A skill, as the operator registers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillSpec {
    /// The name `AdmitRun` uses.
    pub name: SkillName,
    /// Registry-assigned trust.
    pub trust: SkillTrust,
    /// The capabilities the skill needs. An active skill narrows a run to
    /// these; it never adds to them.
    pub declared: Vec<String>,
}

/// How sensitive a workspace's content is. Closed; ordered least to most.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WorkspaceSensitivity {
    /// May reach any model.
    Public,
    /// May reach a contracted vendor, and no further.
    Private,
    /// Must not leave the machine.
    Secret,
}

impl WorkspaceSensitivity {
    /// Every level, least sensitive first.
    pub const ALL: [Self; 3] = [Self::Public, Self::Private, Self::Secret];

    /// The widest privacy class a run in this workspace may have.
    #[must_use]
    pub const fn privacy_ceiling(self) -> PrivacyClass {
        match self {
            Self::Public => PrivacyClass::Any,
            Self::Private => PrivacyClass::VendorOk,
            Self::Secret => PrivacyClass::LocalOnly,
        }
    }

    /// The stored rank: larger is stricter, so a trigger can refuse a decrease.
    #[must_use]
    pub const fn rank(self) -> i64 {
        match self {
            Self::Public => 0,
            Self::Private => 1,
            Self::Secret => 2,
        }
    }

    /// From the stored rank.
    #[must_use]
    pub fn from_rank(rank: i64) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.rank() == rank)
    }

    /// The display spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "PUBLIC",
            Self::Private => "PRIVATE",
            Self::Secret => "SECRET",
        }
    }
}

/// A workspace's kernel-side identity: a name, **not** a path.
///
/// Its security metadata — its sensitivity, and since M4a the filesystem root
/// the operator bound to it — is recorded under this operator-chosen name. The
/// root is a host path plus the identity the directory had when measured; the
/// canonical identity of anything beneath it is only ever built by
/// `crate::resource::fs`, and a runtime can only *name* a workspace, never
/// supply its path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkspaceId(String);

impl WorkspaceId {
    /// Lowercase letters, digits and hyphens, starting with a letter, at most
    /// 64 characters.
    #[must_use]
    pub fn new(text: &str) -> Option<Self> {
        crate::policy::rule::is_lower_kebab(text, 64).then(|| Self(text.to_owned()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WorkspaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A configuration record that could not be installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// The definition is invalid; nothing was written.
    Invalid(String),
    /// The store could not record it.
    Authority(AuthorityError),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(why) => write!(f, "invalid configuration: {why}"),
            Self::Authority(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<AuthorityError> for ConfigError {
    fn from(error: AuthorityError) -> Self {
        Self::Authority(error)
    }
}

/// Parse and canonicalise a declared set. Every entry must parse.
fn canonical_declared(declared: &[String]) -> Result<Vec<String>, ConfigError> {
    if declared.len() > MAX_DECLARED_CAPABILITIES {
        return Err(ConfigError::Invalid(format!(
            "{} declared capabilities exceed the bound of {MAX_DECLARED_CAPABILITIES}",
            declared.len()
        )));
    }
    declared
        .iter()
        .map(|text| {
            capability::parse(text)
                .map(|spec| spec.to_canonical_string())
                .map_err(|error| ConfigError::Invalid(format!("`{text}`: {error}")))
        })
        .collect()
}

fn profile_digest(spec: &AgentProfileSpec, declared: &[String]) -> Sha256Hash {
    let mut hash = DomainHash::new(digest::AGENT_PROFILE)
        .text(spec.name.as_str())
        .text(spec.privacy_default.as_str())
        .int(u64::try_from(declared.len()).unwrap_or(u64::MAX));
    for text in declared {
        hash = hash.text(text);
    }
    hash = hash.int(u64::try_from(spec.baseline_skills.len()).unwrap_or(u64::MAX));
    for skill in &spec.baseline_skills {
        hash = hash.text(skill.as_str());
    }
    hash.finish()
}

fn skill_digest(spec: &SkillSpec, declared: &[String]) -> Sha256Hash {
    let mut hash = DomainHash::new(digest::SKILL)
        .text(spec.name.as_str())
        .text(spec.trust.as_str())
        .int(u64::try_from(declared.len()).unwrap_or(u64::MAX));
    for text in declared {
        hash = hash.text(text);
    }
    hash.finish()
}

/// Record a profile revision, or return the current one if it is identical.
pub(super) fn install_agent_profile(
    tx: &Connection,
    now_ms: i64,
    spec: &AgentProfileSpec,
    audit: &mut dyn FnMut(AuditEvent, Fields) -> Result<(), AuthorityError>,
) -> Result<i64, ConfigError> {
    let declared = canonical_declared(&spec.declared)?;
    if spec.baseline_skills.len() > MAX_BASELINE_SKILLS {
        return Err(ConfigError::Invalid(format!(
            "{} baseline skills exceed the bound of {MAX_BASELINE_SKILLS}",
            spec.baseline_skills.len()
        )));
    }
    for (index, skill) in spec.baseline_skills.iter().enumerate() {
        if spec
            .baseline_skills
            .iter()
            .skip(index + 1)
            .any(|s| s == skill)
        {
            return Err(ConfigError::Invalid(format!(
                "the baseline skill `{}` repeats",
                skill.as_str()
            )));
        }
    }
    let digest = profile_digest(spec, &declared);
    let current: Option<(i64, String)> = tx
        .query_row(
            "SELECT revision, digest FROM agent_profile WHERE name = ?1 \
             ORDER BY revision DESC LIMIT 1",
            [spec.name.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sql)?;
    if let Some((revision, stored)) = &current
        && stored == &digest.to_hex()
    {
        return Ok(*revision);
    }
    let revision = current.map_or(1, |(revision, _)| revision.saturating_add(1));
    tx.execute(
        "INSERT INTO agent_profile (name, revision, digest, privacy_default, installed_ms) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            spec.name.as_str(),
            revision,
            digest.to_hex(),
            spec.privacy_default.as_str(),
            now_ms
        ],
    )
    .map_err(sql)?;
    for (ordinal, text) in declared.iter().enumerate() {
        tx.execute(
            "INSERT INTO agent_profile_capability (name, revision, ordinal, capability) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![spec.name.as_str(), revision, ordinal_sql(ordinal), text],
        )
        .map_err(sql)?;
    }
    for (ordinal, skill) in spec.baseline_skills.iter().enumerate() {
        tx.execute(
            "INSERT INTO agent_profile_skill (name, revision, ordinal, skill) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                spec.name.as_str(),
                revision,
                ordinal_sql(ordinal),
                skill.as_str()
            ],
        )
        .map_err(sql)?;
    }
    audit(
        AuditEvent::AgentProfileInstalled,
        Fields::new()
            .text("agent_profile", spec.name.as_str())
            .int("revision", u64::try_from(revision).unwrap_or(0))
            .text("digest", digest.to_hex()),
    )?;
    Ok(revision)
}

/// Record a skill revision, or return the current one if it is identical.
pub(super) fn install_skill(
    tx: &Connection,
    now_ms: i64,
    spec: &SkillSpec,
    audit: &mut dyn FnMut(AuditEvent, Fields) -> Result<(), AuthorityError>,
) -> Result<i64, ConfigError> {
    let declared = canonical_declared(&spec.declared)?;
    let digest = skill_digest(spec, &declared);
    let current: Option<(i64, String)> = tx
        .query_row(
            "SELECT revision, digest FROM skill WHERE name = ?1 ORDER BY revision DESC LIMIT 1",
            [spec.name.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sql)?;
    if let Some((revision, stored)) = &current
        && stored == &digest.to_hex()
    {
        return Ok(*revision);
    }
    let revision = current.map_or(1, |(revision, _)| revision.saturating_add(1));
    tx.execute(
        "INSERT INTO skill (name, revision, digest, trust, installed_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            spec.name.as_str(),
            revision,
            digest.to_hex(),
            spec.trust.as_str(),
            now_ms
        ],
    )
    .map_err(sql)?;
    for (ordinal, text) in declared.iter().enumerate() {
        tx.execute(
            "INSERT INTO skill_capability (name, revision, ordinal, capability) \
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![spec.name.as_str(), revision, ordinal_sql(ordinal), text],
        )
        .map_err(sql)?;
    }
    audit(
        AuditEvent::SkillInstalled,
        Fields::new()
            .text("skill", spec.name.as_str())
            .int("revision", u64::try_from(revision).unwrap_or(0))
            .text("trust", spec.trust.as_str())
            .text("digest", digest.to_hex()),
    )?;
    Ok(revision)
}

/// Record a workspace, or make an existing one stricter. Loosening is refused.
pub(super) fn install_workspace(
    tx: &Connection,
    now_ms: i64,
    id: &WorkspaceId,
    sensitivity: WorkspaceSensitivity,
    audit: &mut dyn FnMut(AuditEvent, Fields) -> Result<(), AuthorityError>,
) -> Result<(), ConfigError> {
    let current: Option<i64> = tx
        .query_row(
            "SELECT sensitivity FROM workspace WHERE workspace_id = ?1",
            [id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql)?;
    match current {
        Some(rank) if rank == sensitivity.rank() => return Ok(()),
        Some(rank) if rank > sensitivity.rank() => {
            return Err(ConfigError::Invalid(format!(
                "workspace `{id}` may only become stricter; a looser workspace is a new workspace"
            )));
        }
        Some(_) => {
            tx.execute(
                "UPDATE workspace SET sensitivity = ?2 WHERE workspace_id = ?1",
                rusqlite::params![id.as_str(), sensitivity.rank()],
            )
            .map_err(sql)?;
        }
        None => {
            tx.execute(
                "INSERT INTO workspace (workspace_id, sensitivity, installed_ms) VALUES (?1, ?2, ?3)",
                rusqlite::params![id.as_str(), sensitivity.rank(), now_ms],
            )
            .map_err(sql)?;
        }
    }
    audit(
        AuditEvent::WorkspaceInstalled,
        Fields::new()
            .text("workspace_id", id.as_str())
            .text("sensitivity", sensitivity.as_str()),
    )?;
    Ok(())
}

/// A workspace's bound filesystem root, as recorded (M4a, ADR-0042 §8): the
/// operator's host path and the fingerprint the directory had when measured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RootBinding {
    pub(super) host_path: String,
    pub(super) fingerprint: RootFingerprint,
}

/// Bind a workspace to the root the operator measured. Once: the same binding
/// again is a no-op, and any other is refused — a different root is a
/// different workspace.
pub(super) fn install_workspace_root(
    tx: &Connection,
    now_ms: i64,
    id: &WorkspaceId,
    binding: &RootBinding,
    audit: &mut dyn FnMut(AuditEvent, Fields) -> Result<(), AuthorityError>,
) -> Result<(), ConfigError> {
    let known: Option<i64> = tx
        .query_row(
            "SELECT sensitivity FROM workspace WHERE workspace_id = ?1",
            [id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql)?;
    if known.is_none() {
        return Err(ConfigError::Invalid(format!(
            "no workspace `{id}` is installed"
        )));
    }
    if let Some(current) = workspace_root(tx, id.as_str())? {
        if &current == binding {
            return Ok(());
        }
        return Err(ConfigError::Invalid(format!(
            "workspace `{id}` is already bound to a root; a different root is a new workspace"
        )));
    }
    let fingerprint = binding.fingerprint;
    let (seconds, nanoseconds) = fingerprint.birth().map_or((None, None), |birth| {
        (Some(birth.seconds), Some(i64::from(birth.nanoseconds)))
    });
    tx.execute(
        "INSERT INTO workspace_root (workspace_id, host_path, root_device, root_inode, \
         birth_sec, birth_nsec, installed_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            id.as_str(),
            binding.host_path,
            fingerprint.device().to_string(),
            fingerprint.inode().to_string(),
            seconds,
            nanoseconds,
            now_ms
        ],
    )
    .map_err(sql)?;
    audit(
        AuditEvent::WorkspaceRootInstalled,
        Fields::new()
            .text("workspace_id", id.as_str())
            .text("host_path", binding.host_path.as_str())
            .text("root_device", fingerprint.device().to_string())
            .text("root_inode", fingerprint.inode().to_string())
            .flag("birth_time_recorded", fingerprint.birth().is_some()),
    )?;
    Ok(())
}

/// A `workspace_root` row: host path, device, inode, birth seconds and
/// nanoseconds.
type RootRow = (String, String, String, Option<i64>, Option<i64>);

/// The root a workspace is bound to, if it has one.
pub(super) fn workspace_root(
    tx: &Connection,
    workspace: &str,
) -> Result<Option<RootBinding>, AuthorityError> {
    let row: Option<RootRow> = tx
        .query_row(
            "SELECT host_path, root_device, root_inode, birth_sec, birth_nsec \
             FROM workspace_root WHERE workspace_id = ?1",
            [workspace],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .map_err(sql)?;
    let Some((host_path, device, inode, seconds, nanoseconds)) = row else {
        return Ok(None);
    };
    let malformed = || AuthorityError::Invariant("a stored workspace root is malformed");
    let device: u64 = device.parse().map_err(|_| malformed())?;
    let inode: u64 = inode.parse().map_err(|_| malformed())?;
    let birth = match (seconds, nanoseconds) {
        (Some(seconds), Some(nanoseconds)) => Some(BirthTime {
            seconds,
            nanoseconds: u32::try_from(nanoseconds).map_err(|_| malformed())?,
        }),
        (None, None) => None,
        _ => return Err(malformed()),
    };
    Ok(Some(RootBinding {
        host_path,
        fingerprint: RootFingerprint::new(device, inode, birth),
    }))
}

/// Bind a session to a workspace, once.
pub(super) fn bind_session_workspace(
    tx: &Connection,
    now_ms: i64,
    session: &str,
    id: &WorkspaceId,
    audit: &mut dyn FnMut(AuditEvent, Fields) -> Result<(), AuthorityError>,
) -> Result<(), ConfigError> {
    let current: Option<String> = tx
        .query_row(
            "SELECT workspace_id FROM session_workspace WHERE session_id = ?1",
            [session],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql)?;
    match current {
        Some(bound) if bound == id.as_str() => return Ok(()),
        Some(bound) => {
            return Err(ConfigError::Invalid(format!(
                "session {session} is already bound to workspace `{bound}`"
            )));
        }
        None => {}
    }
    let known: Option<i64> = tx
        .query_row(
            "SELECT sensitivity FROM workspace WHERE workspace_id = ?1",
            [id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql)?;
    if known.is_none() {
        return Err(ConfigError::Invalid(format!(
            "no workspace `{id}` is installed"
        )));
    }
    tx.execute(
        "INSERT INTO session_workspace (session_id, workspace_id, bound_ms) VALUES (?1, ?2, ?3)",
        rusqlite::params![session, id.as_str(), now_ms],
    )
    .map_err(sql)?;
    audit(
        AuditEvent::SessionWorkspaceBound,
        Fields::new()
            .text("session_id", session)
            .text("workspace_id", id.as_str()),
    )?;
    Ok(())
}

/// A profile as admission reads it: the current revision, re-parsed.
#[derive(Debug, Clone)]
pub(super) struct ProfileRecord {
    pub(super) revision: i64,
    pub(super) privacy_default: PrivacyClass,
    pub(super) declared: Vec<CapabilitySpec>,
    pub(super) baseline: Vec<String>,
}

/// A skill as admission reads it.
#[derive(Debug, Clone)]
pub(super) struct SkillRecord {
    pub(super) revision: i64,
    pub(super) trust: SkillTrust,
    pub(super) declared: Vec<CapabilitySpec>,
}

fn reparse(texts: &[String]) -> Result<Vec<CapabilitySpec>, AuthorityError> {
    texts
        .iter()
        .map(|text| {
            capability::parse(text).map_err(|_| {
                AuthorityError::Invariant("a stored declared capability no longer parses")
            })
        })
        .collect()
}

fn texts(
    tx: &Connection,
    sql_text: &str,
    name: &str,
    revision: i64,
) -> Result<Vec<String>, AuthorityError> {
    let mut statement = tx.prepare(sql_text).map_err(sql)?;
    let rows = statement
        .query_map(rusqlite::params![name, revision], |row| {
            row.get::<_, String>(0)
        })
        .map_err(sql)?;
    rows.collect::<rusqlite::Result<_>>().map_err(sql)
}

/// The current revision of a profile, or `None` if the kernel holds no profile
/// by that name.
pub(super) fn current_profile(
    tx: &Connection,
    name: &str,
) -> Result<Option<ProfileRecord>, AuthorityError> {
    let row: Option<(i64, String)> = tx
        .query_row(
            "SELECT revision, privacy_default FROM agent_profile WHERE name = ?1 \
             ORDER BY revision DESC LIMIT 1",
            [name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sql)?;
    let Some((revision, privacy)) = row else {
        return Ok(None);
    };
    let privacy_default = PrivacyClass::parse(&privacy).ok_or(AuthorityError::Invariant(
        "a stored privacy class is malformed",
    ))?;
    let declared = reparse(&texts(
        tx,
        "SELECT capability FROM agent_profile_capability WHERE name = ?1 AND revision = ?2 \
         ORDER BY ordinal",
        name,
        revision,
    )?)?;
    let baseline = texts(
        tx,
        "SELECT skill FROM agent_profile_skill WHERE name = ?1 AND revision = ?2 ORDER BY ordinal",
        name,
        revision,
    )?;
    Ok(Some(ProfileRecord {
        revision,
        privacy_default,
        declared,
        baseline,
    }))
}

/// The current revision of a skill, or `None` if the kernel holds none.
pub(super) fn current_skill(
    tx: &Connection,
    name: &str,
) -> Result<Option<SkillRecord>, AuthorityError> {
    let row: Option<(i64, String)> = tx
        .query_row(
            "SELECT revision, trust FROM skill WHERE name = ?1 ORDER BY revision DESC LIMIT 1",
            [name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sql)?;
    let Some((revision, trust)) = row else {
        return Ok(None);
    };
    let trust = SkillTrust::parse(&trust).ok_or(AuthorityError::Invariant(
        "a stored skill trust level is malformed",
    ))?;
    let declared = reparse(&texts(
        tx,
        "SELECT capability FROM skill_capability WHERE name = ?1 AND revision = ?2 ORDER BY ordinal",
        name,
        revision,
    )?)?;
    Ok(Some(SkillRecord {
        revision,
        trust,
        declared,
    }))
}

/// The workspace a session is bound to, and its sensitivity.
pub(super) fn session_workspace(
    tx: &Connection,
    session: &str,
) -> Result<Option<(String, WorkspaceSensitivity)>, AuthorityError> {
    let row: Option<(String, i64)> = tx
        .query_row(
            "SELECT w.workspace_id, w.sensitivity FROM session_workspace s \
             JOIN workspace w ON w.workspace_id = s.workspace_id WHERE s.session_id = ?1",
            [session],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(sql)?;
    row.map(|(id, rank)| {
        WorkspaceSensitivity::from_rank(rank)
            .map(|sensitivity| (id, sensitivity))
            .ok_or(AuthorityError::Invariant(
                "a stored sensitivity is malformed",
            ))
    })
    .transpose()
}

fn ordinal_sql(ordinal: usize) -> i64 {
    i64::try_from(ordinal).unwrap_or(i64::MAX)
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "written point-free as `.map_err(sql)`, which passes the error by value"
)]
fn sql(error: rusqlite::Error) -> AuthorityError {
    super::db::to_error(&super::db::classify(&error))
}

#[cfg(test)]
mod tests {
    use super::{SkillTrust, WorkspaceId, WorkspaceSensitivity};
    use crate::capability::PrivacyClass;

    #[test]
    fn sensitivity_only_narrows_privacy() {
        assert_eq!(
            WorkspaceSensitivity::Public.privacy_ceiling(),
            PrivacyClass::Any
        );
        assert_eq!(
            WorkspaceSensitivity::Private.privacy_ceiling(),
            PrivacyClass::VendorOk
        );
        assert_eq!(
            WorkspaceSensitivity::Secret.privacy_ceiling(),
            PrivacyClass::LocalOnly
        );
        for pair in WorkspaceSensitivity::ALL.windows(2) {
            let [looser, stricter] = pair else {
                unreachable!("windows of two")
            };
            assert!(looser.rank() < stricter.rank());
            assert!(stricter.privacy_ceiling() <= looser.privacy_ceiling());
        }
        for level in WorkspaceSensitivity::ALL {
            assert_eq!(WorkspaceSensitivity::from_rank(level.rank()), Some(level));
        }
        assert_eq!(WorkspaceSensitivity::from_rank(3), None);
    }

    #[test]
    fn only_a_quarantined_skill_is_disbelieved() {
        for trust in SkillTrust::ALL {
            assert_eq!(SkillTrust::parse(trust.as_str()), Some(trust));
            assert_eq!(
                trust.contributes_declaration(),
                trust != SkillTrust::Quarantined
            );
        }
        assert_eq!(SkillTrust::parse("system_trusted"), None);
    }

    #[test]
    fn a_workspace_id_is_a_name_not_a_path() {
        assert!(WorkspaceId::new("project-x").is_some());
        for bad in ["/workspace", "..", "Project", "", "a b", "a/b"] {
            assert!(WorkspaceId::new(bad).is_none(), "{bad}");
        }
    }
}
