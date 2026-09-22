//! The operator's policy, as durable authority state.
//!
//! # A revision is content, and nothing else
//!
//! ```text
//! policy_revision = SHA-256( "direwolf.policy.revision.v1" || 0x00
//!                            || u64be(policy SCHEMA_VERSION)
//!                            || field(selected profile name)
//!                            || u64be(source count)
//!                            || for each source, in composition order:
//!                                 field(logical source name) || field(source bytes) )
//!
//! field(x) = u64be(len(x)) || x
//! ```
//!
//! Composition order is the chain [`compose`] resolves, extending profile
//! first and root last. The same names, bytes, order and schema version give
//! the same revision; one changed byte gives a different one. Nothing about
//! *where* the files were — an absolute path, an mtime, an inode, the time of
//! installation — enters it, because none of those is policy semantics.
//!
//! The exact source set is stored beside the revision, so a historical
//! decision's `rule_source` can be opened at the line it names, and so every
//! start **recomputes** every stored revision from its stored sources. A
//! revision whose sources no longer hash to it was tampered with, and the
//! store is refused.
//!
//! # Installation is at startup, and fails closed
//!
//! The configured policy is loaded through M3c's strict loader and composed.
//! If that fails, **the authority does not start.** There is no fallback to a
//! shipped pack, to a previously stored revision, or to an embedded default: a
//! malformed operator policy is an operator error, and running some *other*
//! policy instead would be deciding on rules nobody configured.
//!
//! M3d activates exactly one policy per authority incarnation. There is no
//! file watcher and no in-process reload, so no decision can observe a
//! half-installed composition: every decision in an incarnation uses the
//! revision activated when it started. Every run admitted under an earlier
//! incarnation was reaped by that restart (see `lease`), so a live run and the
//! active revision always agree.
//!
//! [`compose`]: crate::policy::compose

use rusqlite::{Connection, OptionalExtension as _};

use crate::capability::{self, CapabilitySet, CapabilitySpec};
use crate::policy::{self, CompiledPolicy, ConfigFlags, ProfileName as PolicyProfileName};

use super::Mode;
use super::audit::{AuditEvent, Field, Fields};
use super::digest::{self, DomainHash, Sha256Hash};
use super::error::AuthorityError;

/// Most source files one composition may name.
pub const MAX_POLICY_SOURCES: usize = 16;

/// Most capabilities a mode ceiling may list.
pub const MAX_CEILING_CAPABILITIES: usize = 64;

/// One policy file, as the operator supplied it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySource {
    /// The logical name decisions cite, e.g. `balanced.toml`. Not a path: the
    /// authority layer that read the file chose it, and it is part of the
    /// revision.
    pub name: String,
    /// The file's exact text.
    pub text: String,
}

/// The policy to install: which profile, and every file its composition needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySet {
    /// The profile to compose, by its `meta.name`.
    pub profile: String,
    /// Its source files. Every one must be part of the composition.
    pub sources: Vec<PolicySource>,
}

impl PolicySet {
    /// One of the three packs compiled into this build, by name — `safe`,
    /// `balanced` or `power`. A convenience for tests and bootstrap; an operator
    /// deployment supplies its own files.
    #[must_use]
    pub fn shipped(profile: &str) -> Option<Self> {
        policy::profiles::ALL
            .iter()
            .find(|(file, _)| file.strip_suffix(".toml") == Some(profile))
            .map(|(file, text)| Self {
                profile: profile.to_owned(),
                sources: vec![PolicySource {
                    name: (*file).to_owned(),
                    text: (*text).to_owned(),
                }],
            })
    }
}

/// A policy that loaded, composed and has a revision — not yet stored.
#[derive(Debug)]
pub(super) struct Prepared {
    pub(super) revision: Sha256Hash,
    pub(super) profile: PolicyProfileName,
    /// The sources, in composition order.
    pub(super) chain: Vec<PolicySource>,
    pub(super) compiled: CompiledPolicy,
}

/// A logical source name must render into a wire `RuleSource`
/// (`[A-Za-z0-9._/-]{1,240}`), or no decision citing it could be reported.
fn valid_source_name(name: &str) -> bool {
    (1..=240).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'))
}

/// Load, compose and hash. Pure: no store, no clock.
pub(super) fn prepare(set: &PolicySet) -> Result<Prepared, String> {
    if set.sources.is_empty() {
        return Err("no policy source was supplied".to_owned());
    }
    if set.sources.len() > MAX_POLICY_SOURCES {
        return Err(format!(
            "{} policy sources exceed the bound of {MAX_POLICY_SOURCES}",
            set.sources.len()
        ));
    }
    let mut profiles = Vec::with_capacity(set.sources.len());
    for source in &set.sources {
        if !valid_source_name(&source.name) {
            return Err(format!(
                "`{}` is not a valid logical source name",
                source.name
            ));
        }
        if set
            .sources
            .iter()
            .filter(|other| other.name == source.name)
            .count()
            > 1
        {
            return Err(format!("the source name `{}` repeats", source.name));
        }
        let profile = policy::load(&source.name, &source.text)
            .map_err(|error| format!("{}: {error}", source.name))?;
        profiles.push(profile);
    }
    let profile = PolicyProfileName::new(&set.profile)
        .map_err(|_| format!("`{}` is not a valid profile name", set.profile))?;
    let compiled = policy::compose(&profile, &profiles).map_err(|error| error.to_string())?;

    let mut chain = Vec::with_capacity(compiled.chain().len());
    for name in compiled.chain() {
        let mut matching = set
            .sources
            .iter()
            .zip(&profiles)
            .filter(|(_, loaded)| loaded.name() == name);
        let (Some((source, _)), None) = (matching.next(), matching.next()) else {
            return Err(format!(
                "the profile `{}` is defined by no source, or by more than one",
                name.as_str()
            ));
        };
        chain.push(source.clone());
    }
    if chain.len() != set.sources.len() {
        return Err(
            "a supplied source is not part of the composition; every installed file must be \
             one the active policy uses"
                .to_owned(),
        );
    }
    let revision = revision(&profile, &chain);
    Ok(Prepared {
        revision,
        profile,
        chain,
        compiled,
    })
}

/// The revision formula in the module documentation.
pub(super) fn revision(profile: &PolicyProfileName, chain: &[PolicySource]) -> Sha256Hash {
    let mut hash = DomainHash::new(digest::POLICY_REVISION)
        .int(u64::from(policy::SCHEMA_VERSION))
        .text(profile.as_str())
        .int(u64::try_from(chain.len()).unwrap_or(u64::MAX));
    for source in chain {
        hash = hash.text(&source.name).text(&source.text);
    }
    hash.finish()
}

/// Record the revision if it is new; if it is already stored, prove the stored
/// sources are the ones being installed. Inside the caller's transaction.
pub(super) fn install(
    tx: &Connection,
    now_ms: u64,
    prepared: &Prepared,
    audit: &mut dyn FnMut(AuditEvent, Fields) -> Result<(), AuthorityError>,
) -> Result<(), AuthorityError> {
    let hex = prepared.revision.to_hex();
    let exists: Option<String> = tx
        .query_row(
            "SELECT profile FROM policy_revision WHERE revision = ?1",
            [&hex],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql)?;
    if exists.is_some() {
        let stored = stored_sources(tx, &hex)?;
        if stored != prepared.chain {
            return Err(AuthorityError::Invariant(
                "a stored policy revision's sources differ from the sources it names",
            ));
        }
        return Ok(());
    }
    tx.execute(
        "INSERT INTO policy_revision (revision, schema_version, profile, source_count, installed_ms) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            hex,
            i64::from(policy::SCHEMA_VERSION),
            prepared.profile.as_str(),
            i64::try_from(prepared.chain.len()).unwrap_or(i64::MAX),
            to_sql(now_ms)?,
        ],
    )
    .map_err(sql)?;
    for (ordinal, source) in prepared.chain.iter().enumerate() {
        tx.execute(
            "INSERT INTO policy_source (revision, ordinal, name, text) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                hex,
                i64::try_from(ordinal).unwrap_or(i64::MAX),
                source.name,
                source.text.as_bytes(),
            ],
        )
        .map_err(sql)?;
    }
    audit(
        AuditEvent::PolicyInstalled,
        Fields::new()
            .text("policy_revision", hex)
            .text("profile", prepared.profile.as_str())
            .list(
                "sources",
                prepared
                    .chain
                    .iter()
                    .map(|s| Field::Text(s.name.clone()))
                    .collect(),
            ),
    )
}

fn stored_sources(tx: &Connection, revision: &str) -> Result<Vec<PolicySource>, AuthorityError> {
    let mut statement = tx
        .prepare("SELECT name, text FROM policy_source WHERE revision = ?1 ORDER BY ordinal")
        .map_err(sql)?;
    let rows = statement
        .query_map([revision], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .map_err(sql)?;
    let mut out = Vec::new();
    for row in rows {
        let (name, bytes) = row.map_err(sql)?;
        let text = String::from_utf8(bytes)
            .map_err(|_| AuthorityError::Invariant("a stored policy source is not UTF-8"))?;
        out.push(PolicySource { name, text });
    }
    Ok(out)
}

/// Recompute every stored revision from its stored sources. A mismatch means
/// the snapshot no longer is what it claims to be.
pub(super) fn verify_stored_revisions(tx: &Connection) -> Result<(), AuthorityError> {
    let revisions: Vec<(String, String, i64)> = {
        let mut statement = tx
            .prepare("SELECT revision, profile, schema_version FROM policy_revision")
            .map_err(sql)?;
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(sql)?;
        rows.collect::<rusqlite::Result<_>>().map_err(sql)?
    };
    for (hex, profile, schema_version) in revisions {
        if schema_version != i64::from(policy::SCHEMA_VERSION) {
            // A revision from another policy schema is not recomputable by
            // this build, and nothing in this build decides with it.
            continue;
        }
        let profile = PolicyProfileName::new(&profile)
            .map_err(|_| AuthorityError::Invariant("a stored profile name is malformed"))?;
        let recomputed = revision(&profile, &stored_sources(tx, &hex)?);
        if recomputed.to_hex() != hex {
            return Err(AuthorityError::Invariant(
                "a stored policy revision does not hash to its stored sources",
            ));
        }
    }
    Ok(())
}

/// What is in force for this incarnation.
#[derive(Debug)]
pub(super) struct ActiveAuthority {
    pub(super) activation_id: i64,
    pub(super) revision: Sha256Hash,
    pub(super) mode: Mode,
    pub(super) flags: ConfigFlags,
    pub(super) ceiling: CapabilitySet,
    pub(super) compiled: CompiledPolicy,
}

/// Parse and canonicalise a ceiling. Every entry must parse; `fs` and `process`
/// entries are kept as declared text and cover nothing until M4 can resolve
/// them — which never widens anything, because a request in those families is
/// withheld before the ceiling is consulted.
pub(super) fn prepare_ceiling(texts: &[String]) -> Result<(Vec<String>, CapabilitySet), String> {
    if texts.len() > MAX_CEILING_CAPABILITIES {
        return Err(format!(
            "{} ceiling entries exceed the bound of {MAX_CEILING_CAPABILITIES}",
            texts.len()
        ));
    }
    let mut canonical = Vec::with_capacity(texts.len());
    let mut specs: Vec<CapabilitySpec> = Vec::with_capacity(texts.len());
    for text in texts {
        let spec =
            capability::parse(text).map_err(|error| format!("ceiling entry `{text}`: {error}"))?;
        canonical.push(spec.to_canonical_string());
        specs.push(spec);
    }
    let resolved = specs
        .iter()
        .filter_map(|spec| spec.resolve().ok())
        .collect();
    Ok((canonical, resolved))
}

fn ceiling_digest(canonical: &[String]) -> Sha256Hash {
    let mut hash =
        DomainHash::new(digest::CEILING).int(u64::try_from(canonical.len()).unwrap_or(u64::MAX));
    for text in canonical {
        hash = hash.text(text);
    }
    hash.finish()
}

/// Make `(revision, mode, flags, ceiling)` the active authority, reusing the
/// latest activation when it is identical and appending a new one otherwise.
/// Returns the activation id. Inside the caller's transaction.
pub(super) fn activate(
    tx: &Connection,
    now_ms: u64,
    revision: &Sha256Hash,
    mode: Mode,
    flags: ConfigFlags,
    ceiling: &[String],
    audit: &mut dyn FnMut(AuditEvent, Fields) -> Result<(), AuthorityError>,
) -> Result<i64, AuthorityError> {
    let digest = ceiling_digest(ceiling);
    let host = i64::from(flags.security_allow_host_execution);
    let latest: Option<(i64, String, String, i64, String)> = tx
        .query_row(
            "SELECT id, policy_revision, mode, allow_host_execution, ceiling_digest \
             FROM activation ORDER BY id DESC LIMIT 1",
            [],
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
    if let Some((id, stored_revision, stored_mode, stored_host, stored_digest)) = &latest
        && stored_revision == &revision.to_hex()
        && stored_mode == mode.as_str()
        && *stored_host == host
        && stored_digest == &digest.to_hex()
    {
        if stored_ceiling(tx, *id)? != ceiling {
            return Err(AuthorityError::Invariant(
                "a stored ceiling differs from the digest recorded for it",
            ));
        }
        return Ok(*id);
    }
    let id = latest.map_or(1, |(id, ..)| id.saturating_add(1));
    tx.execute(
        "INSERT INTO activation (id, policy_revision, mode, allow_host_execution, ceiling_digest, \
         activated_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            id,
            revision.to_hex(),
            mode.as_str(),
            host,
            digest.to_hex(),
            to_sql(now_ms)?
        ],
    )
    .map_err(sql)?;
    for (ordinal, text) in ceiling.iter().enumerate() {
        tx.execute(
            "INSERT INTO activation_ceiling (activation_id, ordinal, capability) VALUES (?1, ?2, ?3)",
            rusqlite::params![id, i64::try_from(ordinal).unwrap_or(i64::MAX), text],
        )
        .map_err(sql)?;
    }
    audit(
        AuditEvent::AuthorityActivated,
        Fields::new()
            .int("activation_id", u64::try_from(id).unwrap_or(0))
            .text("policy_revision", revision.to_hex())
            .text("mode", mode.as_str())
            .flag(
                "security_allow_host_execution",
                flags.security_allow_host_execution,
            )
            .text("ceiling_digest", digest.to_hex())
            .list(
                "ceiling",
                ceiling.iter().map(|c| Field::Text(c.clone())).collect(),
            ),
    )?;
    Ok(id)
}

fn stored_ceiling(tx: &Connection, id: i64) -> Result<Vec<String>, AuthorityError> {
    let mut statement = tx
        .prepare(
            "SELECT capability FROM activation_ceiling WHERE activation_id = ?1 ORDER BY ordinal",
        )
        .map_err(sql)?;
    let rows = statement
        .query_map([id], |row| row.get::<_, String>(0))
        .map_err(sql)?;
    rows.collect::<rusqlite::Result<_>>().map_err(sql)
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "written point-free as `.map_err(sql)`, which passes the error by value"
)]
fn sql(error: rusqlite::Error) -> AuthorityError {
    super::db::to_error(&super::db::classify(&error))
}

fn to_sql(value: u64) -> Result<i64, AuthorityError> {
    i64::try_from(value).map_err(|_| AuthorityError::Invariant("a timestamp exceeds i64"))
}

#[cfg(test)]
mod tests {
    use super::{PolicySet, PolicySource, prepare, revision};

    fn set() -> PolicySet {
        let Some(set) = PolicySet::shipped("balanced") else {
            unreachable!("balanced ships")
        };
        set
    }

    #[test]
    fn a_revision_is_reproducible_and_moves_with_one_byte() {
        let (Ok(a), Ok(b)) = (prepare(&set()), prepare(&set())) else {
            unreachable!("the shipped pack prepares")
        };
        assert_eq!(a.revision, b.revision, "same content, same revision");

        let mut edited = set();
        if let Some(source) = edited.sources.first_mut() {
            source.text.push('\n');
        }
        let Ok(c) = prepare(&edited) else {
            unreachable!("a trailing newline still loads")
        };
        assert_ne!(a.revision, c.revision, "one byte moves the revision");
    }

    #[test]
    fn the_logical_name_is_part_of_the_revision_and_a_path_is_not_allowed_in() {
        let Ok(a) = prepare(&set()) else {
            unreachable!("prepares")
        };
        let mut renamed = set();
        if let Some(source) = renamed.sources.first_mut() {
            source.name = "policy/balanced.toml".to_owned();
        }
        let Ok(b) = prepare(&renamed) else {
            unreachable!("a relative logical name is valid")
        };
        assert_ne!(a.revision, b.revision);
        let mut spaced = set();
        if let Some(source) = spaced.sources.first_mut() {
            source.name = "C:\\policy\\balanced.toml".to_owned();
        }
        assert!(
            prepare(&spaced).is_err(),
            "not representable as a rule_source"
        );
    }

    #[test]
    fn a_malformed_policy_does_not_prepare_and_nothing_falls_back() {
        let broken = PolicySet {
            profile: "balanced".to_owned(),
            sources: vec![PolicySource {
                name: "balanced.toml".to_owned(),
                text: "schema_version = 1\n[meta]\nname = \"balanced\"\n[[rule]]\nid = \"x\"\n\
                       effect = \"ALLOW\"\nwhen.verbb = \"fs.read\"\n"
                    .to_owned(),
            }],
        };
        assert!(prepare(&broken).is_err());
    }

    #[test]
    fn a_source_outside_the_composition_is_refused() {
        let mut extra = set();
        let Some(safe) = PolicySet::shipped("safe") else {
            unreachable!("safe ships")
        };
        extra.sources.extend(safe.sources);
        assert!(prepare(&extra).is_err());
    }

    #[test]
    fn the_formula_depends_on_order() {
        let a = PolicySource {
            name: "a.toml".to_owned(),
            text: "x".to_owned(),
        };
        let b = PolicySource {
            name: "b.toml".to_owned(),
            text: "y".to_owned(),
        };
        let Ok(profile) = crate::policy::ProfileName::new("p") else {
            unreachable!("valid")
        };
        assert_ne!(
            revision(&profile, &[a.clone(), b.clone()]),
            revision(&profile, &[b, a])
        );
    }
}
