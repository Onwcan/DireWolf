//! The secret index in `kernel.db` and the authority's in-memory secret state
//! (M4e, ADR-0046 §§3, 5, 20, 21).
//!
//! # What is stored, and what never is
//!
//! `secret_revision` holds each handle's metadata history — backend, entry
//! name or file path, origins, header name and prefix, modes, the executable
//! identities of its consumers, environment name, rotation, sensitivity,
//! revocation — as canonical JSON with its SHA-256. It never holds a value, a
//! prefix of one, a length or anything derived from one. The redaction index
//! lives in memory only ([`SecretsState`]).
//!
//! # When a value is read
//!
//! * **At start**, once per configured secret, to fingerprint it for the
//!   redaction index (ADR-0046 §21): the plaintext is dropped — and zeroized —
//!   as soon as its keyed fingerprint is computed, outside any transaction.
//! * **For a use**, only after both gates allowed it and its intent is
//!   durable (`state::secret_use`).
//!
//! Never at admission, never for a replay, never to rehydrate a stored grant:
//! those read the index (a metadata row) or nothing at all.
//!
//! # Identity
//!
//! A handle's meaning is its current revision. A run is bound, at admission,
//! to the revision each concrete `secret.use:<handle>` it was granted resolved
//! to; a later revision — different metadata under the same spelling — is a
//! different secret, and a use by that run fails closed (`REPLACED`). A
//! revoked or removed handle fails closed whatever a stored grant says.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use dwk_proto::json::{self, Value};
use rusqlite::OptionalExtension as _;

use crate::resource::ExecutableIdentity;
use crate::resource::exec;
use crate::secret::SecretError;
use crate::secret::backend;
use crate::secret::metadata::{SecretConfig, SecretHandle, SecretMetadata};
use crate::secret::redact::exact::{ExactIndex, MIN_EXACT_BYTES};
use crate::secret::redact::{self, Redaction};

use super::Work;
use super::audit::{AuditEvent, Field, Fields};
use super::digest::{self, DomainHash};
use super::error::AuthorityError;
use super::lease::to_sql;

/// Redaction hits: kind and count, never bytes.
pub(crate) type Hits = BTreeMap<redact::HitKind, u64>;

/// A redacted, bounded buffer.
pub(crate) struct Redacted {
    /// The bytes that may leave for cognition.
    pub(crate) bytes: Vec<u8>,
    /// Whether redaction made the output longer than its bound, so it was cut.
    pub(crate) cut: bool,
    /// What was replaced.
    pub(crate) hits: Hits,
}

/// The authority's secret state for one process lifetime.
pub(crate) struct SecretsState {
    config: SecretConfig,
    consumers: BTreeMap<SecretHandle, Vec<ExecutableIdentity>>,
    unresolved_consumers: BTreeMap<SecretHandle, u64>,
    index: Mutex<ExactIndex>,
    fingerprints: FingerprintReport,
}

impl core::fmt::Debug for SecretsState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecretsState")
            .field("secrets", &self.config.secrets.len())
            .finish_non_exhaustive()
    }
}

/// What start-up fingerprinting did: counts and typed failures, never a value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FingerprintReport {
    /// Secrets now matched exactly on the return path.
    pub indexed: u64,
    /// Secrets whose value is shorter than the exact index accepts.
    pub too_short: u64,
    /// Secrets whose value could not be read, with the typed reason.
    pub failed: Vec<(SecretHandle, SecretError)>,
}

impl SecretsState {
    /// No secrets: the exact index is empty and needs no randomness.
    pub(crate) fn none() -> Self {
        Self {
            config: SecretConfig::default(),
            consumers: BTreeMap::new(),
            unresolved_consumers: BTreeMap::new(),
            index: Mutex::new(ExactIndex::empty()),
            fingerprints: FingerprintReport::default(),
        }
    }

    /// Prepare the state for `config`, outside any transaction: resolve every
    /// consumer path to an executable identity, and fingerprint every
    /// configured secret for the exact index — reading each value once and
    /// dropping it at once.
    ///
    /// # Errors
    ///
    /// A message when the OS random source fails: the index is never keyed
    /// predictably.
    pub(crate) fn prepare(config: &SecretConfig, authority_uid: u32) -> Result<Self, String> {
        if config.secrets.is_empty() {
            return Ok(Self::none());
        }
        let mut consumers = BTreeMap::new();
        let mut unresolved_consumers = BTreeMap::new();
        for secret in &config.secrets {
            let mut identities: Vec<ExecutableIdentity> = Vec::new();
            let mut unresolved = 0u64;
            for path in &secret.consumers {
                match exec::resolve(path, authority_uid) {
                    Ok(resolved) => {
                        let identity = resolved.identity().clone();
                        if !identities.contains(&identity) {
                            identities.push(identity);
                        }
                    }
                    Err(_) => unresolved = unresolved.saturating_add(1),
                }
            }
            consumers.insert(secret.handle.clone(), identities);
            unresolved_consumers.insert(secret.handle.clone(), unresolved);
        }
        let mut index = ExactIndex::new().map_err(|_| {
            "the operating system's random source failed: no redaction key".to_owned()
        })?;
        let mut fingerprints = FingerprintReport::default();
        for secret in &config.secrets {
            match backend::read(&secret.storage, config.age.as_ref(), authority_uid) {
                Ok(value) => {
                    if value.len() < MIN_EXACT_BYTES {
                        fingerprints.too_short = fingerprints.too_short.saturating_add(1);
                    } else if index.insert(&secret.handle, &value).is_ok() {
                        fingerprints.indexed = fingerprints.indexed.saturating_add(1);
                    }
                    // `value` is dropped here, and its bytes zeroized.
                }
                Err(error) => fingerprints.failed.push((secret.handle.clone(), error)),
            }
        }
        Ok(Self {
            config: config.clone(),
            consumers,
            unresolved_consumers,
            index: Mutex::new(index),
            fingerprints,
        })
    }

    /// The configuration.
    pub(crate) const fn config(&self) -> &SecretConfig {
        &self.config
    }

    /// One secret's metadata.
    pub(crate) fn metadata(&self, handle: &SecretHandle) -> Option<&SecretMetadata> {
        self.config.get(handle)
    }

    /// The executable identities a secret's consumers resolved to.
    pub(crate) fn consumers(&self, handle: &SecretHandle) -> &[ExecutableIdentity] {
        self.consumers.get(handle).map_or(&[], Vec::as_slice)
    }

    /// Redact `bytes` against the exact index and the known shapes.
    pub(crate) fn redact(&self, bytes: &[u8]) -> Redaction {
        let index = self.index.lock().unwrap_or_else(PoisonError::into_inner);
        redact::redact(bytes, &index)
    }

    /// Redact `raw` for the return path, then zeroize `raw`: the redacted
    /// bytes, cut to `limit` if placeholders made them longer.
    pub(crate) fn redact_bounded(&self, raw: &mut Vec<u8>, limit: usize) -> Redacted {
        let redaction = self.redact(raw);
        zeroize::Zeroize::zeroize(raw);
        let mut bytes = redaction.bytes;
        let cut = bytes.len() > limit;
        if cut {
            bytes.truncate(limit);
        }
        Redacted {
            bytes,
            cut,
            hits: redaction.hits,
        }
    }

    /// Fingerprint a value just resolved for a use (a secret whose start-up
    /// read failed is indexed from its first use on).
    pub(crate) fn register(
        &self,
        handle: &SecretHandle,
        value: &crate::secret::material::SecretMaterial,
    ) {
        let mut index = self.index.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = index.insert(handle, value);
    }

    /// Whether `handle` is in the exact index.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn indexed(&self, handle: &SecretHandle) -> bool {
        self.index
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(handle)
    }
}

/// The canonical, non-secret description of one secret: what a revision
/// records and what its digest covers.
fn canonical(secret: &SecretMetadata, consumers: &[ExecutableIdentity]) -> String {
    let text = |s: &str| Value::String(s.to_owned());
    let list = |items: Vec<String>| Value::Array(items.into_iter().map(Value::String).collect());
    let mut object = json::Object::new();
    let mut put = |key: &str, value: Value| {
        let _ = object.insert(key.to_owned(), value);
    };
    put("type", text(secret.secret_type.as_str()));
    put("description", text(&secret.description));
    put("backend", text(secret.storage.backend()));
    put("reference", text(secret.storage.reference()));
    put(
        "origins",
        list(secret.origins.iter().map(ToString::to_string).collect()),
    );
    put(
        "header",
        secret
            .header
            .as_ref()
            .map_or(Value::Null, |h| text(h.as_str())),
    );
    put(
        "prefix",
        secret
            .prefix
            .as_ref()
            .map_or(Value::Null, |p| text(p.as_str())),
    );
    put(
        "injection",
        list(
            secret
                .injection
                .iter()
                .map(|m| m.as_str().to_owned())
                .collect(),
        ),
    );
    put(
        "consumers",
        list(consumers.iter().map(ToString::to_string).collect()),
    );
    put(
        "env",
        secret
            .env
            .as_ref()
            .map_or(Value::Null, |e| text(e.as_str())),
    );
    put(
        "rotate_after_days",
        secret.rotate_after_days.map_or(Value::Null, |d| {
            Value::Number(json::Number::Int(i64::from(d)))
        }),
    );
    put("sensitivity", text(secret.sensitivity.as_str()));
    json::to_canonical_string(&Value::Object(object))
}

/// A handle's current revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Current {
    pub(crate) revision: i64,
    pub(crate) state: String,
    digest: String,
}

/// Every handle's current revision.
fn latest(work: &Work<'_>) -> Result<BTreeMap<String, Current>, AuthorityError> {
    let mut statement = work.db(work.tx.prepare(
        "SELECT r.handle, r.revision, r.state, r.metadata_sha256 FROM secret_revision r \
         WHERE r.revision = (SELECT max(s.revision) FROM secret_revision s WHERE s.handle = r.handle)",
    ))?;
    let rows = work.db(statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            Current {
                revision: row.get(1)?,
                state: row.get(2)?,
                digest: row.get(3)?,
            },
        ))
    }))?;
    let mut out = BTreeMap::new();
    for row in rows {
        let (handle, current) = work.db(row)?;
        out.insert(handle, current);
    }
    Ok(out)
}

/// One handle's current revision, if any.
pub(crate) fn current(work: &Work<'_>, handle: &str) -> Result<Option<Current>, AuthorityError> {
    work.db(work
        .tx
        .query_row(
            "SELECT revision, state, metadata_sha256 FROM secret_revision WHERE handle = ?1 \
                 ORDER BY revision DESC LIMIT 1",
            [handle],
            |row| {
                Ok(Current {
                    revision: row.get(0)?,
                    state: row.get(1)?,
                    digest: row.get(2)?,
                })
            },
        )
        .optional())
}

/// One new row of `secret_revision`: metadata and its digest, never a value.
fn insert_revision(
    work: &mut Work<'_>,
    handle: &str,
    revision: i64,
    row_state: &str,
    backend: Option<&str>,
    metadata: &str,
) -> Result<(), AuthorityError> {
    let now = to_sql(work.now)?;
    let digest = DomainHash::new(digest::SECRET_METADATA)
        .text(metadata)
        .finish()
        .to_hex();
    work.db(work.tx.execute(
        "INSERT INTO secret_revision (handle, revision, state, backend, metadata, metadata_sha256, \
         recorded_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![handle, revision, row_state, backend, metadata, digest, now],
    ))?;
    Ok(())
}

/// How many configured values the redaction index holds, and which could not
/// be read at start and why: counts and codes, never a value.
fn audit_fingerprints(work: &mut Work<'_>, state: &SecretsState) -> Result<(), AuthorityError> {
    if state.config.secrets.is_empty() {
        return Ok(());
    }
    let report = &state.fingerprints;
    work.audit(
        AuditEvent::SecretFingerprinted,
        Fields::new()
            .int("indexed", report.indexed)
            .int("too_short", report.too_short)
            .list(
                "failed",
                report
                    .failed
                    .iter()
                    .map(|(handle, error)| {
                        Field::Object(vec![
                            ("handle", Field::Text(handle.as_str().to_owned())),
                            ("reason", Field::Text(error.code().to_owned())),
                        ])
                    })
                    .collect(),
            ),
    )
}

/// Record, as new revisions, every way the configuration now differs from
/// the index: a new or changed secret, a revocation, a removal. Inside the
/// start transaction; audited.
pub(crate) fn reconcile(work: &mut Work<'_>, state: &SecretsState) -> Result<u64, AuthorityError> {
    let existing = latest(work)?;
    let mut recorded = 0u64;
    for secret in &state.config.secrets {
        let handle = secret.handle.as_str();
        let metadata = canonical(secret, state.consumers(&secret.handle));
        let row_state = if secret.revoked {
            "REVOKED"
        } else {
            "CONFIGURED"
        };
        let digest = DomainHash::new(digest::SECRET_METADATA)
            .text(&metadata)
            .finish()
            .to_hex();
        let previous = existing.get(handle);
        let unchanged = previous.is_some_and(|p| p.digest == digest && p.state == row_state);
        if unchanged {
            continue;
        }
        let revision = previous.map_or(1, |p| p.revision.saturating_add(1));
        insert_revision(
            work,
            handle,
            revision,
            row_state,
            Some(secret.storage.backend()),
            &metadata,
        )?;
        recorded = recorded.saturating_add(1);
        let unresolved = state
            .unresolved_consumers
            .get(&secret.handle)
            .copied()
            .unwrap_or(0);
        work.audit(
            AuditEvent::SecretConfigured,
            Fields::new()
                .text("handle", handle)
                .int("revision", u64::try_from(revision).unwrap_or(0))
                .text("state", row_state)
                .text("backend", secret.storage.backend())
                .text("type", secret.secret_type.as_str())
                .text("sensitivity", secret.sensitivity.as_str())
                .int(
                    "consumers",
                    u64::try_from(state.consumers(&secret.handle).len()).unwrap_or(0),
                )
                .int("consumers_unresolved", unresolved)
                .text("metadata_sha256", digest),
        )?;
        if secret.revoked && previous.is_none_or(|p| p.state != "REVOKED") {
            work.audit(
                AuditEvent::SecretRevoked,
                Fields::new()
                    .text("handle", handle)
                    .int("revision", u64::try_from(revision).unwrap_or(0)),
            )?;
        }
    }
    for (handle, previous) in &existing {
        let configured = state
            .config
            .secrets
            .iter()
            .any(|s| s.handle.as_str() == handle);
        if configured || previous.state == "REMOVED" {
            continue;
        }
        let revision = previous.revision.saturating_add(1);
        insert_revision(work, handle, revision, "REMOVED", None, "{}")?;
        recorded = recorded.saturating_add(1);
        work.audit(
            AuditEvent::SecretConfigured,
            Fields::new()
                .text("handle", handle.as_str())
                .int("revision", u64::try_from(revision).unwrap_or(0))
                .text("state", "REMOVED"),
        )?;
    }
    audit_fingerprints(work, state)?;
    Ok(recorded)
}

/// The answer for each concrete handle an admission names: its current
/// revision if it is configured and not revoked. A metadata read; no backend
/// is touched.
pub(crate) fn answers(
    work: &Work<'_>,
    handles: &[String],
) -> Result<BTreeMap<String, Option<i64>>, AuthorityError> {
    let mut out = BTreeMap::new();
    for handle in handles {
        let answer = current(work, handle)?
            .filter(|c| c.state == "CONFIGURED")
            .map(|c| c.revision);
        out.insert(handle.clone(), answer);
    }
    Ok(out)
}

/// Bind `run` to `revision` of `handle`: the secret the run was admitted with.
pub(crate) fn bind(
    work: &Work<'_>,
    run: &str,
    handle: &str,
    revision: i64,
) -> Result<(), AuthorityError> {
    work.db(work.tx.execute(
        "INSERT OR IGNORE INTO secret_run_binding (run_id, handle, revision) VALUES (?1, ?2, ?3)",
        rusqlite::params![run, handle, revision],
    ))?;
    Ok(())
}

/// Whether `run` may use `handle` now: the handle is configured, unrevoked,
/// and the revision the run was bound to. A wildcard grant binds at first use.
///
/// # Errors
///
/// [`SecretError::NotConfigured`], [`SecretError::Revoked`] or
/// [`SecretError::Replaced`], inside `Ok`; an `AuthorityError` when the store
/// cannot answer.
pub(crate) fn check_use(
    work: &Work<'_>,
    run: &str,
    handle: &str,
) -> Result<Result<i64, SecretError>, AuthorityError> {
    let Some(now) = current(work, handle)? else {
        return Ok(Err(SecretError::NotConfigured));
    };
    match now.state.as_str() {
        "REMOVED" => return Ok(Err(SecretError::NotConfigured)),
        "REVOKED" => return Ok(Err(SecretError::Revoked)),
        _ => {}
    }
    let bound: Option<i64> = work.db(work
        .tx
        .query_row(
            "SELECT revision FROM secret_run_binding WHERE run_id = ?1 AND handle = ?2",
            [run, handle],
            |row| row.get(0),
        )
        .optional())?;
    match bound {
        Some(revision) if revision != now.revision => Ok(Err(SecretError::Replaced)),
        Some(revision) => Ok(Ok(revision)),
        None => {
            bind(work, run, handle, now.revision)?;
            Ok(Ok(now.revision))
        }
    }
}

/// Record what redaction removed from one invocation's output: which handle
/// or pattern class, how many times — never the bytes, never a prefix.
pub(crate) fn audit_hits(
    work: &mut Work<'_>,
    run: &str,
    invocation: &str,
    tool: &str,
    hits: &Hits,
) -> Result<(), AuthorityError> {
    if hits.is_empty() {
        return Ok(());
    }
    let items = hits
        .iter()
        .map(|(kind, count)| {
            let (key, value) = match kind {
                redact::HitKind::Handle(handle) => ("handle", handle.as_str().to_owned()),
                redact::HitKind::Pattern(class) => ("pattern", class.as_str().to_owned()),
            };
            Field::Object(vec![
                (key, Field::Text(value)),
                ("count", Field::Int(*count)),
            ])
        })
        .collect();
    work.audit(
        AuditEvent::SecretRedactionHit,
        Fields::new()
            .text("run_id", run)
            .text("invocation_id", invocation)
            .text("tool", tool)
            .list("hits", items),
    )
}
