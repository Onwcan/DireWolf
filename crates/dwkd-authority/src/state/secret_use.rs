//! One secret use, mode A (M4e, ADR-0046 §§11–12, 17–20): the authority's
//! pipeline from a handle to a one-shot handoff the broker consumes once —
//! as the credential of one `net.http` hop, its consumer (M5c, ADR-0050 §8).
//!
//! **A secret use is not a tool.** It is the secret side of a containing
//! egress invocation: each hop of a `net.http` that names a credential and is
//! at the request's own origin is one use, decided and recorded on its own.
//! M4e's in-process stand-in for that consumer (`Authority::secret_egress`,
//! and the broker's render-and-drop `broker.secret_egress`) is retired:
//! nothing but a hop reaches this module.
//!
//! # The order (ADR-0046 §17, ADR-0050 §5)
//!
//! | step | where | a value exists? |
//! |---|---|---|
//! | 1. fence, run, key — the request's | the hop's transaction | no |
//! | 2. the handle, typed; the origin, the hop's, concrete | the request's first transaction | no |
//! | 4. metadata only: configured, unrevoked, the run's revision | transaction | no |
//! | 5. the mode, from the operator's metadata, never the request | transaction | no |
//! | 6–8. `secret.use:<handle>` through both gates; obligations enforceable | the hop's transaction | no |
//! | 9. durable intent, audited, with the hop's | commit | no |
//! | 10. the backend read | **no transaction** | the authority's, zeroizing |
//! | 11. the redaction index learns it | memory | yes |
//! | 12. the one-shot pipe; the authority's copy zeroed | no transaction | the pipe's |
//! | 13. the broker reads it once, renders it into the hop's request | the broker | the broker's, for one exchange |
//! | 14–16. the outcome, the use count, durably | transaction | no |
//!
//! Nothing is read from a backend before step 9 commits. A denial at any step
//! before it injects nothing and reads nothing. An intent a previous
//! incarnation left open is ended `UNKNOWN` at start ([`reconcile_open`]) and
//! never injected again: the hop is never performed again either, and there
//! is no standalone retry loop for a secret.

use dwk_proto::brokerp::http::HttpCredential;
use dwk_proto::brokerp::{SecretHeaderName, SecretHeaderPrefix, SecretOrigin};
use dwk_proto::wire::id::{InvocationId, RunId, SessionId};
use dwk_proto::wire::scalar::Epoch;

use crate::capability::{
    Action, Capability, ConstraintSet, Endpoint, Label, Namespace, Scope, SyntacticScope, Verb,
};
use crate::policy::Obligation;
use crate::secret::SecretError;
use crate::secret::metadata::{InjectionMode, SecretHandle, SecretMetadata};
use crate::secret::select::{self, Consumption};

use super::Work;
use super::audit::{AuditEvent, Field, Fields};
use super::error::AuthorityError;
use super::identity::CallerContext;
use super::lease::to_sql;
use super::policy_state::ActiveAuthority;
use super::query::DecisionRecord;
use super::secrets::{self, SecretsState};

/// Who asks for a credential, where: the request's caller and run, the
/// handle its call named, and the hop's origin.
#[derive(Debug, Clone, Copy)]
pub(super) struct Asked<'a> {
    pub(super) caller: &'a CallerContext,
    pub(super) session: &'a SessionId,
    pub(super) run: &'a RunId,
    pub(super) epoch: Epoch,
    /// The handle, as the call named it.
    pub(super) handle: &'a str,
    /// The hop's origin: `host:port`, canonical.
    pub(super) origin: &'a str,
    /// The use's key, once the request has an invocation: `<invocation>:<hop>`.
    pub(super) key: Option<&'a str>,
}

/// A credential the operator's metadata allows at the hop's origin, before
/// either gate: steps 2, 4 and 5.
#[derive(Debug, Clone)]
pub(super) struct Prepared {
    pub(super) handle: SecretHandle,
    pub(super) revision: i64,
    pub(super) metadata: SecretMetadata,
    /// The origin, as the private protocol spells it.
    pub(super) origin: SecretOrigin,
    /// What the broker renders: the handle, the header, the prefix. Never the
    /// value.
    pub(super) credential: HttpCredential,
}

/// A use both gates allowed, whose intent is durable.
#[derive(Debug, Clone)]
pub(super) struct Authorised {
    pub(super) invocation: InvocationId,
    pub(super) prepared: Prepared,
}

/// How a use ended, before it is recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Ending {
    /// The value went into a request the broker wrote.
    Injected,
    /// Provably not sent, with the typed reason.
    Failed(&'static str),
    /// It may have been sent, and nothing proves whether.
    Unknown,
}

fn base_fields(asked: &Asked<'_>) -> Fields {
    Fields::new()
        .text("subject", asked.caller.subject().storage_key())
        .text("holder", asked.caller.holder().to_string())
        .text("session_id", asked.session.as_str())
        .text("run_id", asked.run.as_str())
        .int("epoch", asked.epoch.get())
        .text("handle", asked.handle)
        .text("origin", asked.origin)
        .maybe_text("idempotency_key", asked.key.map(str::to_owned))
        .text("consumer", "net.http")
        .text("environment", "host")
}

fn deny(
    work: &mut Work<'_>,
    asked: &Asked<'_>,
    reason: &'static str,
    extra: Fields,
) -> Result<&'static str, AuthorityError> {
    let mut fields = base_fields(asked).text("reason", reason);
    fields.extend(extra);
    work.audit(AuditEvent::SecretDenied, fields)?;
    Ok(reason)
}

/// The capability a use of `handle` requires: `secret.use:<handle>`.
pub(super) fn required(handle: &SecretHandle) -> Result<Capability, AuthorityError> {
    let verb = Verb::new(Namespace::Secret, Action::Use)
        .ok_or(AuthorityError::Invariant("secret.use is not a verb"))?;
    let label =
        Label::new(handle.as_str()).ok_or(AuthorityError::Invariant("a handle is not a label"))?;
    Capability::new(
        verb,
        Scope::Syntactic(SyntacticScope::CredentialHandle(label)),
        ConstraintSet::unconstrained(),
    )
    .map_err(|_| AuthorityError::Invariant("a secret capability does not assemble"))
}

/// Whether every obligation the decision carries is one a secret use keeps:
/// `audit_level` only. Anything else needs machinery a secret use does not
/// have (an execution environment, an approval), so the use is denied.
pub(super) fn obligations_enforced(record: &DecisionRecord) -> bool {
    record
        .policy()
        .obligations()
        .as_slice()
        .iter()
        .all(|o| matches!(o, Obligation::AuditLevel(_)))
}

pub(super) fn gate_fields(active: &ActiveAuthority, record: &DecisionRecord) -> Fields {
    let policy = record.policy();
    Fields::new()
        .text("policy_revision", active.revision.to_hex())
        .text(
            "required_capability",
            record.required().to_canonical_string(),
        )
        .flag("capability_satisfied", record.capability_satisfied())
        .maybe_text(
            "covering_cap_id",
            record.covering_grant().map(|c| c.as_str().to_owned()),
        )
        .text("policy_effect", policy.effect().as_str())
        .flag("policy_satisfied", record.policy_satisfied())
        .text("rule_id", policy.rule_id().as_str())
        .list(
            "obligations",
            policy
                .obligations()
                .as_slice()
                .iter()
                .map(|o| Field::Text(o.to_string()))
                .collect(),
        )
}

/// Steps 2, 4 and 5: the handle typed, the origin concrete, the metadata and
/// the revision the run may use, the mode — the operator's, never the
/// request's. `Ok(Err(reason))` is a denial, audited; nothing is read.
pub(super) fn prepare(
    work: &mut Work<'_>,
    asked: &Asked<'_>,
    secrets_state: &SecretsState,
    after_metadata: &dyn Fn() -> Result<(), AuthorityError>,
) -> Result<Result<Prepared, &'static str>, AuthorityError> {
    // 2. The handle, typed. The origin is concrete: a lowercase name and a
    // port, never a pattern — the hop's, which the URL parser produced.
    let (Some(handle), Some(origin)) = (
        SecretHandle::new(asked.handle),
        SecretOrigin::new(asked.origin),
    ) else {
        return deny(work, asked, "MALFORMED_REQUEST", Fields::new()).map(Err);
    };
    let Ok(endpoint) = Endpoint::parse(origin.as_str()) else {
        return deny(work, asked, "MALFORMED_REQUEST", Fields::new()).map(Err);
    };
    // 4. The metadata, and the revision the run may use. Nothing else.
    let Some(metadata) = secrets_state.metadata(&handle).cloned() else {
        return deny(
            work,
            asked,
            SecretError::NotConfigured.code(),
            Fields::new(),
        )
        .map(Err);
    };
    let revision = match secrets::check_use(work, asked.run.as_str(), handle.as_str())? {
        Ok(revision) => revision,
        Err(error) => return deny(work, asked, error.code(), Fields::new()).map(Err),
    };
    after_metadata()?;
    // 5. The mode: the operator's allowlist and origins decide, never the
    // request.
    let mode = match select::select(
        &metadata,
        secrets_state.consumers(&handle),
        &Consumption::Egress { origin: &endpoint },
    ) {
        Ok(mode) => mode,
        Err(error) => return deny(work, asked, error.code(), Fields::new()).map(Err),
    };
    if mode != InjectionMode::Egress {
        return Err(AuthorityError::Invariant(
            "an egress use selected another mode",
        ));
    }
    // The header comes from the metadata, which the loader proved an egress
    // secret has.
    let Some(header_name) = metadata
        .header
        .as_ref()
        .and_then(|h| SecretHeaderName::new(h.as_str()))
    else {
        return deny(
            work,
            asked,
            SecretError::InjectionModeUnavailable.code(),
            Fields::new(),
        )
        .map(Err);
    };
    let header_prefix = metadata
        .prefix
        .as_ref()
        .and_then(|p| SecretHeaderPrefix::new(p.as_str()));
    let wire_handle = dwk_proto::brokerp::SecretHandle::new(handle.as_str())
        .ok_or(AuthorityError::Invariant("a handle does not fit the wire"))?;
    Ok(Ok(Prepared {
        handle,
        revision,
        metadata,
        origin,
        credential: HttpCredential {
            handle: wire_handle,
            header_name,
            header_prefix,
        },
    }))
}

/// Steps 6–8, judged: `Some(reason)` when `record` — `secret.use:<handle>`
/// through both gates — does not permit the use, audited with the gates.
pub(super) fn refused_by_gates(
    work: &mut Work<'_>,
    asked: &Asked<'_>,
    active: &ActiveAuthority,
    record: &DecisionRecord,
) -> Result<Option<&'static str>, AuthorityError> {
    let reason = if !record.capability_satisfied() {
        "CAPABILITY_NOT_GRANTED"
    } else if !record.policy_satisfied() {
        "POLICY_DENIED"
    } else if !obligations_enforced(record) {
        "OBLIGATION_UNENFORCEABLE"
    } else {
        return Ok(None);
    };
    let gates = gate_fields(active, record).text("mode", InjectionMode::Egress.as_str());
    deny(work, asked, reason, gates).map(Some)
}

/// Step 9: the durable intent, audited with the gates that allowed it. The
/// hop's own intent is recorded in the same transaction, after this.
pub(super) fn record_intent(
    work: &mut Work<'_>,
    asked: &Asked<'_>,
    prepared: Prepared,
    active: &ActiveAuthority,
    record: &DecisionRecord,
) -> Result<Authorised, AuthorityError> {
    let key = asked.key.ok_or(AuthorityError::Invariant(
        "a credential's intent is recorded without its key",
    ))?;
    let invocation = work.invocation_id()?;
    work.db(work.tx.execute(
        "INSERT INTO secret_injection (invocation_id, run_id, subject, session_id, \
         idempotency_key, handle, revision, mode, consumer, incarnation, state, failure, \
         intent_ms, ended_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'egress', ?8, ?9, 'INTENT', \
         NULL, ?10, NULL)",
        rusqlite::params![
            invocation.as_str(),
            asked.run.as_str(),
            asked.caller.subject().storage_key(),
            asked.session.as_str(),
            key,
            prepared.handle.as_str(),
            prepared.revision,
            prepared.origin.as_str(),
            to_sql(work.incarnation())?,
            to_sql(work.now)?
        ],
    ))?;
    let mut fields = base_fields(asked)
        .text("invocation_id", invocation.as_str())
        .int("revision", u64::try_from(prepared.revision).unwrap_or(0))
        .text("backend", prepared.metadata.storage.backend())
        .text("header", prepared.credential.header_name.as_str());
    fields.extend(gate_fields(active, record).text("mode", InjectionMode::Egress.as_str()));
    work.audit(AuditEvent::SecretIntentRecorded, fields)?;
    Ok(Authorised {
        invocation,
        prepared,
    })
}

/// Steps 14–16: the ending, durably; a confirmed injection counted once.
pub(super) fn record_outcome(
    work: &mut Work<'_>,
    authorised: &Authorised,
    run: &RunId,
    ending: Ending,
    resolved: bool,
) -> Result<(), AuthorityError> {
    let (state, failure, event) = match ending {
        Ending::Injected => ("INJECTED", None, AuditEvent::SecretInjected),
        Ending::Failed(reason) => ("FAILED", Some(reason), AuditEvent::SecretFailed),
        Ending::Unknown => ("UNKNOWN", None, AuditEvent::SecretOutcomeUnknown),
    };
    let ended = work.db(work.tx.execute(
        "UPDATE secret_injection SET state = ?2, failure = ?3, ended_ms = ?4 \
         WHERE invocation_id = ?1 AND state = 'INTENT'",
        rusqlite::params![
            authorised.invocation.as_str(),
            state,
            failure,
            to_sql(work.now)?
        ],
    ))?;
    if ended != 1 {
        return Err(AuthorityError::Invariant("a secret use was not open"));
    }
    let prepared = &authorised.prepared;
    let base = || {
        Fields::new()
            .text("invocation_id", authorised.invocation.as_str())
            .text("run_id", run.as_str())
            .text("handle", prepared.handle.as_str())
            .int("revision", u64::try_from(prepared.revision).unwrap_or(0))
            .text("mode", InjectionMode::Egress.as_str())
            .text("origin", prepared.origin.as_str())
            .text("backend", prepared.metadata.storage.backend())
    };
    if resolved {
        work.audit(AuditEvent::SecretResolved, base())?;
    }
    let mut fields = base().text("state", state);
    if let Some(reason) = failure {
        fields = fields.text("failure", reason);
    }
    if ending == Ending::Injected {
        let uses: i64 = work.db(work.tx.query_row(
            "INSERT INTO secret_use (handle, uses, last_used_ms) VALUES (?1, 1, ?2) \
             ON CONFLICT (handle) DO UPDATE SET uses = uses + 1, last_used_ms = ?2 \
             RETURNING uses",
            rusqlite::params![prepared.handle.as_str(), to_sql(work.now)?],
            |row| row.get(0),
        ))?;
        fields = fields.int("uses", u64::try_from(uses).unwrap_or(0));
    }
    work.audit(event, fields)
}

/// End every secret use a previous incarnation left open: `UNKNOWN`, never
/// injected again. Runs in the start-up transaction; returns how many.
pub(super) fn reconcile_open(work: &mut Work<'_>) -> Result<u64, AuthorityError> {
    let open: Vec<(String, String, String, i64)> = {
        let mut statement = work.db(work.tx.prepare(
            "SELECT invocation_id, run_id, handle, incarnation FROM secret_injection \
             WHERE state = 'INTENT' ORDER BY intent_ms, invocation_id",
        ))?;
        let rows = work.db(statement.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        }))?;
        work.db(rows.collect::<rusqlite::Result<_>>())?
    };
    for (invocation, run, handle, incarnation) in &open {
        let ended = work.db(work.tx.execute(
            "UPDATE secret_injection SET state = 'UNKNOWN', ended_ms = ?2 \
             WHERE invocation_id = ?1 AND state = 'INTENT'",
            rusqlite::params![invocation, to_sql(work.now)?],
        ))?;
        if ended != 1 {
            return Err(AuthorityError::Invariant(
                "an open secret use could not be ended",
            ));
        }
        work.audit(
            AuditEvent::SecretOutcomeUnknown,
            Fields::new()
                .text("invocation_id", invocation.clone())
                .text("run_id", run.clone())
                .text("handle", handle.clone())
                .int(
                    "intent_incarnation",
                    u64::try_from(*incarnation).unwrap_or(0),
                )
                .text("cause", "restart"),
        )?;
    }
    Ok(u64::try_from(open.len()).unwrap_or(u64::MAX))
}

// A real kernel keyring and a real store: Linux only, like the backends.
#[cfg(all(test, target_os = "linux"))]
mod tests;
