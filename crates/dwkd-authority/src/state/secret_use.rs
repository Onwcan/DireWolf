//! One secret use, mode A (M4e, ADR-0046 §§11–12, 17–20): the authority's
//! pipeline from a handle to a one-shot handoff the broker consumes once.
//!
//! **A secret use is not a tool.** It is the secret side of a containing
//! egress invocation — `net.http`, which is M5's. M4e has no such tool, so
//! the pipeline is an in-process authority API ([`super::Authority::secret_egress`])
//! with no DWKP route: no runtime can call it, and nothing on the wire names
//! it. It exists so that everything the secret side must guarantee is real
//! and measured before the consumer arrives.
//!
//! # The order (ADR-0046 §17)
//!
//! | step | where | a value exists? |
//! |---|---|---|
//! | 1. fence, run, key | transaction | no |
//! | 2. the request, typed: handle, concrete origin | transaction | no |
//! | 4. metadata only: configured, unrevoked, the run's revision | transaction | no |
//! | 5. the mode, from the operator's metadata, never the request | transaction | no |
//! | 6–8. `secret.use:<handle>` through both gates; obligations enforceable | transaction | no |
//! | 9. durable intent, audited | commit | no |
//! | 10. the backend read | **no transaction** | the authority's, zeroizing |
//! | 11. the redaction index learns it | memory | yes |
//! | 12. the one-shot pipe; the authority's copy zeroed | no transaction | the pipe's |
//! | 13. the broker reads it once, renders, drops | the broker | the broker's, briefly |
//! | 14–16. the outcome, the use count, durably | transaction | no |
//!
//! Nothing is read from a backend before step 9 commits. A denial at any step
//! before it injects nothing and reads nothing. A key used before answers the
//! recorded outcome and reads nothing. An intent a previous incarnation left
//! open is ended `UNKNOWN` at start ([`reconcile_open`]) and never injected
//! again: the containing invocation's retry rules decide what happens next,
//! and there is no standalone retry loop for a secret.

use dwk_proto::brokerp::{EgressSpec, SecretHeaderName, SecretHeaderPrefix, SecretOrigin};
use dwk_proto::wire::id::{InvocationId, RunId, SessionId};
use dwk_proto::wire::scalar::{Epoch, IdempotencyKey};
use rusqlite::OptionalExtension as _;

use crate::broker::{BrokerDelivery, BrokerError, BrokerFailure};
use crate::capability::{
    Action, Capability, ConstraintSet, Endpoint, Label, Namespace, Scope, SyntacticScope, Verb,
};
use crate::policy::{CanonicalAction, Environment, Obligation};
use crate::secret::SecretError;
use crate::secret::metadata::{InjectionMode, SecretHandle, SecretMetadata};
use crate::secret::select::{self, Consumption};

use super::Work;
use super::admission;
use super::audit::{AuditEvent, Field, Fields};
use super::error::AuthorityError;
use super::identity::CallerContext;
use super::lease::{self, to_sql};
use super::policy_state::ActiveAuthority;
use super::query::{self, DecisionRecord};
use super::secrets::{self, SecretsState};
use super::tool;

/// One mode A use, as the containing invocation would state it: the handle
/// and the concrete origin, and the key that makes it happen at most once.
/// No header, no prefix, no mode: the operator's metadata supplies those.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRequest {
    /// The handle.
    pub handle: String,
    /// The origin the value is for: `host:port`, lowercase, concrete.
    pub origin: String,
    /// The idempotency key.
    pub key: IdempotencyKey,
}

/// What a mode A use came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressReply {
    /// Refused before any decision — the fence, the run, a malformed request
    /// — and recorded. Nothing was read or injected.
    Refused(&'static str),
    /// The key was used before: its recorded outcome. Nothing was read or
    /// injected again.
    Replayed {
        /// The invocation the key is bound to.
        invocation: InvocationId,
        /// Its recorded state.
        state: String,
        /// Its recorded failure, if it failed.
        failure: Option<String>,
    },
    /// Denied — by the metadata, the selector, a gate or an unenforceable
    /// obligation — with the typed reason. Nothing was read or injected.
    Denied(&'static str),
    /// The broker received the value once and accepted it.
    Injected {
        /// The invocation.
        invocation: InvocationId,
    },
    /// Provably not injected: the backend failed, the value cannot be carried
    /// safely, or the broker refused or was never reached.
    Failed {
        /// The invocation.
        invocation: InvocationId,
        /// Why, from a closed vocabulary.
        reason: &'static str,
    },
    /// The broker may have received the value and cannot say.
    Unknown {
        /// The invocation.
        invocation: InvocationId,
    },
}

/// Who asks, about what.
#[derive(Debug, Clone, Copy)]
pub(super) struct Asked<'a> {
    pub(super) caller: &'a CallerContext,
    pub(super) session: &'a SessionId,
    pub(super) run: &'a RunId,
    pub(super) epoch: Epoch,
    pub(super) request: &'a EgressRequest,
}

/// A use both gates allowed, whose intent is durable.
#[derive(Debug, Clone)]
pub(super) struct Authorised {
    pub(super) invocation: InvocationId,
    pub(super) handle: SecretHandle,
    pub(super) revision: i64,
    pub(super) metadata: SecretMetadata,
    pub(super) spec: EgressSpec,
}

/// What steps 1–9 decided.
#[derive(Debug)]
pub(super) enum Decided {
    Refused(&'static str),
    Replayed {
        invocation: InvocationId,
        state: String,
        failure: Option<String>,
    },
    Denied(&'static str),
    Authorised(Box<Authorised>),
}

/// How a use ended, before it is recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Ending {
    Injected,
    Failed(&'static str),
    Unknown,
}

fn base_fields(asked: &Asked<'_>) -> Fields {
    Fields::new()
        .text("subject", asked.caller.subject().storage_key())
        .text("holder", asked.caller.holder().to_string())
        .text("session_id", asked.session.as_str())
        .text("run_id", asked.run.as_str())
        .int("epoch", asked.epoch.get())
        .text("handle", asked.request.handle.as_str())
        .text("origin", asked.request.origin.as_str())
        .text("idempotency_key", asked.request.key.as_str())
        .text("environment", "host")
}

fn deny(
    work: &mut Work<'_>,
    asked: &Asked<'_>,
    reason: &'static str,
    extra: Fields,
) -> Result<Decided, AuthorityError> {
    let mut fields = base_fields(asked).text("reason", reason);
    fields.extend(extra);
    work.audit(AuditEvent::SecretDenied, fields)?;
    Ok(Decided::Denied(reason))
}

/// The capability a use of `handle` requires: `secret.use:<handle>`.
fn required(handle: &SecretHandle) -> Result<Capability, AuthorityError> {
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
fn obligations_enforced(record: &DecisionRecord) -> bool {
    record
        .policy()
        .obligations()
        .as_slice()
        .iter()
        .all(|o| matches!(o, Obligation::AuditLevel(_)))
}

fn gate_fields(active: &ActiveAuthority, record: &DecisionRecord) -> Fields {
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

/// A key already bound: its invocation and recorded outcome.
fn bound(
    work: &Work<'_>,
    asked: &Asked<'_>,
) -> Result<Option<(String, String, Option<String>)>, AuthorityError> {
    work.db(work
        .tx
        .query_row(
            "SELECT invocation_id, state, failure FROM secret_injection WHERE subject = ?1 \
             AND session_id = ?2 AND idempotency_key = ?3",
            rusqlite::params![
                asked.caller.subject().storage_key(),
                asked.session.as_str(),
                asked.request.key.as_str()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional())
}

fn refuse(
    work: &mut Work<'_>,
    asked: &Asked<'_>,
    reason: &'static str,
) -> Result<Decided, AuthorityError> {
    work.audit(
        AuditEvent::SecretDenied,
        base_fields(asked).text("refusal", reason),
    )?;
    Ok(Decided::Refused(reason))
}

/// Step 1: the fence and the run, then the key. `Some` is the answer when
/// the use stops here: a refusal, or a replayed key's recorded outcome.
fn fenced(
    work: &mut Work<'_>,
    asked: &Asked<'_>,
    active: &ActiveAuthority,
) -> Result<Option<Decided>, AuthorityError> {
    if !lease::fence(work, asked.caller, asked.session, asked.epoch)? {
        return refuse(work, asked, "STALE_EPOCH").map(Some);
    }
    if !tool::run_is_held(
        work,
        asked.caller,
        asked.session,
        asked.run,
        asked.epoch,
        active,
    )? {
        return refuse(work, asked, "UNKNOWN_RUN").map(Some);
    }
    if let Some((invocation, state, failure)) = bound(work, asked)? {
        let invocation = InvocationId::parse(&invocation).ok_or(AuthorityError::Invariant(
            "a stored invocation id does not parse",
        ))?;
        work.audit(
            AuditEvent::SecretDenied,
            base_fields(asked)
                .text("refusal", "IDEMPOTENCY_KEY_REPLAYED")
                .text("invocation_id", invocation.as_str())
                .text("recorded_state", state.as_str()),
        )?;
        return Ok(Some(Decided::Replayed {
            invocation,
            state,
            failure,
        }));
    }
    Ok(None)
}

/// Step 9: the durable intent, audited with the gates that allowed it.
fn record_intent(
    work: &mut Work<'_>,
    asked: &Asked<'_>,
    authorised: &Authorised,
    revision: i64,
    gates: Fields,
) -> Result<(), AuthorityError> {
    let invocation = &authorised.invocation;
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
            asked.request.key.as_str(),
            authorised.handle.as_str(),
            revision,
            authorised.spec.origin.as_str(),
            to_sql(work.incarnation())?,
            to_sql(work.now)?
        ],
    ))?;
    let mut fields = base_fields(asked)
        .text("invocation_id", invocation.as_str())
        .int("revision", u64::try_from(revision).unwrap_or(0))
        .text("backend", authorised.metadata.storage.backend())
        .text("header", authorised.spec.header_name.as_str());
    fields.extend(gates);
    work.audit(AuditEvent::SecretIntentRecorded, fields)
}

/// Steps 1–9, in one transaction. No backend is touched.
pub(super) fn decide(
    work: &mut Work<'_>,
    asked: &Asked<'_>,
    secrets_state: &SecretsState,
    active: &ActiveAuthority,
    after_metadata: &dyn Fn() -> Result<(), AuthorityError>,
) -> Result<Decided, AuthorityError> {
    // 1. The fence and the run, then the key.
    if let Some(stopped) = fenced(work, asked, active)? {
        return Ok(stopped);
    }
    // 2. The request, typed. The origin is concrete: a lowercase name and a
    // port, never a pattern.
    let (Some(handle), Some(wire_origin)) = (
        SecretHandle::new(&asked.request.handle),
        SecretOrigin::new(asked.request.origin.as_str()),
    ) else {
        return refuse(work, asked, "MALFORMED_REQUEST");
    };
    let Ok(origin) = Endpoint::parse(wire_origin.as_str()) else {
        return refuse(work, asked, "MALFORMED_REQUEST");
    };
    // 4. The metadata, and the revision the run may use. Nothing else.
    let Some(metadata) = secrets_state.metadata(&handle).cloned() else {
        return deny(
            work,
            asked,
            SecretError::NotConfigured.code(),
            Fields::new(),
        );
    };
    let revision = match secrets::check_use(work, asked.run.as_str(), handle.as_str())? {
        Ok(revision) => revision,
        Err(error) => return deny(work, asked, error.code(), Fields::new()),
    };
    after_metadata()?;
    // 5. The mode: the operator's allowlist and origins decide, never the
    // request.
    let mode = match select::select(
        &metadata,
        secrets_state.consumers(&handle),
        &Consumption::Egress { origin: &origin },
    ) {
        Ok(mode) => mode,
        Err(error) => return deny(work, asked, error.code(), Fields::new()),
    };
    if mode != InjectionMode::Egress {
        return Err(AuthorityError::Invariant(
            "an egress use selected another mode",
        ));
    }
    // The header comes from the metadata, which the loader proved an egress
    // secret has.
    let Some(header) = metadata
        .header
        .as_ref()
        .and_then(|h| SecretHeaderName::new(h.as_str()))
    else {
        return deny(
            work,
            asked,
            SecretError::InjectionModeUnavailable.code(),
            Fields::new(),
        );
    };
    let prefix = metadata
        .prefix
        .as_ref()
        .and_then(|p| SecretHeaderPrefix::new(p.as_str()));
    let wire_handle = dwk_proto::brokerp::SecretHandle::new(handle.as_str())
        .ok_or(AuthorityError::Invariant("a handle does not fit the wire"))?;
    // 6-8. `secret.use:<handle>` through both gates, and the obligations.
    let admission = admission::load(work, asked.run.as_str())?;
    let context = query::policy_context(work, asked.run.as_str(), active)?;
    let action = CanonicalAction::new(required(&handle)?, Environment::Host);
    let record = query::decide(&action, &admission, &context, active);
    let gates = gate_fields(active, &record).text("mode", mode.as_str());
    if !record.capability_satisfied() {
        return deny(work, asked, "CAPABILITY_NOT_GRANTED", gates);
    }
    if !record.policy_satisfied() {
        return deny(work, asked, "POLICY_DENIED", gates);
    }
    if !obligations_enforced(&record) {
        return deny(work, asked, "OBLIGATION_UNENFORCEABLE", gates);
    }
    // 9. The durable intent.
    let authorised = Authorised {
        invocation: work.invocation_id()?,
        handle,
        revision,
        metadata,
        spec: EgressSpec {
            handle: wire_handle,
            origin: wire_origin,
            header_name: header,
            header_prefix: prefix,
        },
    };
    record_intent(work, asked, &authorised, revision, gates)?;
    Ok(Decided::Authorised(Box::new(authorised)))
}

/// The broker's answer, as an ending. A refusal, or a failure before the
/// authorisation left, provably injected nothing.
pub(super) fn classify(result: &Result<BrokerDelivery, BrokerError>) -> Ending {
    match result {
        Ok(BrokerDelivery::SecretEgress) => Ending::Injected,
        Err(error) if !error.sent => Ending::Failed(match error.failure {
            BrokerFailure::Protocol(_) => "BROKER_PROTOCOL_ERROR",
            _ => "BROKER_UNAVAILABLE",
        }),
        Err(BrokerError {
            failure: BrokerFailure::Refused(refusal),
            ..
        }) => Ending::Failed(refusal.as_str()),
        // Another operation's answer, or a failure after the authorisation
        // left: the broker may have read the value and cannot say.
        _ => Ending::Unknown,
    }
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
    let base = || {
        Fields::new()
            .text("invocation_id", authorised.invocation.as_str())
            .text("run_id", run.as_str())
            .text("handle", authorised.handle.as_str())
            .int("revision", u64::try_from(authorised.revision).unwrap_or(0))
            .text("mode", InjectionMode::Egress.as_str())
            .text("origin", authorised.spec.origin.as_str())
            .text("backend", authorised.metadata.storage.backend())
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
            rusqlite::params![authorised.handle.as_str(), to_sql(work.now)?],
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
