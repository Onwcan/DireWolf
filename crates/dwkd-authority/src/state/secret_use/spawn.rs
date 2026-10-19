//! One secret use at spawn (M5d.3, ADR-0046 §§11–12, 15–20; ADR-0052 §7):
//! modes C and B, **only in an execution environment**. The secret side of a
//! sandboxed `process.exec` that names a credential handle: the workload is
//! the containing invocation, and this is its one use, decided and recorded
//! beside it.
//!
//! # The order (ADR-0046 §17, as a workload's)
//!
//! | step | where | a value exists? |
//! |---|---|---|
//! | 1. fence, run, key -- the workload's | the route's transaction | no |
//! | 2. the handle, typed | the same transaction | no |
//! | 4. metadata only: configured, unrevoked, the run's revision | the same | no |
//! | 5. the consumer -- a path the operator's metadata names, as the executable the image manifest pins there -- and the mode, C before B, never the request's; for B, a variable the environment does not set | the same | no |
//! | 6–8. `secret.use:<handle>` through both gates for a `SANDBOX` action, beside the workload's own; obligations: `audit_level` only | the same | no |
//! | 9. the durable intent, linked to the workload's, audited | commit | no |
//! | 10. the backend read | **no transaction** | the authority's, zeroizing |
//! | 11. the redaction index learns it | memory | yes |
//! | 12. the one-shot pipe; the authority's copy zeroed | no transaction | the pipe's |
//! | 13. the broker re-judges the environment, proves the executable, reads it once and hands it, framed, to the launcher, which delivers it and executes the program | the broker, then the environment | the broker's; the program's |
//! | 14–16. the outcome, with the workload's, in one transaction; a delivery counted once | transaction | no |
//!
//! Nothing is read from a backend before step 9 commits. A refusal or a
//! denial before it reads nothing. An intent a previous incarnation left
//! open is `UNKNOWN` at start (`super::reconcile_open`) -- its workload too,
//! and its environment destroyed (`super::super::workload::reconcile_open`):
//! nothing is read, handed over or run again.
//!
//! **What a delivery is.** `INJECTED` means the value entered the
//! environment: the launcher received it and the program ran. It does not
//! mean the program used it, kept it to itself, or kept it from a process it
//! started -- descriptor 3 and the variable are both inherited (ADR-0052 §7).

use dwk_proto::brokerp::workload::{WorkloadSecret, sandbox_secret_name_allowed};
use dwk_proto::brokerp::{SecretDelivery, SecretEnvName};
use dwk_proto::wire::id::{InvocationId, RunId, SessionId};
use dwk_proto::wire::scalar::Epoch;

use crate::resource::ExecutableIdentity;
use crate::sandbox::SandboxConfig;
use crate::secret::SecretError;
use crate::secret::metadata::{EnvName, InjectionMode, SecretHandle, SecretMetadata};
use crate::secret::select::{self, Consumption, InjectionEnvironment};

use super::super::Work;
use super::super::audit::{AuditEvent, Fields};
use super::super::error::AuthorityError;
use super::super::identity::CallerContext;
use super::super::lease::to_sql;
use super::super::policy_state::ActiveAuthority;
use super::super::query::DecisionRecord;
use super::super::secrets::{self, SecretsState};
use super::Ending;

/// Who asks for a credential at spawn, for which consumer: the workload's
/// caller and run, the handle its call named, and the executable it runs --
/// the image's, as the manifest pins it.
#[derive(Debug, Clone, Copy)]
pub(in crate::state) struct SpawnAsked<'a> {
    pub(in crate::state) caller: &'a CallerContext,
    pub(in crate::state) session: &'a SessionId,
    pub(in crate::state) run: &'a RunId,
    pub(in crate::state) epoch: Epoch,
    /// The handle, as the call named it.
    pub(in crate::state) handle: &'a str,
    /// The executable that would receive it.
    pub(in crate::state) consumer: &'a ExecutableIdentity,
}

/// A credential the operator's metadata allows this consumer at spawn, before
/// either gate: steps 2, 4 and 5.
#[derive(Debug, Clone)]
pub(in crate::state) struct SpawnPrepared {
    pub(in crate::state) handle: SecretHandle,
    pub(in crate::state) revision: i64,
    pub(in crate::state) metadata: SecretMetadata,
    /// The mode the kernel chose: C or B.
    pub(in crate::state) mode: InjectionMode,
    /// What the broker is told: the handle, the delivery, mode B's variable.
    /// Never the value.
    pub(in crate::state) secret: WorkloadSecret,
}

/// A use both gates allowed, whose intent is durable -- and, while its
/// workload starts, what became of the value.
#[derive(Debug)]
pub(in crate::state) struct SpawnAuthorised {
    pub(in crate::state) invocation: InvocationId,
    pub(in crate::state) prepared: SpawnPrepared,
    /// Whether the value was read from its backend for this use.
    pub(in crate::state) resolved: bool,
    /// Why the value never reached the broker, if it did not.
    pub(in crate::state) failure: Option<&'static str>,
}

fn base_fields(asked: &SpawnAsked<'_>) -> Fields {
    Fields::new()
        .text("subject", asked.caller.subject().storage_key())
        .text("holder", asked.caller.holder().to_string())
        .text("session_id", asked.session.as_str())
        .text("run_id", asked.run.as_str())
        .int("epoch", asked.epoch.get())
        .text("handle", asked.handle)
        .text("consumer", "process.exec")
        .text("executable", asked.consumer.to_string())
        .text("environment", "sandbox")
}

fn deny(
    work: &mut Work<'_>,
    asked: &SpawnAsked<'_>,
    reason: &'static str,
    extra: Fields,
) -> Result<&'static str, AuthorityError> {
    let mut fields = base_fields(asked).text("reason", reason);
    fields.extend(extra);
    work.audit(AuditEvent::SecretDenied, fields)?;
    Ok(reason)
}

/// Steps 2, 4 and 5: the handle typed, the metadata and the revision the run
/// may use, the consumer, the mode -- the operator's and the kernel's, never
/// the request's -- and, for mode B, a variable the environment does not
/// set. `Ok(Err(reason))` is a refusal, audited; nothing is read.
pub(in crate::state) fn prepare(
    work: &mut Work<'_>,
    asked: &SpawnAsked<'_>,
    (secrets_state, config): (&SecretsState, &SandboxConfig),
    after_metadata: &dyn Fn() -> Result<(), AuthorityError>,
) -> Result<Result<SpawnPrepared, &'static str>, AuthorityError> {
    let Some(handle) = SecretHandle::new(asked.handle) else {
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
    // 5. The consumer. The operator's metadata names paths; in an execution
    // environment each names the executable the image manifest pins at that
    // path -- never the host file there -- and the run is bound to that
    // manifest (OD-9), so a changed binary is not the consumer.
    let consumers: Vec<ExecutableIdentity> = metadata
        .consumers
        .iter()
        .filter_map(|path| super::super::workload::manifest_identity(config, path, None).ok())
        .collect();
    let mode = match select::select(
        &metadata,
        &consumers,
        &Consumption::Spawn {
            consumer: asked.consumer,
            environment: InjectionEnvironment::Sandbox,
        },
    ) {
        Ok(mode) => mode,
        Err(error) => return deny(work, asked, error.code(), Fields::new()).map(Err),
    };
    let (delivery, env_name) = match mode {
        InjectionMode::FdAtSpawn => (SecretDelivery::FdAtSpawn, None),
        InjectionMode::EnvAtSpawn => {
            // Never a process-control name, nor one the environment or
            // `workspace_exec_hygiene` sets: the value would shadow it.
            let name = metadata
                .env
                .as_ref()
                .map(EnvName::as_str)
                .filter(|name| sandbox_secret_name_allowed(name))
                .and_then(SecretEnvName::new);
            let Some(name) = name else {
                return deny(work, asked, "SECRET_VARIABLE_RESERVED", Fields::new()).map(Err);
            };
            (SecretDelivery::EnvAtSpawn, Some(name))
        }
        InjectionMode::Egress => {
            return Err(AuthorityError::Invariant("a spawn use selected egress"));
        }
    };
    let wire_handle = dwk_proto::brokerp::SecretHandle::new(handle.as_str())
        .ok_or(AuthorityError::Invariant("a handle does not fit the wire"))?;
    Ok(Ok(SpawnPrepared {
        handle,
        revision,
        metadata,
        mode,
        secret: WorkloadSecret {
            handle: wire_handle,
            delivery,
            env_name,
        },
    }))
}

/// Steps 6–8, judged: `Some(reason)` when `record` -- `secret.use:<handle>`
/// through both gates -- does not permit the use, audited with the gates.
pub(in crate::state) fn refused_by_gates(
    work: &mut Work<'_>,
    asked: &SpawnAsked<'_>,
    active: &ActiveAuthority,
    (record, mode): (&DecisionRecord, InjectionMode),
) -> Result<Option<&'static str>, AuthorityError> {
    let reason = if !record.capability_satisfied() {
        "CAPABILITY_NOT_GRANTED"
    } else if !record.policy_satisfied() {
        "POLICY_DENIED"
    } else if !super::obligations_enforced(record) {
        "OBLIGATION_UNENFORCEABLE"
    } else {
        return Ok(None);
    };
    let gates = super::gate_fields(active, record).text("mode", mode.as_str());
    deny(work, asked, reason, gates).map(Some)
}

/// Step 9: the durable intent, linked to the workload's -- in the workload's
/// own transaction, after its row -- and audited with the gates that allowed
/// it.
pub(in crate::state) fn record_intent(
    work: &mut Work<'_>,
    (asked, prepared): (&SpawnAsked<'_>, SpawnPrepared),
    (active, record): (&ActiveAuthority, &DecisionRecord),
    workload: &InvocationId,
) -> Result<SpawnAuthorised, AuthorityError> {
    let invocation = work.invocation_id()?;
    // The use's own key: its workload's, which names one invocation for ever.
    let key = format!("{}:secret", workload.as_str());
    work.db(work.tx.execute(
        "INSERT INTO secret_injection (invocation_id, run_id, subject, session_id, \
         idempotency_key, handle, revision, mode, consumer, incarnation, state, failure, \
         intent_ms, ended_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'INTENT', \
         NULL, ?11, NULL)",
        rusqlite::params![
            invocation.as_str(),
            asked.run.as_str(),
            asked.caller.subject().storage_key(),
            asked.session.as_str(),
            key,
            prepared.handle.as_str(),
            prepared.revision,
            prepared.mode.as_str(),
            asked.consumer.to_string(),
            to_sql(work.incarnation())?,
            to_sql(work.now)?
        ],
    ))?;
    work.db(work.tx.execute(
        "INSERT INTO workload_secret (workload_invocation_id, injection_invocation_id, \
         recorded_ms) VALUES (?1, ?2, ?3)",
        rusqlite::params![workload.as_str(), invocation.as_str(), to_sql(work.now)?],
    ))?;
    let mut fields = base_fields(asked)
        .text("invocation_id", invocation.as_str())
        .text("workload_invocation_id", workload.as_str())
        .text("idempotency_key", key)
        .int("revision", u64::try_from(prepared.revision).unwrap_or(0))
        .text("backend", prepared.metadata.storage.backend());
    fields.extend(super::gate_fields(active, record).text("mode", prepared.mode.as_str()));
    work.audit(AuditEvent::SecretIntentRecorded, fields)?;
    Ok(SpawnAuthorised {
        invocation,
        prepared,
        resolved: false,
        failure: None,
    })
}

/// How a use ended, from how its workload did: delivered once the workload
/// ran, never when provably nothing ran, unknown whenever the workload's own
/// ending is.
pub(in crate::state) fn ending_of(
    authorised: &SpawnAuthorised,
    workload: &super::super::workload::Ending,
) -> Ending {
    use super::super::workload::Ending as Workload;
    match workload {
        Workload::Completed(_) => Ending::Injected,
        Workload::Failed { reason } => Ending::Failed(authorised.failure.unwrap_or(reason)),
        Workload::Unknown { .. } => Ending::Unknown,
    }
}

/// Steps 14–16: the ending, durably, in the workload's outcome transaction;
/// a delivery counted once.
pub(in crate::state) fn record_outcome(
    work: &mut Work<'_>,
    authorised: &SpawnAuthorised,
    run: &RunId,
    ending: Ending,
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
            .text("mode", prepared.mode.as_str())
            .text("consumer", "process.exec")
            .text("environment", "sandbox")
            .text("backend", prepared.metadata.storage.backend())
    };
    if authorised.resolved {
        work.audit(AuditEvent::SecretResolved, base())?;
    }
    let mut fields = base().text("state", state);
    if let Some(reason) = failure {
        fields = fields.text("failure", reason);
    }
    if ending == Ending::Injected {
        let uses = super::count_use(work, &prepared.handle)?;
        fields = fields.int("uses", u64::try_from(uses).unwrap_or(0));
    }
    work.audit(event, fields)
}
