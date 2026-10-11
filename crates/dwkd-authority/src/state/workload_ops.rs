//! The authority's workload operation (M5d.1, ADR-0052): an in-process API
//! with **no DWKP route**, like M5a's environment operations. No runtime can
//! call it and nothing on the wire names it; the evidence harness attaches a
//! sandbox with an image manifest and calls it. The public `process.exec`
//! reaching an environment is M5d.2's.
//!
//! Every workload's intent is durable before the broker is told anything
//! ([`super::workload`]); every decision is the authority's — both gates for
//! a sandbox action, the environment's measured level, the manifest, the
//! budget — and the broker only re-judges what it is about to touch.

use dwk_proto::brokerp::workload::{WorkloadEnding, WorkloadRunDone, WorkloadSpec};
use dwk_proto::wire::id::{EnvironmentId, InvocationId, RunId};

use crate::broker::{BrokerDelivery, BrokerError, BrokerFailure, BrokerOrder, Operation};
use crate::sandbox;

use super::Authority;
use super::crash::CrashPoint;
use super::environment::DestroyBegun;
use super::environment_ops::{EnvironmentReply, runtime, specification};
use super::error::AuthorityError;
use super::workload::{self, Begun, Ending, WorkloadRecord, WorkloadRequest};

/// What a workload's run came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadReply {
    /// Refused before anything was recorded or run, and why.
    Refused(&'static str),
    /// A gate denied it, and why. Nothing was recorded but the decision.
    Denied(&'static str),
    /// Its key names a workload already: that one's record. Nothing ran.
    Replayed(WorkloadRecord),
    /// It ran and ended as it says.
    Completed(Box<WorkloadOutcome>),
    /// Refused after its intent: provably nothing ran.
    Failed {
        /// The invocation.
        invocation: InvocationId,
        /// Why.
        reason: &'static str,
        /// Whether its environment, found not to be what was recorded, was
        /// destroyed.
        environment_destroyed: bool,
    },
    /// It may have run and nothing proves how it ended: never run again,
    /// and its environment destroyed.
    Unknown {
        /// The invocation.
        invocation: InvocationId,
        /// Why nothing is known.
        reason: &'static str,
        /// Whether its environment is gone (or its destruction pending).
        environment_destroyed: bool,
    },
}

/// A completed workload, as the authority returns it: its output redacted
/// and bounded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadOutcome {
    /// The invocation.
    pub invocation: InvocationId,
    /// The environment it ran in.
    pub environment: EnvironmentId,
    /// How it ended: exited, killed or timed out.
    pub ending: WorkloadEnding,
    /// Its exit code, for an exit.
    pub exit_code: Option<u8>,
    /// The signal that ended it, for a kill.
    pub signal: Option<u8>,
    /// Its standard output, redacted, within the bound.
    pub stdout: Vec<u8>,
    /// Its standard error, redacted, within the bound.
    pub stderr: Vec<u8>,
    /// Whether either stream was cut.
    pub truncated: bool,
    /// What `reap` found: `PASS` when every other process was proved gone.
    pub residue: dwk_proto::brokerp::sandbox::Verdict,
    /// How many processes, besides init, `reap` ended.
    pub ended_processes: u32,
    /// How long it ran, in milliseconds.
    pub elapsed_ms: u32,
    /// Whether its environment was destroyed after it (its residue was not
    /// proved clean).
    pub environment_destroyed: bool,
}

/// How a broker failure of a workload is recorded: a failure only when
/// nothing can have run, `UNKNOWN` otherwise.
fn ending_of(result: Result<BrokerDelivery, BrokerError>) -> Ending {
    match result {
        Ok(BrokerDelivery::WorkloadRan(done)) => match done.ending {
            WorkloadEnding::Exited | WorkloadEnding::Killed | WorkloadEnding::TimedOut => {
                Ending::Completed(done)
            }
            WorkloadEnding::EnvironmentGone => Ending::Unknown {
                reason: "ENVIRONMENT_GONE",
                done: Some(done),
            },
            WorkloadEnding::RuntimeUnavailable => Ending::Unknown {
                reason: "RUNTIME_UNAVAILABLE",
                done: Some(done),
            },
            WorkloadEnding::Unobservable => Ending::Unknown {
                reason: "WORKLOAD_UNOBSERVABLE",
                done: Some(done),
            },
        },
        Ok(_) => Ending::Unknown {
            reason: "BROKER_PROTOCOL_ERROR",
            done: None,
        },
        Err(error) if error.provably_without_effect() => Ending::Failed {
            reason: match error.failure {
                BrokerFailure::Refused(refusal) => sandbox::refusal_class(refusal),
                BrokerFailure::NotConfigured
                | BrokerFailure::Unreachable(_)
                | BrokerFailure::PeerRefused { .. } => "BROKER_UNAVAILABLE",
                BrokerFailure::Protocol(_) | BrokerFailure::Indeterminate(_) => {
                    "BROKER_PROTOCOL_ERROR"
                }
            },
        },
        Err(error) => Ending::Unknown {
            reason: match error.failure {
                BrokerFailure::Indeterminate(_) => "WORKLOAD_UNCONFIRMED",
                BrokerFailure::Protocol(_) => "BROKER_PROTOCOL_ERROR",
                _ => "BROKER_UNAVAILABLE",
            },
            done: None,
        },
    }
}

impl Authority {
    /// Run one workload in `run`'s `READY` environment (M5d.1, ADR-0052):
    /// decided by both gates for a sandbox action, its intent durable before
    /// the broker hears of it, its output redacted, and its environment
    /// destroyed whenever its ending or what it left is uncertain. **The
    /// evidence harness's entry point**: no DWKP route reaches it.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the authority cannot answer. A crash hook at
    /// a [`CrashPoint::WORKLOAD`] point poisons the store, as a crash would.
    pub fn workload_run(
        &mut self,
        run: &RunId,
        request: &WorkloadRequest,
    ) -> Result<WorkloadReply, AuthorityError> {
        let Some(attached) = self.attached() else {
            return Ok(WorkloadReply::Refused("SANDBOX_NOT_ATTACHED"));
        };
        let shared = std::sync::Arc::clone(&attached.shared);
        let active = shared.active()?;
        let checked = match workload::check(request, &attached.config) {
            Ok(checked) => checked,
            Err(reason) => {
                self.transact(|work| {
                    workload::refuse(work, run, &request.executable, reason).map(|_| ())
                })?;
                return Ok(WorkloadReply::Refused(reason));
            }
        };
        let budget = attached.config.workload_budget();
        let begun = self.transact(|work| workload::begin(work, run, &checked, budget, active))?;
        let intent = match begun {
            Begun::Refused(reason) => return Ok(WorkloadReply::Refused(reason)),
            Begun::Denied(reason) => return Ok(WorkloadReply::Denied(reason)),
            Begun::Replayed(record) => return Ok(WorkloadReply::Replayed(*record)),
            Begun::Intent(intent) => *intent,
        };
        shared.crash(CrashPoint::WorkloadAfterIntent)?;
        let ending = perform(&attached, run, &intent, &checked)?;
        // Return-path redaction (ADR-0046 §21): each stream's bytes, before
        // anything of them is recorded or answered; the raw buffers zeroed.
        let limit = usize::try_from(intent.stream_limit).unwrap_or(usize::MAX);
        let mut redacted: Option<(Vec<u8>, Vec<u8>, bool)> = None;
        if let Ending::Completed(done) = &ending {
            let (stdout, stderr, truncated) = redact(&shared, done, limit);
            redacted = Some((stdout, stderr, truncated));
        }
        let sizes = redacted.as_ref().map(|(stdout, stderr, truncated)| {
            (
                u64::try_from(stdout.len()).unwrap_or(u64::MAX),
                u64::try_from(stderr.len()).unwrap_or(u64::MAX),
                *truncated,
            )
        });
        let recorded =
            self.transact(|work| workload::record_outcome(work, run, &intent, &ending, sizes))?;
        shared.crash(CrashPoint::WorkloadAfterOutcome)?;
        let environment_destroyed = match recorded.destroy {
            Some(DestroyBegun::Pending { record, invocation }) => {
                matches!(
                    self.perform_destroy(record, invocation)?,
                    EnvironmentReply::Destroyed { .. } | EnvironmentReply::DestroyPending { .. }
                )
            }
            Some(DestroyBegun::Refused(_)) | None => false,
        };
        Ok(match ending {
            Ending::Completed(done) => {
                let (stdout, stderr, truncated) = redacted.unwrap_or_default();
                WorkloadReply::Completed(Box::new(outcome(
                    &intent.invocation,
                    &intent.environment.environment,
                    &done,
                    (stdout, stderr, truncated),
                    environment_destroyed,
                )))
            }
            Ending::Unknown { reason, .. } => WorkloadReply::Unknown {
                invocation: intent.invocation,
                reason,
                environment_destroyed,
            },
            Ending::Failed { reason } => WorkloadReply::Failed {
                invocation: intent.invocation,
                reason,
                environment_destroyed,
            },
        })
    }

    /// One workload's record (the evidence's view of the ledger).
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the authority cannot answer.
    pub fn workload_record(
        &mut self,
        invocation: &InvocationId,
    ) -> Result<Option<WorkloadRecord>, AuthorityError> {
        self.transact(|work| workload::record(work, invocation))
    }
}

/// Steps 3 and 4, outside any transaction: the runtime client resolved and
/// hashed, the workspace re-pinned, and the broker's one exchange. A failure
/// before anything was sent is a failure; a crash hook after the broker's
/// answer poisons the store, as a crash would.
fn perform(
    attached: &super::environment_ops::Attached,
    run: &RunId,
    intent: &workload::Intent,
    checked: &workload::Checked,
) -> Result<Ending, AuthorityError> {
    let order = runtime(&attached.shared, &attached.config).and_then(|handoff| {
        specification(
            &attached.shared,
            &attached.config,
            (&intent.environment.environment, run),
            &intent.binding,
            None,
        )
        .map(|spec| (spec, handoff))
    });
    let (spec, handoff) = match order {
        Err(reason) => return Ok(Ending::Failed { reason }),
        Ok(order) => order,
    };
    let stream_limit = dwk_proto::brokerp::StreamLimit::new(intent.stream_limit).ok_or(
        AuthorityError::Invariant("a decided stream bound is out of range"),
    )?;
    let result = attached.broker.perform(BrokerOrder::new(
        intent.invocation.clone(),
        Operation::WorkloadRun {
            spec,
            container: intent.environment.container.clone(),
            runtime: handoff,
            workload: WorkloadSpec {
                executable: checked.executable.clone(),
                executable_sha256: checked.sha256.clone(),
                args: checked.wire_args.clone(),
                stream_limit,
                wall_clock: checked.wall_clock,
            },
        },
    ));
    attached.shared.crash(CrashPoint::WorkloadAfterBroker)?;
    Ok(ending_of(result))
}

/// Redact both streams with the exact index and the known shapes, each cut
/// to the bound if placeholders lengthened it.
fn redact(
    shared: &super::Shared,
    done: &WorkloadRunDone,
    limit: usize,
) -> (Vec<u8>, Vec<u8>, bool) {
    let mut stdout = done.stdout.content.to_bytes();
    let mut stderr = done.stderr.content.to_bytes();
    let out = shared.secrets.redact_bounded(&mut stdout, limit);
    let err = shared.secrets.redact_bounded(&mut stderr, limit);
    let truncated = done.stdout.truncated || done.stderr.truncated || out.cut || err.cut;
    (out.bytes, err.bytes, truncated)
}

fn outcome(
    invocation: &InvocationId,
    environment: &EnvironmentId,
    done: &WorkloadRunDone,
    (stdout, stderr, truncated): (Vec<u8>, Vec<u8>, bool),
    environment_destroyed: bool,
) -> WorkloadOutcome {
    WorkloadOutcome {
        invocation: invocation.clone(),
        environment: environment.clone(),
        ending: done.ending,
        exit_code: done.exit_code.map(dwk_proto::wire::scalar::ExitCode::get),
        signal: done.signal.map(dwk_proto::wire::scalar::SignalNumber::get),
        stdout,
        stderr,
        truncated,
        residue: done.residue,
        ended_processes: done.ended_processes.get(),
        elapsed_ms: done.elapsed_ms.get(),
        environment_destroyed,
    }
}
