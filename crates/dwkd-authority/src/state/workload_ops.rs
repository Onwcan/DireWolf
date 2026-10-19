//! The authority's workload operations (M5d, ADR-0052): one workload's
//! start, its collections, and its settlement.
//!
//! **Started, then collected** (M5d.2, ADR-0052 §8). The broker answers a
//! start once it has re-judged the environment and proved the executable,
//! and supervises the run; the authority collects it with short exchanges
//! until it ends, so no broker exchange holds the private channel for a
//! workload's wall clock. A start the broker does not answer for, or a
//! collection that cannot say how it ended, is `UNKNOWN` and costs the
//! environment.
//!
//! Two callers share these steps: the in-process API ([`Authority::workload_run`],
//! the evidence harness's since M5d.1), which collects in a loop, and the
//! public `process.exec` (M5d.2, `super::workload_route`), whose collections
//! the authority's worker makes between other requests.
//!
//! Every workload's intent is durable before the broker is told anything
//! ([`super::workload`]); every decision is the authority's — both gates for
//! a sandbox action, the environment's measured level, the manifest, the
//! budget — and the broker only re-judges what it is about to touch.

use std::time::{Duration, Instant};

use dwk_proto::brokerp::BrokerGeneration;
use dwk_proto::brokerp::workload::{
    WORKLOAD_SUPERVISION_SECONDS, WorkloadEnding, WorkloadRunDone, WorkloadSpec,
};
use dwk_proto::wire::id::{EnvironmentId, InvocationId, RunId};

use crate::broker::{
    BrokerDelivery, BrokerError, BrokerFailure, BrokerOrder, Collected, Operation,
};
use crate::sandbox;

use super::Authority;
use super::crash::CrashPoint;
use super::environment::DestroyBegun;
use super::environment_ops::{Attached, EnvironmentReply, runtime, specification};
use super::error::AuthorityError;
use super::workload::{self, Begun, Ending, WorkloadRecord, WorkloadRequest};

/// How often the in-process API collects a running workload.
const COLLECT_EVERY: Duration = Duration::from_millis(200);

/// How long past the broker's own supervision bound a workload may still
/// say `RUNNING` before the authority stops believing it: the broker's
/// thread is gone by its bound, so a later `RUNNING` is a broker that does
/// not keep its word.
const OVERDUE_MARGIN: Duration = Duration::from_secs(30);

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
#[allow(
    clippy::struct_excessive_bools,
    reason = "each flag is a separate fact of the ending the answer states"
)]
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
    /// Every stdout byte it wrote, kept or not, as the broker counted them.
    pub stdout_observed: u64,
    /// Every stderr byte it wrote, kept or not.
    pub stderr_observed: u64,
    /// Whether stdout was cut — by its bound, or by redaction lengthening it.
    pub stdout_truncated: bool,
    /// Whether stderr was cut.
    pub stderr_truncated: bool,
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

/// A workload whose start the broker answered: it is collected until it
/// ends, and its ending is recorded against its intent.
#[derive(Debug)]
pub(super) struct Started {
    pub(super) run: RunId,
    pub(super) intent: workload::Intent,
    generation: BrokerGeneration,
    /// After this, a `RUNNING` answer is not believed.
    overdue: Instant,
}

/// What a start came to.
#[derive(Debug)]
pub(super) enum Launched {
    /// It ended before it was supervised: refused, or not known to have
    /// been started.
    Ended(Box<workload::Intent>, Ending),
    /// The broker supervises it.
    Running(Box<Started>),
}

/// How a run's ending is recorded: a completion only when it exited, was
/// killed or outran its wall clock; `UNKNOWN` when the ending says the
/// environment, the runtime or the observation failed.
fn ending_of_run(done: Box<WorkloadRunDone>) -> Ending {
    match done.ending {
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
    }
}

/// A workload's refusal class: a digest the broker found wrong is the
/// executable's -- the workload's in the image, or the runtime client's --
/// never ambiguous with an environment's.
const fn refusal_class(refusal: dwk_proto::brokerp::BrokerRefusal) -> &'static str {
    match refusal {
        dwk_proto::brokerp::BrokerRefusal::DigestMismatch => "EXECUTABLE_DIGEST_MISMATCH",
        refusal => sandbox::refusal_class(refusal),
    }
}

/// How a start's failure is recorded: a failure only when nothing can have
/// run, `UNKNOWN` otherwise.
fn ending_of_start(error: &BrokerError) -> Ending {
    if error.provably_without_effect() {
        return Ending::Failed {
            reason: match error.failure {
                BrokerFailure::Refused(refusal) => refusal_class(refusal),
                BrokerFailure::NotConfigured
                | BrokerFailure::Unreachable(_)
                | BrokerFailure::PeerRefused { .. } => "BROKER_UNAVAILABLE",
                BrokerFailure::Protocol(_) | BrokerFailure::Indeterminate(_) => {
                    "BROKER_PROTOCOL_ERROR"
                }
            },
        };
    }
    Ending::Unknown {
        reason: match error.failure {
            BrokerFailure::Indeterminate(_) => "WORKLOAD_UNCONFIRMED",
            BrokerFailure::Protocol(_) => "BROKER_PROTOCOL_ERROR",
            _ => "BROKER_UNAVAILABLE",
        },
        done: None,
    }
}

/// What one collection says, or `None` while it runs. **Every failed
/// collection is `UNKNOWN`**: a collection changes nothing, so even one the
/// broker refused or never heard says nothing of the workload, which it
/// started and may still be running.
fn ending_of_collection(result: Result<BrokerDelivery, BrokerError>) -> Option<Ending> {
    match result {
        Ok(BrokerDelivery::WorkloadCollected(Collected::Running)) => None,
        Ok(BrokerDelivery::WorkloadCollected(Collected::Ended(done))) => Some(ending_of_run(done)),
        // The supervisor never began the run: the runtime's client could not
        // be started after the start was answered. Provably nothing ran.
        Ok(BrokerDelivery::WorkloadCollected(Collected::NeverRan(refusal))) => {
            Some(Ending::Failed {
                reason: refusal_class(refusal),
            })
        }
        Ok(_) => Some(Ending::Unknown {
            reason: "BROKER_PROTOCOL_ERROR",
            done: None,
        }),
        Err(error) => Some(Ending::Unknown {
            reason: match error.failure {
                BrokerFailure::Indeterminate(_) | BrokerFailure::Refused(_) => {
                    "WORKLOAD_UNCONFIRMED"
                }
                BrokerFailure::Protocol(_) => "BROKER_PROTOCOL_ERROR",
                _ => "BROKER_UNAVAILABLE",
            },
            done: None,
        }),
    }
}

/// Steps 3 and 4 of a workload, outside any transaction: the runtime client
/// resolved and hashed, the workspace re-pinned, and the broker's start. A
/// failure before anything was sent is a failure; a crash hook after the
/// start's answer poisons the store, as a crash would (W9).
pub(super) fn start(
    attached: &Attached,
    run: &RunId,
    intent: workload::Intent,
    workload: WorkloadSpec,
) -> Result<Launched, AuthorityError> {
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
        Err(reason) => {
            return Ok(Launched::Ended(Box::new(intent), Ending::Failed { reason }));
        }
        Ok(order) => order,
    };
    let since = Instant::now();
    let result = attached.broker.perform(BrokerOrder::new(
        intent.invocation.clone(),
        Operation::WorkloadStart {
            spec,
            container: intent.environment.container.clone(),
            runtime: handoff,
            workload,
        },
    ));
    let ending = match result {
        Ok(BrokerDelivery::WorkloadStarted(generation)) => {
            attached.shared.crash(CrashPoint::WorkloadAfterStart)?;
            return Ok(Launched::Running(Box::new(Started {
                run: run.clone(),
                intent,
                generation,
                overdue: since + Duration::from_secs(WORKLOAD_SUPERVISION_SECONDS) + OVERDUE_MARGIN,
            })));
        }
        // Answered as something else: nothing proves what the broker did.
        Ok(_) => Ending::Unknown {
            reason: "BROKER_PROTOCOL_ERROR",
            done: None,
        },
        Err(error) => ending_of_start(&error),
    };
    // The broker's answer, and not a start: W10 as much as a collection's.
    attached.shared.crash(CrashPoint::WorkloadAfterBroker)?;
    Ok(Launched::Ended(Box::new(intent), ending))
}

/// One collection of `started`: its ending, or `None` while it runs. A
/// workload still `RUNNING` past the broker's own bound is not believed.
/// A crash hook after an ending is in hand poisons the store (W10).
pub(super) fn collect(
    attached: &Attached,
    started: &Started,
) -> Result<Option<Ending>, AuthorityError> {
    let stream_limit = started.intent.stream_limit;
    let result = attached.broker.perform(BrokerOrder::new(
        started.intent.invocation.clone(),
        Operation::WorkloadCollect {
            generation: started.generation.clone(),
            stream_limit,
        },
    ));
    let ending = match ending_of_collection(result) {
        None if Instant::now() > started.overdue => Some(Ending::Unknown {
            reason: "WORKLOAD_OVERDUE",
            done: None,
        }),
        ending => ending,
    };
    if ending.is_some() {
        attached.shared.crash(CrashPoint::WorkloadAfterBroker)?;
    }
    Ok(ending)
}

impl Authority {
    /// Run one workload in `run`'s `READY` environment (M5d.1, ADR-0052):
    /// decided by both gates for a sandbox action, its intent durable before
    /// the broker hears of it, started and collected until it ends, its
    /// output redacted, and its environment destroyed whenever its ending
    /// or what it left is uncertain. **The evidence harness's entry point**;
    /// the public route is `process.exec` at tool version 5 (M5d.2).
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
        let image = workload::ImageBinding::of(&attached.config);
        let begun = self.transact(|work| {
            workload::begin(
                work,
                run,
                &checked,
                (budget, active, &image),
                (&workload::Binding::Run, workload::Missing::Refuse),
            )
        })?;
        let intent = match begun {
            Begun::Refused(reason) => return Ok(WorkloadReply::Refused(reason)),
            Begun::NeedsEnvironment => {
                return Err(AuthorityError::Invariant(
                    "the in-process API was asked to prepare an environment",
                ));
            }
            Begun::Denied(decided) => return Ok(WorkloadReply::Denied(decided.plan.reason())),
            Begun::Replayed(record) => return Ok(WorkloadReply::Replayed(*record)),
            Begun::Intent(intent) => *intent,
        };
        shared.crash(CrashPoint::WorkloadAfterIntent)?;
        let spec = workload::spec(&checked, &intent)?;
        let (intent, ending) = match start(&attached, run, intent, spec)? {
            Launched::Running(started) => {
                let ending = loop {
                    if let Some(ending) = collect(&attached, &started)? {
                        break ending;
                    }
                    std::thread::sleep(COLLECT_EVERY);
                };
                (started.intent, ending)
            }
            Launched::Ended(intent, ending) => (*intent, ending),
        };
        self.settle_workload(run, &intent, ending)
    }

    /// Step 5: record how `intent` ended — redacted output, taint, and the
    /// environment's destruction whenever its ending or its residue is
    /// uncertain — and say so.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the authority cannot answer.
    pub(super) fn settle_workload(
        &mut self,
        run: &RunId,
        intent: &workload::Intent,
        ending: Ending,
    ) -> Result<WorkloadReply, AuthorityError> {
        let Some(attached) = self.attached() else {
            return Err(AuthorityError::Invariant(
                "a started workload's sandbox is no longer attached",
            ));
        };
        let shared = std::sync::Arc::clone(&attached.shared);
        // Return-path redaction (ADR-0046 §21): each stream's bytes, before
        // anything of them is recorded or answered; the raw buffers zeroed.
        let limit = usize::try_from(intent.stream_limit).unwrap_or(usize::MAX);
        let mut redacted: Option<Redacted> = None;
        if let Ending::Completed(done) = &ending {
            redacted = Some(redact(&shared, done, limit));
        }
        let sizes = redacted.as_ref().map(|r| {
            (
                u64::try_from(r.stdout.len()).unwrap_or(u64::MAX),
                u64::try_from(r.stderr.len()).unwrap_or(u64::MAX),
                r.stdout_cut || r.stderr_cut,
            )
        });
        let recorded =
            self.transact(|work| workload::record_outcome(work, run, intent, &ending, sizes))?;
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
                let redacted = redacted.unwrap_or_default();
                WorkloadReply::Completed(Box::new(outcome(
                    &intent.invocation,
                    &intent.environment.environment,
                    &done,
                    redacted,
                    environment_destroyed,
                )))
            }
            Ending::Unknown { reason, .. } => WorkloadReply::Unknown {
                invocation: intent.invocation.clone(),
                reason,
                environment_destroyed,
            },
            Ending::Failed { reason } => WorkloadReply::Failed {
                invocation: intent.invocation.clone(),
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

/// Both streams, redacted, and whether each was cut.
#[derive(Debug, Default)]
struct Redacted {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_cut: bool,
    stderr_cut: bool,
}

/// Redact both streams with the exact index and the known shapes, each cut
/// to the bound if placeholders lengthened it.
fn redact(shared: &super::Shared, done: &WorkloadRunDone, limit: usize) -> Redacted {
    let mut stdout = done.stdout.content.to_bytes();
    let mut stderr = done.stderr.content.to_bytes();
    let out = shared.secrets.redact_bounded(&mut stdout, limit);
    let err = shared.secrets.redact_bounded(&mut stderr, limit);
    Redacted {
        stdout_cut: done.stdout.truncated || out.cut,
        stderr_cut: done.stderr.truncated || err.cut,
        stdout: out.bytes,
        stderr: err.bytes,
    }
}

fn outcome(
    invocation: &InvocationId,
    environment: &EnvironmentId,
    done: &WorkloadRunDone,
    redacted: Redacted,
    environment_destroyed: bool,
) -> WorkloadOutcome {
    WorkloadOutcome {
        invocation: invocation.clone(),
        environment: environment.clone(),
        ending: done.ending,
        exit_code: done.exit_code.map(dwk_proto::wire::scalar::ExitCode::get),
        signal: done.signal.map(dwk_proto::wire::scalar::SignalNumber::get),
        truncated: redacted.stdout_cut || redacted.stderr_cut,
        stdout_observed: done.stdout.observed.get(),
        stderr_observed: done.stderr.observed.get(),
        stdout_truncated: redacted.stdout_cut,
        stderr_truncated: redacted.stderr_cut,
        stdout: redacted.stdout,
        stderr: redacted.stderr,
        residue: done.residue,
        ended_processes: done.ended_processes.get(),
        elapsed_ms: done.elapsed_ms.get(),
        environment_destroyed,
    }
}
