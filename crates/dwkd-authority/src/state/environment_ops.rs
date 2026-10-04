//! The authority's execution-environment operations (M5a, ADR-0047): an
//! in-process API with **no DWKP route**. No runtime can call it and nothing
//! on the wire names it; in M5a only the evidence harness attaches a sandbox
//! ([`Authority::attach_sandbox`]), and `dwkd-authority serve` has no option
//! that does. A sandboxed `process.exec` is M5d's.
//!
//! Every operation that can change what exists records its intent before the
//! broker is told anything ([`super::environment`]); every judgement of a
//! level is made here, from the broker's per-invariant report, by
//! [`crate::sandbox::judge`] — never by the broker, and never by a score.

use std::sync::Arc;
use std::time::Instant;

use dwk_proto::brokerp::egress::{EgressCounters, EgressGrant};
use dwk_proto::brokerp::sandbox::{
    ContainerRef, ContainerRole, EnvironmentProfile, SandboxInvariant, StoreInstance, Verdict,
};
use dwk_proto::brokerp::{DestroyState, EnvironmentMeasurement, EnvironmentSpec, OwnedEnvironment};
use dwk_proto::wire::id::{EnvironmentId, InvocationId, RunId};
use dwk_proto::wire::scalar::HostPath;

use crate::broker::{
    BrokerDelivery, BrokerError, BrokerFailure, BrokerOrder, EffectBroker, Operation,
    RuntimeHandoff,
};
use crate::capability::DeclaredPath;
use crate::resource::fs::{Access, Expect, PinnedRoot};
use crate::sandbox::{self, EnvironmentKind, Judgement, SandboxConfig};

use super::audit::{AuditEvent, Fields};
use super::config::RootBinding;
use super::crash::CrashPoint;
use super::environment::{
    self, Begun, DestroyBegun, DestroyEnding, EnvironmentRecord, EnvironmentState, Prepared,
    ReconcileClass, ReconcileReport,
};
use super::error::AuthorityError;
use super::{Authority, Shared, resolution};

/// What a measurement came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentReport {
    /// The environment.
    pub environment: EnvironmentId,
    /// Its container.
    pub container: Option<ContainerRef>,
    /// The levels, and which invariants denied one.
    pub judgement: Judgement,
    /// Every invariant, as the broker reported it.
    pub checks: Vec<(SandboxInvariant, Verdict)>,
    /// The runtime's version, as it reported it.
    pub runtime_version: Option<String>,
    /// How long the broker's measurement took.
    pub measure_ms: u32,
    /// What the environment's proxy had done when it was measured (M5b):
    /// counts by disposition and bytes. `None` without one.
    pub egress: Option<EgressCounters>,
}

/// What an environment operation came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvironmentReply {
    /// Refused before anything was recorded or sent.
    Refused(&'static str),
    /// Prepared and measured clean: usable at its effective level.
    Ready {
        /// The measurement.
        report: EnvironmentReport,
        /// How long the broker's preparation took, measurement included.
        prepare_ms: u32,
    },
    /// Refused after its intent: provably none of it remains.
    Failed {
        /// The environment.
        environment: EnvironmentId,
        /// Why.
        reason: &'static str,
        /// The measurement, if one was made.
        report: Option<EnvironmentReport>,
    },
    /// It may exist; reconciliation decides by label.
    Unknown {
        /// The environment.
        environment: EnvironmentId,
        /// Why nothing is known.
        reason: &'static str,
    },
    /// Measured again and still clean.
    Clean(EnvironmentReport),
    /// No longer clean (or no longer measurable): destroyed, or destruction
    /// pending.
    Drifted {
        /// The environment.
        environment: EnvironmentId,
        /// Why.
        reason: &'static str,
        /// The measurement, if one was made.
        report: Option<EnvironmentReport>,
        /// Whether it is gone.
        destroyed: bool,
    },
    /// Gone.
    Destroyed {
        /// The environment.
        environment: EnvironmentId,
        /// Its container, if one was known or removed.
        container: Option<ContainerRef>,
        /// Whether it was already gone.
        already_gone: bool,
        /// How long the broker's destruction took.
        destroy_ms: u32,
        /// What its proxy did over its life (M5b); `None` without one.
        egress: Option<EgressCounters>,
    },
    /// Its destruction is recorded and could not be completed now; it is
    /// retried by the next destruction or reconciliation.
    DestroyPending {
        /// The environment.
        environment: EnvironmentId,
        /// Why.
        reason: &'static str,
    },
}

/// The class of a broker failure of an environment operation.
const fn failure_of(error: &BrokerError) -> &'static str {
    match error.failure {
        BrokerFailure::Refused(refusal) => sandbox::refusal_class(refusal),
        BrokerFailure::NotConfigured
        | BrokerFailure::Unreachable(_)
        | BrokerFailure::PeerRefused { .. } => "BROKER_UNAVAILABLE",
        BrokerFailure::Protocol(_) => "BROKER_PROTOCOL_ERROR",
        BrokerFailure::Indeterminate(_) => "ENVIRONMENT_UNCONFIRMED",
    }
}

fn report_of(
    environment: &EnvironmentId,
    container: Option<ContainerRef>,
    measurement: &EnvironmentMeasurement,
    topology: dwk_proto::brokerp::sandbox::NetworkTopology,
    egress: Option<EgressCounters>,
) -> EnvironmentReport {
    let checks: Vec<(SandboxInvariant, Verdict)> = measurement
        .checks
        .iter()
        .map(|c| (c.invariant, c.verdict))
        .collect();
    EnvironmentReport {
        environment: environment.clone(),
        container,
        judgement: sandbox::judge(EnvironmentKind::Oci, topology, &checks),
        checks,
        runtime_version: measurement
            .runtime_version
            .as_ref()
            .map(|v| v.as_str().to_owned()),
        measure_ms: measurement.measure_ms.get(),
        egress,
    }
}

/// This store's instance, as environments are labelled with it.
fn store(shared: &Shared) -> Result<StoreInstance, AuthorityError> {
    StoreInstance::new(format!("{:08x}", shared.store_instance)).ok_or(AuthorityError::Invariant(
        "a store instance does not fit a label",
    ))
}

/// The runtime client, resolved and hashed now, and the neutral directory
/// it runs in (`/`, opened and proved like any directory handed over). No
/// transaction may be open: hashing reads the whole client.
fn runtime(shared: &Shared, config: &SandboxConfig) -> Result<RuntimeHandoff, &'static str> {
    let resolved = crate::resource::exec::resolve(config.runtime(), shared.authority_uid)
        .map_err(|_| "RUNTIME_CLIENT_UNTRUSTED")?;
    let executable = resolved
        .into_exec_handoff()
        .map_err(|_| "RUNTIME_CLIENT_CHANGED")?;
    let (root, _) = PinnedRoot::install("/").map_err(|_| "RUNTIME_CWD_UNAVAILABLE")?;
    let anchor = DeclaredPath::new("/workspace").ok_or("RUNTIME_CWD_UNAVAILABLE")?;
    let cwd = root
        .resolve(&anchor, Access::Observe, Expect::Directory)
        .and_then(crate::resource::fs::ResolvedResource::into_list_handoff)
        .map_err(|_| "RUNTIME_CWD_UNAVAILABLE")?;
    Ok(RuntimeHandoff {
        executable,
        cwd,
        socket: config.socket().clone(),
    })
}

/// The environment's specification, with the run's workspace re-pinned now:
/// its path, proved still to name the directory the operator bound, and
/// that directory's identity, which the probe proves from inside. A
/// `PROXY_ONLY` one carries the relay's digest and, to be prepared, its
/// grant (M5b); a measurement needs no grant.
fn specification(
    shared: &Shared,
    config: &SandboxConfig,
    (environment, run): (&EnvironmentId, &RunId),
    binding: &RootBinding,
    egress: Option<EgressGrant>,
) -> Result<EnvironmentSpec, &'static str> {
    let root = PinnedRoot::reopen(&binding.host_path, &binding.fingerprint)
        .map_err(|_| "WORKSPACE_CHANGED")?;
    let identity = root.identity();
    Ok(EnvironmentSpec {
        environment_id: environment.clone(),
        run_id: run.clone(),
        store: store(shared).map_err(|_| "STORE_INSTANCE")?,
        profile: EnvironmentProfile::OciStrict,
        network: config.topology(),
        image: config.image().clone(),
        probe_sha256: config.probe_sha256().clone(),
        workspace_path: HostPath::new(binding.host_path.clone()).ok_or("WORKSPACE_PATH")?,
        workspace: (identity.device(), identity.inode()),
        relay_sha256: config.egress().map(|e| e.relay_sha256().clone()),
        egress,
    })
}

fn elapsed(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// What the harness needs of the attached configuration and the broker.
struct Attached {
    shared: Arc<Shared>,
    config: SandboxConfig,
    broker: Arc<dyn EffectBroker>,
}

impl Authority {
    fn attached(&self) -> Option<Attached> {
        let config = self.shared.sandbox.get()?.clone();
        let broker = self.shared.broker.clone()?;
        Some(Attached {
            shared: Arc::clone(&self.shared),
            config,
            broker,
        })
    }

    fn mint_invocation(&mut self) -> Result<InvocationId, AuthorityError> {
        self.transact(|work| work.invocation_id())
    }

    /// Attach the execution-environment configuration (M5a), once, and
    /// reconcile what the runtime holds under this store's labels with the
    /// records. **The evidence harness's entry point**: no production path
    /// calls it.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the authority cannot answer, or a sandbox is
    /// already attached.
    pub fn attach_sandbox(
        &mut self,
        config: SandboxConfig,
    ) -> Result<ReconcileReport, AuthorityError> {
        if self.shared.sandbox.set(config).is_err() {
            return Err(AuthorityError::Invariant("a sandbox is attached once"));
        }
        self.environment_reconcile()
    }

    /// Prepare `run`'s one execution environment: record the intent, have
    /// the broker prepare and measure it, and judge the measurement.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the authority cannot answer. A crash hook at a
    /// [`CrashPoint::ENVIRONMENT`] point poisons the store, as a crash would.
    pub fn environment_prepare(&mut self, run: &RunId) -> Result<EnvironmentReply, AuthorityError> {
        let Some(Attached {
            shared,
            config,
            broker,
        }) = self.attached()
        else {
            return Ok(EnvironmentReply::Refused("SANDBOX_NOT_ATTACHED"));
        };
        let begun = self.transact(|work| environment::begin_prepare(work, run, &config))?;
        let intent = match begun {
            Begun::Refused(reason) => return Ok(EnvironmentReply::Refused(reason)),
            Begun::Intent(intent) => *intent,
        };
        shared.crash(CrashPoint::EnvironmentAfterIntent)?;
        let since = Instant::now();
        let environment = intent.environment.clone();
        let refuse = |reason: &'static str| Prepared::Refused {
            reason,
            judgement: None,
        };
        // Outside any transaction: the client hashed, the workspace re-pinned.
        let order = runtime(&shared, &config).and_then(|handoff| {
            specification(
                &shared,
                &config,
                (&environment, run),
                &intent.binding,
                intent.egress.clone(),
            )
            .map(|spec| (spec, handoff))
        });
        let (prepared, report, prepare_ms) = match order {
            Err(reason) => (refuse(reason), None, 0),
            Ok((spec, handoff)) => {
                let result = broker.perform(BrokerOrder::new(
                    intent.invocation.clone(),
                    Operation::EnvironmentPrepare {
                        spec,
                        runtime: handoff,
                    },
                ));
                shared.crash(CrashPoint::EnvironmentAfterBroker)?;
                judge_preparation(&environment, &config, result)
            }
        };
        let timing = Fields::new()
            .int("prepare_ms", u64::from(prepare_ms))
            .int("authority_ms", elapsed(since));
        self.transact(|work| {
            environment::record_prepared(work, &environment, run, &prepared, timing)
        })?;
        shared.crash(CrashPoint::EnvironmentAfterOutcome)?;
        Ok(match prepared {
            Prepared::Ready { .. } => match report {
                Some(report) => EnvironmentReply::Ready { report, prepare_ms },
                None => {
                    return Err(AuthorityError::Invariant(
                        "a ready environment has no measurement",
                    ));
                }
            },
            Prepared::Refused { reason, .. } => EnvironmentReply::Failed {
                environment,
                reason,
                report,
            },
            Prepared::Unknown { reason, .. } => EnvironmentReply::Unknown {
                environment,
                reason,
            },
            // Kept by the broker, not usable here: destroyed now.
            Prepared::Unusable { reason, .. } => {
                let invocation = self.mint_invocation()?;
                let record = self.transact(|work| environment::record(work, &environment))?;
                if let Some(record) = record {
                    self.perform_destroy(record, invocation)?;
                }
                EnvironmentReply::Failed {
                    environment,
                    reason,
                    report,
                }
            }
        })
    }

    /// Measure a `READY` environment again. Still clean: it stays `READY`.
    /// Anything else — a failed or unobservable invariant, a container gone,
    /// a runtime that cannot answer — is drift: the environment is destroyed.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the authority cannot answer.
    pub fn environment_measure(
        &mut self,
        environment: &EnvironmentId,
    ) -> Result<EnvironmentReply, AuthorityError> {
        let Some(attached) = self.attached() else {
            return Ok(EnvironmentReply::Refused("SANDBOX_NOT_ATTACHED"));
        };
        let (record, binding, invocation) = self.transact(|work| {
            let record = environment::record(work, environment)?;
            let binding = match &record {
                Some(record) => resolution::recorded_root(work, record.run.as_str())?,
                None => None,
            };
            Ok((record, binding, work.invocation_id()?))
        })?;
        let Some(record) = record else {
            return Ok(EnvironmentReply::Refused("UNKNOWN_ENVIRONMENT"));
        };
        if record.state != EnvironmentState::Ready {
            return Ok(EnvironmentReply::Refused("ENVIRONMENT_NOT_READY"));
        }
        self.remeasure(&attached, record, binding.as_ref(), invocation)
    }

    /// The measurement of a `READY` record, and what follows from it.
    fn remeasure(
        &mut self,
        attached: &Attached,
        record: EnvironmentRecord,
        binding: Option<&RootBinding>,
        invocation: InvocationId,
    ) -> Result<EnvironmentReply, AuthorityError> {
        let Attached {
            shared,
            config,
            broker,
        } = attached;
        let Some(container) = record.container.clone() else {
            return Err(AuthorityError::Invariant(
                "a ready environment has no container",
            ));
        };
        let order = binding
            .ok_or("NO_WORKSPACE_ROOT")
            .and_then(|binding| {
                specification(
                    shared,
                    config,
                    (&record.environment, &record.run),
                    binding,
                    None,
                )
            })
            .and_then(|spec| runtime(shared, config).map(|handoff| (spec, handoff)));
        let outcome: Result<EnvironmentReport, (&'static str, Option<EnvironmentReport>)> =
            match order {
                Err(reason) => Err((reason, None)),
                Ok((spec, handoff)) => match broker.perform(BrokerOrder::new(
                    invocation,
                    Operation::EnvironmentMeasure {
                        spec,
                        container: container.clone(),
                        runtime: handoff,
                    },
                )) {
                    Ok(BrokerDelivery::EnvironmentMeasured(done)) => match &done.measurement {
                        Some(measurement) => {
                            let report = report_of(
                                &record.environment,
                                Some(container),
                                measurement,
                                config.topology(),
                                done.egress.clone(),
                            );
                            match report.judgement.failure(EnvironmentKind::Oci) {
                                None => Ok(report),
                                Some(reason) => Err((reason, Some(report))),
                            }
                        }
                        None => Err(("ASSURANCE_UNOBSERVABLE", None)),
                    },
                    Ok(_) => Err(("BROKER_PROTOCOL_ERROR", None)),
                    Err(error) => Err((failure_of(&error), None)),
                },
            };
        match outcome {
            Ok(report) => {
                let mut timing = Fields::new().int("measure_ms", u64::from(report.measure_ms));
                if let Some(counters) = &report.egress {
                    timing = environment::egress_fields(timing, counters);
                }
                self.transact(|work| {
                    environment::record_measured(work, &record, &report.judgement, timing)
                })?;
                Ok(EnvironmentReply::Clean(report))
            }
            Err((reason, report)) => {
                let begun = self.transact(|work| {
                    environment::record_drifted(
                        work,
                        &record,
                        reason,
                        report.as_ref().map(|r| &r.judgement),
                    )?;
                    environment::begin_destroy(work, &record.environment, "DRIFTED")
                })?;
                let destroyed = match begun {
                    DestroyBegun::Pending { record, invocation } => matches!(
                        self.perform_destroy(record, invocation)?,
                        EnvironmentReply::Destroyed { .. }
                    ),
                    DestroyBegun::Refused(_) => false,
                };
                Ok(EnvironmentReply::Drifted {
                    environment: record.environment,
                    reason,
                    report,
                    destroyed,
                })
            }
        }
    }

    /// Destroy an environment: the destruction is durable first, then the
    /// broker removes exactly the container labelled as it.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the authority cannot answer.
    pub fn environment_destroy(
        &mut self,
        environment: &EnvironmentId,
    ) -> Result<EnvironmentReply, AuthorityError> {
        if self.attached().is_none() {
            return Ok(EnvironmentReply::Refused("SANDBOX_NOT_ATTACHED"));
        }
        let begun =
            self.transact(|work| environment::begin_destroy(work, environment, "REQUESTED"))?;
        match begun {
            DestroyBegun::Refused(reason) => Ok(EnvironmentReply::Refused(reason)),
            DestroyBegun::Pending { record, invocation } => {
                self.perform_destroy(record, invocation)
            }
        }
    }

    /// The broker's half of a recorded destruction, and its outcome.
    fn perform_destroy(
        &mut self,
        record: EnvironmentRecord,
        invocation: InvocationId,
    ) -> Result<EnvironmentReply, AuthorityError> {
        let Some(attached) = self.attached() else {
            return Ok(EnvironmentReply::DestroyPending {
                environment: record.environment,
                reason: "SANDBOX_NOT_ATTACHED",
            });
        };
        attached
            .shared
            .crash(CrashPoint::EnvironmentDestroyAfterIntent)?;
        let since = Instant::now();
        let (ending, destroy_ms) = broker_destroy(
            &attached,
            (&record.environment, &record.run),
            record.container.clone(),
            invocation,
        );
        attached
            .shared
            .crash(CrashPoint::EnvironmentDestroyAfterBroker)?;
        let timing = Fields::new()
            .int("destroy_ms", u64::from(destroy_ms))
            .int("authority_ms", elapsed(since));
        self.transact(|work| environment::record_destroyed(work, &record, &ending, timing))?;
        Ok(match ending {
            DestroyEnding::Gone {
                container,
                already,
                egress,
            } => EnvironmentReply::Destroyed {
                environment: record.environment,
                container: container.or(record.container),
                already_gone: already,
                destroy_ms,
                egress,
            },
            DestroyEnding::Pending { reason } => EnvironmentReply::DestroyPending {
                environment: record.environment,
                reason,
            },
        })
    }

    /// Compare the records with every container the runtime holds under this
    /// store's labels, and settle each by its class (ADR-0047 §11): a `READY`
    /// one is measured again, a stopped or pending one destroyed, a missing
    /// one recorded lost, an orphan removed — exactly, by its own labels —
    /// and anything ambiguous or malformed left untouched. A runtime that
    /// cannot be listed completely changes nothing.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the authority cannot answer.
    pub fn environment_reconcile(&mut self) -> Result<ReconcileReport, AuthorityError> {
        let mut report = ReconcileReport::default();
        let Some(attached) = self.attached() else {
            report.unobservable = true;
            return Ok(report);
        };
        let (records, invocation, current) = self.transact(|work| {
            Ok((
                environment::live(work)?,
                work.invocation_id()?,
                work.incarnation(),
            ))
        })?;
        let listed = list(&attached, invocation);
        let Some(listed) = listed else {
            report.unobservable = true;
            let fields = report.fields();
            self.transact(|work| work.audit(AuditEvent::EnvironmentReconciled, fields))?;
            return Ok(report);
        };
        // The record of every environment a listed container names, whatever
        // its state: an ended one is an orphan's, and no record at all means
        // the label was copied. Live records were read before the listing, so
        // one that became READY since was PREPARING — in flight — then.
        let records = self.transact(|work| {
            let mut records = records;
            for owned in &listed {
                let Some(environment) = &owned.environment_id else {
                    continue;
                };
                if records.iter().any(|r| &r.environment == environment) {
                    continue;
                }
                if let Some(record) = environment::record(work, environment)? {
                    records.push(record);
                }
            }
            Ok(records)
        })?;
        for class in environment::classify(&records, &listed, current) {
            self.settle(&attached, class, &mut report)?;
        }
        let fields = report.fields();
        self.transact(|work| work.audit(AuditEvent::EnvironmentReconciled, fields))?;
        Ok(report)
    }

    fn settle(
        &mut self,
        attached: &Attached,
        class: ReconcileClass,
        report: &mut ReconcileReport,
    ) -> Result<(), AuthorityError> {
        match class {
            ReconcileClass::StillRunning(record) => {
                let (binding, invocation) = self.transact(|work| {
                    Ok((
                        resolution::recorded_root(work, record.run.as_str())?,
                        work.invocation_id()?,
                    ))
                })?;
                match self.remeasure(attached, record, binding.as_ref(), invocation)? {
                    EnvironmentReply::Clean(_) => report.still_running += 1,
                    _ => report.drifted += 1,
                }
            }
            ReconcileClass::Stopped(record) | ReconcileClass::Pending(record) => {
                let stopped = record.state == EnvironmentState::Ready;
                let reason = if stopped { "STOPPED" } else { "RECONCILED" };
                let begun = self.transact(|work| {
                    environment::begin_destroy(work, &record.environment, reason)
                })?;
                let done = match begun {
                    DestroyBegun::Pending { record, invocation } => matches!(
                        self.perform_destroy(record, invocation)?,
                        EnvironmentReply::Destroyed { .. }
                    ),
                    DestroyBegun::Refused(_) => false,
                };
                match (done, stopped) {
                    (true, true) => report.stopped += 1,
                    (true, false) => report.pending_destroyed += 1,
                    (false, _) => report.incomplete += 1,
                }
            }
            ReconcileClass::Missing(record) => {
                self.transact(|work| environment::record_lost(work, &record))?;
                report.missing += 1;
            }
            ReconcileClass::Ambiguous(_) => report.ambiguous += 1,
            ReconcileClass::Foreign(_) => report.foreign += 1,
            ReconcileClass::Orphan(owned) => {
                let removed = self.reap(attached, &owned)?;
                if removed {
                    report.orphans_reaped += 1;
                } else {
                    report.incomplete += 1;
                }
            }
        }
        Ok(())
    }

    /// Remove an orphan: exactly the container its own labels name, through
    /// the same destruction that proves the labels immediately before.
    fn reap(
        &mut self,
        attached: &Attached,
        owned: &OwnedEnvironment,
    ) -> Result<bool, AuthorityError> {
        let (Some(environment), Some(run)) = (&owned.environment_id, &owned.run_id) else {
            return Ok(false);
        };
        let invocation = self.mint_invocation()?;
        // A helper is reaped through its environment's destruction, which
        // finds the environment's own container by its labels (M5b).
        let recorded =
            (owned.role == Some(ContainerRole::Environment)).then(|| owned.container.clone());
        let (ending, _) = broker_destroy(attached, (environment, run), recorded, invocation);
        let removed = matches!(ending, DestroyEnding::Gone { .. });
        self.transact(|work| environment::record_orphan(work, owned, removed))?;
        Ok(removed)
    }

    /// One environment's record: for the evidence and the operator.
    ///
    /// # Errors
    ///
    /// [`AuthorityError`] when the authority cannot answer.
    pub fn environment_record(
        &mut self,
        environment: &EnvironmentId,
    ) -> Result<Option<EnvironmentRecord>, AuthorityError> {
        self.transact(|work| environment::record(work, environment))
    }
}

/// The broker's answer to a preparation, judged: how it ended, the
/// measurement, and how long the broker took.
fn judge_preparation(
    environment: &EnvironmentId,
    config: &SandboxConfig,
    result: Result<BrokerDelivery, BrokerError>,
) -> (Prepared, Option<EnvironmentReport>, u32) {
    match result {
        Ok(BrokerDelivery::EnvironmentPrepared(done)) => {
            let prepare_ms = done.prepare_ms.get();
            let report = done.measurement.as_ref().map(|m| {
                report_of(
                    environment,
                    done.container.clone(),
                    m,
                    config.topology(),
                    None,
                )
            });
            let judgement = report.as_ref().map(|r| r.judgement.clone());
            let failure = judgement
                .as_ref()
                .map_or(Some("ASSURANCE_UNOBSERVABLE"), |j| {
                    j.failure(EnvironmentKind::Oci)
                });
            let prepared = match (done.retained, done.container, judgement, failure) {
                (true, Some(container), Some(judgement), None) => Prepared::Ready {
                    container,
                    judgement,
                },
                (true, Some(container), Some(judgement), Some(reason)) => Prepared::Unusable {
                    container,
                    reason,
                    judgement,
                },
                (true, container, _, _) => Prepared::Unknown {
                    container,
                    reason: "BROKER_PROTOCOL_ERROR",
                },
                (false, _, judgement, reason) => Prepared::Refused {
                    reason: reason.unwrap_or("ASSURANCE_UNOBSERVABLE"),
                    judgement,
                },
            };
            (prepared, report, prepare_ms)
        }
        Ok(_) => (
            Prepared::Unknown {
                container: None,
                reason: "BROKER_PROTOCOL_ERROR",
            },
            None,
            0,
        ),
        Err(error) if error.provably_without_effect() => (
            Prepared::Refused {
                reason: failure_of(&error),
                judgement: None,
            },
            None,
            0,
        ),
        Err(error) => (
            Prepared::Unknown {
                container: None,
                reason: failure_of(&error),
            },
            None,
            0,
        ),
    }
}

/// Have the broker remove `environment` (of `run`) — `container`, when one
/// is known — and say how it ended.
fn broker_destroy(
    attached: &Attached,
    (environment, run): (&EnvironmentId, &RunId),
    container: Option<ContainerRef>,
    invocation: InvocationId,
) -> (DestroyEnding, u32) {
    let pending = |reason| (DestroyEnding::Pending { reason }, 0);
    let Ok(store) = store(&attached.shared) else {
        return pending("STORE_INSTANCE");
    };
    let handoff = match runtime(&attached.shared, &attached.config) {
        Ok(handoff) => handoff,
        Err(reason) => return pending(reason),
    };
    match attached.broker.perform(BrokerOrder::new(
        invocation,
        Operation::EnvironmentDestroy {
            environment: (environment.clone(), run.clone(), store),
            container,
            runtime: handoff,
        },
    )) {
        Ok(BrokerDelivery::EnvironmentDestroyed(done)) => (
            DestroyEnding::Gone {
                container: done.container,
                already: done.state == DestroyState::AlreadyGone,
                egress: done.egress,
            },
            done.destroy_ms.get(),
        ),
        Ok(_) => pending("BROKER_PROTOCOL_ERROR"),
        Err(error) => pending(failure_of(&error)),
    }
}

/// Every environment the runtime holds under this store's labels, or `None`
/// when that cannot be known completely.
fn list(attached: &Attached, invocation: InvocationId) -> Option<Vec<OwnedEnvironment>> {
    let store = store(&attached.shared).ok()?;
    let handoff = runtime(&attached.shared, &attached.config).ok()?;
    match attached.broker.perform(BrokerOrder::new(
        invocation,
        Operation::EnvironmentList {
            store,
            runtime: handoff,
        },
    )) {
        Ok(BrokerDelivery::EnvironmentListed(done)) if done.complete => {
            Some(done.environments.into_iter().collect())
        }
        _ => None,
    }
}
