//! The sandbox supervisor (M5a, [ADR-0047]): execution environments —
//! prepared, measured, destroyed and listed — and, since M5d ([ADR-0052]),
//! authorised workloads run inside them, one at a time in each: started,
//! supervised on their own threads, and collected (M5d.2, `supervisor`).
//!
//! | operation | what the broker does | what it never does |
//! |---|---|---|
//! | `environment_prepare` | re-prove the runtime client; check the pinned image is present; create an `oci-strict` container from the typed plan; start it; measure it from the runtime's record and from inside; keep it only if every required invariant passed | pull an image, accept a flag, leave a failing environment running |
//! | `environment_measure` | the same measurement, of a container the authority recorded, after proving it carries this environment's labels | measure or touch a container labelled otherwise |
//! | `environment_destroy` | remove the one container labelled as this environment of this store | touch anything labelled otherwise, or guess between two |
//! | `environment_list` | report every container labelled as this store's | report or touch another store's, or an unlabelled one |
//! | `workload_start` | re-judge the recorded container from the runtime's record; prove the executable's bytes in the image; answer; then, supervised, run exactly the plan's command line as uid 10001 in `/workspace`, bounded, and end every other process of the environment | run anything in a container that is not the clean, running, recorded one; run anything it did not answer for; run as anyone else; take a flag, a variable or a shell string from the authorisation; leave a process of the workload behind unreported |
//! | `workload_collect` | answer `RUNNING`, or the ending it kept | say how a workload of another generation, or one it does not hold, ended |
//!
//! The broker judges no assurance level. It reports every invariant with its
//! verdict; the authority takes the level from them, and never higher than
//! the environment kind declares (ADR-0047 §6). The one decision the broker
//! makes on its own is conservative: a prepared container that did not
//! measure clean is removed before the answer is sent.
//!
//! `PROXY_ONLY` (M5b, [ADR-0048]) is the topology a sandboxed workload will
//! have: the runtime's `none` network, one relay in that namespace, and this
//! broker's CONNECT proxy ([`crate::egress`]) behind it, opened before the
//! environment is created and closed when it is destroyed — its counters
//! returned with the destruction. `NO_NETWORK` is still the M5a evidence
//! harness's topology, built only by a broker started with
//! `--allow-evidence-topology` (ADR-0047 §10). Nothing runs inside either
//! but the probe and, from M5d, the workloads the authority authorises.
//!
//! [ADR-0047]: ../../../../docs/adr/0047-m5a-oci-execution-environment-and-measured-assurance.md
//! [ADR-0048]: ../../../../docs/adr/0048-m5b-proxy-only-topology-and-connect-proxy.md
//! [ADR-0052]: ../../../../docs/adr/0052-m5d-sandboxed-process-exec.md

mod digest;
mod environment;
mod inspect;
mod oci;
mod plan;
mod relay_plan;
mod supervisor;
mod workload_plan;
mod workload_secret_plan;

use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dwk_proto::brokerp::EnvironmentSpec;
use dwk_proto::brokerp::sandbox::{
    ContainerRef, InvariantCheck, InvariantChecks, Milliseconds, NetworkTopology, SandboxInvariant,
    Verdict,
};
use dwk_proto::brokerp::workload::{
    ProcessCount, RedactionCount, WORKLOAD_SUPERVISION_SECONDS, WorkloadCollectAuthorisation,
    WorkloadCollectDone, WorkloadEnding, WorkloadProgress, WorkloadRunDone, WorkloadSecret,
    WorkloadSecretStartAuthorisation, WorkloadSpec, WorkloadStartAuthorisation,
};
use dwk_proto::brokerp::{
    BrokerDone, BrokerGeneration, BrokerRefusal, DestroyState, EnvironmentDestroyAuthorisation,
    EnvironmentDestroyDone, EnvironmentListAuthorisation, EnvironmentListDone,
    EnvironmentMeasureAuthorisation, EnvironmentMeasureDone, EnvironmentMeasurement,
    EnvironmentPrepareAuthorisation, EnvironmentPrepareDone, Indeterminate, OutcomeResult,
    OwnedEnvironments, ProcessStreamSnapshot, RuntimeSpec, SecretDelivery,
};
use dwk_proto::wire::scalar::{ByteCount, ExitCode, SignalNumber, StreamContent};

use environment::{
    Destroyed, EnvFailure, EnvHandle, ExecOutcome, ExecutionEnvironment, Measured, Ran, SecretRun,
};

use crate::egress::proxy::Proxies;

/// One measurement: every invariant, with its verdict.
pub(crate) type Checks = Vec<(SandboxInvariant, Verdict)>;

/// What the listener prepared for the sandbox, in the broker's own private
/// directory: the seccomp profile file the runtime client reads, and the
/// client's empty configuration directory.
#[derive(Debug, Clone)]
pub(crate) struct SandboxFiles {
    /// The `oci-strict` seccomp profile, exactly
    /// [`dwk_sandbox_profile::seccomp_profile_json`].
    pub(crate) seccomp: PathBuf,
    /// An empty directory the client uses as its home and configuration.
    pub(crate) client_config: PathBuf,
}

/// What driving a runtime needs, shared with every workload's thread.
#[derive(Debug)]
struct Parts {
    helper: PathBuf,
    authority_uid: u32,
    files: SandboxFiles,
    profile: String,
    proxies: Arc<Proxies>,
}

/// The sandbox supervisor: what it needs to drive a runtime, the workloads
/// it supervises, and nothing it could decide with.
#[derive(Debug)]
pub(crate) struct Sandbox {
    parts: Arc<Parts>,
    evidence_topology: bool,
    workloads: supervisor::Workloads,
}

/// The margin kept at the end of an exchange's deadline for the answer.
const ANSWER_MARGIN: std::time::Duration = std::time::Duration::from_secs(5);

fn failure(failure: EnvFailure) -> OutcomeResult {
    match failure {
        EnvFailure::Refused(why) => OutcomeResult::Refused(why),
        EnvFailure::Unconfirmed => {
            OutcomeResult::Indeterminate(Indeterminate::EnvironmentUnconfirmed)
        }
    }
}

/// One stream as it crosses the wire: what was kept, every byte observed.
fn stream(kept: &[u8], observed: u64) -> Option<ProcessStreamSnapshot> {
    let kept_len = u64::try_from(kept.len()).ok()?;
    Some(ProcessStreamSnapshot {
        content: StreamContent::from_bytes(kept)?,
        observed: ByteCount::new(observed.max(kept_len))?,
        truncated: observed > kept_len,
    })
}

/// A run's answer, or `None` when it cannot be stated in the protocol's own
/// terms (a count past its bound): the caller says nothing proves how it
/// ended.
fn ran_done(ran: &Ran) -> Option<WorkloadRunDone> {
    let (ending, exit_code, signal) = match ran.outcome {
        ExecOutcome::Exited(code) => (WorkloadEnding::Exited, ExitCode::new(code), None),
        ExecOutcome::Killed(signal) => (
            WorkloadEnding::Killed,
            None,
            Some(SignalNumber::new(signal)?),
        ),
        ExecOutcome::TimedOut => (WorkloadEnding::TimedOut, None, None),
        ExecOutcome::EnvironmentGone => (WorkloadEnding::EnvironmentGone, None, None),
        ExecOutcome::RuntimeUnavailable => (WorkloadEnding::RuntimeUnavailable, None, None),
        ExecOutcome::Unobservable => (WorkloadEnding::Unobservable, None, None),
    };
    if ending == WorkloadEnding::Exited && exit_code.is_none() {
        return None;
    }
    let done = WorkloadRunDone {
        ending,
        exit_code,
        signal,
        stdout: stream(&ran.stdout, ran.stdout_observed)?,
        stderr: stream(&ran.stderr, ran.stderr_observed)?,
        elapsed_ms: ran.elapsed,
        residue: ran.residue,
        ended_processes: ProcessCount::new(ran.ended)?,
        remaining_processes: ProcessCount::new(ran.remaining)?,
        redactions: match ran.redactions {
            Some(count) => Some(RedactionCount::new(count)?),
            None => None,
        },
    };
    dwk_proto::brokerp::workload::check_done(&done).ok()?;
    Some(done)
}

/// A workload's judgement as a start answers it: a refusal, or -- when the
/// steps that read could not say what they found -- indeterminate.
fn judgement(failure: EnvFailure) -> OutcomeResult {
    match failure {
        EnvFailure::Refused(why) => OutcomeResult::Refused(why),
        EnvFailure::Unconfirmed => OutcomeResult::Indeterminate(Indeterminate::WorkloadUnconfirmed),
    }
}

/// A run's ending as every collection answers it.
fn ending(ran: Result<Ran, EnvFailure>) -> OutcomeResult {
    match ran {
        Ok(ran) => match ran_done(&ran) {
            Some(done) => OutcomeResult::done(BrokerDone::workload_collect(WorkloadCollectDone {
                progress: WorkloadProgress::Ended,
                result: Some(done),
                never_ran: None,
            })),
            // It ran and its answer cannot be stated: nothing proves how it
            // ended.
            None => OutcomeResult::Indeterminate(Indeterminate::WorkloadUnconfirmed),
        },
        // The client never ran: nothing was executed. Said in the
        // collection's own answer, so no refusal of a collection is ever
        // read as one.
        Err(EnvFailure::Refused(why)) => {
            OutcomeResult::done(BrokerDone::workload_collect(WorkloadCollectDone {
                progress: WorkloadProgress::Ended,
                result: None,
                never_ran: Some(why),
            }))
        }
        Err(EnvFailure::Unconfirmed) => {
            OutcomeResult::Indeterminate(Indeterminate::WorkloadUnconfirmed)
        }
    }
}

/// Re-prove the runtime and run `step` over the `oci` environment.
fn with_oci<T>(
    parts: &Parts,
    descriptors: (OwnedFd, OwnedFd),
    runtime: &RuntimeSpec,
    until: Instant,
    step: impl FnOnce(&oci::Oci<'_>) -> T,
) -> Result<T, BrokerRefusal> {
    let seccomp = parts
        .files
        .seccomp
        .to_str()
        .ok_or(BrokerRefusal::Unsupported)?;
    let held = oci::Runtime::new(
        &parts.helper,
        descriptors,
        runtime,
        (&parts.files.client_config, parts.authority_uid),
        until.checked_sub(ANSWER_MARGIN).unwrap_or(until),
    )?;
    Ok(step(&oci::Oci::new(
        held,
        (seccomp, &parts.profile),
        runtime.socket.as_str(),
        &parts.proxies,
    )))
}

/// What a workload's thread needs of its start.
struct Workload {
    handle: EnvHandle,
    spec: EnvironmentSpec,
    program: WorkloadSpec,
    runtime: RuntimeSpec,
    /// A secret-bearing workload's secret (M5d.3), and the descriptor that
    /// holds its value -- read only after the judgement.
    secret: Option<(WorkloadSecret, OwnedFd)>,
}

/// Read a secret-bearing workload's value -- once, bounded, from a pipe the
/// authority filled and closed -- and refuse what its delivery cannot carry
/// (M5d.3, ADR-0046 §11, ADR-0052 §7). Called only once the environment is
/// judged and the executable proved, so a refused workload never reads it.
/// A variable the environment sets never reaches here: the shared decoder
/// refuses the authorisation (`workload::sandbox_secret_name_allowed`), and
/// the launcher refuses the name again inside the environment.
fn secret_run(
    secret: Option<&(WorkloadSecret, OwnedFd)>,
) -> Result<Option<SecretRun>, BrokerRefusal> {
    let Some((secret, fd)) = secret else {
        return Ok(None);
    };
    let value = crate::secret::read_value(fd)?;
    crate::crash::point("workload_secret_after_read");
    if secret.delivery == SecretDelivery::EnvAtSpawn && value.contains(&0) {
        return Err(BrokerRefusal::SecretUnsafeBytes);
    }
    let needle =
        crate::secret::Needle::new(value, &secret.handle).ok_or(BrokerRefusal::SecretEmpty)?;
    Ok(Some(SecretRun {
        secret: secret.clone(),
        launch: crate::process::launch::SecretLaunch {
            delivery: crate::process::launch::Delivery::Stdin,
            needle,
        },
    }))
}

/// A workload's thread (ADR-0052 §§5, 8): re-prove the runtime, re-judge
/// the environment and prove the executable; for a secret-bearing workload
/// (M5d.3), only then read its value; report it through `gate`; and only on
/// the exchange's word, run it, bounded by `until`. `None` when it never
/// ran.
fn supervise(
    parts: &Parts,
    descriptors: (OwnedFd, OwnedFd),
    work: &Workload,
    gate: supervisor::Gate,
    until: Instant,
) -> Option<OutcomeResult> {
    let mut gate = Some(gate);
    let ran = with_oci(parts, descriptors, &work.runtime, until, |env| {
        let judged = env
            .ready_workload(&work.handle, &work.spec, &work.program)
            .map_err(judgement)
            .and_then(|()| secret_run(work.secret.as_ref()).map_err(OutcomeResult::Refused));
        let (judged, secret) = match judged {
            Ok(secret) => (Ok(()), secret),
            Err(refused) => (Err(refused), None),
        };
        let go = gate.take().is_some_and(|gate| gate.judged(judged));
        go.then(|| env.exec_workload(&work.handle, &work.program, until, secret))
    });
    match ran {
        Ok(ran) => ran.map(ending),
        Err(refusal) => {
            if let Some(gate) = gate {
                let _ = gate.judged(Err(OutcomeResult::Refused(refusal)));
            }
            None
        }
    }
}

fn measurement(measured: &Measured) -> Option<EnvironmentMeasurement> {
    let checks = measured.checks.as_ref()?;
    let checks = InvariantChecks::new(
        checks
            .iter()
            .map(|(invariant, verdict)| InvariantCheck {
                invariant: *invariant,
                verdict: *verdict,
            })
            .collect(),
    )?;
    Some(EnvironmentMeasurement {
        checks,
        runtime_version: measured.runtime_version.clone(),
        measure_ms: measured.measure_ms,
    })
}

impl Sandbox {
    /// The supervisor. `helper` is this binary (the launch helper),
    /// `evidence_topology` the operator's acknowledgement that the evidence
    /// harness's `NO_NETWORK` topology may be built, and `proxies` the
    /// broker's `PROXY_ONLY` listeners.
    pub(crate) fn new(
        helper: PathBuf,
        authority_uid: u32,
        files: SandboxFiles,
        (evidence_topology, generation): (bool, BrokerGeneration),
        proxies: Arc<Proxies>,
    ) -> Self {
        Self {
            parts: Arc::new(Parts {
                helper,
                authority_uid,
                files,
                profile: dwk_sandbox_profile::seccomp_profile_json(),
                proxies,
            }),
            evidence_topology,
            workloads: supervisor::Workloads::new(generation),
        }
    }

    fn topology(&self, network: NetworkTopology) -> Result<(), BrokerRefusal> {
        match network {
            NetworkTopology::ProxyOnly => Ok(()),
            NetworkTopology::NoNetwork if self.evidence_topology => Ok(()),
            NetworkTopology::NoNetwork => Err(BrokerRefusal::TopologyUnavailable),
        }
    }

    /// Re-prove the runtime and run `step` over the `oci` environment.
    fn with_oci(
        &self,
        descriptors: (OwnedFd, OwnedFd),
        runtime: &RuntimeSpec,
        until: Instant,
        step: impl FnOnce(&oci::Oci<'_>) -> OutcomeResult,
    ) -> OutcomeResult {
        with_oci(&self.parts, descriptors, runtime, until, step)
            .unwrap_or_else(OutcomeResult::Refused)
    }

    /// `broker.environment_prepare`.
    pub(crate) fn prepare(
        &self,
        authorisation: &EnvironmentPrepareAuthorisation,
        descriptors: (OwnedFd, OwnedFd),
        until: Instant,
    ) -> OutcomeResult {
        let spec = authorisation.environment();
        if let Err(why) = self.topology(spec.network) {
            return OutcomeResult::Refused(why);
        }
        // The probe's own question must stay unanswerable: a grant that
        // names it would let a listener that is not the proxy pass for it.
        if spec.egress.as_ref().is_some_and(|grant| {
            grant
                .targets
                .iter()
                .any(|t| t.host.as_str() == dwk_sandbox_profile::PROXY_PROBE_HOST)
        }) {
            return OutcomeResult::Refused(BrokerRefusal::Unsupported);
        }
        let since = Instant::now();
        self.with_oci(descriptors, &authorisation.runtime(), until, |env| {
            match env.prepare(&spec) {
                Ok(prepared) => {
                    // What the kind claims, beside what was found: the
                    // authority takes the lower of the two (ADR-0047 §6).
                    crate::event(&format!(
                        "environment_prepared declared={} retained={}",
                        env.declared().as_str(),
                        prepared.retained
                    ));
                    let measurement = prepared.measured.as_ref().and_then(measurement);
                    OutcomeResult::Done(Box::new(BrokerDone::environment_prepare(
                        EnvironmentPrepareDone {
                            container: prepared.handle.map(|h| h.container),
                            retained: prepared.retained,
                            measurement,
                            prepare_ms: Milliseconds::of(since.elapsed()),
                        },
                    )))
                }
                Err(why) => failure(why),
            }
        })
    }

    /// `broker.environment_measure`.
    pub(crate) fn measure(
        &self,
        authorisation: &EnvironmentMeasureAuthorisation,
        descriptors: (OwnedFd, OwnedFd),
        until: Instant,
    ) -> OutcomeResult {
        let spec = authorisation.environment();
        if let Err(why) = self.topology(spec.network) {
            return OutcomeResult::Refused(why);
        }
        let handle = EnvHandle {
            environment: spec.environment_id.clone(),
            container: authorisation.container.clone(),
        };
        self.with_oci(
            descriptors,
            &authorisation.runtime(),
            until,
            |env| match env.measure(&handle, &spec) {
                Ok(measured) => OutcomeResult::Done(Box::new(BrokerDone::environment_measure(
                    EnvironmentMeasureDone {
                        state: measured.state,
                        measurement: measurement(&measured),
                        egress: self.parts.proxies.counters(spec.environment_id.as_str()),
                    },
                ))),
                Err(why) => failure(why),
            },
        )
    }

    /// `broker.environment_destroy`.
    pub(crate) fn destroy(
        &self,
        authorisation: &EnvironmentDestroyAuthorisation,
        descriptors: (OwnedFd, OwnedFd),
        until: Instant,
    ) -> OutcomeResult {
        let since = Instant::now();
        self.with_oci(descriptors, &authorisation.runtime(), until, |env| {
            let destroyed = env.destroy(
                &authorisation.store,
                (&authorisation.environment_id, &authorisation.run_id),
                authorisation.container.as_ref(),
            );
            // Whatever the runtime managed, the environment's proxy is
            // closed: a destruction never leaves its egress open.
            let egress = self
                .parts
                .proxies
                .close(authorisation.environment_id.as_str());
            match destroyed {
                Ok(destroyed) => {
                    let (state, container): (DestroyState, Option<ContainerRef>) = match destroyed {
                        Destroyed::Removed(container) => (DestroyState::Removed, Some(container)),
                        Destroyed::AlreadyGone => (DestroyState::AlreadyGone, None),
                    };
                    if let Some(counters) = &egress {
                        crate::event(&format!(
                            "egress_closed upstream={} downstream={}",
                            counters.bytes_upstream.get(),
                            counters.bytes_downstream.get()
                        ));
                    }
                    OutcomeResult::Done(Box::new(BrokerDone::environment_destroy(
                        EnvironmentDestroyDone {
                            state,
                            container,
                            destroy_ms: Milliseconds::of(since.elapsed()),
                            egress,
                        },
                    )))
                }
                Err(why) => failure(why),
            }
        })
    }

    /// `broker.workload_start` (M5d.2, ADR-0052 §§5, 8): one workload, in
    /// the recorded container of a `READY` environment. The authority
    /// decided it; this re-judges the environment and proves the executable
    /// before the answer, and the supervisor's thread then runs it and ends
    /// whatever it left. Nothing runs that this did not answer for.
    pub(crate) fn workload_start(
        &self,
        authorisation: &WorkloadStartAuthorisation,
        descriptors: (OwnedFd, OwnedFd),
        until: Instant,
    ) -> OutcomeResult {
        self.start_workload(authorisation, descriptors, None, until)
    }

    /// `broker.workload_secret_start` (M5d.3, ADR-0052 §7): a workload's
    /// start that delivers one secret. Everything `workload_start` proves;
    /// then -- on the supervisor's thread, before the answer -- the value is
    /// read once from the last descriptor; the runtime's client receives it
    /// framed on its standard input and the trusted launcher delivers it.
    /// The output is redacted of it as it is drained.
    pub(crate) fn workload_secret_start(
        &self,
        authorisation: &WorkloadSecretStartAuthorisation,
        descriptors: (OwnedFd, OwnedFd),
        secret: OwnedFd,
        until: Instant,
    ) -> OutcomeResult {
        let answer = self.start_workload(
            &authorisation.start(),
            descriptors,
            Some((authorisation.secret(), secret)),
            until,
        );
        // The same answer, under the operation that asked it.
        match answer {
            OutcomeResult::Done(done) => match done.workload_start {
                Some(started) => OutcomeResult::done(BrokerDone::workload_secret_start(started)),
                None => OutcomeResult::Done(done),
            },
            other => other,
        }
    }

    fn start_workload(
        &self,
        authorisation: &WorkloadStartAuthorisation,
        descriptors: (OwnedFd, OwnedFd),
        secret: Option<(WorkloadSecret, OwnedFd)>,
        until: Instant,
    ) -> OutcomeResult {
        let spec = authorisation.environment();
        if let Err(why) = self.topology(spec.network) {
            return OutcomeResult::Refused(why);
        }
        let environment = spec.environment_id.clone();
        let work = Workload {
            handle: EnvHandle {
                environment: spec.environment_id.clone(),
                container: authorisation.container.clone(),
            },
            program: authorisation.workload(),
            runtime: authorisation.runtime(),
            spec,
            secret,
        };
        let parts = Arc::clone(&self.parts);
        // The workload's own bound, from now: its longest wall clock and the
        // steps before and after it. Its thread is gone by then.
        let supervised = Instant::now() + Duration::from_secs(WORKLOAD_SUPERVISION_SECONDS);
        self.workloads.start(
            &authorisation.invocation_id,
            &environment,
            until.checked_sub(ANSWER_MARGIN).unwrap_or(until),
            move |gate| supervise(&parts, descriptors, &work, gate, supervised),
        )
    }

    /// `broker.workload_collect` (M5d.2): `RUNNING`, or the ending kept.
    pub(crate) fn workload_collect(&self, collect: &WorkloadCollectAuthorisation) -> OutcomeResult {
        self.workloads.collect(collect)
    }

    /// `broker.environment_list`.
    pub(crate) fn list(
        &self,
        authorisation: &EnvironmentListAuthorisation,
        descriptors: (OwnedFd, OwnedFd),
        until: Instant,
    ) -> OutcomeResult {
        self.with_oci(
            descriptors,
            &authorisation.runtime(),
            until,
            |env| match env.list(&authorisation.store) {
                Ok(listed) => match OwnedEnvironments::new(listed.environments) {
                    Some(environments) => OutcomeResult::Done(Box::new(
                        BrokerDone::environment_list(EnvironmentListDone {
                            environments,
                            complete: listed.complete,
                        }),
                    )),
                    None => OutcomeResult::Refused(BrokerRefusal::RuntimeOutputMalformed),
                },
                Err(why) => failure(why),
            },
        )
    }
}
