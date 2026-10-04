//! The sandbox supervisor's first slice (M5a, [ADR-0047]): execution
//! environments — prepared, measured, destroyed and listed — and nothing run
//! inside them but the trusted probe.
//!
//! | operation | what the broker does | what it never does |
//! |---|---|---|
//! | `environment_prepare` | re-prove the runtime client; check the pinned image is present; create an `oci-strict` container from the typed plan; start it; measure it from the runtime's record and from inside; keep it only if every required invariant passed | pull an image, accept a flag, leave a failing environment running |
//! | `environment_measure` | the same measurement, of a container the authority recorded, after proving it carries this environment's labels | measure or touch a container labelled otherwise |
//! | `environment_destroy` | remove the one container labelled as this environment of this store | touch anything labelled otherwise, or guess between two |
//! | `environment_list` | report every container labelled as this store's | report or touch another store's, or an unlabelled one |
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
//! but the probe: workloads are M5d's.
//!
//! [ADR-0047]: ../../../../docs/adr/0047-m5a-oci-execution-environment-and-measured-assurance.md
//! [ADR-0048]: ../../../../docs/adr/0048-m5b-proxy-only-topology-and-connect-proxy.md

mod digest;
mod environment;
mod inspect;
mod oci;
mod plan;
mod relay_plan;

use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use dwk_proto::brokerp::sandbox::{
    ContainerRef, InvariantCheck, InvariantChecks, Milliseconds, NetworkTopology, SandboxInvariant,
    Verdict,
};
use dwk_proto::brokerp::{
    BrokerDone, BrokerRefusal, DestroyState, EnvironmentDestroyAuthorisation,
    EnvironmentDestroyDone, EnvironmentListAuthorisation, EnvironmentListDone,
    EnvironmentMeasureAuthorisation, EnvironmentMeasureDone, EnvironmentMeasurement,
    EnvironmentPrepareAuthorisation, EnvironmentPrepareDone, Indeterminate, OutcomeResult,
    OwnedEnvironments, RuntimeSpec,
};

use environment::{Destroyed, EnvFailure, EnvHandle, ExecutionEnvironment, Measured};

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

/// The sandbox supervisor: what it needs to drive a runtime, and nothing it
/// could decide with.
#[derive(Debug)]
pub(crate) struct Sandbox {
    helper: PathBuf,
    authority_uid: u32,
    files: SandboxFiles,
    profile: String,
    evidence_topology: bool,
    proxies: Arc<Proxies>,
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
        evidence_topology: bool,
        proxies: Arc<Proxies>,
    ) -> Self {
        Self {
            helper,
            authority_uid,
            files,
            profile: dwk_sandbox_profile::seccomp_profile_json(),
            evidence_topology,
            proxies,
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
        let Some(seccomp) = self.files.seccomp.to_str() else {
            return OutcomeResult::Refused(BrokerRefusal::Unsupported);
        };
        let held = oci::Runtime::new(
            &self.helper,
            descriptors,
            runtime,
            (&self.files.client_config, self.authority_uid),
            until.checked_sub(ANSWER_MARGIN).unwrap_or(until),
        );
        match held {
            Ok(held) => step(&oci::Oci::new(
                held,
                (seccomp, &self.profile),
                runtime.socket.as_str(),
                &self.proxies,
            )),
            Err(why) => OutcomeResult::Refused(why),
        }
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
                        egress: self.proxies.counters(spec.environment_id.as_str()),
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
            let egress = self.proxies.close(authorisation.environment_id.as_str());
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
