//! The execution-environment abstraction (SANDBOX.md §1, ADR-0047 §3).
//!
//! Designed against exactly two implementations — `oci` and `local` — and no
//! others (SANDBOX.md §1): not SSH, not a microVM, not a remote worker. M5a
//! implements `oci` only; `local` is the host execution M4d already has
//! behind the authority's floor, and stays there until M6 (ADR-0052 §12).
//! M5d adds a workload (SANDBOX.md §1's spawn, then collect, of one
//! bounded program): `ready_workload`, then -- supervised, once the start
//! is answered (M5d.2) -- `exec_workload`. Nothing here decides: the broker prepares what the
//! authority specified, measures it, runs what it authorised, and reports;
//! the authority judges the level.

use dwk_proto::brokerp::sandbox::{
    AssuranceLevel, ContainerRef, Milliseconds, RuntimeVersion, StoreInstance, Verdict,
};
use dwk_proto::brokerp::workload::WorkloadSpec;
use dwk_proto::brokerp::{BrokerRefusal, ContainerState, EnvironmentSpec, OwnedEnvironment};
use dwk_proto::wire::id::{EnvironmentId, RunId};

use super::Checks;

/// A prepared environment, as this broker knows it: DireWolf's name for it
/// and the runtime's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnvHandle {
    /// DireWolf's name: the authority's, minted with the intent.
    pub(crate) environment: EnvironmentId,
    /// The runtime's name.
    pub(crate) container: ContainerRef,
}

/// How a process in an environment ended — or why that is not known. A lost
/// container is never mistaken for a process that finished (SANDBOX.md §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecOutcome {
    /// It exited with this code.
    Exited(u8),
    /// A signal ended it (the runtime reports `128 + signal`).
    Killed(u8),
    /// It outran its deadline and was stopped.
    TimedOut,
    /// The environment is gone or no longer running.
    EnvironmentGone,
    /// The runtime could not be reached.
    RuntimeUnavailable,
    /// Nothing observable says what happened.
    Unobservable,
}

/// What preparing an environment produced.
#[derive(Debug)]
pub(crate) struct Prepared {
    /// The environment, if the runtime created one.
    pub(crate) handle: Option<EnvHandle>,
    /// What measuring it found, if it could be measured.
    pub(crate) measured: Option<Measured>,
    /// Whether it is kept: only when every required invariant passed.
    pub(crate) retained: bool,
}

/// What measuring an existing environment found.
#[derive(Debug)]
pub(crate) struct Measured {
    /// What the runtime says it is doing.
    pub(crate) state: ContainerState,
    /// The measurement, when it could be made.
    pub(crate) checks: Option<Checks>,
    /// The runtime's version, as it reported it.
    pub(crate) runtime_version: Option<RuntimeVersion>,
    /// How long the measurement took.
    pub(crate) measure_ms: Milliseconds,
}

/// What destroying an environment found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Destroyed {
    /// It was this environment, and it is gone.
    Removed(ContainerRef),
    /// There was nothing to remove.
    AlreadyGone,
}

/// What a workload's run produced (M5d, ADR-0052 §5).
#[derive(Debug)]
pub(crate) struct Ran {
    /// How it ended.
    pub(crate) outcome: ExecOutcome,
    /// Its standard output, to the bound.
    pub(crate) stdout: Vec<u8>,
    /// Every stdout byte it wrote, kept or not.
    pub(crate) stdout_observed: u64,
    /// Its standard error, to the bound.
    pub(crate) stderr: Vec<u8>,
    /// Every stderr byte it wrote, kept or not.
    pub(crate) stderr_observed: u64,
    /// How long it ran.
    pub(crate) elapsed: Milliseconds,
    /// Whether every other process of the environment was then proved gone.
    pub(crate) residue: Verdict,
    /// How many processes, besides init, were found and ended.
    pub(crate) ended: u32,
    /// How many remained.
    pub(crate) remaining: u32,
}

/// Why an environment operation has no result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnvFailure {
    /// Provably nothing was created or removed.
    Refused(BrokerRefusal),
    /// Something may have been created or removed, and nothing proves which.
    Unconfirmed,
}

/// One kind of execution environment.
pub(crate) trait ExecutionEnvironment {
    /// What it claims before anything is measured. Never evidence: the
    /// authority takes the lower of this and what measurement shows.
    fn declared(&self) -> AssuranceLevel;

    /// Create the environment `spec` describes, start it, and measure it. An
    /// environment that fails any required invariant is not left running.
    ///
    /// # Errors
    ///
    /// [`EnvFailure`].
    fn prepare(&self, spec: &EnvironmentSpec) -> Result<Prepared, EnvFailure>;

    /// Measure an environment that exists, against `spec`.
    ///
    /// # Errors
    ///
    /// [`EnvFailure`].
    fn measure(&self, handle: &EnvHandle, spec: &EnvironmentSpec) -> Result<Measured, EnvFailure>;

    /// Run the environment's trusted probe and collect its report: the one
    /// program M5a runs in an environment (spawn, then collect). Arbitrary
    /// workloads are M5d's.
    ///
    /// # Errors
    ///
    /// [`EnvFailure`].
    fn run_probe(
        &self,
        handle: &EnvHandle,
        spec: &EnvironmentSpec,
    ) -> Result<(ExecOutcome, Vec<u8>), EnvFailure>;

    /// Whether one workload may run in an environment that exists (M5d,
    /// ADR-0052 §5, steps 1-3): the environment re-judged from the
    /// runtime's record, and the executable's bytes proved. Nothing is run
    /// inside.
    ///
    /// # Errors
    ///
    /// [`EnvFailure::Refused`]: it may not, and nothing ran.
    fn ready_workload(
        &self,
        handle: &EnvHandle,
        spec: &EnvironmentSpec,
        workload: &WorkloadSpec,
    ) -> Result<(), EnvFailure>;

    /// Run one workload [`Self::ready_workload`] passed (steps 4-6): the
    /// plan's one command line within its bounds, then every other process
    /// of the environment ended. `until` bounds it all.
    ///
    /// # Errors
    ///
    /// [`EnvFailure::Refused`] when provably nothing ran;
    /// [`EnvFailure::Unconfirmed`] when it may have, and nothing proves how
    /// it ended.
    fn exec_workload(
        &self,
        handle: &EnvHandle,
        workload: &WorkloadSpec,
        until: std::time::Instant,
    ) -> Result<Ran, EnvFailure>;

    /// Remove exactly the environment `environment` of `run` in `store` —
    /// `container`, when the authority recorded it. Nothing labelled
    /// otherwise is touched.
    ///
    /// # Errors
    ///
    /// [`EnvFailure`].
    fn destroy(
        &self,
        store: &StoreInstance,
        environment: (&EnvironmentId, &RunId),
        container: Option<&ContainerRef>,
    ) -> Result<Destroyed, EnvFailure>;

    /// Every environment labelled as `store`'s, for reconciliation.
    ///
    /// # Errors
    ///
    /// [`EnvFailure`].
    fn list(&self, store: &StoreInstance) -> Result<Listed, EnvFailure>;
}

/// What a listing found.
#[derive(Debug)]
pub(crate) struct Listed {
    /// The environments, at most the bound.
    pub(crate) environments: Vec<OwnedEnvironment>,
    /// Whether that is every one.
    pub(crate) complete: bool,
}
