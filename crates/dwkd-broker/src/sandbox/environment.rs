//! The execution-environment abstraction (SANDBOX.md §1, ADR-0047 §3).
//!
//! Designed against exactly two implementations — `oci` and `local` — and no
//! others (SANDBOX.md §1): not SSH, not a microVM, not a remote worker. M5a
//! implements `oci` only; `local` is the host execution M4d already has
//! behind the authority's floor, and it joins this trait when M5d moves host
//! execution under it. Nothing here decides: the broker prepares what the
//! authority specified, measures it, and reports; the authority judges the
//! level.

use dwk_proto::brokerp::sandbox::{
    AssuranceLevel, ContainerRef, Milliseconds, RuntimeVersion, StoreInstance,
};
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
