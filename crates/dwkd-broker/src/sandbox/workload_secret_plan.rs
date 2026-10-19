//! The one command line that attaches the runtime client's standard input
//! (M5d.3, ADR-0052 §§5, 7): a secret-bearing workload's.
//!
//! A workload's secret reaches the environment's trusted launcher -- the
//! digest-pinned probe -- over the `exec`'s standard input, framed, and
//! nowhere else: never an argument, never `--env`, never a file. The client
//! forwards its standard input only when told to (measured on Docker Engine
//! 29.8.2: without it the process reads `/dev/null`), so this plan says so,
//! with the one word it alone may spell (TX055), and is otherwise exactly an
//! ordinary workload's (`workload_plan::run_with`): the profile's user, the
//! workspace, the recorded container, then the launcher's closed words and
//! the executable with exactly its arguments. The variable of mode B is the
//! operator's, already refused if it names a control, proxy or hygiene
//! variable, and is placed after the container's name, where the client
//! reads no option.

use dwk_proto::brokerp::SecretDelivery;
use dwk_proto::brokerp::sandbox::ContainerRef;
use dwk_proto::brokerp::workload::{WorkloadLaunch, WorkloadSecret, WorkloadSpec};
use dwk_sandbox_profile::{
    LAUNCH_SECRET_ENV, LAUNCH_SECRET_ENV_HYGIENE, LAUNCH_SECRET_FD, LAUNCH_SECRET_FD_HYGIENE,
    PROBE_LAUNCH, PROBE_PATH,
};

use super::plan::words;

/// The word that attaches the client's standard input: spelled here and
/// nowhere else.
const ATTACH_STDIN: &str = "--interactive";

/// The launcher's profile for `secret`, with or without
/// `workspace_exec_hygiene`'s variables.
fn profile(secret: &WorkloadSecret, hygiene: bool) -> &'static str {
    match (secret.delivery, hygiene) {
        (SecretDelivery::FdAtSpawn, false) => LAUNCH_SECRET_FD,
        (SecretDelivery::FdAtSpawn, true) => LAUNCH_SECRET_FD_HYGIENE,
        (SecretDelivery::EnvAtSpawn, false) => LAUNCH_SECRET_ENV,
        (SecretDelivery::EnvAtSpawn, true) => LAUNCH_SECRET_ENV_HYGIENE,
    }
}

/// Run a secret-bearing workload: always through the trusted launcher, which
/// reads the framed value from standard input.
#[must_use]
pub(crate) fn run(
    container: &ContainerRef,
    workload: &WorkloadSpec,
    secret: &WorkloadSecret,
) -> Vec<String> {
    let hygiene = workload.launch == WorkloadLaunch::Hygiene;
    let mut launcher = words(&[PROBE_PATH, PROBE_LAUNCH, profile(secret, hygiene)]);
    if secret.delivery == SecretDelivery::EnvAtSpawn
        && let Some(name) = &secret.env_name
    {
        launcher.push(name.as_str().to_owned());
    }
    super::workload_plan::run_with(container, workload, Some(ATTACH_STDIN), launcher)
}

#[cfg(test)]
#[path = "workload_secret_plan_tests.rs"]
mod tests;
