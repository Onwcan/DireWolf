//! Every argument vector a workload's run hands the container runtime (M5d,
//! ADR-0052 §5) — the `exec` that runs it and the `exec` that ends what it
//! left — built from the typed workload and the profile's constants, and
//! nothing else (TX050).
//!
//! The words are this module's literals. The user is the profile's numeric
//! `10001:10001` — never a name the image's `/etc/passwd` could map, never
//! root — the working directory is the workspace's mount, and nothing is
//! added to the environment by the runtime. Every launch runs the trusted
//! probe as the launcher, which sets the workspace's umask -- so that what a
//! workload makes is the workspace group's (M5d.4) -- and executes the
//! program: a `DIRECT` launch with exactly the container's own variables
//! (for `PROXY_ONLY`, the proxy's), a `HYGIENE` one with the profile's fixed
//! `workspace_exec_hygiene` variables set over them (M5d.2, ADR-0052 §5a).
//! No `--privileged`, no extra
//! capability, no environment option, no standard input, no terminal, no
//! detaching. The runtime client stops reading its own options at the
//! container's name, so every word after it is the program's: an argument
//! reaches the workload as exactly its bytes, whatever it spells.

use dwk_proto::brokerp::sandbox::ContainerRef;
use dwk_proto::brokerp::workload::{WorkloadLaunch, WorkloadSpec};
use dwk_sandbox_profile::{
    LAUNCH_DIRECT, LAUNCH_HYGIENE, PROBE_LAUNCH, PROBE_PATH, PROBE_REAP, SANDBOX_GID, SANDBOX_UID,
    WORKSPACE_TARGET,
};

use super::plan::words;

/// `user:group`, numerically: the profile's, and nobody else's.
fn user() -> String {
    format!("{SANDBOX_UID}:{SANDBOX_GID}")
}

/// Run the workload: `container exec`, as the environment's user, in the
/// workspace, with exactly its arguments, through the trusted launcher --
/// its `hygiene` profile for a `HYGIENE` launch, its `direct` one otherwise.
#[must_use]
pub(crate) fn run(container: &ContainerRef, workload: &WorkloadSpec) -> Vec<String> {
    let profile = if workload.launch == WorkloadLaunch::Hygiene {
        LAUNCH_HYGIENE
    } else {
        LAUNCH_DIRECT
    };
    run_with(
        container,
        workload,
        None,
        words(&[PROBE_PATH, PROBE_LAUNCH, profile]),
    )
}

/// The one shape of a workload's command line: `container exec`, then -- for
/// a secret-bearing workload only -- `attach`, the word that attaches the
/// client's standard input, which only `workload_secret_plan` spells
/// (M5d.3); then the profile's user, the workspace, the recorded container;
/// then `launcher`'s words, if the workload is launched, and the executable
/// with exactly its arguments. Nothing a caller says is placed before the
/// container's name.
#[must_use]
pub(super) fn run_with(
    container: &ContainerRef,
    workload: &WorkloadSpec,
    attach: Option<&'static str>,
    launcher: Vec<String>,
) -> Vec<String> {
    let mut argv = words(&["container", "exec"]);
    argv.extend(attach.map(str::to_owned));
    argv.extend(words(&["--user"]));
    argv.push(user());
    argv.extend(words(&["--workdir", WORKSPACE_TARGET]));
    argv.push(container.as_str().to_owned());
    argv.extend(launcher);
    argv.push(workload.executable.as_str().to_owned());
    argv.extend(workload.args.iter().map(|arg| arg.as_str().to_owned()));
    argv
}

/// End every other process of the environment: the trusted probe's `reap`,
/// as the environment's user, who owns every process a workload can start.
#[must_use]
pub(crate) fn reap(container: &ContainerRef) -> Vec<String> {
    let mut argv = words(&["container", "exec", "--user"]);
    argv.push(user());
    argv.push(container.as_str().to_owned());
    argv.push(PROBE_PATH.to_owned());
    argv.push(PROBE_REAP.to_owned());
    argv
}

#[cfg(test)]
#[path = "workload_plan_tests.rs"]
mod tests;
