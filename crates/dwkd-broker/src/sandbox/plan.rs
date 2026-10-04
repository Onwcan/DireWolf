//! Every argument vector the broker hands the container runtime (M5a,
//! ADR-0047 §4), built from typed values and the profile's constants — and
//! nothing else.
//!
//! No authorisation carries a runtime flag, and nothing here copies one out
//! of an authorisation: each vector is this module's literal words, the
//! profile's numbers, and the few typed values the authority decided (the
//! image digest, the workspace path, the environment and run ids, the store
//! instance, the container the runtime named). A vector is a list of words,
//! executed by descriptor through the launch helper: no shell ever reads it.
//!
//! The `oci-strict` rules (SANDBOX.md §2) are spelled once, in
//! [`create`]. There is no parameter that turns one off: the profile is the
//! only profile, and a weaker one is not a variant of it (ADR-0047 §5).

use dwk_proto::brokerp::EnvironmentSpec;
use dwk_proto::brokerp::sandbox::{ContainerRef, ContainerRole, NetworkTopology, StoreInstance};
use dwk_proto::wire::id::{EnvironmentId, RunId};
use dwk_sandbox_profile::{
    LABEL_ENVIRONMENT, LABEL_OWNER, LABEL_OWNER_VALUE, LABEL_PROFILE, LABEL_ROLE, LABEL_RUN,
    LABEL_SCHEMA, LABEL_SCHEMA_VALUE, LABEL_STORE, MEMORY_BYTES, MEMORY_SWAP_BYTES, NANO_CPUS,
    OOM_SCORE_ADJ, PIDS_LIMIT, PROBE_HOLD, PROBE_MEASURE, PROBE_PATH, PROXY_VARIABLES, RELAY_PATH,
    RLIMIT_CORE, RLIMIT_FSIZE, RLIMIT_NOFILE, RLIMIT_NPROC, SANDBOX_GID, SANDBOX_UID, TMPFS,
    WORKSPACE_TARGET,
};

/// The container name an environment is created under: unique per runtime,
/// so a second creation of the same environment — a retry after a crash —
/// fails instead of making a twin.
#[must_use]
pub(crate) fn container_name(store: &StoreInstance, environment: &EnvironmentId) -> String {
    format!("direwolf-{}-{}", store.as_str(), environment.as_str())
}

/// Whether `path` can be named in a `--mount` value without being able to
/// change its meaning: absolute, and free of the separators the runtime's
/// field syntax gives meaning to (`,` between fields, `"` for quoting, `=`
/// between key and value) and of control characters.
#[must_use]
pub(crate) fn mountable(path: &str) -> bool {
    path.starts_with('/')
        && !path
            .chars()
            .any(|c| c.is_control() || matches!(c, ',' | '"' | '=' | '\''))
}

/// `user:group`, numerically: no name the image's `/etc/passwd` could map.
fn user() -> String {
    format!("{SANDBOX_UID}:{SANDBOX_GID}")
}

pub(crate) fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|w| (*w).to_owned()).collect()
}

/// The labels every container of an environment carries, in a fixed order:
/// the environment's, and what this container is to it.
#[must_use]
pub(crate) fn labels(spec: &EnvironmentSpec, role: ContainerRole) -> Vec<(&'static str, String)> {
    vec![
        (LABEL_OWNER, LABEL_OWNER_VALUE.to_owned()),
        (LABEL_SCHEMA, LABEL_SCHEMA_VALUE.to_owned()),
        (LABEL_STORE, spec.store.as_str().to_owned()),
        (LABEL_ENVIRONMENT, spec.environment_id.as_str().to_owned()),
        (LABEL_RUN, spec.run_id.as_str().to_owned()),
        (LABEL_PROFILE, spec.profile.label().to_owned()),
        (LABEL_ROLE, role.label().to_owned()),
    ]
}

/// The network the environment joins: none — no interface but loopback —
/// for both topologies. `PROXY_ONLY`'s one peer is added inside that
/// namespace afterwards ([`super::relay_plan`]), never by joining a network
/// the runtime routes (ADR-0048).
const fn network(topology: NetworkTopology) -> &'static str {
    match topology {
        NetworkTopology::NoNetwork | NetworkTopology::ProxyOnly => "none",
    }
}

/// The `tmpfs` mounts, as the profile spells them: never a device or set-id
/// file, bounded, writable by the environment's user.
fn tmpfs() -> impl Iterator<Item = String> {
    TMPFS
        .iter()
        .map(|(target, options)| format!("{target}:{options}"))
}

/// The workspace bind: exactly one writable host directory, at
/// `/workspace`, never propagating a mount either way.
fn workspace_mount(path: &str) -> String {
    format!("type=bind,source={path},target={WORKSPACE_TARGET},bind-propagation=rprivate")
}

/// `docker create` for an `oci-strict` environment (SANDBOX.md §2). `None`
/// for a workspace path the mount syntax could misread.
#[must_use]
pub(crate) fn create(spec: &EnvironmentSpec, seccomp_profile: &str) -> Option<Vec<String>> {
    let network = network(spec.network);
    if !mountable(spec.workspace_path.as_str()) || !mountable(seccomp_profile) {
        return None;
    }
    let mut argv = words(&["create", "--pull", "never"]);
    argv.push("--name".to_owned());
    argv.push(container_name(&spec.store, &spec.environment_id));
    for (key, value) in labels(spec, ContainerRole::Environment) {
        argv.push("--label".to_owned());
        argv.push(format!("{key}={value}"));
    }
    // The proxy variables, for `PROXY_ONLY` only: the profile's constants,
    // never the broker's own environment or a caller's value. A tool that
    // ignores them has no other path (ADR-0048).
    if spec.network == NetworkTopology::ProxyOnly {
        for (name, value) in PROXY_VARIABLES {
            argv.push("--env".to_owned());
            argv.push(format!("{name}={value}"));
        }
    }
    // Identity and privilege.
    argv.extend(words(&["--user"]));
    argv.push(user());
    argv.extend(words(&[
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--security-opt",
    ]));
    argv.push(format!("seccomp={seccomp_profile}"));
    // Namespaces: PID, UTS and user namespaces are the runtime's private
    // default and are left so; IPC and cgroup are named.
    argv.extend(words(&[
        "--ipc",
        "private",
        "--cgroupns",
        "private",
        "--network",
    ]));
    argv.push(network.to_owned());
    // Filesystem: a read-only root, two bounded temporary directories, one
    // workspace.
    for mount in tmpfs() {
        argv.push("--tmpfs".to_owned());
        argv.push(mount);
    }
    argv.push("--mount".to_owned());
    argv.push(workspace_mount(spec.workspace_path.as_str()));
    argv.extend(words(&["--workdir", WORKSPACE_TARGET]));
    // Resources.
    argv.push("--pids-limit".to_owned());
    argv.push(PIDS_LIMIT.to_string());
    argv.push("--memory".to_owned());
    argv.push(MEMORY_BYTES.to_string());
    argv.push("--memory-swap".to_owned());
    argv.push(MEMORY_SWAP_BYTES.to_string());
    argv.push("--cpus".to_owned());
    argv.push(cpus());
    for (name, value) in [
        ("nofile", RLIMIT_NOFILE),
        ("nproc", RLIMIT_NPROC),
        ("fsize", RLIMIT_FSIZE),
        ("core", RLIMIT_CORE),
    ] {
        argv.push("--ulimit".to_owned());
        argv.push(format!("{name}={value}:{value}"));
    }
    argv.push("--oom-score-adj".to_owned());
    argv.push(OOM_SCORE_ADJ.to_string());
    // Lifecycle: never restarted by the runtime, nothing logged by it.
    argv.extend(words(&["--restart", "no", "--log-driver", "none"]));
    // The first process is the probe, holding.
    argv.extend(words(&["--entrypoint", PROBE_PATH]));
    argv.push(spec.image.as_str().to_owned());
    argv.push(PROBE_HOLD.to_owned());
    Some(argv)
}

/// `NANO_CPUS` as the runtime's `--cpus` decimal.
fn cpus() -> String {
    cpus_of(NANO_CPUS)
}

/// Nanocpus as the runtime's `--cpus` decimal.
#[allow(
    clippy::integer_division,
    reason = "whole CPUs and the exact nanosecond remainder"
)]
pub(crate) fn cpus_of(nano: u64) -> String {
    let whole = nano / 1_000_000_000;
    let fraction = nano % 1_000_000_000;
    if fraction == 0 {
        whole.to_string()
    } else {
        format!("{whole}.{fraction:09}")
    }
}

/// The runtime's server version, one line.
#[must_use]
pub(crate) fn version() -> Vec<String> {
    words(&["version", "--format", "{{.Server.Version}}"])
}

/// The image's own id, if the runtime holds it.
#[must_use]
pub(crate) fn image_id(spec: &EnvironmentSpec) -> Vec<String> {
    let mut argv = words(&["image", "inspect", "--format", "{{.Id}}"]);
    argv.push(spec.image.as_str().to_owned());
    argv
}

/// Start a created container.
#[must_use]
pub(crate) fn start(container: &ContainerRef) -> Vec<String> {
    let mut argv = words(&["start"]);
    argv.push(container.as_str().to_owned());
    argv
}

/// The runtime's whole record of containers, one JSON array.
#[must_use]
pub(crate) fn inspect(containers: &[&ContainerRef]) -> Vec<String> {
    let mut argv = words(&["container", "inspect"]);
    argv.extend(containers.iter().map(|c| c.as_str().to_owned()));
    argv
}

/// The probe's bytes, as a tar stream, out of the container's own root.
#[must_use]
pub(crate) fn copy_probe(container: &ContainerRef) -> Vec<String> {
    copy_out(container, PROBE_PATH)
}

/// The relay's bytes, as a tar stream, out of a container's own root.
#[must_use]
pub(crate) fn copy_relay(container: &ContainerRef) -> Vec<String> {
    copy_out(container, RELAY_PATH)
}

fn copy_out(container: &ContainerRef, path: &str) -> Vec<String> {
    let mut argv = words(&["container", "cp"]);
    argv.push(format!("{}:{path}", container.as_str()));
    argv.push("-".to_owned());
    argv
}

/// Run the probe's measurement inside the container — as the container's
/// own configured user, never one this step chooses: the probe measures what
/// a workload there would be, so a container configured as root is seen as
/// root from inside too.
#[must_use]
pub(crate) fn measure(container: &ContainerRef, spec: &EnvironmentSpec) -> Vec<String> {
    let mut argv = words(&["container", "exec"]);
    argv.push(container.as_str().to_owned());
    argv.push(PROBE_PATH.to_owned());
    argv.push(PROBE_MEASURE.to_owned());
    argv.push(spec.environment_id.as_str().to_owned());
    argv.push(spec.network.as_str().to_owned());
    argv
}

/// Remove exactly this container, and its anonymous volumes.
#[must_use]
pub(crate) fn remove(container: &ContainerRef) -> Vec<String> {
    let mut argv = words(&["container", "rm", "--force", "--volumes"]);
    argv.push(container.as_str().to_owned());
    argv
}

/// Every container carrying this store's labels — and, given one, this
/// environment's, and given one, this role's — by full id.
#[must_use]
pub(crate) fn owned(
    store: &StoreInstance,
    environment: Option<(&EnvironmentId, &RunId)>,
    role: Option<ContainerRole>,
) -> Vec<String> {
    let mut argv = words(&["container", "ls", "--all", "--no-trunc", "--quiet"]);
    argv.push("--filter".to_owned());
    argv.push(format!("label={LABEL_OWNER}={LABEL_OWNER_VALUE}"));
    argv.push("--filter".to_owned());
    argv.push(format!("label={LABEL_STORE}={}", store.as_str()));
    if let Some((environment, run)) = environment {
        argv.push("--filter".to_owned());
        argv.push(format!(
            "label={LABEL_ENVIRONMENT}={}",
            environment.as_str()
        ));
        argv.push("--filter".to_owned());
        argv.push(format!("label={LABEL_RUN}={}", run.as_str()));
    }
    if let Some(role) = role {
        argv.push("--filter".to_owned());
        argv.push(format!("label={LABEL_ROLE}={}", role.label()));
    }
    argv
}

#[cfg(test)]
#[path = "plan_tests.rs"]
mod tests;
