//! The argument vectors of a `PROXY_ONLY` environment's two helper
//! containers (M5b, ADR-0048), built — like [`super::plan`]'s — from typed
//! values and the profile's constants, and nothing else.
//!
//! | container | what it is | runs |
//! |---|---|---|
//! | setup | one-shot, removed by the runtime when it exits (`--rm`) | `sandbox-relay setup`: adds `169.254.7.1/32` to the environment's loopback, then exits |
//! | relay | the environment's one network peer, for its whole life | `sandbox-relay serve`: `169.254.7.1:8080` → the broker's socket |
//!
//! Both join the environment's network namespace and nothing else
//! (`--network container:<environment>`): no interface is added, no network
//! the runtime routes is joined, no host or bridge address becomes reachable.
//! Both run the pinned image's relay — its digest checked before either is
//! started — with a read-only root, no new privileges, the `oci-strict`
//! seccomp profile, private IPC and cgroup namespaces, and bounded resources.
//!
//! **The setup container is the one place a DireWolf container holds a
//! capability**: `NET_ADMIN`, and nothing else, as root inside — because
//! adding an address to a namespace's interface is what that capability is
//! for, and it is held by a program that does exactly that one netlink
//! request and exits, before any workload exists. It is never added to the
//! environment or the relay: the environment's capability sets stay empty,
//! so nothing inside it can change the namespace afterwards. The architecture
//! checks admit this one `--cap-add` here and nowhere else (TX040), and no
//! other capability or weakening in this file (TX041).
//!
//! The relay is unprivileged (its own uid, no capability) and is given one
//! mount: the broker's per-environment directory, read-only, at
//! [`EGRESS_TARGET`].

use dwk_proto::brokerp::EnvironmentSpec;
use dwk_proto::brokerp::sandbox::{ContainerRef, ContainerRole, StoreInstance};
use dwk_proto::wire::id::EnvironmentId;
use dwk_sandbox_profile::{
    EGRESS_TARGET, RELAY_GID, RELAY_MEMORY_BYTES, RELAY_NANO_CPUS, RELAY_PATH, RELAY_PIDS_LIMIT,
    RELAY_SERVE, RELAY_SETUP, RELAY_UID,
};

use super::plan::{self, mountable, words};

/// A helper container's name: the environment's, and its role.
#[must_use]
pub(crate) fn name(
    store: &StoreInstance,
    environment: &EnvironmentId,
    role: ContainerRole,
) -> String {
    format!(
        "{}-{}",
        plan::container_name(store, environment),
        role.label()
    )
}

/// The relay's user, numerically.
#[must_use]
pub(crate) fn relay_user() -> String {
    format!("{RELAY_UID}:{RELAY_GID}")
}

/// The relay's one mount: the broker's directory for this environment,
/// read-only, never propagating.
#[must_use]
pub(crate) fn egress_mount(dir: &str) -> String {
    format!("type=bind,source={dir},target={EGRESS_TARGET},readonly,bind-propagation=rprivate")
}

/// What both helpers share, from `--name` to the entrypoint's argument.
fn helper(
    spec: &EnvironmentSpec,
    role: ContainerRole,
    (environment, seccomp_profile): (&ContainerRef, &str),
    user: &str,
) -> Vec<String> {
    let mut argv = vec![
        "--name".to_owned(),
        name(&spec.store, &spec.environment_id, role),
    ];
    for (key, value) in plan::labels(spec, role) {
        argv.push("--label".to_owned());
        argv.push(format!("{key}={value}"));
    }
    argv.push("--user".to_owned());
    argv.push(user.to_owned());
    argv.extend(words(&["--read-only", "--cap-drop", "ALL"]));
    if role == ContainerRole::Setup {
        // The one capability, for the one netlink request (module docs).
        argv.extend(words(&["--cap-add", "NET_ADMIN"]));
    }
    argv.extend(words(&[
        "--security-opt",
        "no-new-privileges=true",
        "--security-opt",
    ]));
    argv.push(format!("seccomp={seccomp_profile}"));
    argv.extend(words(&[
        "--ipc",
        "private",
        "--cgroupns",
        "private",
        "--network",
    ]));
    argv.push(format!("container:{}", environment.as_str()));
    argv.push("--pids-limit".to_owned());
    argv.push(RELAY_PIDS_LIMIT.to_string());
    argv.push("--memory".to_owned());
    argv.push(RELAY_MEMORY_BYTES.to_string());
    argv.push("--memory-swap".to_owned());
    argv.push(RELAY_MEMORY_BYTES.to_string());
    argv.push("--cpus".to_owned());
    argv.push(plan::cpus_of(RELAY_NANO_CPUS));
    argv.extend(words(&["--restart", "no", "--log-driver", "none"]));
    argv.extend(words(&["--entrypoint", RELAY_PATH]));
    argv
}

/// `docker run --rm` for the setup container: it adds the proxy address to
/// `environment`'s loopback and exits; the runtime removes it. `None` for a
/// profile path the option syntax could misread.
#[must_use]
pub(crate) fn setup(
    spec: &EnvironmentSpec,
    environment: &ContainerRef,
    seccomp_profile: &str,
) -> Option<Vec<String>> {
    if !mountable(seccomp_profile) {
        return None;
    }
    let mut argv = words(&["run", "--rm", "--pull", "never"]);
    argv.extend(helper(
        spec,
        ContainerRole::Setup,
        (environment, seccomp_profile),
        "0:0",
    ));
    argv.push(spec.image.as_str().to_owned());
    argv.push(RELAY_SETUP.to_owned());
    Some(argv)
}

/// `docker create` for the relay. `None` for a path the mount or option
/// syntax could misread.
#[must_use]
pub(crate) fn relay(
    spec: &EnvironmentSpec,
    environment: &ContainerRef,
    seccomp_profile: &str,
    egress_dir: &str,
) -> Option<Vec<String>> {
    if !mountable(seccomp_profile) || !mountable(egress_dir) {
        return None;
    }
    let mut argv = words(&["create", "--pull", "never"]);
    argv.extend(helper(
        spec,
        ContainerRole::Relay,
        (environment, seccomp_profile),
        &relay_user(),
    ));
    argv.push("--mount".to_owned());
    argv.push(egress_mount(egress_dir));
    argv.push(spec.image.as_str().to_owned());
    argv.push(RELAY_SERVE.to_owned());
    Some(argv)
}
