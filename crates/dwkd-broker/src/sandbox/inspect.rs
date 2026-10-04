//! The host vantage (M5a, ADR-0047 §8): what the container runtime's own
//! record says an environment is, judged invariant by invariant against the
//! `oci-strict` profile.
//!
//! The record is the runtime's `container inspect` document, parsed by the
//! same strict JSON lexer the protocol uses (UTF-8, no duplicate key, bounded
//! depth). Each invariant reads the fields that state it and nothing else:
//! a field that is absent or of another shape is `UNOBSERVABLE`, never a
//! guess, and a value that is not the profile's is `FAIL`. The runtime is
//! trusted to report its own configuration truthfully — it is the host's
//! most privileged component — and the probe inside checks what the kernel
//! actually applied (ADR-0047 §8 states the split).

use dwk_proto::brokerp::sandbox::{
    ContainerRef, ContainerRole, ImageId, NetworkTopology, SandboxInvariant, StoreInstance, Verdict,
};
use dwk_proto::brokerp::{ContainerState, EnvironmentSpec, OwnedEnvironment};
use dwk_proto::json::{self, Number, Object, ParseOptions, Value};
use dwk_proto::wire::id::{EnvironmentId, RunId};
use dwk_sandbox_profile::{
    EGRESS_TARGET, LABEL_ENVIRONMENT, LABEL_OWNER, LABEL_OWNER_VALUE, LABEL_PROFILE, LABEL_ROLE,
    LABEL_RUN, LABEL_SCHEMA, LABEL_SCHEMA_VALUE, LABEL_STORE, MEMORY_BYTES, MEMORY_SWAP_BYTES,
    NANO_CPUS, OOM_SCORE_ADJ, PIDS_LIMIT, PROXY_VARIABLE_NAMES, PROXY_VARIABLES,
    RELAY_MEMORY_BYTES, RELAY_NANO_CPUS, RELAY_PATH, RELAY_PIDS_LIMIT, RELAY_SERVE, RLIMIT_CORE,
    RLIMIT_FSIZE, RLIMIT_NOFILE, RLIMIT_NPROC, RUNTIME_SOCKET_NAMES, SANDBOX_GID, SANDBOX_UID,
    TMP_TARGET, TMPFS, VAR_TMP_TARGET, WORKSPACE_TARGET,
};

use super::Checks;
use super::{plan, relay_plan};

/// The namespace every DireWolf label is in.
const DIREWOLF_LABELS: &str = "io.direwolf.";

/// The most bytes of an inspect document read: far beyond any real record,
/// and a bound on what a hostile runtime can make the broker parse.
pub(crate) const MAX_INSPECT_BYTES: usize = 1 << 20;

/// What the runtime's record is, before it is judged.
pub(crate) struct Record<'a> {
    object: &'a Object,
}

/// One inspect document: a JSON array of container records.
///
/// # Errors
///
/// Not a strict JSON array of objects.
pub(crate) fn parse(bytes: &[u8]) -> Result<Vec<Object>, ()> {
    let Value::Array(items) = json::parse(bytes, ParseOptions::ijson()).map_err(|_| ())? else {
        return Err(());
    };
    items
        .into_iter()
        .map(|item| match item {
            Value::Object(object) => Ok(object),
            _ => Err(()),
        })
        .collect()
}

fn at<'a>(object: &'a Object, path: &[&str]) -> Option<&'a Value> {
    let (first, rest) = path.split_first()?;
    let mut value = object.get(first)?;
    for key in rest {
        match value {
            Value::Object(inner) => value = inner.get(key)?,
            _ => return None,
        }
    }
    Some(value)
}

fn text<'a>(object: &'a Object, path: &[&str]) -> Option<&'a str> {
    match at(object, path)? {
        Value::String(s) => Some(s),
        _ => None,
    }
}

fn boolean(object: &Object, path: &[&str]) -> Option<bool> {
    match at(object, path)? {
        Value::Bool(b) => Some(*b),
        _ => None,
    }
}

fn integer(object: &Object, path: &[&str]) -> Option<i64> {
    match at(object, path)? {
        Value::Number(Number::Int(i)) => Some(*i),
        _ => None,
    }
}

/// An array of strings; `null` is the runtime's spelling of none.
fn strings<'a>(object: &'a Object, path: &[&str]) -> Option<Vec<&'a str>> {
    match at(object, path)? {
        Value::Null => Some(Vec::new()),
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::String(s) => Some(s.as_str()),
                _ => None,
            })
            .collect(),
        _ => None,
    }
}

/// An array of objects; `null` is none.
fn objects<'a>(object: &'a Object, path: &[&str]) -> Option<Vec<&'a Object>> {
    match at(object, path)? {
        Value::Null => Some(Vec::new()),
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::Object(o) => Some(o),
                _ => None,
            })
            .collect(),
        _ => None,
    }
}

/// Empty: `null`, `[]` or `{}`; absent counts as empty only where the runtime
/// omits empty members.
fn empty(object: &Object, path: &[&str]) -> Option<bool> {
    match at(object, path) {
        None | Some(Value::Null) => Some(true),
        Some(Value::Array(items)) => Some(items.is_empty()),
        Some(Value::Object(inner)) => Some(inner.is_empty()),
        Some(_) => None,
    }
}

fn verdict(found: Option<bool>) -> Verdict {
    match found {
        Some(true) => Verdict::Pass,
        Some(false) => Verdict::Fail,
        None => Verdict::Unobservable,
    }
}

/// Every judgement holds: any `false` fails, any unknown is unobservable.
fn all(parts: &[Option<bool>]) -> Option<bool> {
    if parts.contains(&Some(false)) {
        return Some(false);
    }
    if parts.contains(&None) {
        return None;
    }
    Some(true)
}

impl<'a> Record<'a> {
    /// A record to judge.
    pub(crate) const fn new(object: &'a Object) -> Self {
        Self { object }
    }

    /// The runtime's id for the container.
    pub(crate) fn id(&self) -> Option<ContainerRef> {
        ContainerRef::new(text(self.object, &["Id"])?.to_owned())
    }

    /// What the runtime says it is doing.
    pub(crate) fn state(&self) -> Option<ContainerState> {
        Some(match text(self.object, &["State", "Status"])? {
            "created" => ContainerState::Created,
            "running" => ContainerState::Running,
            "paused" => ContainerState::Paused,
            "restarting" => ContainerState::Restarting,
            "exited" => ContainerState::Exited,
            "dead" => ContainerState::Dead,
            "removing" => ContainerState::Removing,
            _ => return None,
        })
    }

    fn labels(&self) -> Option<Vec<(&'a str, &'a str)>> {
        match at(self.object, &["Config", "Labels"])? {
            Value::Null => Some(Vec::new()),
            Value::Object(labels) => labels
                .iter()
                .map(|(k, v)| match v {
                    Value::String(s) => Some((k, s.as_str())),
                    _ => None,
                })
                .collect(),
            _ => None,
        }
    }

    fn label(&self, key: &str) -> Option<&'a str> {
        self.labels()?
            .into_iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v)
    }

    /// What the container is to its environment, by its role label.
    pub(crate) fn role(&self) -> Option<ContainerRole> {
        ContainerRole::from_label(self.label(LABEL_ROLE)?)
    }

    /// Whether the record is labelled as `environment` of `store`: the only
    /// containers any environment operation touches.
    pub(crate) fn is(
        &self,
        store: &StoreInstance,
        (environment, run): (&EnvironmentId, &RunId),
    ) -> bool {
        self.label(LABEL_OWNER) == Some(LABEL_OWNER_VALUE)
            && self.label(LABEL_STORE) == Some(store.as_str())
            && self.label(LABEL_ENVIRONMENT) == Some(environment.as_str())
            && self.label(LABEL_RUN) == Some(run.as_str())
    }

    /// What a listing reports of it.
    pub(crate) fn owned(&self, store: &StoreInstance) -> Option<OwnedEnvironment> {
        let container = self.id()?;
        let state = self.state()?;
        let environment_id = self.label(LABEL_ENVIRONMENT).and_then(EnvironmentId::parse);
        let run_id = self.label(LABEL_RUN).and_then(RunId::parse);
        let role = self.role();
        let ours = self.labels().is_some_and(|labels| {
            let direwolf: Vec<_> = labels
                .iter()
                .filter(|(k, _)| k.starts_with(DIREWOLF_LABELS))
                .collect();
            direwolf.len() == 7
        });
        let labels_exact = ours
            && role.is_some()
            && self.label(LABEL_OWNER) == Some(LABEL_OWNER_VALUE)
            && self.label(LABEL_SCHEMA) == Some(LABEL_SCHEMA_VALUE)
            && self.label(LABEL_STORE) == Some(store.as_str())
            && self.label(LABEL_PROFILE)
                == Some(dwk_proto::brokerp::sandbox::EnvironmentProfile::OciStrict.label())
            && environment_id.is_some()
            && run_id.is_some();
        Some(OwnedEnvironment {
            container,
            state,
            image: text(self.object, &["Image"]).and_then(|s| ImageId::new(s.to_owned())),
            environment_id,
            run_id,
            labels_exact,
            role,
        })
    }

    /// The host invariants this record can speak to, each judged. The probe
    /// digest and the workspace identity come from elsewhere.
    pub(crate) fn judge(
        &self,
        spec: &EnvironmentSpec,
        seccomp_profile: &str,
        runtime_socket: &str,
    ) -> Checks {
        let o = self.object;
        let security = strings(o, &["HostConfig", "SecurityOpt"]);
        vec![
            (
                SandboxInvariant::HostImagePinned,
                verdict(self.image_pinned(spec)),
            ),
            (
                SandboxInvariant::HostNotPrivileged,
                verdict(self.not_privileged(security.as_deref())),
            ),
            (
                SandboxInvariant::HostUserNonRoot,
                verdict(
                    text(o, &["Config", "User"])
                        .map(|u| u == format!("{SANDBOX_UID}:{SANDBOX_GID}")),
                ),
            ),
            (
                SandboxInvariant::HostRootReadOnly,
                verdict(boolean(o, &["HostConfig", "ReadonlyRootfs"])),
            ),
            (
                SandboxInvariant::HostCapabilitiesDropped,
                verdict(self.capabilities_dropped()),
            ),
            (
                SandboxInvariant::HostNoNewPrivileges,
                verdict(security.as_deref().map(no_new_privileges)),
            ),
            (
                SandboxInvariant::HostSeccompProfile,
                verdict(security.as_deref().map(|s| seccomp(s, seccomp_profile))),
            ),
            (
                SandboxInvariant::HostPidNamespacePrivate,
                verdict(text(o, &["HostConfig", "PidMode"]).map(str::is_empty)),
            ),
            (
                SandboxInvariant::HostIpcNamespacePrivate,
                verdict(text(o, &["HostConfig", "IpcMode"]).map(|m| m == "private")),
            ),
            (
                SandboxInvariant::HostUtsNamespacePrivate,
                verdict(text(o, &["HostConfig", "UTSMode"]).map(str::is_empty)),
            ),
            (
                SandboxInvariant::HostUsernsNotHost,
                verdict(text(o, &["HostConfig", "UsernsMode"]).map(|m| m != "host")),
            ),
            (
                SandboxInvariant::HostCgroupNamespacePrivate,
                verdict(text(o, &["HostConfig", "CgroupnsMode"]).map(|m| m == "private")),
            ),
            (
                SandboxInvariant::HostNetworkIsolated,
                verdict(self.network_isolated()),
            ),
            (
                SandboxInvariant::HostMountsExact,
                verdict(self.mounts_exact(spec)),
            ),
            (
                SandboxInvariant::HostNoRuntimeSocket,
                verdict(self.no_runtime_socket(runtime_socket)),
            ),
            (SandboxInvariant::HostNoDevices, verdict(self.no_devices())),
            (
                SandboxInvariant::HostResourceLimits,
                verdict(self.resource_limits()),
            ),
            (
                SandboxInvariant::HostLabelsExact,
                verdict(self.labels_exact(spec)),
            ),
            (SandboxInvariant::HostRunning, verdict(self.running())),
            (
                SandboxInvariant::HostProxyEnvironment,
                verdict(self.proxy_environment(spec.network)),
            ),
        ]
    }

    /// The environment's proxy variables, as the runtime records its whole
    /// environment (the image's and the plan's together): for `PROXY_ONLY`
    /// exactly the broker's, each once; for `NO_NETWORK` none. A proxy
    /// variable the image carries, or one the runtime's client injected from
    /// a user configuration, fails it — in any spelling of its name.
    fn proxy_environment(&self, topology: NetworkTopology) -> Option<bool> {
        let env = strings(self.object, &["Config", "Env"])?;
        let mut found: Vec<(&str, &str)> = Vec::new();
        for entry in env {
            let (name, value) = entry.split_once('=').unwrap_or((entry, ""));
            if PROXY_VARIABLE_NAMES
                .iter()
                .any(|n| n.eq_ignore_ascii_case(name))
            {
                found.push((name, value));
            }
        }
        Some(match topology {
            NetworkTopology::NoNetwork => found.is_empty(),
            NetworkTopology::ProxyOnly => {
                found.len() == PROXY_VARIABLES.len()
                    && PROXY_VARIABLES
                        .iter()
                        .all(|wanted| found.iter().filter(|f| *f == wanted).count() == 1)
            }
        })
    }

    /// Whether this record is exactly the relay a `PROXY_ONLY` environment
    /// needs: running, the pinned image and its relay, unprivileged, a
    /// read-only root, no capability, the profile's seccomp filter, in
    /// exactly `environment`'s network namespace, with exactly the broker's
    /// directory for it mounted read-only, no proxy variable, the profile's
    /// limits, and labelled as this environment's relay.
    pub(crate) fn relay_exact(
        &self,
        spec: &EnvironmentSpec,
        environment: &ContainerRef,
        egress_dir: &str,
        seccomp_profile: &str,
    ) -> Option<bool> {
        let o = self.object;
        let security = strings(o, &["HostConfig", "SecurityOpt"]);
        let labels = self.labels().map(|labels| {
            let ours: Vec<&(&str, &str)> = labels
                .iter()
                .filter(|(k, _)| k.starts_with(DIREWOLF_LABELS))
                .collect();
            let expected = plan::labels(spec, ContainerRole::Relay);
            ours.len() == expected.len()
                && expected
                    .iter()
                    .all(|(k, v)| ours.iter().any(|(lk, lv)| lk == k && lv == v))
        });
        let mounts = objects(o, &["Mounts"]).map(|mounts| {
            mounts.len() == 1
                && mounts.iter().all(|m| {
                    text(m, &["Type"]) == Some("bind")
                        && text(m, &["Source"]) == Some(egress_dir)
                        && text(m, &["Destination"]) == Some(EGRESS_TARGET)
                        && boolean(m, &["RW"]) == Some(false)
                })
        });
        let requested = objects(o, &["HostConfig", "Mounts"]).map(|mounts| {
            mounts.len() == 1
                && mounts.iter().all(|m| {
                    text(m, &["Type"]) == Some("bind")
                        && text(m, &["Source"]) == Some(egress_dir)
                        && text(m, &["Target"]) == Some(EGRESS_TARGET)
                        && boolean(m, &["ReadOnly"]) == Some(true)
                })
        });
        let number = |path: &[&str], want: u64| {
            integer(o, path).map(|found| i64::try_from(want).is_ok_and(|w| w == found))
        };
        let command = strings(o, &["Config", "Entrypoint"])
            .zip(strings(o, &["Config", "Cmd"]))
            .map(|(entry, cmd)| entry == [RELAY_PATH] && cmd == [RELAY_SERVE]);
        let no_proxy_variables = strings(o, &["Config", "Env"]).map(|env| {
            env.iter().all(|entry| {
                let name = entry.split_once('=').map_or(*entry, |(n, _)| n);
                !PROXY_VARIABLE_NAMES
                    .iter()
                    .any(|n| n.eq_ignore_ascii_case(name))
            })
        });
        all(&[
            self.image_pinned(spec),
            text(o, &["Config", "User"]).map(|u| u == relay_plan::relay_user()),
            self.not_privileged(security.as_deref()),
            boolean(o, &["HostConfig", "ReadonlyRootfs"]),
            self.capabilities_dropped(),
            security.as_deref().map(no_new_privileges),
            security.as_deref().map(|s| seccomp(s, seccomp_profile)),
            text(o, &["HostConfig", "NetworkMode"])
                .map(|m| m == format!("container:{}", environment.as_str())),
            text(o, &["HostConfig", "PidMode"]).map(str::is_empty),
            text(o, &["HostConfig", "IpcMode"]).map(|m| m == "private"),
            text(o, &["HostConfig", "UsernsMode"]).map(|m| m != "host"),
            mounts,
            requested,
            empty(o, &["HostConfig", "Binds"]),
            empty(o, &["HostConfig", "VolumesFrom"]),
            self.no_devices(),
            number(&["HostConfig", "PidsLimit"], RELAY_PIDS_LIMIT),
            number(&["HostConfig", "Memory"], RELAY_MEMORY_BYTES),
            number(&["HostConfig", "NanoCpus"], RELAY_NANO_CPUS),
            command,
            no_proxy_variables,
            labels,
            self.running(),
        ])
    }

    fn image_pinned(&self, spec: &EnvironmentSpec) -> Option<bool> {
        let o = self.object;
        let image = text(o, &["Image"])?;
        let named = text(o, &["Config", "Image"])?;
        // The container runs the image the authority pinned, and was created
        // naming that digest — never a tag that happened to resolve to it.
        Some(image == spec.image.as_str() && named == spec.image.as_str())
    }

    fn not_privileged(&self, security: Option<&[&str]>) -> Option<bool> {
        let o = self.object;
        let privileged = boolean(o, &["HostConfig", "Privileged"]).map(|p| !p);
        // Only the two options the plan sets: anything else — an unconfined
        // AppArmor or SELinux label, unmasked system paths — widens it.
        let options = security.map(|opts| {
            opts.iter().all(|opt| {
                opt.starts_with("seccomp=")
                    || opt.starts_with("seccomp:")
                    || opt.starts_with("no-new-privileges")
            })
        });
        let masked = strings(o, &["HostConfig", "MaskedPaths"]).map(|p| !p.is_empty());
        let read_only = strings(o, &["HostConfig", "ReadonlyPaths"]).map(|p| !p.is_empty());
        all(&[privileged, options, masked, read_only])
    }

    fn capabilities_dropped(&self) -> Option<bool> {
        let o = self.object;
        let dropped = strings(o, &["HostConfig", "CapDrop"])?;
        let added = strings(o, &["HostConfig", "CapAdd"])?;
        Some(
            dropped.len() == 1
                && dropped.iter().all(|c| c.eq_ignore_ascii_case("ALL"))
                && added.is_empty(),
        )
    }

    /// Both topologies' environment containers have the runtime's `none`
    /// network: no interface but loopback, nothing published, no host entry
    /// added. `PROXY_ONLY`'s one peer is judged separately
    /// (`HOST_PROXY_RELAY`).
    fn network_isolated(&self) -> Option<bool> {
        let o = self.object;
        let mode = text(o, &["HostConfig", "NetworkMode"]).map(|m| m == "none");
        let networks = match at(o, &["NetworkSettings", "Networks"]) {
            Some(Value::Object(networks)) => Some(networks.iter().all(|(name, _)| name == "none")),
            Some(Value::Null) => Some(true),
            _ => None,
        };
        let ports = empty(o, &["HostConfig", "PortBindings"]);
        let publish = boolean(o, &["HostConfig", "PublishAllPorts"]).map(|p| !p);
        let extra_hosts = empty(o, &["HostConfig", "ExtraHosts"]);
        all(&[mode, networks, ports, publish, extra_hosts])
    }

    fn mounts_exact(&self, spec: &EnvironmentSpec) -> Option<bool> {
        let o = self.object;
        let workspace = spec.workspace_path.as_str();
        // What the container has mounted: the workspace, and at most the two
        // temporary directories.
        let mounts = objects(o, &["Mounts"])?;
        let mut binds = 0usize;
        let mut exact = true;
        for mount in &mounts {
            match text(mount, &["Type"])? {
                "bind" => {
                    binds += 1;
                    exact &= text(mount, &["Source"])? == workspace
                        && text(mount, &["Destination"])? == WORKSPACE_TARGET
                        && boolean(mount, &["RW"])?
                        && text(mount, &["Propagation"])? == "rprivate";
                }
                "tmpfs" => {
                    let target = text(mount, &["Destination"])?;
                    exact &= target == TMP_TARGET || target == VAR_TMP_TARGET;
                }
                _ => exact = false,
            }
        }
        exact &= binds == 1;
        // What was asked for: one `--mount`, no `-v`, nothing inherited.
        let requested = objects(o, &["HostConfig", "Mounts"])?;
        exact &= requested.len() == 1
            && requested.iter().all(|m| {
                text(m, &["Type"]) == Some("bind")
                    && text(m, &["Source"]) == Some(workspace)
                    && text(m, &["Target"]) == Some(WORKSPACE_TARGET)
                    && boolean(m, &["ReadOnly"]) != Some(true)
            });
        exact &= empty(o, &["HostConfig", "Binds"])?;
        exact &= empty(o, &["HostConfig", "VolumesFrom"])?;
        exact &= text(o, &["HostConfig", "VolumeDriver"]).is_none_or(str::is_empty);
        // The two temporary directories, bounded as the plan bounds them.
        let Value::Object(tmpfs) = at(o, &["HostConfig", "Tmpfs"])? else {
            return Some(false);
        };
        exact &= tmpfs.len() == TMPFS.len()
            && TMPFS.iter().all(|(target, wanted)| {
                matches!(tmpfs.get(target), Some(Value::String(options)) if options == wanted)
            });
        Some(exact)
    }

    fn no_runtime_socket(&self, runtime_socket: &str) -> Option<bool> {
        let o = self.object;
        let mut sources: Vec<&str> = Vec::new();
        for mount in objects(o, &["Mounts"])? {
            if let Some(source) = text(mount, &["Source"]) {
                sources.push(source);
            }
        }
        for mount in objects(o, &["HostConfig", "Mounts"])? {
            if let Some(source) = text(mount, &["Source"]) {
                sources.push(source);
            }
        }
        for bind in strings(o, &["HostConfig", "Binds"])? {
            sources.push(bind.split(':').next().unwrap_or(bind));
        }
        Some(
            sources
                .iter()
                .all(|source| !exposes(source, runtime_socket)),
        )
    }

    fn no_devices(&self) -> Option<bool> {
        let o = self.object;
        all(&[
            empty(o, &["HostConfig", "Devices"]),
            empty(o, &["HostConfig", "DeviceCgroupRules"]),
            empty(o, &["HostConfig", "DeviceRequests"]),
        ])
    }

    fn resource_limits(&self) -> Option<bool> {
        let o = self.object;
        let number = |path: &[&str], want: u64| {
            integer(o, path).map(|found| i64::try_from(want).is_ok_and(|w| w == found))
        };
        let ulimits = objects(o, &["HostConfig", "Ulimits"]).map(|limits| {
            let expected = [
                ("nofile", RLIMIT_NOFILE),
                ("nproc", RLIMIT_NPROC),
                ("fsize", RLIMIT_FSIZE),
                ("core", RLIMIT_CORE),
            ];
            limits.len() == expected.len()
                && expected.iter().all(|(name, value)| {
                    let value = i64::try_from(*value).ok();
                    limits.iter().any(|l| {
                        text(l, &["Name"]) == Some(*name)
                            && integer(l, &["Soft"]) == value
                            && integer(l, &["Hard"]) == value
                    })
                })
        });
        let oom_kill = match at(o, &["HostConfig", "OomKillDisable"]) {
            None | Some(Value::Null) => Some(true),
            Some(Value::Bool(disabled)) => Some(!disabled),
            Some(_) => None,
        };
        all(&[
            number(&["HostConfig", "PidsLimit"], PIDS_LIMIT),
            number(&["HostConfig", "Memory"], MEMORY_BYTES),
            number(&["HostConfig", "MemorySwap"], MEMORY_SWAP_BYTES),
            number(&["HostConfig", "NanoCpus"], NANO_CPUS),
            integer(o, &["HostConfig", "OomScoreAdj"]).map(|a| a == i64::from(OOM_SCORE_ADJ)),
            ulimits,
            oom_kill,
        ])
    }

    /// Every `io.direwolf.` label is exactly this environment's, and there
    /// is no other. Labels in other namespaces are the runtime's own metadata
    /// — Docker Desktop's client adds `desktop.docker.io/wsl-distro` to every
    /// container it creates — and say nothing about isolation; they are not
    /// DireWolf's to require or refuse.
    fn labels_exact(&self, spec: &EnvironmentSpec) -> Option<bool> {
        let labels = self.labels()?;
        let ours: Vec<&(&str, &str)> = labels
            .iter()
            .filter(|(k, _)| k.starts_with(DIREWOLF_LABELS))
            .collect();
        let expected = plan::labels(spec, ContainerRole::Environment);
        Some(
            ours.len() == expected.len()
                && expected
                    .iter()
                    .all(|(k, v)| ours.iter().any(|(lk, lv)| lk == k && lv == v)),
        )
    }

    fn running(&self) -> Option<bool> {
        let o = self.object;
        all(&[
            boolean(o, &["State", "Running"]),
            boolean(o, &["State", "Paused"]).map(|p| !p),
            boolean(o, &["State", "Restarting"]).map(|r| !r),
            text(o, &["State", "Status"]).map(|s| s == "running"),
            text(o, &["HostConfig", "RestartPolicy", "Name"]).map(|n| n == "no" || n.is_empty()),
        ])
    }
}

/// Whether a mount of `source` would put the runtime's control socket — or
/// any runtime's, by its well-known name — inside the environment.
fn exposes(source: &str, runtime_socket: &str) -> bool {
    let source = source.trim_end_matches('/');
    // `path` is `source`, or inside it (`/` contains everything).
    let under =
        |path: &str| source.is_empty() || path == source || path.starts_with(&format!("{source}/"));
    let name = source.rsplit('/').next().unwrap_or(source);
    under(runtime_socket)
        || WELL_KNOWN_SOCKETS.iter().any(|path| under(path))
        || RUNTIME_SOCKET_NAMES.contains(&name)
}

/// Where runtimes keep their control sockets by default.
const WELL_KNOWN_SOCKETS: &[&str] = &[
    "/run/docker.sock",
    "/var/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/run/podman/podman.sock",
    "/var/run/crio/crio.sock",
    "/run/buildkit/buildkitd.sock",
];

fn no_new_privileges(options: &[&str]) -> bool {
    let set = options.iter().filter(|opt| {
        matches!(
            **opt,
            "no-new-privileges" | "no-new-privileges=true" | "no-new-privileges:true"
        )
    });
    let unset = options.iter().any(|opt| {
        opt.starts_with("no-new-privileges")
            && !matches!(
                *opt,
                "no-new-privileges" | "no-new-privileges=true" | "no-new-privileges:true"
            )
    });
    set.count() >= 1 && !unset
}

fn seccomp(options: &[&str], profile: &str) -> bool {
    let profiles: Vec<&str> = options
        .iter()
        .filter_map(|opt| {
            opt.strip_prefix("seccomp=")
                .or_else(|| opt.strip_prefix("seccomp:"))
        })
        .collect();
    profiles.len() == 1 && profiles.iter().all(|p| *p == profile)
}

#[cfg(test)]
#[path = "inspect_tests.rs"]
mod tests;
