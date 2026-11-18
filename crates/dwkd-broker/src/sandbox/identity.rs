//! What an environment's own kernel says of who runs in it and what confines
//! it (F-05, [ADR-0069], Proposed), judged against the runtime's record of
//! the container and the host's kernel -- and **reported, never admitted
//! on**: admission is the invariants' (ADR-0047), and nothing here changes
//! one. The one exception is the operator's own: a broker started with
//! `--require-lsm` refuses an environment its required module does not
//! confine ([ADR-0070], Proposed, OD-2).
//!
//! # The user namespace
//!
//! The deployment contract shares the host's initial user namespace: the
//! workload's uid 10001 *is* host uid 10001 and the relay's 10002 *is* host
//! uid 10002. The workspace group (ADR-0052 §6), the task backstop
//! (ADR-0056), the proxy directory's ACL (ADR-0048) and the proxy's peer
//! check (ADR-0068) all depend on it. `HOST_USERNS_NOT_HOST` says only that
//! the runtime was not told to use the host's mode; what the container's
//! mapping is, two kernels say. The probe reads its own
//! (`/proc/self/uid_map`, `gid_map`); and where this broker shares the
//! runtime's pid namespace, it reads the same two files of the container's
//! first process itself, from the host's side (`/proc/<pid>/`), once that
//! process's control group names the container (ADR-0070, OD-1):
//!
//! | observed | reported |
//! |---|---|
//! | the identity map, uid and gid, from both | `UNSUPPORTED`, `both`, `shared`: no remapping, as the contract states |
//! | the identity map from one vantage, nothing from the other | `UNSUPPORTED`, `inside` or `host`, `shared` |
//! | two vantages that disagree | `UNVERIFIED`, `both`, `contradiction` |
//! | any other map | `UNVERIFIED`, `remapped`: the contract serves no remapped runtime, and one environment's view cannot say whether others share its range |
//! | the runtime's record says `host` | `UNSUPPORTED`, `host-mode` (`HOST_USERNS_NOT_HOST` refuses it) |
//! | nothing | `UNVERIFIED`, `unobserved` |
//!
//! On Docker Desktop the container's processes live in another kernel's pid
//! namespace, so the host vantage is absent and the map is said from inside.
//!
//! # Security modules
//!
//! A module counts as confining an environment only when the host's kernel
//! runs it, the probe's own kernel gives the process a label in its
//! enforcing mode, and the runtime's record names the same profile or
//! label. A label alone is not confinement -- a kernel with SELinux built in
//! but never initialised labels every process `kernel` -- and neither is a
//! module the kernel offers (Landlock) or a profile the runtime names.
//!
//! The states are F-03's spellings (`crate::effective::Condition`). Here
//! `REDUCED` means a weaker mode than the module's enforcement was observed
//! -- complain, unconfined, permissive, an unconfined domain -- not an
//! operator's acknowledgement. Each says where it was seen: `both` (two
//! vantages agree), `inside`, `record`, `host` (the host's kernel alone),
//! `build` (what this build does), `none`.
//!
//! # A required module
//!
//! An operator may require AppArmor or SELinux (`--require-lsm`). The broker
//! then refuses to serve unless the host's kernel runs that module in its
//! enforcing mode, and refuses every environment the judgement above does
//! not call `ENFORCED` for it -- `REDUCED`, `UNVERIFIED` and `UNSUPPORTED`
//! alike -- with `UNSUPPORTED`, after taking it down. Nothing turns the
//! requirement off once given, and nothing falls back to reporting.
//!
//! Nothing here reaches the authority but that refusal: carrying the
//! judgement on the private protocol is protocol 13's, with F-03's broker
//! posture (ADR-0069 OD-3).
//!
//! [ADR-0069]: ../../../../docs/adr/0069-f05-user-namespace-and-lsm-assurance-are-measured-not-assumed.md
//! [ADR-0070]: ../../../../docs/adr/0070-adr-0069-decisions-host-vantage-required-lsm-and-what-stays-deferred.md

use std::io::Read as _;

use dwk_proto::brokerp::BrokerRefusal;
use dwk_proto::brokerp::sandbox::{
    IdMap, IdentityFacts, LsmLabel, id_map_from_kernel, is_identity_map,
};

use crate::config::RequiredLsm;
use crate::effective::Condition;

/// What the runtime's record says of the container's identity and
/// confinement: its user-namespace mode, its AppArmor profile and its
/// SELinux process label, each as recorded, an empty value as none.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Recorded<'a> {
    pub(crate) userns_mode: Option<&'a str>,
    pub(crate) apparmor_profile: Option<&'a str>,
    pub(crate) process_label: Option<&'a str>,
}

/// What the host's kernel runs, read now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HostLsm {
    /// AppArmor is enabled, and not left out of the module list.
    pub(crate) apparmor: bool,
    /// SELinux's mode where it runs (`selinuxfs` mounted): `true`
    /// enforcing, `false` permissive. `None`: it does not run here.
    pub(crate) selinux_enforcing: Option<bool>,
}

impl HostLsm {
    /// Read from this host's kernel.
    pub(crate) fn read() -> Self {
        let read = |path: &str| std::fs::read_to_string(path).ok();
        Self::from_kernel(
            read("/sys/kernel/security/lsm").as_deref(),
            read("/sys/module/apparmor/parameters/enabled").as_deref(),
            read("/sys/fs/selinux/enforce").as_deref(),
        )
    }

    /// From the kernel's files: the module list (`/sys/kernel/security/lsm`,
    /// absent where `securityfs` is not mounted), AppArmor's `enabled`
    /// parameter and SELinux's `enforce`.
    pub(crate) fn from_kernel(
        lsm: Option<&str>,
        apparmor_enabled: Option<&str>,
        selinux_enforce: Option<&str>,
    ) -> Self {
        let listed = lsm.map(|list| list.trim().split(',').any(|m| m == "apparmor"));
        Self {
            apparmor: apparmor_enabled.is_some_and(|e| e.trim() == "Y") && listed != Some(false),
            selinux_enforcing: selinux_enforce.map(|e| e.trim() == "1"),
        }
    }
}

/// The container's uid and gid maps as the host's kernel states them, read
/// by this broker from `/proc/<pid>/` of the container's first process
/// (ADR-0070, OD-1): the user namespace's second vantage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostMaps {
    pub(crate) uid: IdMap,
    pub(crate) gid: IdMap,
}

/// At most this many bytes of one `/proc` file are read: a map is at most
/// eight short lines, a control-group file a few.
const PROC_READ: u64 = 4096;

impl HostMaps {
    /// Read from this host's `/proc`, or `None`: no pid, a container id that
    /// is not the runtime's 64 hexadecimal digits, a pid this broker cannot
    /// see (another kernel's, as on Docker Desktop), or a process whose
    /// control group -- read before the maps and again after them -- does not
    /// name the container. A pid reused between the reads is another
    /// process, in another group: it is no vantage.
    pub(crate) fn read(pid: Option<u32>, container: Option<&str>) -> Option<Self> {
        let pid = pid.filter(|pid| *pid > 0)?;
        let container =
            container.filter(|id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()))?;
        let read = |name: &str| -> Option<String> {
            let mut text = String::new();
            std::fs::File::open(format!("/proc/{pid}/{name}"))
                .ok()?
                .take(PROC_READ)
                .read_to_string(&mut text)
                .ok()?;
            Some(text)
        };
        let placed = || read("cgroup").is_some_and(|text| cgroup_names(&text, container));
        if !placed() {
            return None;
        }
        let maps = Self::from_kernel(&read("uid_map")?, &read("gid_map")?)?;
        placed().then_some(maps)
    }

    /// From the kernel's two map files' text; `None` unless both are maps.
    pub(crate) fn from_kernel(uid: &str, gid: &str) -> Option<Self> {
        Some(Self {
            uid: id_map_from_kernel(uid)?,
            gid: id_map_from_kernel(gid)?,
        })
    }
}

/// Whether a `/proc/<pid>/cgroup` text places the process in `container`'s
/// own control group: a line whose path's last segment is exactly the
/// container's id (the `cgroupfs` driver) or `docker-<id>.scope` (systemd's).
/// Nothing else counts -- not a prefix, a substring or a parent group.
pub(crate) fn cgroup_names(text: &str, container: &str) -> bool {
    let scope = format!("docker-{container}.scope");
    text.lines().any(|line| {
        let path = line.splitn(3, ':').nth(2).unwrap_or_default();
        let last = path.rsplit('/').next().unwrap_or_default();
        !container.is_empty() && (last == container || last == scope)
    })
}

/// One property's judgement: its condition, where it was seen, and a short
/// code -- or a profile or domain name, sanitised -- saying why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Judged {
    pub(crate) condition: Condition,
    pub(crate) seen: &'static str,
    pub(crate) detail: String,
}

fn judged(condition: Condition, seen: &'static str, detail: &str) -> Judged {
    Judged {
        condition,
        seen,
        detail: sanitised(detail),
    }
}

/// A name fit for one field of an event line: `[A-Za-z0-9._/-]`, anything
/// else `_`, at most 64 characters.
fn sanitised(text: &str) -> String {
    text.chars()
        .take(64)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// An environment's identity and confinement, judged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Identity {
    pub(crate) userns: Judged,
    pub(crate) apparmor: Judged,
    pub(crate) selinux: Judged,
    pub(crate) landlock: Judged,
}

/// Judge what the probe's kernel said (`facts`, absent from a probe built
/// before F-05) against the runtime's record and the host's kernel, with no
/// host vantage on the user namespace: the tables' form of
/// [`judge_with`].
#[cfg(test)]
pub(crate) fn judge(
    recorded: &Recorded<'_>,
    facts: Option<&IdentityFacts>,
    host: HostLsm,
) -> Identity {
    judge_with(recorded, facts, host, None)
}

/// [`judge`], with the container's maps as the host's kernel states them
/// where this broker could read them (`maps`, OD-1).
pub(crate) fn judge_with(
    recorded: &Recorded<'_>,
    facts: Option<&IdentityFacts>,
    host: HostLsm,
    maps: Option<&HostMaps>,
) -> Identity {
    Identity {
        userns: userns(recorded, facts, maps),
        apparmor: apparmor(recorded, facts, host),
        selinux: selinux(recorded, facts, host),
        // DireWolf installs no Landlock ruleset on any process: a kernel that
        // offers it confines nothing by offering it.
        landlock: judged(Condition::NotApplicable, "build", "no-ruleset"),
    }
}

fn userns(
    recorded: &Recorded<'_>,
    facts: Option<&IdentityFacts>,
    host: Option<&HostMaps>,
) -> Judged {
    if recorded.userns_mode == Some("host") {
        return judged(Condition::Unsupported, "record", "host-mode");
    }
    let inside = facts.and_then(|f| f.uid_map.as_ref().zip(f.gid_map.as_ref()));
    let host = host.map(|maps| (&maps.uid, &maps.gid));
    let shared = |(uid, gid): (&IdMap, &IdMap)| is_identity_map(uid) && is_identity_map(gid);
    match (inside, host) {
        (None, None) => judged(Condition::Unverified, "none", "unobserved"),
        (Some(seen), Some(hosted)) if seen != hosted => {
            judged(Condition::Unverified, "both", "contradiction")
        }
        (Some(_), Some(hosted)) if shared(hosted) => {
            judged(Condition::Unsupported, "both", "shared")
        }
        (Some(_), Some(_)) => judged(Condition::Unverified, "both", "remapped"),
        (Some(seen), None) if shared(seen) => judged(Condition::Unsupported, "inside", "shared"),
        (Some(_), None) => judged(Condition::Unverified, "inside", "remapped"),
        (None, Some(hosted)) if shared(hosted) => judged(Condition::Unsupported, "host", "shared"),
        (None, Some(_)) => judged(Condition::Unverified, "host", "remapped"),
    }
}

/// An AppArmor label as the kernel prints it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Profile<'a> {
    Enforce(&'a str),
    Complain(&'a str),
    Unconfined,
    Other,
}

fn profile(label: &LsmLabel) -> Profile<'_> {
    let text = label.as_str();
    if text == "unconfined" {
        Profile::Unconfined
    } else if let Some(name) = text.strip_suffix(" (enforce)") {
        Profile::Enforce(name)
    } else if let Some(name) = text.strip_suffix(" (complain)") {
        Profile::Complain(name)
    } else {
        Profile::Other
    }
}

fn apparmor(recorded: &Recorded<'_>, facts: Option<&IdentityFacts>, host: HostLsm) -> Judged {
    if !host.apparmor {
        return judged(Condition::Unsupported, "host", "kernel-has-none");
    }
    // AppArmor's own attribute where the kernel has it; the major module's
    // otherwise, unless that is SELinux's.
    let label = facts.and_then(|f| {
        f.apparmor
            .as_ref()
            .or_else(|| f.lsm.as_ref().filter(|_| host.selinux_enforcing.is_none()))
    });
    let record = recorded.apparmor_profile.filter(|p| !p.is_empty());
    let Some(label) = label else {
        return judged(Condition::Unverified, "none", "unobserved");
    };
    match (profile(label), record) {
        (Profile::Enforce(name), Some(named)) if name == named && name != "unconfined" => {
            judged(Condition::Enforced, "both", name)
        }
        (Profile::Complain(name), Some(named)) if name == named => {
            judged(Condition::Reduced, "both", "complain")
        }
        (Profile::Unconfined, None | Some("unconfined")) => {
            judged(Condition::Reduced, "both", "unconfined")
        }
        (Profile::Other, _) => judged(Condition::Unverified, "inside", "unrecognised"),
        _ => judged(Condition::Unverified, "inside", "contradiction"),
    }
}

/// SELinux domains that confine nothing a container needs confined.
const UNCONFINED_DOMAINS: [&str; 5] = [
    "unconfined_t",
    "spc_t",
    "unconfined_service_t",
    "kernel_t",
    "initrc_t",
];

fn selinux(recorded: &Recorded<'_>, facts: Option<&IdentityFacts>, host: HostLsm) -> Judged {
    let Some(enforcing) = host.selinux_enforcing else {
        return judged(Condition::Unsupported, "host", "kernel-has-none");
    };
    let Some(label) = facts.and_then(|f| f.lsm.as_ref()) else {
        return judged(Condition::Unverified, "none", "unobserved");
    };
    let Some(record) = recorded.process_label.filter(|l| !l.is_empty()) else {
        return judged(Condition::Unverified, "inside", "unrecorded");
    };
    if label.as_str() != record {
        return judged(Condition::Unverified, "inside", "contradiction");
    }
    let domain = label.as_str().split(':').nth(2).unwrap_or_default();
    if domain.is_empty() || UNCONFINED_DOMAINS.contains(&domain) {
        return judged(Condition::Reduced, "both", "unconfined-domain");
    }
    if enforcing {
        judged(Condition::Enforced, "both", domain)
    } else {
        judged(Condition::Reduced, "both", "permissive")
    }
}

/// Whether this host's kernel runs `required` in its enforcing mode: what a
/// broker started with `--require-lsm` checks before it serves. SELinux
/// permissive is not enforcement.
pub(crate) const fn host_runs(required: RequiredLsm, host: HostLsm) -> bool {
    match required {
        RequiredLsm::AppArmor => host.apparmor,
        RequiredLsm::SeLinux => matches!(host.selinux_enforcing, Some(true)),
    }
}

/// The judgement of the module the operator requires.
const fn of_required(required: RequiredLsm, identity: &Identity) -> &Judged {
    match required {
        RequiredLsm::AppArmor => &identity.apparmor,
        RequiredLsm::SeLinux => &identity.selinux,
    }
}

/// Whether `identity` meets the module the operator requires: only
/// `ENFORCED` does. `REDUCED`, `UNVERIFIED` and `UNSUPPORTED` are each a
/// refusal of the environment; nothing falls back to reporting.
pub(crate) fn meets(required: RequiredLsm, identity: &Identity) -> bool {
    of_required(required, identity).condition == Condition::Enforced
}

/// The operator's requirement applied to one environment (OD-2): with no
/// module required, nothing here refuses; a required module admits only an
/// environment it confines, and refuses every other with `UNSUPPORTED`.
pub(crate) fn admits(
    required: Option<RequiredLsm>,
    identity: &Identity,
) -> Result<(), BrokerRefusal> {
    match required {
        Some(module) if !meets(module, identity) => Err(BrokerRefusal::Unsupported),
        _ => Ok(()),
    }
}

/// The broker's event line for one environment's judgement.
pub(crate) fn line(environment: &str, identity: &Identity) -> String {
    let field = |j: &Judged| format!("{}:{}:{}", j.condition.as_str(), j.seen, j.detail);
    format!(
        "sandbox_identity environment={} userns={} apparmor={} selinux={} landlock={}",
        sanitised(environment),
        field(&identity.userns),
        field(&identity.apparmor),
        field(&identity.selinux),
        field(&identity.landlock),
    )
}

/// The broker's event line for a required module's judgement of one
/// environment: `met`, or `refused` and the state that refused it.
pub(crate) fn required_line(
    environment: &str,
    required: RequiredLsm,
    identity: &Identity,
) -> String {
    let judged = of_required(required, identity);
    format!(
        "sandbox_lsm_required environment={} module={} outcome={} state={}:{}:{}",
        sanitised(environment),
        required.as_str(),
        if meets(required, identity) {
            "met"
        } else {
            "refused"
        },
        judged.condition.as_str(),
        judged.seen,
        judged.detail,
    )
}
