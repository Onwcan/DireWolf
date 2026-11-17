//! What an environment's own kernel says of who runs in it and what confines
//! it (F-05, [ADR-0069], Proposed), judged against the runtime's record of
//! the container and the host's kernel -- and **reported, never admitted
//! on**: admission is the invariants' (ADR-0047), and nothing here changes
//! one.
//!
//! # The user namespace
//!
//! The deployment contract shares the host's initial user namespace: the
//! workload's uid 10001 *is* host uid 10001 and the relay's 10002 *is* host
//! uid 10002. The workspace group (ADR-0052 §6), the task backstop
//! (ADR-0056), the proxy directory's ACL (ADR-0048) and the proxy's peer
//! check (ADR-0068) all depend on it. `HOST_USERNS_NOT_HOST` says only that
//! the runtime was not told to use the host's mode; what the container's
//! mapping is, the probe reads from its own kernel (`/proc/self/uid_map`,
//! `gid_map`):
//!
//! | observed from inside | reported |
//! |---|---|
//! | the identity map, uid and gid | `UNSUPPORTED`, `shared`: no remapping, as the contract states |
//! | any other map | `UNVERIFIED`, `remapped`: seen from inside only; the contract serves no remapped runtime, and its workspace and relay invariants refuse one |
//! | the runtime's record says `host` | `UNSUPPORTED`, `host-mode` (`HOST_USERNS_NOT_HOST` refuses it) |
//! | nothing | `UNVERIFIED`, `unobserved` |
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
//! operator's acknowledgement. Each says where it was seen: `both` (the
//! record and the probe's kernel agree, on a host whose kernel runs the
//! module), `inside`, `record`, `host` (the host's kernel alone), `build`
//! (what this build does), `none`.
//!
//! Nothing here reaches the authority: carrying it on the private protocol
//! is protocol 13's, with F-03's broker posture (ADR-0069 OD-3).
//!
//! [ADR-0069]: ../../../../docs/adr/0069-f05-user-namespace-and-lsm-assurance-are-measured-not-assumed.md

use dwk_proto::brokerp::sandbox::{IdentityFacts, LsmLabel, is_identity_map};

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
/// before F-05) against the runtime's record and the host's kernel.
pub(crate) fn judge(
    recorded: &Recorded<'_>,
    facts: Option<&IdentityFacts>,
    host: HostLsm,
) -> Identity {
    Identity {
        userns: userns(recorded, facts),
        apparmor: apparmor(recorded, facts, host),
        selinux: selinux(recorded, facts, host),
        // DireWolf installs no Landlock ruleset on any process: a kernel that
        // offers it confines nothing by offering it.
        landlock: judged(Condition::NotApplicable, "build", "no-ruleset"),
    }
}

fn userns(recorded: &Recorded<'_>, facts: Option<&IdentityFacts>) -> Judged {
    if recorded.userns_mode == Some("host") {
        return judged(Condition::Unsupported, "record", "host-mode");
    }
    let maps = facts.and_then(|f| f.uid_map.as_ref().zip(f.gid_map.as_ref()));
    match maps {
        None => judged(Condition::Unverified, "none", "unobserved"),
        Some((uid, gid)) if is_identity_map(uid) && is_identity_map(gid) => {
            judged(Condition::Unsupported, "inside", "shared")
        }
        Some(_) => judged(Condition::Unverified, "inside", "remapped"),
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
