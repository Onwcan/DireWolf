//! The environment's identity judgement (F-05, ADR-0069): what the probe's
//! kernel says, against the runtime's record and the host's kernel.
//!
//! The tables are **synthetic** -- facts as the probe and the runtime would
//! give them, every state each module can reach -- and say so. Two cases are
//! the kernel's own: this host's security-module files, read now, and a
//! user-namespace mapping read in the initial namespace and in an
//! unprivileged one of the test's own. The real environments' judgement is
//! `sandbox_foundation.rs`'s (an OCI runtime).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::unix::net::UnixStream;

use dwk_proto::brokerp::sandbox::{IdentityFacts, LsmLabel, id_map_from_kernel, is_identity_map};

use super::identity::{
    HostLsm, HostMaps, Identity, Judged, Recorded, admits, cgroup_names, host_runs, judge,
    judge_with, line, meets, required_line,
};
use crate::effective::Condition as C;
use crate::peer::harness;

const IDENTITY: &str = "0 0 4294967295\n";
const REMAPPED: &str = "0 100000 65536\n";

/// The host this was built on: Docker Desktop's WSL2 kernel, with AppArmor
/// compiled in and disabled, no `securityfs` list and no `selinuxfs`.
const NO_LSM: HostLsm = HostLsm {
    apparmor: false,
    selinux_enforcing: None,
};
const APPARMOR: HostLsm = HostLsm {
    apparmor: true,
    selinux_enforcing: None,
};
const SELINUX_ENFORCING: HostLsm = HostLsm {
    apparmor: false,
    selinux_enforcing: Some(true),
};
const SELINUX_PERMISSIVE: HostLsm = HostLsm {
    apparmor: false,
    selinux_enforcing: Some(false),
};

fn label(text: &str) -> LsmLabel {
    LsmLabel::from_kernel(text.as_bytes()).unwrap()
}

fn facts(uid: &str, gid: &str, lsm: Option<&str>, apparmor: Option<&str>) -> IdentityFacts {
    IdentityFacts {
        uid_map: id_map_from_kernel(uid),
        gid_map: id_map_from_kernel(gid),
        lsm: lsm.map(label),
        apparmor: apparmor.map(label),
    }
}

fn of(judged: &Judged) -> (C, &str, &str) {
    (judged.condition, judged.seen, judged.detail.as_str())
}

fn recorded<'a>(apparmor: Option<&'a str>, selinux: Option<&'a str>) -> Recorded<'a> {
    Recorded {
        userns_mode: Some(""),
        apparmor_profile: apparmor,
        process_label: selinux,
    }
}

/// One line per F-05 case, printed after its assertions held.
fn f05_evidence(case: &str, level: &str) {
    println!("F05-EVIDENCE {{\"case\":\"{case}\",\"level\":\"{level}\",\"contained\":true}}");
}

#[test]
fn the_host_kernel_is_read_as_its_files_say() {
    // This host as measured: no list, AppArmor's parameter `N`, no SELinux.
    assert_eq!(HostLsm::from_kernel(None, Some("N\n"), None), NO_LSM);
    assert_eq!(HostLsm::from_kernel(None, None, None), NO_LSM);
    // An Ubuntu host: listed and enabled.
    let ubuntu = HostLsm::from_kernel(
        Some("lockdown,capability,landlock,yama,apparmor"),
        Some("Y\n"),
        None,
    );
    assert_eq!(ubuntu, APPARMOR);
    // Enabled but left out of the list, or listed and disabled: not running.
    assert!(!HostLsm::from_kernel(Some("capability,landlock"), Some("Y"), None).apparmor);
    assert!(!HostLsm::from_kernel(Some("capability,apparmor"), Some("N"), None).apparmor);
    // SELinux by its mode, only where `selinuxfs` says it runs.
    let fedora = HostLsm::from_kernel(Some("capability,selinux"), None, Some("1\n"));
    assert_eq!(fedora, SELINUX_ENFORCING);
    assert_eq!(
        HostLsm::from_kernel(Some("capability,selinux"), None, Some("0")),
        SELINUX_PERMISSIVE
    );
    // And this host's own files, read now, are read the same way.
    let read = |path: &str| std::fs::read_to_string(path).ok();
    assert_eq!(
        HostLsm::read(),
        HostLsm::from_kernel(
            read("/sys/kernel/security/lsm").as_deref(),
            read("/sys/module/apparmor/parameters/enabled").as_deref(),
            read("/sys/fs/selinux/enforce").as_deref(),
        )
    );
    f05_evidence("host-security-modules-read-from-the-kernel", "unit+kernel");
}

#[test]
fn the_user_namespace_is_reported_as_the_kernel_maps_it() {
    let judged = |r: &Recorded<'_>, f: Option<&IdentityFacts>| judge(r, f, NO_LSM).userns;
    let none = recorded(None, None);
    // The deployment contract: the identity map, uid and gid -- shared with
    // the host, no remapping. Never ENFORCED.
    let shared = facts(IDENTITY, IDENTITY, None, None);
    assert_eq!(
        of(&judged(&none, Some(&shared))),
        (C::Unsupported, "inside", "shared")
    );
    // Any other map, uid's or gid's: remapped, seen from inside only.
    for (uid, gid) in [
        (REMAPPED, REMAPPED),
        (IDENTITY, REMAPPED),
        (REMAPPED, IDENTITY),
    ] {
        let remapped = facts(uid, gid, None, None);
        assert_eq!(
            of(&judged(&none, Some(&remapped))),
            (C::Unverified, "inside", "remapped"),
            "{uid:?} {gid:?}"
        );
    }
    // A map the probe could not read, or a probe built before F-05.
    let half = IdentityFacts {
        gid_map: None,
        ..shared.clone()
    };
    assert_eq!(
        of(&judged(&none, Some(&half))),
        (C::Unverified, "none", "unobserved")
    );
    assert_eq!(
        of(&judged(&none, None)),
        (C::Unverified, "none", "unobserved")
    );
    // The record asking for the host's mode, whatever is seen inside.
    let host_mode = Recorded {
        userns_mode: Some("host"),
        ..none
    };
    assert_eq!(
        of(&judged(&host_mode, Some(&shared))),
        (C::Unsupported, "record", "host-mode")
    );
    f05_evidence("userns-shared-remapped-unobserved-host-mode", "unit");
}

#[test]
fn apparmor_counts_only_an_enforcing_profile_both_vantages_name() {
    let judged = |r: Option<&str>, lsm: Option<&str>, own: Option<&str>, host: HostLsm| {
        judge(
            &recorded(r, None),
            Some(&facts(IDENTITY, IDENTITY, lsm, own)),
            host,
        )
        .apparmor
    };
    let enforce = Some("docker-default (enforce)");
    // Enforcing, the profile the record names, on a kernel running AppArmor.
    assert_eq!(
        of(&judged(Some("docker-default"), None, enforce, APPARMOR)),
        (C::Enforced, "both", "docker-default")
    );
    // The major module's attribute serves where AppArmor's own is missing.
    assert_eq!(
        of(&judged(Some("docker-default"), enforce, None, APPARMOR)),
        (C::Enforced, "both", "docker-default")
    );
    // Weaker modes, as the record has them.
    assert_eq!(
        of(&judged(
            Some("docker-default"),
            None,
            Some("docker-default (complain)"),
            APPARMOR
        )),
        (C::Reduced, "both", "complain")
    );
    for record in [None, Some(""), Some("unconfined")] {
        assert_eq!(
            of(&judged(record, None, Some("unconfined"), APPARMOR)),
            (C::Reduced, "both", "unconfined"),
            "{record:?}"
        );
    }
    // The two vantages disagree: the record names a profile the process
    // does not run, or the process runs one the record does not name.
    for (record, own) in [
        (Some("docker-default"), Some("unconfined")),
        (Some("docker-default"), Some("other (enforce)")),
        (None, enforce),
        (Some("other"), Some("docker-default (complain)")),
    ] {
        assert_eq!(
            of(&judged(record, None, own, APPARMOR)),
            (C::Unverified, "inside", "contradiction"),
            "{record:?} {own:?}"
        );
    }
    // A label the kernel prints for no AppArmor profile -- SELinux built in
    // and never initialised says `kernel` -- is not one.
    assert_eq!(
        of(&judged(
            Some("docker-default"),
            Some("kernel"),
            None,
            APPARMOR
        )),
        (C::Unverified, "inside", "unrecognised")
    );
    // Where SELinux runs too, the major module's label is SELinux's, never
    // read as an AppArmor profile.
    let both = HostLsm {
        apparmor: true,
        selinux_enforcing: Some(true),
    };
    assert_eq!(
        of(&judged(
            Some("docker-default"),
            Some("system_u:system_r:container_t:s0 (enforce)"),
            None,
            both
        )),
        (C::Unverified, "none", "unobserved")
    );
    // Nothing seen inside: the record alone is never confinement.
    assert_eq!(
        of(&judge(&recorded(Some("docker-default"), None), None, APPARMOR).apparmor),
        (C::Unverified, "none", "unobserved")
    );
    // A kernel not running AppArmor: unsupported, whatever either side says.
    assert_eq!(
        of(&judged(
            Some("docker-default"),
            Some("kernel"),
            enforce,
            NO_LSM
        )),
        (C::Unsupported, "host", "kernel-has-none")
    );
    f05_evidence("apparmor-enforced-only-when-both-vantages-agree", "unit");
}

#[test]
fn selinux_counts_only_an_enforcing_confined_domain_both_vantages_name() {
    let context = "system_u:system_r:container_t:s0:c1,c2";
    let judged = |r: Option<&str>, own: Option<&str>, host: HostLsm| {
        judge(
            &recorded(None, r),
            Some(&facts(IDENTITY, IDENTITY, own, None)),
            host,
        )
        .selinux
    };
    assert_eq!(
        of(&judged(Some(context), Some(context), SELINUX_ENFORCING)),
        (C::Enforced, "both", "container_t")
    );
    // Permissive: the label is there and nothing is refused.
    assert_eq!(
        of(&judged(Some(context), Some(context), SELINUX_PERMISSIVE)),
        (C::Reduced, "both", "permissive")
    );
    // A domain that confines nothing, however enforcing the kernel.
    for domain in ["spc_t", "unconfined_t", "kernel_t"] {
        let label = format!("system_u:system_r:{domain}:s0");
        assert_eq!(
            of(&judged(Some(&label), Some(&label), SELINUX_ENFORCING)),
            (C::Reduced, "both", "unconfined-domain"),
            "{domain}"
        );
    }
    // An unexpected label, an unrecorded one, nothing seen.
    assert_eq!(
        of(&judged(
            Some(context),
            Some("system_u:system_r:spc_t:s0"),
            SELINUX_ENFORCING
        )),
        (C::Unverified, "inside", "contradiction")
    );
    assert_eq!(
        of(&judged(None, Some(context), SELINUX_ENFORCING)),
        (C::Unverified, "inside", "unrecorded")
    );
    assert_eq!(
        of(&judged(Some(context), None, SELINUX_ENFORCING)),
        (C::Unverified, "none", "unobserved")
    );
    // `kernel` -- this host's label for every process -- where SELinux does
    // not run is nothing at all.
    assert_eq!(
        of(&judged(None, Some("kernel"), NO_LSM)),
        (C::Unsupported, "host", "kernel-has-none")
    );
    f05_evidence("selinux-enforced-only-when-enforcing-and-confined", "unit");
}

#[test]
fn landlock_is_never_counted_as_confinement() {
    // DireWolf installs no ruleset: a kernel offering Landlock (this one
    // does, ABI 7) confines nothing by offering it.
    for host in [NO_LSM, APPARMOR, SELINUX_ENFORCING] {
        let identity = judge(&recorded(None, None), None, host);
        assert_eq!(
            of(&identity.landlock),
            (C::NotApplicable, "build", "no-ruleset")
        );
    }
    f05_evidence("landlock-not-applicable-no-ruleset", "unit");
}

#[test]
fn the_event_line_names_every_property_and_carries_nothing_unbounded() {
    // A profile name the kernel could print and the record could name, with
    // spaces, separators and far more than a field holds: a field of the
    // line, sanitised and bounded. (A label with a control character never
    // gets this far: it is not a label.)
    let name = format!("evil profile;name=x{}", "y".repeat(120));
    let own = format!("{name} (enforce)");
    let identity = Identity {
        userns: Judged {
            condition: C::Unsupported,
            seen: "inside",
            detail: "shared".to_owned(),
        },
        ..judge(
            &recorded(Some(&name), None),
            Some(&facts(IDENTITY, IDENTITY, None, Some(&own))),
            APPARMOR,
        )
    };
    assert_eq!(identity.apparmor.condition, C::Enforced);
    assert_eq!(identity.apparmor.detail.len(), 64);
    assert!(identity.apparmor.detail.starts_with("evil_profile_name_x"));
    let text = line("env_01M24BB8G3E0A851TRWE3M8FZF", &identity);
    assert!(text.starts_with(
        "sandbox_identity environment=env_01M24BB8G3E0A851TRWE3M8FZF userns=UNSUPPORTED:inside:shared apparmor=ENFORCED:both:evil_profile_name_x"
    ));
    assert!(text.contains(
        " selinux=UNSUPPORTED:host:kernel-has-none landlock=NOT_APPLICABLE:build:no-ruleset"
    ));
    assert!(
        text.chars().all(|c| c.is_ascii_graphic() || c == ' '),
        "{text:?}"
    );
    assert_eq!(text.split(' ').count(), 6, "{text}");
    f05_evidence("event-line-bounded", "unit");
}

#[test]
fn a_real_kernel_mapping_is_judged_where_it_is_read() {
    let own_maps = || {
        let read = |path: &str| std::fs::read_to_string(path).unwrap();
        facts(
            &read("/proc/self/uid_map"),
            &read("/proc/self/gid_map"),
            None,
            None,
        )
    };
    if harness::is_hidden_judge() {
        // In an unprivileged user namespace of its own: the kernel maps this
        // process's uid to itself and nothing else -- not the identity.
        let judged = judge(&recorded(None, None), Some(&own_maps()), NO_LSM).userns;
        println!(
            "F05-USERNS {}:{}:{}",
            judged.condition.as_str(),
            judged.seen,
            judged.detail
        );
        return;
    }
    // Here, whatever namespace the test runs in, the judgement is the map's.
    let outside = own_maps();
    let judged = judge(&recorded(None, None), Some(&outside), NO_LSM).userns;
    let expected = if outside.uid_map.as_ref().is_some_and(is_identity_map)
        && outside.gid_map.as_ref().is_some_and(is_identity_map)
    {
        "shared"
    } else {
        "remapped"
    };
    assert_eq!(judged.detail, expected);
    let (_ours, theirs) = UnixStream::pair().unwrap();
    let Some(output) = harness::judge_hidden(
        "sandbox::identity_tests::a_real_kernel_mapping_is_judged_where_it_is_read",
        std::os::fd::OwnedFd::from(theirs),
    ) else {
        return;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{text}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        text.contains("F05-USERNS UNVERIFIED:inside:remapped"),
        "{text}"
    );
    f05_evidence(
        "userns-real-kernel-initial-and-unprivileged-namespace",
        "kernel",
    );
}

// ---- ADR-0070 (Proposed): the host vantage (OD-1) and a required module (OD-2)

const CONTAINER: &str = "4f1c0a2e9b7d6c5a4f1c0a2e9b7d6c5a4f1c0a2e9b7d6c5a4f1c0a2e9b7d6c5a";

#[test]
fn a_process_is_the_container_only_where_its_own_control_group_names_it() {
    // systemd's driver, cgroup v2; the cgroupfs driver; cgroup v1's many
    // lines with one naming it: each places the process in the container.
    for text in [
        format!("0::/system.slice/docker-{CONTAINER}.scope\n"),
        format!("0::/docker/{CONTAINER}\n"),
        format!("12:pids:/docker/{CONTAINER}\n11:memory:/docker/{CONTAINER}\n1:name=systemd:/\n"),
    ] {
        assert!(cgroup_names(&text, CONTAINER), "{text:?}");
    }
    // A parent group, a child group, a prefix, a substring, another
    // container, the host's own group, nothing: never.
    let other = "a".repeat(64);
    for text in [
        "0::/docker\n".to_owned(),
        format!("0::/docker/{CONTAINER}/init\n"),
        format!("0::/docker/{}\n", &CONTAINER[..32]),
        format!("0::/docker/x{CONTAINER}\n"),
        format!("0::/system.slice/docker-{CONTAINER}.scope.d\n"),
        format!("0::/system.slice/containerd-{CONTAINER}.scope\n"),
        format!("0::/docker/{other}\n"),
        "0::/user.slice/user-1000.slice/session-1.scope\n".to_owned(),
        String::new(),
    ] {
        assert!(!cgroup_names(&text, CONTAINER), "{text:?}");
    }
    assert!(!cgroup_names("0::/\n", ""));
    // No vantage without a pid, with pid 0, with an id that is not the
    // runtime's 64 hexadecimal digits -- or, on this kernel, for this very
    // process: its control group names no container.
    assert_eq!(HostMaps::read(None, Some(CONTAINER)), None);
    assert_eq!(HostMaps::read(Some(0), Some(CONTAINER)), None);
    assert_eq!(HostMaps::read(Some(std::process::id()), None), None);
    for bad in ["", "abc", &"g".repeat(64), &format!("{CONTAINER}0")] {
        assert_eq!(HostMaps::read(Some(std::process::id()), Some(bad)), None);
    }
    assert_eq!(
        HostMaps::read(Some(std::process::id()), Some(CONTAINER)),
        None
    );
    assert_eq!(HostMaps::read(Some(u32::MAX), Some(CONTAINER)), None);
    f05_evidence("host-vantage-only-for-the-named-container", "unit+kernel");
}

#[test]
fn the_user_namespace_is_judged_from_both_vantages_where_the_host_shows_it() {
    let judged = |r: &Recorded<'_>, f: Option<&IdentityFacts>, h: Option<&HostMaps>| {
        of(&judge_with(r, f, NO_LSM, h).userns).0
    };
    let detail = |r: &Recorded<'_>, f: Option<&IdentityFacts>, h: Option<&HostMaps>| {
        let j = judge_with(r, f, NO_LSM, h).userns;
        (j.condition, j.seen, j.detail)
    };
    let none = recorded(None, None);
    let shared = facts(IDENTITY, IDENTITY, None, None);
    let remapped = facts(REMAPPED, REMAPPED, None, None);
    let host_shared = HostMaps::from_kernel(IDENTITY, IDENTITY).unwrap();
    let host_remapped = HostMaps::from_kernel(REMAPPED, REMAPPED).unwrap();
    let host_half = HostMaps::from_kernel(IDENTITY, REMAPPED).unwrap();
    // Both vantages: the identity map is still shared, never ENFORCED.
    assert_eq!(
        detail(&none, Some(&shared), Some(&host_shared)),
        (C::Unsupported, "both", "shared".to_owned())
    );
    assert_eq!(
        detail(&none, Some(&remapped), Some(&host_remapped)),
        (C::Unverified, "both", "remapped".to_owned())
    );
    // The two disagree -- the probe's map is not the host's, either way, or
    // in its gid alone: never shared, never remapped.
    for (inside, host) in [
        (&shared, &host_remapped),
        (&remapped, &host_shared),
        (&shared, &host_half),
    ] {
        assert_eq!(
            detail(&none, Some(inside), Some(host)),
            (C::Unverified, "both", "contradiction".to_owned())
        );
    }
    // One vantage: said as that one.
    assert_eq!(
        detail(&none, None, Some(&host_shared)),
        (C::Unsupported, "host", "shared".to_owned())
    );
    assert_eq!(
        detail(&none, None, Some(&host_remapped)),
        (C::Unverified, "host", "remapped".to_owned())
    );
    assert_eq!(
        detail(&none, Some(&shared), None),
        (C::Unsupported, "inside", "shared".to_owned())
    );
    // `judge` is `judge_with` and no host vantage.
    assert_eq!(
        judge(&none, Some(&shared), NO_LSM),
        judge_with(&none, Some(&shared), NO_LSM, None)
    );
    // The record's host mode, whatever both kernels show.
    let host_mode = Recorded {
        userns_mode: Some("host"),
        ..none
    };
    assert_eq!(
        judged(&host_mode, Some(&shared), Some(&host_shared)),
        C::Unsupported
    );
    assert_eq!(
        detail(&host_mode, Some(&shared), Some(&host_shared)).2,
        "host-mode"
    );
    f05_evidence("userns-two-vantages-shared-remapped-contradiction", "unit");
}

#[test]
fn a_real_namespace_reads_the_same_from_inside_and_from_the_host() {
    // The contradiction rule rests on a kernel fact: a process's maps read
    // by the process itself and read by another process outside its user
    // namespace state the same ids. Shown here on a real unprivileged user
    // namespace (`unshare --user --map-root-user`): its own view printed,
    // the host's read from `/proc/<pid>/` while it lives.
    let Some(((users, groups), host)) = harness::namespace_views(|pid| {
        let read = |name: &str| std::fs::read_to_string(format!("/proc/{pid}/{name}"));
        HostMaps::from_kernel(&read("uid_map").unwrap(), &read("gid_map").unwrap())
    }) else {
        return;
    };
    let inside = facts(&users, &groups, None, None);
    let host = host.expect("the host's view is a map");
    assert_eq!(inside.uid_map.as_ref(), Some(&host.uid));
    assert_eq!(inside.gid_map.as_ref(), Some(&host.gid));
    assert!(!is_identity_map(&host.uid));
    assert_eq!(
        of(&judge_with(&recorded(None, None), Some(&inside), NO_LSM, Some(&host)).userns),
        (C::Unverified, "both", "remapped")
    );
    f05_evidence("userns-real-kernel-two-vantages-agree", "kernel");
}

#[test]
fn a_required_module_is_met_only_where_it_is_enforced() {
    use crate::config::RequiredLsm;
    // Before serving: the host's kernel must enforce it. SELinux permissive
    // is not enforcement; a module the kernel does not run is not either.
    assert!(host_runs(RequiredLsm::AppArmor, APPARMOR));
    assert!(!host_runs(RequiredLsm::AppArmor, NO_LSM));
    assert!(!host_runs(RequiredLsm::AppArmor, SELINUX_ENFORCING));
    assert!(host_runs(RequiredLsm::SeLinux, SELINUX_ENFORCING));
    assert!(!host_runs(RequiredLsm::SeLinux, SELINUX_PERMISSIVE));
    assert!(!host_runs(RequiredLsm::SeLinux, APPARMOR));
    // Per environment: ENFORCED alone meets it; every other state refuses.
    let enforced = judge(
        &recorded(Some("docker-default"), None),
        Some(&facts(
            IDENTITY,
            IDENTITY,
            None,
            Some("docker-default (enforce)"),
        )),
        APPARMOR,
    );
    assert!(meets(RequiredLsm::AppArmor, &enforced));
    assert!(!meets(RequiredLsm::SeLinux, &enforced));
    let refused = [
        // complain
        judge(
            &recorded(Some("docker-default"), None),
            Some(&facts(
                IDENTITY,
                IDENTITY,
                None,
                Some("docker-default (complain)"),
            )),
            APPARMOR,
        ),
        // unconfined
        judge(
            &recorded(Some("unconfined"), None),
            Some(&facts(IDENTITY, IDENTITY, None, Some("unconfined"))),
            APPARMOR,
        ),
        // the record and the process disagree
        judge(
            &recorded(Some("other"), None),
            Some(&facts(
                IDENTITY,
                IDENTITY,
                None,
                Some("docker-default (enforce)"),
            )),
            APPARMOR,
        ),
        // nothing seen inside
        judge(&recorded(Some("docker-default"), None), None, APPARMOR),
        // a host without the module
        judge(
            &recorded(Some("docker-default"), None),
            Some(&facts(
                IDENTITY,
                IDENTITY,
                None,
                Some("docker-default (enforce)"),
            )),
            NO_LSM,
        ),
    ];
    for identity in &refused {
        assert!(
            !meets(RequiredLsm::AppArmor, identity),
            "{:?}",
            identity.apparmor
        );
    }
    let permissive = judge(
        &recorded(None, Some("system_u:system_r:container_t:s0")),
        Some(&facts(
            IDENTITY,
            IDENTITY,
            Some("system_u:system_r:container_t:s0"),
            None,
        )),
        SELINUX_PERMISSIVE,
    );
    assert!(!meets(RequiredLsm::SeLinux, &permissive));
    let confined = judge(
        &recorded(None, Some("system_u:system_r:container_t:s0")),
        Some(&facts(
            IDENTITY,
            IDENTITY,
            Some("system_u:system_r:container_t:s0"),
            None,
        )),
        SELINUX_ENFORCING,
    );
    assert!(meets(RequiredLsm::SeLinux, &confined));
    f05_evidence("required-lsm-met-only-when-enforced", "unit");
}

#[test]
fn a_required_module_refuses_every_environment_it_does_not_confine() {
    use crate::config::RequiredLsm;
    let enforced = judge(
        &recorded(Some("docker-default"), None),
        Some(&facts(
            IDENTITY,
            IDENTITY,
            None,
            Some("docker-default (enforce)"),
        )),
        APPARMOR,
    );
    let refused = [
        judge(
            &recorded(Some("docker-default"), None),
            Some(&facts(
                IDENTITY,
                IDENTITY,
                None,
                Some("docker-default (complain)"),
            )),
            APPARMOR,
        ),
        judge(&recorded(Some("docker-default"), None), None, APPARMOR),
        judge(
            &recorded(Some("docker-default"), None),
            Some(&facts(
                IDENTITY,
                IDENTITY,
                None,
                Some("docker-default (enforce)"),
            )),
            NO_LSM,
        ),
    ];
    // Applied to an environment: nothing required refuses nothing; a
    // required module admits what it confines and refuses the rest as
    // UNSUPPORTED.
    for identity in &refused {
        assert_eq!(admits(None, identity), Ok(()));
        assert_eq!(
            admits(Some(RequiredLsm::AppArmor), identity),
            Err(dwk_proto::brokerp::BrokerRefusal::Unsupported)
        );
    }
    assert_eq!(admits(Some(RequiredLsm::AppArmor), &enforced), Ok(()));
    assert_eq!(
        admits(Some(RequiredLsm::SeLinux), &enforced),
        Err(dwk_proto::brokerp::BrokerRefusal::Unsupported)
    );
    // The event says which, and why.
    assert_eq!(
        required_line("env_1", RequiredLsm::AppArmor, &enforced),
        "sandbox_lsm_required environment=env_1 module=apparmor outcome=met \
         state=ENFORCED:both:docker-default"
    );
    assert_eq!(
        required_line("env_1", RequiredLsm::AppArmor, &refused[2]),
        "sandbox_lsm_required environment=env_1 module=apparmor outcome=refused \
         state=UNSUPPORTED:host:kernel-has-none"
    );
    f05_evidence("required-lsm-refuses-what-it-does-not-confine", "unit");
}
