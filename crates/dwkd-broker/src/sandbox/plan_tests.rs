//! The plan's tests: every hard rule spelled, and no weakening word in any
//! plan. Kept beside `plan.rs` rather than in it, so that TX032 can scan
//! the plan itself for the very words these tests must name.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test assertions"
)]

use dwk_proto::brokerp::EnvironmentSpec;
use dwk_proto::brokerp::sandbox::{
    ContainerRef, ContainerRole, EnvironmentProfile, ImageId, NetworkTopology, StoreInstance,
};
use dwk_proto::wire::id::{EnvironmentId, RunId};
use dwk_proto::wire::scalar::{ContentDigest, HostPath};

use super::super::relay_plan;
use super::{container_name, copy_relay, create, mountable, owned, remove};

pub(crate) fn spec(workspace: &str, network: NetworkTopology) -> EnvironmentSpec {
    EnvironmentSpec {
        environment_id: EnvironmentId::parse("env_01M24BB8G3E0A851TRWE3M8FZF").unwrap(),
        run_id: RunId::parse("run_01M24BB8G3E0A851TRWE3M8FZF").unwrap(),
        store: StoreInstance::new("0123abcd".to_owned()).unwrap(),
        profile: EnvironmentProfile::OciStrict,
        network,
        image: ImageId::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
        probe_sha256: ContentDigest::new("b".repeat(64)).unwrap(),
        workspace_path: HostPath::new(workspace.to_owned()).unwrap(),
        workspace: (1, 2),
        relay_sha256: None,
        egress: None,
    }
}

fn after<'a>(argv: &'a [String], flag: &str) -> Vec<&'a str> {
    argv.windows(2)
        .filter(|w| w[0] == flag)
        .map(|w| w[1].as_str())
        .collect()
}

#[test]
fn the_strict_plan_spells_every_hard_rule_and_no_weakening() {
    let argv = create(
        &spec("/srv/ws", NetworkTopology::NoNetwork),
        "/run/dw/seccomp.json",
    )
    .unwrap();
    assert_eq!(argv[0], "create");
    assert_eq!(after(&argv, "--pull"), ["never"]);
    assert_eq!(after(&argv, "--user"), ["10001:10001"]);
    assert!(argv.iter().any(|w| w == "--read-only"));
    assert_eq!(after(&argv, "--cap-drop"), ["ALL"]);
    assert_eq!(
        after(&argv, "--security-opt"),
        ["no-new-privileges=true", "seccomp=/run/dw/seccomp.json"]
    );
    assert_eq!(after(&argv, "--network"), ["none"]);
    assert_eq!(after(&argv, "--ipc"), ["private"]);
    assert_eq!(after(&argv, "--cgroupns"), ["private"]);
    assert_eq!(after(&argv, "--pids-limit"), ["256"]);
    assert_eq!(after(&argv, "--memory"), ["2147483648"]);
    assert_eq!(after(&argv, "--memory-swap"), ["2147483648"]);
    assert_eq!(after(&argv, "--cpus"), ["2"]);
    assert_eq!(
        after(&argv, "--ulimit"),
        [
            "nofile=1024:1024",
            "nproc=256:256",
            "fsize=1073741824:1073741824",
            "core=0:0"
        ]
    );
    assert_eq!(
        after(&argv, "--mount"),
        ["type=bind,source=/srv/ws,target=/workspace,bind-propagation=rprivate"]
    );
    assert_eq!(after(&argv, "--tmpfs").len(), 2);
    assert_eq!(after(&argv, "--restart"), ["no"]);
    assert_eq!(
        after(&argv, "--entrypoint"),
        ["/usr/libexec/direwolf/sandbox-probe"]
    );
    // The image by digest, then the probe's one argument, last.
    assert_eq!(argv[argv.len() - 2], format!("sha256:{}", "a".repeat(64)));
    assert_eq!(argv[argv.len() - 1], "hold");
    // No word that weakens: no privilege, no capability, no device, no
    // host namespace, no second volume, no unconfined profile.
    for word in &argv {
        for banned in [
            "--privileged",
            "--cap-add",
            "--device",
            "--volume",
            "-v",
            "--volumes-from",
            "--pid",
            "--uts",
            "--userns",
            "--ipc=host",
            "host",
            "unconfined",
            "--security-opt=",
            "--init",
            "--group-add",
        ] {
            assert_ne!(word, banned, "{argv:?}");
        }
        assert!(!word.contains("docker.sock"), "{word}");
    }
    assert_eq!(after(&argv, "--label").len(), 7);
    assert!(after(&argv, "--label").contains(&"io.direwolf.role=environment"));
    // `NO_NETWORK`: no proxy variable at all.
    assert!(after(&argv, "--env").is_empty());
}

#[test]
fn a_proxy_only_environment_differs_only_by_the_broker_s_proxy_variables() {
    let none = create(&spec("/srv/ws", NetworkTopology::NoNetwork), "/p.json").unwrap();
    let proxy = create(&spec("/srv/ws", NetworkTopology::ProxyOnly), "/p.json").unwrap();
    // The same namespace: no interface but loopback, no network joined.
    assert_eq!(after(&proxy, "--network"), ["none"]);
    assert_eq!(
        after(&proxy, "--env"),
        [
            "HTTP_PROXY=http://169.254.7.1:8080",
            "HTTPS_PROXY=http://169.254.7.1:8080",
            "ALL_PROXY=http://169.254.7.1:8080",
            "NO_PROXY=localhost,127.0.0.1,::1",
            "http_proxy=http://169.254.7.1:8080",
            "https_proxy=http://169.254.7.1:8080",
            "all_proxy=http://169.254.7.1:8080",
            "no_proxy=localhost,127.0.0.1,::1",
        ]
    );
    let without: Vec<&String> = proxy
        .iter()
        .enumerate()
        .filter(|(i, w)| *w != "--env" && !(*i > 0 && proxy[i - 1] == "--env"))
        .map(|(_, w)| w)
        .collect();
    assert_eq!(without, none.iter().collect::<Vec<_>>());
    // Nothing in it comes from this process's own environment.
    for word in &proxy {
        assert!(!word.contains("proxy.example"), "{word}");
    }
}

#[test]
fn a_misreadable_path_has_no_plan() {
    for bad in [
        "/srv/ws,readonly=false",
        "/srv/ws\",x",
        "/srv/a=b",
        "/srv/new\nline",
    ] {
        assert!(!mountable(bad), "{bad:?}");
    }
    assert!(mountable("/home/user/My Project"));
    assert!(create(&spec("/srv/ws", NetworkTopology::NoNetwork), "/a,b.json").is_none());
}

#[test]
fn names_and_filters_are_exact() {
    let s = spec("/srv/ws", NetworkTopology::NoNetwork);
    assert_eq!(
        container_name(&s.store, &s.environment_id),
        "direwolf-0123abcd-env_01M24BB8G3E0A851TRWE3M8FZF"
    );
    let listed = owned(&s.store, Some((&s.environment_id, &s.run_id)), None);
    assert_eq!(
        after(&listed, "--filter"),
        [
            "label=io.direwolf.owner=direwolf",
            "label=io.direwolf.store=0123abcd",
            "label=io.direwolf.environment=env_01M24BB8G3E0A851TRWE3M8FZF",
            "label=io.direwolf.run=run_01M24BB8G3E0A851TRWE3M8FZF"
        ]
    );
    let relays = owned(
        &s.store,
        Some((&s.environment_id, &s.run_id)),
        Some(ContainerRole::Relay),
    );
    assert_eq!(
        after(&relays, "--filter").last(),
        Some(&"label=io.direwolf.role=relay")
    );
    assert_eq!(
        relay_plan::name(&s.store, &s.environment_id, ContainerRole::Setup),
        "direwolf-0123abcd-env_01M24BB8G3E0A851TRWE3M8FZF-setup"
    );
    let container = ContainerRef::new("c".repeat(64)).unwrap();
    assert_eq!(
        remove(&container),
        ["container", "rm", "--force", "--volumes", &"c".repeat(64)]
    );
}

fn helper_env() -> ContainerRef {
    ContainerRef::new("c".repeat(64)).unwrap()
}

#[test]
fn the_setup_alone_holds_one_capability_and_is_removed_when_it_exits() {
    let s = spec("/srv/ws", NetworkTopology::ProxyOnly);
    let argv = relay_plan::setup(&s, &helper_env(), "/p/seccomp.json").unwrap();
    assert_eq!(&argv[..4], ["run", "--rm", "--pull", "never"]);
    assert_eq!(after(&argv, "--cap-add"), ["NET_ADMIN"]);
    assert_eq!(after(&argv, "--cap-drop"), ["ALL"]);
    assert_eq!(after(&argv, "--user"), ["0:0"]);
    assert_eq!(
        after(&argv, "--network"),
        [format!("container:{}", "c".repeat(64))]
    );
    assert_eq!(
        after(&argv, "--security-opt"),
        ["no-new-privileges=true", "seccomp=/p/seccomp.json"]
    );
    assert!(argv.contains(&"--read-only".to_owned()));
    assert_eq!(
        after(&argv, "--entrypoint"),
        ["/usr/libexec/direwolf/sandbox-relay"]
    );
    assert_eq!(argv.last().unwrap(), "setup");
    assert!(after(&argv, "--label").contains(&"io.direwolf.role=setup"));
    assert!(after(&argv, "--mount").is_empty());
    assert!(after(&argv, "--env").is_empty());
    for word in &argv {
        for banned in [
            "--privileged",
            "--device",
            "--volume",
            "-v",
            "--pid",
            "--userns",
            "host",
        ] {
            assert_ne!(word, banned, "{argv:?}");
        }
    }
}

#[test]
fn the_relay_is_unprivileged_with_one_read_only_mount() {
    let s = spec("/srv/ws", NetworkTopology::ProxyOnly);
    let argv = relay_plan::relay(&s, &helper_env(), "/p/seccomp.json", "/b/egress/env_1").unwrap();
    assert_eq!(&argv[..3], ["create", "--pull", "never"]);
    assert!(after(&argv, "--cap-add").is_empty());
    assert_eq!(after(&argv, "--cap-drop"), ["ALL"]);
    assert_eq!(after(&argv, "--user"), ["10002:10002"]);
    assert_eq!(
        after(&argv, "--mount"),
        [
            "type=bind,source=/b/egress/env_1,target=/run/direwolf-egress,readonly,bind-propagation=rprivate"
        ]
    );
    assert_eq!(argv.last().unwrap(), "serve");
    assert!(after(&argv, "--label").contains(&"io.direwolf.role=relay"));
    assert!(after(&argv, "--env").is_empty());
    assert_eq!(after(&argv, "--pids-limit"), ["144"]);
    assert_eq!(after(&argv, "--cpus"), ["0.500000000"]);
    // A path that could rewrite the mount's fields is refused.
    assert!(
        relay_plan::relay(&s, &helper_env(), "/p/seccomp.json", "/b/x,readonly=false").is_none()
    );
    assert!(relay_plan::relay(&s, &helper_env(), "/p/seccomp.json", "relative").is_none());
    assert_eq!(
        copy_relay(&helper_env()),
        [
            "container",
            "cp",
            &format!("{}:/usr/libexec/direwolf/sandbox-relay", "c".repeat(64)),
            "-"
        ]
    );
}
