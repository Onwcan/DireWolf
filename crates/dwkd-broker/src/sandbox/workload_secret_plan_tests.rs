//! `workload_secret_plan.rs`'s own tests (M5d.3): they name the word that
//! attaches standard input and words TX056 bans, to assert where each may
//! stand, so they live beside the plan, outside both rules.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use dwk_proto::brokerp::sandbox::ContainerRef;
use dwk_proto::brokerp::workload::{
    ImagePath, WorkloadLaunch, WorkloadSeconds, WorkloadSecret, WorkloadSpec,
};
use dwk_proto::brokerp::{ProcessArgs, SecretDelivery, SecretEnvName, SecretHandle, StreamLimit};
use dwk_proto::wire::scalar::{ContentDigest, ProcessArg};

fn workload(launch: WorkloadLaunch, args: &[&str]) -> WorkloadSpec {
    WorkloadSpec {
        executable: ImagePath::new("/usr/bin/git").unwrap(),
        executable_sha256: ContentDigest::new("ab".repeat(32)).unwrap(),
        args: ProcessArgs::new(args.iter().map(|a| ProcessArg::new(*a).unwrap()).collect())
            .unwrap(),
        stream_limit: StreamLimit::new(4096).unwrap(),
        wall_clock: WorkloadSeconds::new(30).unwrap(),
        launch,
    }
}

fn secret(delivery: SecretDelivery, name: Option<&str>) -> WorkloadSecret {
    WorkloadSecret {
        handle: SecretHandle::new("deploy-key").unwrap(),
        delivery,
        env_name: name.map(|n| SecretEnvName::new(n).unwrap()),
    }
}

#[test]
fn only_a_secret_bearing_plan_attaches_standard_input_and_once() {
    let container = ContainerRef::new("c".repeat(64)).unwrap();
    let ordinary = super::super::workload_plan::run(
        &container,
        &workload(WorkloadLaunch::Hygiene, &["status"]),
    );
    assert!(!ordinary.iter().any(|w| w == super::ATTACH_STDIN));
    for (delivery, name, launch, profile, rest) in [
        (
            SecretDelivery::FdAtSpawn,
            None,
            WorkloadLaunch::Direct,
            "secret-fd",
            &["/usr/bin/git", "fetch"][..],
        ),
        (
            SecretDelivery::FdAtSpawn,
            None,
            WorkloadLaunch::Hygiene,
            "secret-fd-hygiene",
            &["/usr/bin/git", "fetch"],
        ),
        (
            SecretDelivery::EnvAtSpawn,
            Some("GH_TOKEN"),
            WorkloadLaunch::Direct,
            "secret-env",
            &["GH_TOKEN", "/usr/bin/git", "fetch"],
        ),
        (
            SecretDelivery::EnvAtSpawn,
            Some("GH_TOKEN"),
            WorkloadLaunch::Hygiene,
            "secret-env-hygiene",
            &["GH_TOKEN", "/usr/bin/git", "fetch"],
        ),
    ] {
        let argv = super::run(
            &container,
            &workload(launch, &["fetch"]),
            &secret(delivery, name),
        );
        let mut expected = vec![
            "container",
            "exec",
            "--interactive",
            "--user",
            "10001:10001",
            "--workdir",
            "/workspace",
            container.as_str(),
            "/usr/libexec/direwolf/sandbox-probe",
            "launch",
            profile,
        ];
        expected.extend_from_slice(rest);
        assert_eq!(argv, expected, "{profile}");
        assert_eq!(argv.iter().filter(|w| *w == super::ATTACH_STDIN).count(), 1);
    }
}

#[test]
fn every_variable_the_environment_sets_is_one_no_secret_may_carry() {
    // The environment's own lists, which the authority does not link,
    // against the shared contract it refuses with before a value is read.
    for (name, _) in dwk_sandbox_profile::HYGIENE_ENVIRONMENT
        .iter()
        .chain(dwk_sandbox_profile::PROXY_VARIABLES)
    {
        assert!(dwk_sandbox_profile::sandbox_secret_name_reserved(name));
        assert!(
            !dwk_proto::brokerp::workload::sandbox_secret_name_allowed(name),
            "{name}: the authority would hand it over"
        );
    }
    for name in dwk_proto::brokerp::workload::SANDBOX_RESERVED_SECRET_VARIABLES {
        assert!(
            dwk_sandbox_profile::sandbox_secret_name_reserved(name),
            "{name}"
        );
    }
}

#[test]
fn an_argument_that_spells_a_flag_or_a_value_stays_the_programs() {
    let container = ContainerRef::new("c".repeat(64)).unwrap();
    let argv = super::run(
        &container,
        &workload(
            WorkloadLaunch::Direct,
            &["--env", "TOKEN=x", "-it", "--privileged"],
        ),
        &secret(SecretDelivery::FdAtSpawn, None),
    );
    let at = argv.iter().position(|w| w == container.as_str()).unwrap();
    // Before the container: exactly the plan's words.
    assert_eq!(
        argv.get(..at).unwrap(),
        [
            "container",
            "exec",
            "--interactive",
            "--user",
            "10001:10001",
            "--workdir",
            "/workspace"
        ]
    );
    assert_eq!(
        argv.get(at + 4..).unwrap(),
        ["/usr/bin/git", "--env", "TOKEN=x", "-it", "--privileged"]
    );
}
