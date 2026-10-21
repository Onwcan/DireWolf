//! `workload_plan.rs`'s own tests (M5d.1): they name every word TX050
//! bans, to assert none is in a plan, so they live beside it, outside the
//! rule.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use dwk_proto::brokerp::sandbox::ContainerRef;
use dwk_proto::brokerp::workload::{ImagePath, WorkloadLaunch, WorkloadSeconds, WorkloadSpec};
use dwk_proto::brokerp::{ProcessArgs, StreamLimit};
use dwk_proto::wire::scalar::{ContentDigest, ProcessArg};

use super::{reap, run};

fn container() -> ContainerRef {
    ContainerRef::new("c".repeat(64)).unwrap()
}

fn workload(args: &[&str]) -> WorkloadSpec {
    WorkloadSpec {
        executable: ImagePath::new("/usr/libexec/direwolf/sandbox-fixture").unwrap(),
        executable_sha256: ContentDigest::new("ab".repeat(32)).unwrap(),
        args: ProcessArgs::new(args.iter().map(|a| ProcessArg::new(*a).unwrap()).collect())
            .unwrap(),
        stream_limit: StreamLimit::new(4096).unwrap(),
        wall_clock: WorkloadSeconds::new(30).unwrap(),
        launch: WorkloadLaunch::Direct,
    }
}

#[test]
fn a_workload_runs_as_the_environment_user_in_the_workspace_with_exactly_its_arguments() {
    let hostile = [
        "--user",
        "0:0",
        "--privileged",
        "-e",
        "LD_PRELOAD=/x",
        "$(id)",
        "",
    ];
    let argv = run(&container(), &workload(&hostile));
    let mut expected: Vec<String> = [
        "container",
        "exec",
        "--user",
        "10001:10001",
        "--workdir",
        "/workspace",
    ]
    .iter()
    .map(|w| (*w).to_owned())
    .collect();
    expected.push("c".repeat(64));
    // M5d.4: even a direct launch is the trusted launcher's, which sets the
    // workspace's umask and nothing else.
    expected.extend(
        ["/usr/libexec/direwolf/sandbox-probe", "launch", "direct"]
            .iter()
            .map(|w| (*w).to_owned()),
    );
    expected.push("/usr/libexec/direwolf/sandbox-fixture".to_owned());
    expected.extend(hostile.iter().map(|a| (*a).to_owned()));
    assert_eq!(argv, expected);
    // Before the container's name, only the plan's own words: the client
    // reads options there and nowhere after it.
    let name = argv.iter().position(|w| *w == "c".repeat(64)).unwrap();
    let options = argv.get(..name).unwrap();
    for banned in [
        "--privileged",
        "--env",
        "-e",
        "--env-file",
        "--interactive",
        "-i",
        "--tty",
        "-t",
        "--detach",
        "-d",
        "--cap-add",
        "--security-opt",
        "--device",
    ] {
        assert!(!options.iter().any(|w| w == banned), "{banned}");
    }
    assert_eq!(options.iter().filter(|w| *w == "--user").count(), 1);
    assert!(
        !options
            .iter()
            .any(|w| w == "0" || w.starts_with("0:") || w == "root")
    );
}

#[test]
fn a_hygiene_launch_runs_the_trusted_probe_as_the_launcher_and_adds_no_option() {
    // M5d.2 (ADR-0052 §5a): the launcher's words follow the container's
    // name, where the client reads no option; before it, exactly the direct
    // plan's words. No `--env`: the probe sets the variables itself.
    let hostile = ["--env", "A=B", "-e", "PYTHONSAFEPATH=", "$(id)"];
    let mut hygienic = workload(&hostile);
    hygienic.launch = WorkloadLaunch::Hygiene;
    let argv = run(&container(), &hygienic);
    let direct = run(&container(), &workload(&hostile));
    let name = argv.iter().position(|w| *w == "c".repeat(64)).unwrap();
    assert_eq!(argv.get(..=name), direct.get(..=name));
    assert_eq!(
        argv.get(name + 1..name + 4).unwrap(),
        ["/usr/libexec/direwolf/sandbox-probe", "launch", "hygiene"]
    );
    // The launch's profile is the only word that differs (M5d.4).
    assert_eq!(direct.get(name + 3).unwrap(), "direct");
    assert_eq!(argv.get(name + 4..), direct.get(name + 4..));
    assert!(
        !argv
            .get(..name)
            .unwrap()
            .iter()
            .any(|w| w == "--env" || w == "-e")
    );
}

#[test]
fn reap_is_the_trusted_probe_as_the_environment_user_and_nothing_else() {
    assert_eq!(
        reap(&container()),
        vec![
            "container".to_owned(),
            "exec".to_owned(),
            "--user".to_owned(),
            "10001:10001".to_owned(),
            "c".repeat(64),
            "/usr/libexec/direwolf/sandbox-probe".to_owned(),
            "reap".to_owned(),
        ]
    );
}
