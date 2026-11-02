//! The host judgement, against a record of the shape the runtime reports,
//! and one weakening at a time.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test assertions: a panic is the failure report"
)]

use dwk_proto::brokerp::EnvironmentSpec;
use dwk_proto::brokerp::sandbox::{
    ContainerRef, ContainerRole, EnvironmentProfile, ImageId, NetworkTopology, SandboxInvariant,
    StoreInstance, Verdict,
};
use dwk_proto::json::{Object, Value};
use dwk_proto::wire::id::{EnvironmentId, RunId};
use dwk_proto::wire::scalar::{ContentDigest, HostPath};

use super::{Record, parse};

const ENV: &str = "env_01M24BB8G3E0A851TRWE3M8FZF";
const RUN: &str = "run_01M24BB8G3E0A851TRWE3M8FZF";
const SOCKET: &str = "/var/run/docker.sock";
const PROFILE: &str = r#"{"defaultAction":"SCMP_ACT_ERRNO"}"#;

fn image() -> String {
    format!("sha256:{}", "a".repeat(64))
}

fn spec() -> EnvironmentSpec {
    spec_with(NetworkTopology::NoNetwork)
}

fn spec_with(network: NetworkTopology) -> EnvironmentSpec {
    EnvironmentSpec {
        environment_id: EnvironmentId::parse(ENV).unwrap(),
        run_id: RunId::parse(RUN).unwrap(),
        store: StoreInstance::new("0123abcd".to_owned()).unwrap(),
        profile: EnvironmentProfile::OciStrict,
        network,
        image: ImageId::new(image()).unwrap(),
        probe_sha256: ContentDigest::new("b".repeat(64)).unwrap(),
        workspace_path: HostPath::new("/srv/ws".to_owned()).unwrap(),
        workspace: (1, 2),
        workspace_bound: None,
        relay_sha256: None,
        egress: None,
    }
}

/// A conforming record, in the runtime's own field names.
fn conforming() -> String {
    let seccomp = serde_like_escape(PROFILE);
    let image = image();
    format!(
        r#"[{{
  "Id": "{id}",
  "Image": "{image}",
  "State": {{"Status": "running", "Running": true, "Paused": false, "Restarting": false,
             "OOMKilled": false, "Dead": false, "Pid": 4242, "ExitCode": 0}},
  "Config": {{
    "User": "10001:10001",
    "Image": "{image}",
    "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
    "Labels": {{
      "io.direwolf.owner": "direwolf",
      "io.direwolf.schema": "2",
      "io.direwolf.store": "0123abcd",
      "io.direwolf.environment": "{ENV}",
      "io.direwolf.run": "{RUN}",
      "io.direwolf.profile": "oci-strict",
      "io.direwolf.role": "environment"
    }}
  }},
  "HostConfig": {{
    "Binds": null,
    "NetworkMode": "none",
    "PortBindings": {{}},
    "RestartPolicy": {{"Name": "no", "MaximumRetryCount": 0}},
    "VolumeDriver": "",
    "VolumesFrom": null,
    "Mounts": [{{"Type": "bind", "Source": "/srv/ws", "Target": "/workspace",
                "BindOptions": {{"Propagation": "rprivate"}}}}],
    "CapAdd": null,
    "CapDrop": ["ALL"],
    "CgroupnsMode": "private",
    "ExtraHosts": null,
    "IpcMode": "private",
    "OomScoreAdj": 500,
    "PidMode": "",
    "Privileged": false,
    "PublishAllPorts": false,
    "ReadonlyRootfs": true,
    "SecurityOpt": ["no-new-privileges=true", "seccomp={seccomp}"],
    "Tmpfs": {{"/tmp": "rw,nosuid,nodev,exec,size=536870912,mode=1777",
              "/var/tmp": "rw,nosuid,nodev,noexec,size=134217728,mode=1777"}},
    "UTSMode": "",
    "UsernsMode": "",
    "Memory": 2147483648,
    "NanoCpus": 2000000000,
    "Devices": [],
    "DeviceCgroupRules": null,
    "DeviceRequests": null,
    "MemorySwap": 2147483648,
    "OomKillDisable": null,
    "PidsLimit": 256,
    "Ulimits": [
      {{"Name": "nofile", "Hard": 1024, "Soft": 1024}},
      {{"Name": "nproc", "Hard": 8192, "Soft": 8192}},
      {{"Name": "fsize", "Hard": 1073741824, "Soft": 1073741824}},
      {{"Name": "core", "Hard": 0, "Soft": 0}}
    ],
    "MaskedPaths": ["/proc/kcore", "/proc/keys"],
    "ReadonlyPaths": ["/proc/bus", "/proc/sys"]
  }},
  "Mounts": [{{"Type": "bind", "Source": "/srv/ws", "Destination": "/workspace", "Mode": "",
              "RW": true, "Propagation": "rprivate"}}],
  "NetworkSettings": {{"Networks": {{"none": {{"NetworkID": "x"}}}}}}
}}]"#,
        id = "c".repeat(64),
    )
}

/// Enough JSON escaping for the profile text.
fn serde_like_escape(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

fn record(text: &str) -> Object {
    let mut all = parse(text.as_bytes()).unwrap();
    assert_eq!(all.len(), 1);
    all.remove(0)
}

fn verdicts(object: &Object) -> Vec<(SandboxInvariant, Verdict)> {
    Record::new(object).judge(&spec(), PROFILE, SOCKET)
}

fn failing(object: &Object) -> Vec<SandboxInvariant> {
    verdicts(object)
        .into_iter()
        .filter(|(_, v)| *v != Verdict::Pass)
        .map(|(i, _)| i)
        .collect()
}

fn strings(items: &[&str]) -> Value {
    Value::Array(
        items
            .iter()
            .map(|s| Value::String((*s).to_owned()))
            .collect(),
    )
}

fn mutated(path: &[&str], value: Value) -> Object {
    let text = conforming();
    let parsed =
        dwk_proto::json::parse(text.as_bytes(), dwk_proto::json::ParseOptions::ijson()).unwrap();
    let Value::Array(mut items) = parsed else {
        panic!("not an array")
    };
    let Value::Object(object) = items.remove(0) else {
        panic!("not an object")
    };
    replace(object, path, value)
}

/// `object` with the member at `path` replaced by `value`.
fn replace(mut object: Object, path: &[&str], value: Value) -> Object {
    let (first, rest) = path.split_first().unwrap();
    if rest.is_empty() {
        object.remove(first);
        object.insert((*first).to_owned(), value).unwrap();
        return object;
    }
    let Some(Value::Object(inner)) = object.remove(first) else {
        panic!("no object at {first}")
    };
    object
        .insert(
            (*first).to_owned(),
            Value::Object(replace(inner, rest, value)),
        )
        .unwrap();
    object
}

#[test]
fn a_conforming_record_passes_every_host_invariant_it_speaks_to() {
    let object = record(&conforming());
    assert_eq!(failing(&object), Vec::<SandboxInvariant>::new());
    assert_eq!(verdicts(&object).len(), 20);
    let record = Record::new(&object);
    assert!(record.is(&spec().store, (&spec().environment_id, &spec().run_id)));
    let owned = record.owned(&spec().store).unwrap();
    assert!(owned.labels_exact);
    assert_eq!(owned.role, Some(ContainerRole::Environment));
    assert_eq!(owned.environment_id.unwrap().as_str(), ENV);
}

/// One weakening, and the invariant that must catch it.
fn caught(path: &[&str], value: Value, invariant: SandboxInvariant) {
    let object = mutated(path, value);
    let found = failing(&object);
    assert!(
        found.contains(&invariant),
        "{path:?} was not caught by {invariant:?}: {found:?}"
    );
}

#[test]
fn every_single_weakening_is_caught_from_the_host() {
    use SandboxInvariant as I;
    caught(
        &["HostConfig", "ReadonlyRootfs"],
        Value::Bool(false),
        I::HostRootReadOnly,
    );
    caught(
        &["Config", "User"],
        Value::String("0:0".to_owned()),
        I::HostUserNonRoot,
    );
    caught(
        &["Config", "User"],
        Value::String(String::new()),
        I::HostUserNonRoot,
    );
    caught(
        &["HostConfig", "Privileged"],
        Value::Bool(true),
        I::HostNotPrivileged,
    );
    caught(
        &["HostConfig", "CapAdd"],
        strings(&["CAP_NET_RAW"]),
        I::HostCapabilitiesDropped,
    );
    caught(
        &["HostConfig", "CapDrop"],
        strings(&["NET_RAW"]),
        I::HostCapabilitiesDropped,
    );
    caught(
        &["HostConfig", "SecurityOpt"],
        strings(&[&format!("seccomp={PROFILE}")]),
        I::HostNoNewPrivileges,
    );
    caught(
        &["HostConfig", "SecurityOpt"],
        strings(&["no-new-privileges=false", &format!("seccomp={PROFILE}")]),
        I::HostNoNewPrivileges,
    );
    caught(
        &["HostConfig", "SecurityOpt"],
        strings(&["no-new-privileges=true", "seccomp=unconfined"]),
        I::HostSeccompProfile,
    );
    caught(
        &["HostConfig", "SecurityOpt"],
        strings(&["no-new-privileges=true"]),
        I::HostSeccompProfile,
    );
    caught(
        &["HostConfig", "SecurityOpt"],
        strings(&[
            "no-new-privileges=true",
            &format!("seccomp={PROFILE}"),
            "apparmor=unconfined",
        ]),
        I::HostNotPrivileged,
    );
    caught(
        &["HostConfig", "MaskedPaths"],
        strings(&[]),
        I::HostNotPrivileged,
    );
    caught(
        &["HostConfig", "PidMode"],
        Value::String("host".to_owned()),
        I::HostPidNamespacePrivate,
    );
    caught(
        &["HostConfig", "IpcMode"],
        Value::String("host".to_owned()),
        I::HostIpcNamespacePrivate,
    );
    caught(
        &["HostConfig", "UTSMode"],
        Value::String("host".to_owned()),
        I::HostUtsNamespacePrivate,
    );
    caught(
        &["HostConfig", "UsernsMode"],
        Value::String("host".to_owned()),
        I::HostUsernsNotHost,
    );
    caught(
        &["HostConfig", "CgroupnsMode"],
        Value::String("host".to_owned()),
        I::HostCgroupNamespacePrivate,
    );
    caught(
        &["HostConfig", "NetworkMode"],
        Value::String("host".to_owned()),
        I::HostNetworkIsolated,
    );
    caught(
        &["HostConfig", "NetworkMode"],
        Value::String("bridge".to_owned()),
        I::HostNetworkIsolated,
    );
    caught(
        &["Config", "Image"],
        Value::String("alpine:3".to_owned()),
        I::HostImagePinned,
    );
    caught(
        &["Image"],
        Value::String(format!("sha256:{}", "d".repeat(64))),
        I::HostImagePinned,
    );
    caught(
        &["HostConfig", "Binds"],
        strings(&["/var/run/docker.sock:/var/run/docker.sock"]),
        I::HostNoRuntimeSocket,
    );
    caught(
        &["HostConfig", "Binds"],
        strings(&["/var/run/docker.sock:/var/run/docker.sock"]),
        I::HostMountsExact,
    );
    caught(
        &["HostConfig", "Devices"],
        dwk_proto::json::parse(
            br#"[{"PathOnHost":"/dev/kmsg","PathInContainer":"/dev/kmsg","CgroupPermissions":"rwm"}]"#,
            dwk_proto::json::ParseOptions::ijson(),
        )
        .unwrap(),
        I::HostNoDevices,
    );
    caught(
        &["HostConfig", "DeviceCgroupRules"],
        strings(&["c 1:11 rwm"]),
        I::HostNoDevices,
    );
    caught(
        &["HostConfig", "PidsLimit"],
        Value::Number(dwk_proto::json::Number::Int(4096)),
        I::HostResourceLimits,
    );
    caught(
        &["HostConfig", "MemorySwap"],
        Value::Number(dwk_proto::json::Number::Int(-1)),
        I::HostResourceLimits,
    );
    caught(
        &["HostConfig", "Ulimits"],
        Value::Null,
        I::HostResourceLimits,
    );
    caught(
        &["State", "Status"],
        Value::String("exited".to_owned()),
        I::HostRunning,
    );
    caught(
        &["HostConfig", "Tmpfs"],
        dwk_proto::json::parse(
            br#"{"/tmp":"rw,exec,size=536870912,mode=1777","/var/tmp":"rw,nosuid,nodev,noexec,size=134217728,mode=1777"}"#,
            dwk_proto::json::ParseOptions::ijson(),
        )
        .unwrap(),
        I::HostMountsExact,
    );
}

#[test]
fn a_runtime_socket_is_found_by_path_by_parent_and_by_name() {
    use super::exposes;
    assert!(exposes("/var/run/docker.sock", SOCKET));
    assert!(exposes("/var/run", SOCKET));
    assert!(exposes("/var/run/", SOCKET));
    assert!(exposes("/", SOCKET));
    assert!(exposes("/run", "/run/user/1000/docker.sock"));
    assert!(exposes("/home/me/.docker/run/docker.sock", SOCKET));
    assert!(exposes("/srv/podman.sock", SOCKET));
    assert!(exposes("/run", SOCKET), "the well-known /run/docker.sock");
    assert!(!exposes("/srv/ws", SOCKET));
    assert!(!exposes("/var/runner", SOCKET));
}

#[test]
fn a_missing_field_is_unobservable_never_a_pass() {
    let object = mutated(&["HostConfig", "ReadonlyRootfs"], Value::Null);
    let found: Vec<_> = verdicts(&object)
        .into_iter()
        .filter(|(i, _)| *i == SandboxInvariant::HostRootReadOnly)
        .collect();
    assert_eq!(
        found,
        [(SandboxInvariant::HostRootReadOnly, Verdict::Unobservable)]
    );
}

#[test]
fn foreign_and_malformed_labels_are_not_ours() {
    let object = mutated(
        &["Config", "Labels", "io.direwolf.store"],
        Value::String("ffff".to_owned()),
    );
    let record = Record::new(&object);
    assert!(!record.is(&spec().store, (&spec().environment_id, &spec().run_id)));
    let object = mutated(
        &["Config", "Labels", "io.direwolf.run"],
        Value::String("not-a-run".to_owned()),
    );
    let owned = Record::new(&object).owned(&spec().store).unwrap();
    assert!(!owned.labels_exact);
    assert!(owned.run_id.is_none());
    let object = mutated(
        &["Config", "Labels", "io.direwolf.extra"],
        Value::String("x".to_owned()),
    );
    assert!(
        !Record::new(&object)
            .owned(&spec().store)
            .unwrap()
            .labels_exact
    );
    assert!(failing(&object).contains(&SandboxInvariant::HostLabelsExact));
}

#[test]
fn only_a_strict_array_of_objects_is_a_record() {
    for bad in [
        &b"{}"[..],
        b"[1]",
        b"[{\"a\":1,\"a\":2}]",
        b"[{}] trailing",
        b"\xff",
    ] {
        assert!(parse(bad).is_err(), "{bad:?}");
    }
    assert_eq!(parse(b"[]").unwrap().len(), 0);
}

#[test]
fn replace_changes_exactly_one_member() {
    let object = mutated(
        &["HostConfig", "PidsLimit"],
        Value::Number(dwk_proto::json::Number::Int(1)),
    );
    let base = record(&conforming());
    let differing: Vec<_> = verdicts(&object)
        .into_iter()
        .zip(verdicts(&base))
        .filter(|(a, b)| a != b)
        .map(|(a, _)| a.0)
        .collect();
    assert_eq!(differing, [SandboxInvariant::HostResourceLimits]);
}

/// ADR-0056 §6, "the measurement still bites": the task backstop is measured
/// exactly from the runtime's record, the old per-environment value and an
/// unlimited one included, and a record without its pids limit is never
/// used -- since the backstop no longer bounds one environment, that limit is
/// the bound, and its absence must refuse.
#[test]
fn the_task_backstop_is_measured_exactly_and_the_pids_limit_is_required() {
    let ulimits = |nproc: &str| {
        dwk_proto::json::parse(
            format!(
                r#"[{{"Name": "nofile", "Hard": 1024, "Soft": 1024}}, {nproc}
                   {{"Name": "fsize", "Hard": 1073741824, "Soft": 1073741824}},
                   {{"Name": "core", "Hard": 0, "Soft": 0}}]"#
            )
            .as_bytes(),
            dwk_proto::json::ParseOptions::ijson(),
        )
        .unwrap()
    };
    let base = record(&conforming());
    let only_limits = |object: &Object| {
        let moved: Vec<_> = verdicts(object)
            .into_iter()
            .zip(verdicts(&base))
            .filter(|(after, before)| after != before)
            .map(|(after, _)| after)
            .collect();
        assert_eq!(moved.len(), 1, "{moved:?}");
        assert_eq!(moved[0].0, SandboxInvariant::HostResourceLimits);
        assert_ne!(moved[0].1, Verdict::Pass);
    };
    // The value the profile applies passes; it is what the record says.
    let kept = mutated(
        &["HostConfig", "Ulimits"],
        ulimits(r#"{"Name": "nproc", "Hard": 8192, "Soft": 8192},"#),
    );
    assert_eq!(failing(&kept), Vec::<SandboxInvariant>::new());
    for (what, nproc) in [
        (
            "the old per-environment value",
            r#"{"Name": "nproc", "Hard": 256, "Soft": 256},"#,
        ),
        ("unlimited", r#"{"Name": "nproc", "Hard": -1, "Soft": -1},"#),
        (
            "a raisable soft limit",
            r#"{"Name": "nproc", "Hard": -1, "Soft": 8192},"#,
        ),
        (
            "one above the backstop",
            r#"{"Name": "nproc", "Hard": 8193, "Soft": 8193},"#,
        ),
        ("no nproc at all", ""),
    ] {
        let weakened = mutated(&["HostConfig", "Ulimits"], ulimits(nproc));
        assert!(
            failing(&weakened).contains(&SandboxInvariant::HostResourceLimits),
            "{what} was not refused"
        );
        only_limits(&weakened);
    }
    // No pids limit, however the record says it: the environment is refused.
    for (what, value) in [
        ("null", Value::Null),
        (
            "0, unlimited",
            Value::Number(dwk_proto::json::Number::Int(0)),
        ),
        (
            "-1, unlimited",
            Value::Number(dwk_proto::json::Number::Int(-1)),
        ),
        (
            "the backstop instead",
            Value::Number(dwk_proto::json::Number::Int(8192)),
        ),
    ] {
        let weakened = mutated(&["HostConfig", "PidsLimit"], value);
        assert!(
            failing(&weakened).contains(&SandboxInvariant::HostResourceLimits),
            "a pids limit of {what} was not refused"
        );
        only_limits(&weakened);
    }
    let Some(Value::Object(mut host)) = base.clone().remove("HostConfig") else {
        panic!("no HostConfig")
    };
    host.remove("PidsLimit");
    let mut absent = base.clone();
    absent.remove("HostConfig");
    absent
        .insert("HostConfig".to_owned(), Value::Object(host))
        .unwrap();
    assert!(failing(&absent).contains(&SandboxInvariant::HostResourceLimits));
    only_limits(&absent);
}

fn env_list(items: &[&str]) -> Value {
    strings(items)
}

fn proxy_verdict(object: &Object, network: NetworkTopology) -> Verdict {
    Record::new(object)
        .judge(&spec_with(network), PROFILE, SOCKET)
        .into_iter()
        .find(|(i, _)| *i == SandboxInvariant::HostProxyEnvironment)
        .map(|(_, v)| v)
        .unwrap()
}

const BROKER_VARIABLES: [&str; 8] = [
    "HTTP_PROXY=http://169.254.7.1:8080",
    "HTTPS_PROXY=http://169.254.7.1:8080",
    "ALL_PROXY=http://169.254.7.1:8080",
    "NO_PROXY=localhost,127.0.0.1,::1",
    "http_proxy=http://169.254.7.1:8080",
    "https_proxy=http://169.254.7.1:8080",
    "all_proxy=http://169.254.7.1:8080",
    "no_proxy=localhost,127.0.0.1,::1",
];

#[test]
fn proxy_variables_are_exactly_the_broker_s_or_none() {
    let none = record(&conforming());
    assert_eq!(
        proxy_verdict(&none, NetworkTopology::NoNetwork),
        Verdict::Pass
    );
    assert_eq!(
        proxy_verdict(&none, NetworkTopology::ProxyOnly),
        Verdict::Fail
    );
    let mut with: Vec<&str> = vec!["PATH=/usr/bin"];
    with.extend(BROKER_VARIABLES);
    let exact = mutated(&["Config", "Env"], env_list(&with));
    assert_eq!(
        proxy_verdict(&exact, NetworkTopology::ProxyOnly),
        Verdict::Pass
    );
    assert_eq!(
        proxy_verdict(&exact, NetworkTopology::NoNetwork),
        Verdict::Fail
    );
    // One inherited or redirected value, one extra name in any spelling, one
    // repeated: each fails.
    for extra in [
        "HTTPS_PROXY=http://proxy.corp.example:3128",
        "FTP_PROXY=http://169.254.7.1:8080",
        "Https_Proxy=http://169.254.7.1:8080",
        "no_proxy=*",
        "HTTP_PROXY=http://169.254.7.1:8080",
    ] {
        let mut weakened = with.clone();
        weakened.push(extra);
        let object = mutated(&["Config", "Env"], env_list(&weakened));
        assert_eq!(
            proxy_verdict(&object, NetworkTopology::ProxyOnly),
            Verdict::Fail,
            "{extra}"
        );
    }
    let mut missing = with.clone();
    missing.retain(|e| !e.starts_with("no_proxy="));
    let object = mutated(&["Config", "Env"], env_list(&missing));
    assert_eq!(
        proxy_verdict(&object, NetworkTopology::ProxyOnly),
        Verdict::Fail
    );
    let object = mutated(&["Config", "Env"], Value::Bool(true));
    assert_eq!(
        proxy_verdict(&object, NetworkTopology::ProxyOnly),
        Verdict::Unobservable
    );
}

// ---- M5e.2: every hard rule refused in PROXY_ONLY too (R2, R3) -------------

/// One line of M5e.2's in-process assurance evidence for `make
/// sandbox-foundation-evidence`: the production host judgement and the
/// production decision (`oci::clean`) in this process, never a container --
/// `in-process`, so it is never offered as an environment's measurement.
fn assurance_evidence(case: &str, outcome: &str, enforcement: &str) {
    use dwk_proto::json::to_canonical_string;
    let mut fields = Object::new();
    for (key, value) in [
        ("suite", "broker-assurance"),
        ("case", case),
        ("outcome", outcome),
        ("level", "in-process"),
        ("enforcement", enforcement),
    ] {
        fields
            .insert(key.to_owned(), Value::String(value.to_owned()))
            .unwrap();
    }
    println!(
        "ASSURANCE-EVIDENCE {}",
        to_canonical_string(&Value::Object(fields))
    );
}

/// A conforming record for `network`: `PROXY_ONLY`'s carries exactly the
/// broker's proxy variables, as the broker launches it.
fn conforming_for(network: NetworkTopology) -> Object {
    let object = record(&conforming());
    if network != NetworkTopology::ProxyOnly {
        return object;
    }
    let mut with: Vec<&str> = vec!["PATH=/usr/bin"];
    with.extend(BROKER_VARIABLES);
    replace(object, &["Config", "Env"], env_list(&with))
}

/// Every invariant `spec` requires, the host's as `object` is judged and
/// every other one passing: what the broker's decision sees when the record
/// is the only thing wrong.
fn all_checks(object: &Object, spec: &EnvironmentSpec) -> super::super::Checks {
    all_checks_against(object, spec, (PROFILE, SOCKET))
}

/// [`all_checks`], judged against `(seccomp profile, runtime socket)`.
fn all_checks_against(
    object: &Object,
    spec: &EnvironmentSpec,
    (profile, socket): (&str, &str),
) -> super::super::Checks {
    let judged = Record::new(object).judge(spec, profile, socket);
    dwk_proto::brokerp::sandbox::required_invariants(
        spec.network,
        super::super::oci::contract(spec),
    )
    .into_iter()
    .map(|invariant| {
        let verdict = judged
            .iter()
            .find(|(i, _)| *i == invariant)
            .map_or(Verdict::Pass, |(_, v)| *v);
        (invariant, verdict)
    })
    .collect()
}

/// The host invariants whose verdict `weakened` changes from `base`, judged
/// against `(seccomp profile, runtime socket)`.
fn changed_against(
    base: &Object,
    weakened: &Object,
    spec: &EnvironmentSpec,
    (profile, socket): (&str, &str),
) -> Vec<SandboxInvariant> {
    Record::new(weakened)
        .judge(spec, profile, socket)
        .into_iter()
        .zip(Record::new(base).judge(spec, profile, socket))
        .filter(|(after, before)| after != before)
        .map(|(after, _)| after.0)
        .collect()
}

/// One case: its name, the topology it is judged under, the record's field
/// and the nonconforming value put there, and the invariants that must fail.
type Nonconforming<'a> = (
    &'a str,
    NetworkTopology,
    &'a [&'a str],
    Value,
    &'a [SandboxInvariant],
);

#[test]
fn every_hard_rule_is_refused_in_proxy_only_and_host_uts_in_both_topologies() {
    // The conforming record, judged by the production decision: kept.
    for (case, network) in [
        ("no-network-conforming-kept", NetworkTopology::NoNetwork),
        ("proxy-only-conforming-kept", NetworkTopology::ProxyOnly),
    ] {
        let spec = spec_with(network);
        let base = conforming_for(network);
        let checks = all_checks(&base, &spec);
        assert!(
            super::super::oci::clean(&checks, &spec),
            "{case}: {:?}",
            checks
                .iter()
                .filter(|(_, v)| *v != Verdict::Pass)
                .collect::<Vec<_>>()
        );
        assurance_evidence(case, "every-required-invariant-pass-kept", "measured-host");
    }
    // One nonconforming observation at a time, against the topology it is
    // judged under: exactly the invariants it states fail, and the
    // production decision refuses the environment.
    for (case, network, path, value, expected) in hard_rule_weakenings(PROFILE) {
        let spec = spec_with(network);
        let base = conforming_for(network);
        refused(
            case,
            &base,
            &[(path, value)],
            expected,
            &spec,
            (PROFILE, SOCKET),
        );
    }
    // U4: the limits lifted as the real NO_NETWORK case lifts them.
    let spec = spec_with(NetworkTopology::ProxyOnly);
    refused(
        LIMITS_LIFTED,
        &conforming_for(NetworkTopology::ProxyOnly),
        &limits_lifted(),
        &[SandboxInvariant::HostResourceLimits],
        &spec,
        (PROFILE, SOCKET),
    );
}

/// One nonconforming observation: the record's field and the value put there.
type Edit<'a> = (&'a [&'a str], Value);

/// `base` with every one of `edits` made, judged under `spec` against
/// `against`: exactly `expected` fail, the production decision refuses the
/// environment, and the case's line says so.
fn refused(
    case: &str,
    base: &Object,
    edits: &[Edit<'_>],
    expected: &[SandboxInvariant],
    spec: &EnvironmentSpec,
    against: (&str, &str),
) {
    let weakened = edits.iter().fold(base.clone(), |object, (path, value)| {
        replace(object, path, value.clone())
    });
    let mut flipped = changed_against(base, &weakened, spec, against);
    flipped.sort_by_key(|i| i.as_str());
    let mut wanted = expected.to_vec();
    wanted.sort_by_key(|i| i.as_str());
    assert_eq!(flipped, wanted, "{case}: other invariants moved");
    let checks = all_checks_against(&weakened, spec, against);
    for invariant in expected {
        assert!(
            checks.contains(&(*invariant, Verdict::Fail)),
            "{case}: {invariant:?} did not fail"
        );
    }
    assert!(
        !super::super::oci::clean(&checks, spec),
        "{case}: a nonconforming record was kept"
    );
    assurance_evidence(
        case,
        &format!(
            "refused:{}",
            expected
                .iter()
                .map(|i| i.as_str())
                .collect::<Vec<_>>()
                .join("+")
        ),
        "measured-host",
    );
}

/// Every hard rule broken one at a time (M5e.2, R2 and R3): its case, the
/// topology it is judged under, the record's field, the nonconforming value
/// and the invariants that must fail. `seccomp` is the profile the record
/// carries, kept as it is where a case changes the security options.
fn hard_rule_weakenings(seccomp: &str) -> Vec<Nonconforming<'static>> {
    use SandboxInvariant as I;
    let device = dwk_proto::json::parse(
        br#"[{"PathOnHost":"/dev/kmsg","PathInContainer":"/dev/kmsg","CgroupPermissions":"rwm"}]"#,
        dwk_proto::json::ParseOptions::ijson(),
    )
    .unwrap();
    vec![
        (
            "no-network-weakened-host-uts-refused",
            NetworkTopology::NoNetwork,
            &["HostConfig", "UTSMode"],
            Value::String("host".to_owned()),
            &[I::HostUtsNamespacePrivate],
        ),
        (
            "proxy-only-weakened-host-uts-refused",
            NetworkTopology::ProxyOnly,
            &["HostConfig", "UTSMode"],
            Value::String("host".to_owned()),
            &[I::HostUtsNamespacePrivate],
        ),
        (
            "proxy-only-weakened-writable-root-refused",
            NetworkTopology::ProxyOnly,
            &["HostConfig", "ReadonlyRootfs"],
            Value::Bool(false),
            &[I::HostRootReadOnly],
        ),
        (
            "proxy-only-weakened-root-user-refused",
            NetworkTopology::ProxyOnly,
            &["Config", "User"],
            Value::String("0:0".to_owned()),
            &[I::HostUserNonRoot],
        ),
        (
            "proxy-only-weakened-privileged-refused",
            NetworkTopology::ProxyOnly,
            &["HostConfig", "Privileged"],
            Value::Bool(true),
            &[I::HostNotPrivileged],
        ),
        (
            "proxy-only-weakened-capability-added-refused",
            NetworkTopology::ProxyOnly,
            &["HostConfig", "CapAdd"],
            strings(&["CAP_NET_RAW"]),
            &[I::HostCapabilitiesDropped],
        ),
        (
            "proxy-only-weakened-no-new-privileges-disabled-refused",
            NetworkTopology::ProxyOnly,
            &["HostConfig", "SecurityOpt"],
            strings(&["no-new-privileges=false", &format!("seccomp={seccomp}")]),
            &[I::HostNoNewPrivileges],
        ),
        (
            "proxy-only-weakened-seccomp-unconfined-refused",
            NetworkTopology::ProxyOnly,
            &["HostConfig", "SecurityOpt"],
            strings(&["no-new-privileges=true", "seccomp=unconfined"]),
            &[I::HostSeccompProfile],
        ),
        (
            // ADR-0057 §3, U4: a filter is on -- the runtime's default, which
            // it applies when no profile is named, as the real NO_NETWORK
            // case leaves it -- but it is not DireWolf's.
            "proxy-only-weakened-seccomp-default-profile-refused",
            NetworkTopology::ProxyOnly,
            &["HostConfig", "SecurityOpt"],
            strings(&["no-new-privileges=true"]),
            &[I::HostSeccompProfile],
        ),
        (
            "proxy-only-weakened-host-pid-refused",
            NetworkTopology::ProxyOnly,
            &["HostConfig", "PidMode"],
            Value::String("host".to_owned()),
            &[I::HostPidNamespacePrivate],
        ),
        (
            "proxy-only-weakened-host-ipc-refused",
            NetworkTopology::ProxyOnly,
            &["HostConfig", "IpcMode"],
            Value::String("host".to_owned()),
            &[I::HostIpcNamespacePrivate],
        ),
        (
            "proxy-only-weakened-host-network-refused",
            NetworkTopology::ProxyOnly,
            &["HostConfig", "NetworkMode"],
            Value::String("host".to_owned()),
            &[I::HostNetworkIsolated],
        ),
        (
            "proxy-only-weakened-mutable-image-tag-refused",
            NetworkTopology::ProxyOnly,
            &["Config", "Image"],
            Value::String("alpine:3".to_owned()),
            &[I::HostImagePinned],
        ),
        (
            "proxy-only-weakened-runtime-socket-mounted-refused",
            NetworkTopology::ProxyOnly,
            &["HostConfig", "Binds"],
            strings(&["/var/run/docker.sock:/var/run/docker.sock"]),
            &[I::HostMountsExact, I::HostNoRuntimeSocket],
        ),
        (
            "proxy-only-weakened-extra-device-refused",
            NetworkTopology::ProxyOnly,
            &["HostConfig", "Devices"],
            device,
            &[I::HostNoDevices],
        ),
        (
            "proxy-only-weakened-resource-limits-dropped-refused",
            NetworkTopology::ProxyOnly,
            &["HostConfig", "PidsLimit"],
            Value::Number(dwk_proto::json::Number::Int(4096)),
            &[I::HostResourceLimits],
        ),
        (
            // U4: the swap limit lifted alone, the pids limit kept.
            "proxy-only-weakened-swap-limit-lifted-refused",
            NetworkTopology::ProxyOnly,
            &["HostConfig", "MemorySwap"],
            Value::Number(dwk_proto::json::Number::Int(-1)),
            &[I::HostResourceLimits],
        ),
    ]
}

/// ADR-0057 §3, U4: the limits lifted as the real `NO_NETWORK` case asks
/// the runtime to lift them (`--pids-limit -1`, `--memory-swap -1`), both at
/// once, judged under `PROXY_ONLY`.
const LIMITS_LIFTED: &str = "proxy-only-weakened-pids-and-swap-limits-lifted-refused";

fn limits_lifted() -> [Edit<'static>; 2] {
    let unlimited = || Value::Number(dwk_proto::json::Number::Int(-1));
    [
        (&["HostConfig", "PidsLimit"], unlimited()),
        (&["HostConfig", "MemorySwap"], unlimited()),
    ]
}

/// U4's controls for the seccomp profile under `PROXY_ONLY`: the pinned
/// profile, named once, is kept; the runtime's default (no profile named),
/// another profile, or a second one beside the pinned one is refused by the
/// production decision -- each by the profile invariant alone.
#[test]
fn only_the_pinned_seccomp_profile_is_kept_in_proxy_only() {
    let spec = spec_with(NetworkTopology::ProxyOnly);
    let base = conforming_for(NetworkTopology::ProxyOnly);
    assert!(super::super::oci::clean(&all_checks(&base, &spec), &spec));
    let pinned = format!("seccomp={PROFILE}");
    let pinned = pinned.as_str();
    for options in [
        &["no-new-privileges=true"][..],
        &["no-new-privileges=true", "seccomp=unconfined"],
        &[
            "no-new-privileges=true",
            r#"seccomp={"defaultAction":"SCMP_ACT_ALLOW"}"#,
        ],
        &["no-new-privileges=true", pinned, "seccomp=unconfined"],
        &["no-new-privileges=true", pinned, pinned],
    ] {
        let weakened = replace(
            base.clone(),
            &["HostConfig", "SecurityOpt"],
            strings(options),
        );
        assert_eq!(
            changed_against(&base, &weakened, &spec, (PROFILE, SOCKET)),
            [SandboxInvariant::HostSeccompProfile],
            "{options:?}"
        );
        assert!(
            !super::super::oci::clean(&all_checks(&weakened, &spec), &spec),
            "{options:?} was kept"
        );
    }
}

/// U4's controls for the resource limits under `PROXY_ONLY`: ADR-0056's
/// accepted values are the profile's, and every field the resource-limit
/// invariant reads, mismatched or missing, is refused by the production
/// decision -- a missing one unobservable, never a pass -- with nothing else
/// moving.
#[test]
fn every_resource_limit_is_required_in_proxy_only_missing_or_mismatched() {
    use dwk_sandbox_profile::{
        MAX_LIVE_ENVIRONMENTS, MEMORY_BYTES, MEMORY_SWAP_BYTES, PIDS_LIMIT, RLIMIT_NPROC,
    };
    // ADR-0056, accepted: the per-environment bound, the live-environment
    // cap the backstop is derived from, and the backstop.
    assert_eq!(
        (PIDS_LIMIT, MAX_LIVE_ENVIRONMENTS, RLIMIT_NPROC),
        (256, 16, 8192)
    );
    let spec = spec_with(NetworkTopology::ProxyOnly);
    let base = conforming_for(NetworkTopology::ProxyOnly);
    assert!(super::super::oci::clean(&all_checks(&base, &spec), &spec));
    let int = |i: i64| Value::Number(dwk_proto::json::Number::Int(i));
    let wide = |u: u64| int(i64::try_from(u).unwrap());
    let refused_by_limits = |what: &str, weakened: &Object, want: Verdict| {
        assert_eq!(
            changed_against(&base, weakened, &spec, (PROFILE, SOCKET)),
            [SandboxInvariant::HostResourceLimits],
            "{what}: other invariants moved"
        );
        let checks = all_checks(weakened, &spec);
        assert!(
            checks.contains(&(SandboxInvariant::HostResourceLimits, want)),
            "{what}: not {want:?}"
        );
        assert!(
            !super::super::oci::clean(&checks, &spec),
            "{what}: a nonconforming record was kept"
        );
    };
    // Mismatched: each fails.
    for (field, value) in [
        ("PidsLimit", wide(PIDS_LIMIT + 1)),
        ("PidsLimit", int(-1)),
        ("Memory", wide(MEMORY_BYTES * 2)),
        ("MemorySwap", int(-1)),
        ("MemorySwap", wide(MEMORY_SWAP_BYTES * 2)),
        ("NanoCpus", int(4_000_000_000)),
        ("OomScoreAdj", int(-1000)),
        ("OomKillDisable", Value::Bool(true)),
        ("Ulimits", Value::Null),
    ] {
        let weakened = replace(base.clone(), &["HostConfig", field], value);
        refused_by_limits(&format!("{field} mismatched"), &weakened, Verdict::Fail);
    }
    // Missing, or of another type: unobservable, never a pass. An absent
    // `OomKillDisable` is the runtime's spelling of "not disabled", so it is
    // not among these.
    for field in [
        "PidsLimit",
        "Memory",
        "MemorySwap",
        "NanoCpus",
        "OomScoreAdj",
        "Ulimits",
    ] {
        let Some(Value::Object(mut host)) = base.clone().remove("HostConfig") else {
            panic!("no HostConfig")
        };
        assert!(host.remove(field).is_some(), "{field} is in the record");
        let missing = replace(base.clone(), &["HostConfig"], Value::Object(host));
        refused_by_limits(&format!("{field} missing"), &missing, Verdict::Unobservable);
        let typed = replace(
            base.clone(),
            &["HostConfig", field],
            Value::String("256".to_owned()),
        );
        refused_by_limits(&format!("{field} a string"), &typed, Verdict::Unobservable);
    }
}

/// Where `make sandbox-egress-evidence` leaves the runtime's own record of
/// a real `PROXY_ONLY` environment that measured clean, and the facts of
/// its specification the host judgement reads: one fixed directory beneath
/// the repository's `target/`, which the task empties before and after. No
/// variable names it -- the broker's source reads no environment (TX042).
const CAPTURED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/m5e-captured-proxy-only"
);

/// R3 against a real runtime's own record (M5e.2): the record the runtime
/// keeps of a real `PROXY_ONLY` environment the broker prepared and
/// measured clean -- captured by the egress evidence, never written here --
/// kept by the production host judgement and decision; then each hard rule
/// broken in that record, one at a time, in this process, and refused.
///
/// What this is not: a weakened container. The runtime never ran any of the
/// weakened records, so every line is `in-process` -- the judgement over the
/// runtime's real field names, defaults and ordering, which the hand-written
/// record of [`every_hard_rule_is_refused_in_proxy_only_and_host_uts_in_both_topologies`]
/// can only imitate. A real weakened `PROXY_ONLY` container is not built
/// (`docs/M5E_ASSURANCE_PLAN.md`, R3).
#[test]
#[ignore = "needs a captured PROXY_ONLY record: make sandbox-egress-evidence"]
fn a_real_proxy_only_record_is_kept_and_each_hard_rule_broken_in_it_refused() {
    let dir = std::path::Path::new(CAPTURED);
    let Ok(text) = std::fs::read_to_string(dir.join("proxy-only-spec.txt")) else {
        panic!(
            "NOT EXERCISED: nothing captured at {CAPTURED}; run `make sandbox-egress-evidence`, \
             which captures a real PROXY_ONLY environment's record first"
        )
    };
    let fact = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
            .unwrap_or_else(|| panic!("no {key} captured"))
            .to_owned()
    };
    let spec = EnvironmentSpec {
        environment_id: EnvironmentId::parse(&fact("environment_id")).unwrap(),
        run_id: RunId::parse(&fact("run_id")).unwrap(),
        store: StoreInstance::new(fact("store")).unwrap(),
        profile: EnvironmentProfile::OciStrict,
        network: NetworkTopology::ProxyOnly,
        image: ImageId::new(fact("image")).unwrap(),
        // Neither is judged from the record: the probe's digest and the
        // workspace's identity are measured elsewhere.
        probe_sha256: ContentDigest::new("b".repeat(64)).unwrap(),
        workspace_path: HostPath::new(fact("workspace_path")).unwrap(),
        workspace: (1, 2),
        workspace_bound: None,
        relay_sha256: None,
        egress: None,
    };
    let seccomp = dwk_sandbox_profile::seccomp_profile_json();
    let socket = fact("socket");
    let against = (seccomp.as_str(), socket.as_str());
    let mut records = parse(&std::fs::read(dir.join("proxy-only-record.json")).unwrap()).unwrap();
    assert_eq!(records.len(), 1, "one record captured");
    let base = records.remove(0);
    // The runtime's own record, as captured: kept.
    let checks = all_checks_against(&base, &spec, against);
    assert!(
        super::super::oci::clean(&checks, &spec),
        "the captured record: {:?}",
        checks
            .iter()
            .filter(|(_, v)| *v != Verdict::Pass)
            .collect::<Vec<_>>()
    );
    assurance_evidence(
        "captured-proxy-only-conforming-kept",
        "every-required-invariant-pass-kept",
        "measured-host",
    );
    // Each hard rule broken in it, alone: refused.
    let mut cases = hard_rule_weakenings(&seccomp);
    cases.retain(|(_, network, ..)| *network == NetworkTopology::ProxyOnly);
    // ADR-0056: the task backstop measured exactly -- the per-environment
    // value it replaced is refused too.
    let old_backstop = dwk_proto::json::parse(
        br#"[{"Name": "nofile", "Hard": 1024, "Soft": 1024},
             {"Name": "nproc", "Hard": 256, "Soft": 256},
             {"Name": "fsize", "Hard": 1073741824, "Soft": 1073741824},
             {"Name": "core", "Hard": 0, "Soft": 0}]"#,
        dwk_proto::json::ParseOptions::ijson(),
    )
    .unwrap();
    cases.push((
        "proxy-only-weakened-task-backstop-at-256-refused",
        NetworkTopology::ProxyOnly,
        &["HostConfig", "Ulimits"],
        old_backstop,
        &[SandboxInvariant::HostResourceLimits],
    ));
    assert_eq!(cases.len(), 17);
    for (case, _, path, value, expected) in cases {
        let case = format!("captured-{case}");
        refused(&case, &base, &[(path, value)], expected, &spec, against);
    }
    // U4: the limits lifted in it as the real NO_NETWORK case lifts them.
    refused(
        &format!("captured-{LIMITS_LIFTED}"),
        &base,
        &limits_lifted(),
        &[SandboxInvariant::HostResourceLimits],
        &spec,
        against,
    );
}

const EGRESS_DIR: &str = "/run/dw/egress/env_01M24BB8G3E0A851TRWE3M8FZF";

fn environment_container() -> ContainerRef {
    ContainerRef::new("c".repeat(64)).unwrap()
}

/// A conforming relay record.
fn relay_record() -> String {
    let seccomp = serde_like_escape(PROFILE);
    let image = image();
    format!(
        r#"[{{
  "Id": "{id}",
  "Image": "{image}",
  "State": {{"Status": "running", "Running": true, "Paused": false, "Restarting": false}},
  "Config": {{
    "User": "10002:10002",
    "Image": "{image}",
    "Env": ["PATH=/usr/bin"],
    "Entrypoint": ["/usr/libexec/direwolf/sandbox-relay"],
    "Cmd": ["serve"],
    "Labels": {{
      "io.direwolf.owner": "direwolf",
      "io.direwolf.schema": "2",
      "io.direwolf.store": "0123abcd",
      "io.direwolf.environment": "{ENV}",
      "io.direwolf.run": "{RUN}",
      "io.direwolf.profile": "oci-strict",
      "io.direwolf.role": "relay",
      "desktop.docker.io/wsl-distro": "Ubuntu"
    }}
  }},
  "HostConfig": {{
    "Binds": null,
    "NetworkMode": "container:{env}",
    "RestartPolicy": {{"Name": "no", "MaximumRetryCount": 0}},
    "VolumesFrom": null,
    "Mounts": [{{"Type": "bind", "Source": "{EGRESS_DIR}", "Target": "/run/direwolf-egress",
                "ReadOnly": true, "BindOptions": {{"Propagation": "rprivate"}}}}],
    "CapAdd": null,
    "CapDrop": ["ALL"],
    "IpcMode": "private",
    "CgroupnsMode": "private",
    "PidMode": "",
    "UTSMode": "",
    "UsernsMode": "",
    "Privileged": false,
    "ReadonlyRootfs": true,
    "SecurityOpt": ["no-new-privileges=true", "seccomp={seccomp}"],
    "Memory": 67108864,
    "MemorySwap": 67108864,
    "NanoCpus": 500000000,
    "PidsLimit": 144,
    "Devices": [],
    "DeviceCgroupRules": null,
    "DeviceRequests": null,
    "MaskedPaths": ["/proc/kcore"],
    "ReadonlyPaths": ["/proc/sys"]
  }},
  "Mounts": [{{"Type": "bind", "Source": "{EGRESS_DIR}", "Destination": "/run/direwolf-egress",
              "Mode": "", "RW": false, "Propagation": "rprivate"}}]
}}]"#,
        id = "d".repeat(64),
        env = "c".repeat(64),
    )
}

fn relay_mutated(path: &[&str], value: Value) -> Object {
    let text = relay_record();
    let parsed =
        dwk_proto::json::parse(text.as_bytes(), dwk_proto::json::ParseOptions::ijson()).unwrap();
    let Value::Array(mut items) = parsed else {
        panic!("not an array")
    };
    let Value::Object(object) = items.remove(0) else {
        panic!("not an object")
    };
    replace(object, path, value)
}

fn relay_verdict(object: &Object) -> Option<bool> {
    Record::new(object).relay_exact(
        &spec_with(NetworkTopology::ProxyOnly),
        &environment_container(),
        EGRESS_DIR,
        PROFILE,
    )
}

#[test]
fn the_relay_record_is_judged_exactly_and_every_weakening_is_caught() {
    let relay = record(&relay_record());
    assert_eq!(relay_verdict(&relay), Some(true));
    assert_eq!(Record::new(&relay).role(), Some(ContainerRole::Relay));
    let owned = Record::new(&relay).owned(&spec().store).unwrap();
    assert!(owned.labels_exact);
    assert_eq!(owned.role, Some(ContainerRole::Relay));
    for (path, value) in [
        (&["Config", "User"][..], Value::String("0:0".to_owned())),
        (&["Config", "User"], Value::String("10001:10001".to_owned())),
        (&["HostConfig", "CapAdd"], strings(&["NET_ADMIN"])),
        (&["HostConfig", "Privileged"], Value::Bool(true)),
        (&["HostConfig", "ReadonlyRootfs"], Value::Bool(false)),
        (
            &["HostConfig", "NetworkMode"],
            Value::String("bridge".to_owned()),
        ),
        (
            &["HostConfig", "NetworkMode"],
            Value::String("host".to_owned()),
        ),
        (
            &["HostConfig", "NetworkMode"],
            Value::String(format!("container:{}", "e".repeat(64))),
        ),
        (
            &["HostConfig", "SecurityOpt"],
            strings(&["no-new-privileges=true", "seccomp=unconfined"]),
        ),
        (&["HostConfig", "PidMode"], Value::String("host".to_owned())),
        // The plan's private cgroup namespace, the runtime's private UTS
        // one, and no swap beyond the relay's memory: what the runtime was
        // asked for, read back, or the relay is not the one planned.
        (&["HostConfig", "UTSMode"], Value::String("host".to_owned())),
        (
            &["HostConfig", "CgroupnsMode"],
            Value::String("host".to_owned()),
        ),
        (
            &["HostConfig", "MemorySwap"],
            Value::Number(dwk_proto::json::Number::Int(-1)),
        ),
        (
            &["HostConfig", "MemorySwap"],
            Value::Number(dwk_proto::json::Number::Int(2 * 67_108_864)),
        ),
        (
            &["HostConfig", "Binds"],
            strings(&["/var/run/docker.sock:/var/run/docker.sock"]),
        ),
        (&["Config", "Cmd"], strings(&["setup"])),
        (
            &["Config", "Entrypoint"],
            strings(&["/usr/libexec/direwolf/sandbox-probe"]),
        ),
        (
            &["Config", "Env"],
            strings(&["HTTPS_PROXY=http://169.254.7.1:8080"]),
        ),
        (&["Config", "Image"], Value::String("alpine:3".to_owned())),
        (
            &["HostConfig", "PidsLimit"],
            Value::Number(dwk_proto::json::Number::Int(4096)),
        ),
        (&["State", "Status"], Value::String("exited".to_owned())),
        (
            &["Config", "Labels", "io.direwolf.role"],
            Value::String("environment".to_owned()),
        ),
    ] {
        let object = relay_mutated(path, value);
        assert_eq!(relay_verdict(&object), Some(false), "{path:?}");
    }
    // A second mount, a writable one, another source -- each with the
    // plan's propagation, so that check cannot be what refuses it.
    for mounts in [
        format!(
            r#"[{{"Type":"bind","Source":"{EGRESS_DIR}","Destination":"/run/direwolf-egress","RW":true,"Propagation":"rprivate"}}]"#
        ),
        r#"[{"Type":"bind","Source":"/run/dw/egress/other","Destination":"/run/direwolf-egress","RW":false,"Propagation":"rprivate"}]"#
            .to_owned(),
        format!(
            r#"[{{"Type":"bind","Source":"{EGRESS_DIR}","Destination":"/run/direwolf-egress","RW":false,"Propagation":"rprivate"}},{{"Type":"bind","Source":"/srv/ws","Destination":"/workspace","RW":true,"Propagation":"rprivate"}}]"#
        ),
    ] {
        let value =
            dwk_proto::json::parse(mounts.as_bytes(), dwk_proto::json::ParseOptions::ijson())
                .unwrap();
        let object = relay_mutated(&["Mounts"], value);
        assert_eq!(relay_verdict(&object), Some(false), "{mounts}");
    }
    // Absent fields are unobservable, never a pass.
    for path in [
        &["Config", "Entrypoint"][..],
        &["HostConfig", "UTSMode"],
        &["HostConfig", "CgroupnsMode"],
        &["HostConfig", "MemorySwap"],
    ] {
        let object = relay_mutated(path, Value::Bool(false));
        assert_eq!(relay_verdict(&object), None, "{path:?}");
    }
}

#[test]
fn the_relays_requested_and_effective_mount_propagation_must_be_recursive_private() {
    // The relay plan requests rprivate: neither an applied propagation nor
    // a requested one that differs may pass HOST_PROXY_RELAY. Keep the
    // other record unchanged so each side must detect its own mismatch.
    let mut missed = Vec::new();
    for (propagation, expected) in [
        (r#""Propagation":"rprivate""#, Some(true)),
        (r#""Propagation":"private""#, Some(false)),
        (r#""Propagation":"shared""#, Some(false)),
        (r#""Propagation":"rshared""#, Some(false)),
        (r#""Propagation":"slave""#, Some(false)),
        (r#""Propagation":"rslave""#, Some(false)),
        (r#""Propagation":"""#, Some(false)),
        (r#""Propagation":null"#, Some(false)),
        (r#""Propagation":false"#, Some(false)),
        (r#""Propagation":[]"#, Some(false)),
        (r#""other":"rprivate""#, Some(false)),
    ] {
        for (path, mounts) in [
            (
                &["Mounts"][..],
                format!(
                    r#"[{{"Type":"bind","Source":"{EGRESS_DIR}","Destination":"/run/direwolf-egress","RW":false,{propagation}}}]"#
                ),
            ),
            (
                &["HostConfig", "Mounts"][..],
                format!(
                    r#"[{{"Type":"bind","Source":"{EGRESS_DIR}","Target":"/run/direwolf-egress","ReadOnly":true,"BindOptions":{{{propagation}}}}}]"#
                ),
            ),
        ] {
            let value =
                dwk_proto::json::parse(mounts.as_bytes(), dwk_proto::json::ParseOptions::ijson())
                    .unwrap();
            let found = relay_verdict(&relay_mutated(path, value));
            if found != expected {
                missed.push(format!(
                    "{path:?}: {propagation}: {found:?} != {expected:?}"
                ));
            }
        }
    }
    assert!(missed.is_empty(), "{}", missed.join("\n"));
}

#[test]
fn every_field_of_the_relays_one_mount_is_judged_on_both_records() {
    // The conforming mount, requested and as applied; then each field
    // changed alone, and the mount given twice. Every other field -- the
    // propagation too -- stays the plan's, so only that field's check can
    // refuse it; both conforming records pass, so the shapes are sound.
    let effective = format!(
        r#"{{"Type":"bind","Source":"{EGRESS_DIR}","Destination":"/run/direwolf-egress","RW":false,"Propagation":"rprivate"}}"#
    );
    let requested = format!(
        r#"{{"Type":"bind","Source":"{EGRESS_DIR}","Target":"/run/direwolf-egress","ReadOnly":true,"BindOptions":{{"Propagation":"rprivate"}}}}"#
    );
    let mut missed = Vec::new();
    for (path, mount, changes) in [
        (
            &["Mounts"][..],
            &effective,
            [
                (r#""Type":"bind""#, r#""Type":"volume""#),
                (EGRESS_DIR, "/run/dw/egress/other"),
                (
                    r#""Destination":"/run/direwolf-egress""#,
                    r#""Destination":"/run/other""#,
                ),
                (r#""RW":false"#, r#""RW":true"#),
            ],
        ),
        (
            &["HostConfig", "Mounts"],
            &requested,
            [
                (r#""Type":"bind""#, r#""Type":"volume""#),
                (EGRESS_DIR, "/run/dw/egress/other"),
                (
                    r#""Target":"/run/direwolf-egress""#,
                    r#""Target":"/run/other""#,
                ),
                (r#""ReadOnly":true"#, r#""ReadOnly":false"#),
            ],
        ),
    ] {
        let mut records = vec![
            (format!("[{mount}]"), Some(true)),
            (format!("[{mount},{mount}]"), Some(false)),
        ];
        for (from, to) in changes {
            assert_eq!(mount.matches(from).count(), 1, "{from}");
            records.push((format!("[{}]", mount.replace(from, to)), Some(false)));
        }
        for (mounts, expected) in records {
            let value =
                dwk_proto::json::parse(mounts.as_bytes(), dwk_proto::json::ParseOptions::ijson())
                    .unwrap();
            let found = relay_verdict(&relay_mutated(path, value));
            if found != expected {
                missed.push(format!("{path:?}: {mounts}: {found:?} != {expected:?}"));
            }
        }
    }
    assert!(missed.is_empty(), "{}", missed.join("\n"));
}
