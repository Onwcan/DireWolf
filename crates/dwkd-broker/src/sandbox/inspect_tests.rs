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
    EnvironmentProfile, ImageId, NetworkTopology, SandboxInvariant, StoreInstance, Verdict,
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
    EnvironmentSpec {
        environment_id: EnvironmentId::parse(ENV).unwrap(),
        run_id: RunId::parse(RUN).unwrap(),
        store: StoreInstance::new("0123abcd".to_owned()).unwrap(),
        profile: EnvironmentProfile::OciStrict,
        network: NetworkTopology::NoNetwork,
        image: ImageId::new(image()).unwrap(),
        probe_sha256: ContentDigest::new("b".repeat(64)).unwrap(),
        workspace_path: HostPath::new("/srv/ws".to_owned()).unwrap(),
        workspace: (1, 2),
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
    "Labels": {{
      "io.direwolf.owner": "direwolf",
      "io.direwolf.schema": "1",
      "io.direwolf.store": "0123abcd",
      "io.direwolf.environment": "{ENV}",
      "io.direwolf.run": "{RUN}",
      "io.direwolf.profile": "oci-strict"
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
      {{"Name": "nproc", "Hard": 256, "Soft": 256}},
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
    assert_eq!(verdicts(&object).len(), 19);
    let record = Record::new(&object);
    assert!(record.is(&spec().store, (&spec().environment_id, &spec().run_id)));
    let owned = record.owned(&spec().store).unwrap();
    assert!(owned.labels_exact);
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
