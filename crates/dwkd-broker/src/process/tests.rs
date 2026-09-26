//! The process module against real targets, through the real launch helper
//! (the built `dwkd-broker`, `exec-helper`), in this crate's unit tests
//! (ADR-0045 §22, evidence C).
//!
//! These drive [`Processes`] directly — the operation the private channel
//! reaches after its own checks — with descriptors the test opened the way
//! the authority opens them. The real broker binary behind a test authority
//! peer is exercised again by `tests/private_protocol.rs`; the authority's
//! production refusal by the authority's own suites.
//!
//! Targets: `/usr/bin/python3` (root-owned, as a system executable is) runs
//! the reporting fixtures; a copy of this test binary, owned by the test's
//! own uid, is the executable whose path is replaced or rewritten. The test's
//! uid stands in for the authority's. Every test holds [`SERIAL`]: they read
//! and change this process's descriptor table.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use dwk_proto::brokerp::{
    BrokerGeneration, BrokerRefusal, ChannelNonce, Common, ExecEnvironment, OutcomeResult,
    ProcessArgs, ProcessKillAuthorisation, ProcessSpec, ProcessStartAuthorisation,
    ProcessStatusAuthorisation, ProcessStatusDone, StreamLimit,
};
use dwk_proto::wire::id::{InvocationId, ProcessId};
use dwk_proto::wire::scalar::{
    ContentDigest, ExitCode, HostPath, KillOutcome, ProcessArg, ProcessState, SignalNumber,
};
use sha2::{Digest as _, Sha256};

use super::{MAX_PROCESSES, Processes, fdcheck};

/// One process test at a time: they read this process's descriptor table.
static SERIAL: Mutex<()> = Mutex::new(());

/// The lock, and a clean descriptor table: a test process that inherited a
/// descriptor without close-on-exec (a terminal's `/dev/ptmx`, say) would
/// have every launch rightly refused. Run through `make test`
/// (`scripts/dw.py`, which closes them) or from a shell that holds none.
fn serial() -> MutexGuard<'static, ()> {
    let guard = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let inherited = fdcheck::inheritable().unwrap();
    assert!(
        inherited.is_empty(),
        "this test process inherited descriptors {inherited:?} without close-on-exec; \
         the broker refuses to launch beside them -- run the tests through `make test`"
    );
    guard
}

const PYTHON: &str = "/usr/bin/python3";

/// One line of M4d evidence for `make process-broker-evidence`.
fn evidence(case: &str, outcome: &str) {
    println!(
        "PROC-EVIDENCE {{\"suite\":\"broker-process\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\"count\":1}}"
    );
}

/// The built broker binary: the launch helper the unit tests use. Cargo
/// builds it before any test runs.
fn helper_binary() -> PathBuf {
    let this = std::env::current_exe().unwrap();
    let binary = this
        .parent()
        .and_then(Path::parent)
        .map(|dir| dir.join("dwkd-broker"))
        .unwrap();
    assert!(
        binary.is_file(),
        "the broker binary {} is built",
        binary.display()
    );
    binary
}

fn own_uid() -> u32 {
    let dir = Scratch::new("uid");
    let probe = dir.0.join("probe");
    fs::write(&probe, b"").unwrap();
    fs::metadata(&probe).unwrap().uid()
}

fn processes(wall_clock: Duration) -> Processes {
    Processes::for_tests(helper_binary(), own_uid(), wall_clock)
}

/// A private scratch directory, removed with everything in it.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("dwp-{tag}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(fs::canonicalize(&path).unwrap())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn uuid(n: u64) -> u128 {
    let ts = u128::from(1_758_000_000_000u64);
    let n = u128::from(n);
    (ts << 80) | (0x7 << 76) | ((n & 0x0fff) << 64) | (0b10 << 62) | (n & ((1 << 62) - 1))
}

fn process_id(n: u64) -> ProcessId {
    ProcessId::from_uuid(uuid(n)).unwrap()
}

fn common() -> Common {
    Common::new(
        ChannelNonce::new("c".repeat(32)).unwrap(),
        InvocationId::from_uuid(uuid(9999)).unwrap(),
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut text, b| {
            let _ = write!(text, "{b:02x}");
            text
        })
}

/// A launch of `executable`, as the authority would authorise it: its
/// identity, its digest, the working directory's identity.
struct Launch {
    executable: PathBuf,
    argv0: String,
    args: Vec<String>,
    cwd: PathBuf,
    stream_limit: u32,
    digest: Option<String>,
}

impl Launch {
    fn new(executable: impl Into<PathBuf>, args: &[&str], cwd: &Path) -> Self {
        let executable = executable.into();
        Self {
            argv0: executable.display().to_string(),
            executable,
            args: args.iter().map(|a| (*a).to_owned()).collect(),
            cwd: cwd.to_path_buf(),
            stream_limit: 131_072,
            digest: None,
        }
    }

    fn open(&self) -> (OwnedFd, OwnedFd, ProcessStartAuthorisation) {
        let exe = fs::File::open(&self.executable).unwrap();
        let cwd = fs::File::open(&self.cwd).unwrap();
        let (em, cm) = (exe.metadata().unwrap(), cwd.metadata().unwrap());
        let digest = self
            .digest
            .clone()
            .unwrap_or_else(|| sha256_hex(&fs::read(&self.executable).unwrap()));
        let args: Vec<ProcessArg> = self
            .args
            .iter()
            .map(|a| ProcessArg::new(a.clone()).unwrap())
            .collect();
        let start = ProcessStartAuthorisation::new(
            common(),
            ProcessSpec {
                process_id: process_id(next()),
                executable: (em.dev(), em.ino()),
                executable_sha256: ContentDigest::new(digest).unwrap(),
                cwd: (cm.dev(), cm.ino()),
                argv0: HostPath::new(self.argv0.clone()).unwrap(),
                args: ProcessArgs::new(args).unwrap(),
                environment: ExecEnvironment::Base,
                stream_limit: StreamLimit::new(self.stream_limit).unwrap(),
            },
        );
        (exe.into(), cwd.into(), start)
    }
}

fn next() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Start `launch`; the handle and the generation it was started under.
fn start(p: &Processes, launch: &Launch) -> Result<(ProcessId, BrokerGeneration), BrokerRefusal> {
    let (exe, cwd, start) = launch.open();
    let id = start.process_id.clone();
    match p.start(&start, exe, cwd) {
        OutcomeResult::Done(done) => {
            let started = done.process_start.expect("a launch's answer");
            assert_eq!(started.state, ProcessState::Running);
            Ok((id, started.generation))
        }
        OutcomeResult::Refused(why) => Err(why),
        OutcomeResult::Indeterminate(why) => panic!("indeterminate: {why:?}"),
    }
}

fn status(
    p: &Processes,
    id: &ProcessId,
    generation: &BrokerGeneration,
) -> Result<ProcessStatusDone, BrokerRefusal> {
    let ask = ProcessStatusAuthorisation::new(common(), id.clone(), generation.clone());
    match p.status(&ask) {
        OutcomeResult::Done(done) => Ok(done.process_status.expect("a status")),
        OutcomeResult::Refused(why) => Err(why),
        OutcomeResult::Indeterminate(why) => panic!("indeterminate: {why:?}"),
    }
}

fn kill(
    p: &Processes,
    id: &ProcessId,
    generation: &BrokerGeneration,
) -> Result<KillOutcome, BrokerRefusal> {
    let ask = ProcessKillAuthorisation::new(common(), id.clone(), generation.clone());
    match p.kill(&ask) {
        OutcomeResult::Done(done) => Ok(done.process_kill.expect("a kill").outcome),
        OutcomeResult::Refused(why) => Err(why),
        OutcomeResult::Indeterminate(why) => panic!("indeterminate: {why:?}"),
    }
}

/// Status until it has ended and both streams reached end of file.
fn finished(p: &Processes, id: &ProcessId, generation: &BrokerGeneration) -> ProcessStatusDone {
    let until = Instant::now() + Duration::from_secs(60);
    loop {
        let done = status(p, id, generation).unwrap();
        if done.state != ProcessState::Running {
            // Give the drains a moment to reach end of file, then take the
            // final snapshot.
            std::thread::sleep(Duration::from_millis(100));
            return status(p, id, generation).unwrap();
        }
        assert!(Instant::now() < until, "the process ended in time");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn stdout_of(done: &ProcessStatusDone) -> Vec<u8> {
    done.stdout.content.to_bytes()
}

/// Run a Python program to completion; its status.
fn python(p: &Processes, program: &str, args: &[&str], cwd: &Path) -> ProcessStatusDone {
    let mut all = vec!["-I", "-c", program];
    all.extend_from_slice(args);
    let (id, generation) = start(p, &Launch::new(PYTHON, &all, cwd)).unwrap();
    finished(p, &id, &generation)
}

#[test]
fn a_launch_runs_with_literal_argv_an_environment_built_from_nothing_and_fixed_limits() {
    let _serial = serial();
    let p = processes(Duration::from_secs(60));
    let dir = Scratch::new("literal");
    let args = [
        "$HOME",
        "$(id)",
        ";",
        "|",
        "&&",
        "*",
        "?",
        "a b",
        "'",
        "\"",
        "line\nbreak",
        "",
        "-c",
    ];
    let program = r#"
import json, os, resource, sys
limits = {name: resource.getrlimit(getattr(resource, name)) for name in
          ["RLIMIT_NOFILE", "RLIMIT_CORE", "RLIMIT_FSIZE", "RLIMIT_CPU", "RLIMIT_AS", "RLIMIT_NPROC"]}
status = dict(line.split(":\t", 1) for line in open("/proc/self/status").read().splitlines() if ":\t" in line)
fds = sorted(int(n) for n in os.listdir("/proc/self/fd"))
sys.stdout.write(json.dumps({"argv": sys.argv[1:], "exe": os.readlink("/proc/self/exe"),
  "env": dict(os.environ), "cwd": os.getcwd(), "fds": fds, "limits": limits,
  "nnp": status["NoNewPrivs"].strip(), "pgid_is_pid": os.getpgid(0) == os.getpid(),
  "stdin": os.readlink("/proc/self/fd/0")}))
"#;
    let done = python(&p, program, &args, &dir.0);
    assert_eq!(done.state, ProcessState::Exited, "{done:?}");
    assert_eq!(done.exit_code.map(ExitCode::get), Some(0));
    let report: serde_like::Value = serde_like::parse(&stdout_of(&done));
    // argv: exactly the bytes sent, no shell anywhere.
    assert_eq!(
        report.get("argv").strings(),
        args.map(str::to_owned).to_vec()
    );
    // The environment: exactly the base profile, nothing inherited.
    assert_eq!(
        report.get("env").pairs(),
        vec![
            ("HOME".to_owned(), "/nonexistent".to_owned()),
            ("LANG".to_owned(), "C.UTF-8".to_owned()),
            (
                "PATH".to_owned(),
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_owned()
            ),
        ]
    );
    assert_eq!(report.get("cwd").string(), dir.0.display().to_string());
    // 0, 1, 2 and the listing's own descriptor: nothing else reached it.
    assert_eq!(
        report.get("fds").ints().len(),
        4,
        "{:?}",
        report.get("fds").ints()
    );
    assert_eq!(report.get("stdin").string(), "/dev/null");
    let limits = report.get("limits");
    for (name, value) in [
        ("RLIMIT_NOFILE", 1024i64),
        ("RLIMIT_CORE", 0),
        ("RLIMIT_FSIZE", 1 << 30),
        ("RLIMIT_CPU", 600),
        ("RLIMIT_AS", 16 << 30),
    ] {
        assert_eq!(limits.get(name).ints(), vec![value, value], "{name}");
    }
    assert_eq!(report.get("nnp").string(), "1");
    assert!(report.get("pgid_is_pid").boolean());
    evidence("argv-literal", "exact-bytes-no-shell");
    evidence("env-built-from-nothing", "HOME,LANG,PATH-only");
    evidence("rlimits-applied", "nofile,core,fsize,cpu,as");
    evidence("fd-hygiene-target", "0,1,2-only");
    evidence("stdin", "/dev/null");
    evidence("no-new-privs", "1");
}

/// A copy of this test binary, owned by the test's uid: an executable whose
/// path this test can replace and whose bytes it can rewrite.
fn own_executable(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[test]
fn the_object_executed_is_the_descriptor_not_what_the_path_names_by_then() {
    let _serial = serial();
    let p = processes(Duration::from_secs(60));
    let dir = Scratch::new("replace");
    let tool = own_executable(&dir.0, "tool");
    let launch = Launch::new(&tool, &["--list", "--format", "terse"], &dir.0);
    let (exe, cwd, authorisation) = launch.open();
    // After the checked descriptor exists: the path now names something else.
    fs::rename(&tool, dir.0.join("original")).unwrap();
    fs::write(&tool, b"#!/bin/sh\necho replaced\n").unwrap();
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
    let id = authorisation.process_id.clone();
    let OutcomeResult::Done(done) = p.start(&authorisation, exe, cwd) else {
        panic!("the checked object is launched")
    };
    let generation = done.process_start.unwrap().generation;
    let done = finished(&p, &id, &generation);
    let out = String::from_utf8_lossy(&stdout_of(&done)).into_owned();
    assert!(out.contains(": test"), "the original ran: {out}");
    assert!(!out.contains("REPLACEMENT-RAN-7f3a"));
    evidence("path-replaced-after-handoff", "checked-object-executed");
    evidence("R1-executable-path-replaced", "checked-object-executed");
    evidence("R2-executable-renamed", "checked-object-executed");
}

#[test]
fn a_changed_or_untrusted_executable_is_refused_and_nothing_starts() {
    let _serial = serial();
    let p = processes(Duration::from_secs(60));
    let dir = Scratch::new("refuse");
    let tool = own_executable(&dir.0, "tool");
    // A digest the file does not have.
    let mut wrong = Launch::new(&tool, &["--list"], &dir.0);
    wrong.digest = Some("00".repeat(32));
    assert_eq!(start(&p, &wrong), Err(BrokerRefusal::DigestMismatch));
    // Rewritten in place after the authority hashed it.
    let launch = Launch::new(&tool, &["--list"], &dir.0);
    let (exe, cwd, authorisation) = launch.open();
    let mut bytes = fs::read(&tool).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    fs::write(&tool, &bytes).unwrap();
    assert!(matches!(
        p.start(&authorisation, exe, cwd),
        OutcomeResult::Refused(BrokerRefusal::DigestMismatch)
    ));
    // Truncated after it was hashed.
    let launch = Launch::new(&tool, &["--list"], &dir.0);
    let (exe, cwd, authorisation) = launch.open();
    fs::OpenOptions::new()
        .write(true)
        .open(&tool)
        .unwrap()
        .set_len(64)
        .unwrap();
    assert!(matches!(
        p.start(&authorisation, exe, cwd),
        OutcomeResult::Refused(BrokerRefusal::DigestMismatch)
    ));
    // Writable by the group: another principal could change it.
    let tool = own_executable(&dir.0, "shared");
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o775)).unwrap();
    assert_eq!(
        start(&p, &Launch::new(&tool, &[], &dir.0)),
        Err(BrokerRefusal::ExecutableUntrusted)
    );
    // Set-uid.
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o4755)).unwrap();
    assert_eq!(
        start(&p, &Launch::new(&tool, &[], &dir.0)),
        Err(BrokerRefusal::ExecutableUntrusted)
    );
    // A script is not a native executable: its interpreter would run.
    let script = dir.0.join("script");
    fs::write(&script, b"#!/bin/sh\necho hi\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        start(&p, &Launch::new(&script, &[], &dir.0)),
        Err(BrokerRefusal::ExecutableUntrusted)
    );
    // Owned by neither root nor the authority: a Processes whose authority is
    // another uid refuses the test's own file.
    let other = Processes::for_tests(
        helper_binary(),
        own_uid().wrapping_add(1),
        Duration::from_secs(5),
    );
    let tool = own_executable(&dir.0, "foreign");
    assert_eq!(
        start(&other, &Launch::new(&tool, &[], &dir.0)),
        Err(BrokerRefusal::ExecutableUntrusted)
    );
    assert!(p.table().is_empty(), "nothing was started");
    evidence("digest-mismatch", "refused-zero-exec");
    evidence("rewritten-after-hash", "refused-zero-exec");
    evidence(
        "R4-executable-rewritten-in-place",
        "DIGEST_MISMATCH-zero-exec",
    );
    evidence("truncated-after-hash", "refused-zero-exec");
    evidence("R5-executable-truncated", "DIGEST_MISMATCH-zero-exec");
    evidence("group-writable", "refused-zero-exec");
    evidence("setuid", "refused-zero-exec");
    evidence("script", "refused-zero-exec");
    evidence("foreign-owner", "refused-zero-exec");
}

#[test]
fn an_executable_deleted_or_made_writable_after_handoff() {
    let _serial = serial();
    let p = processes(Duration::from_secs(60));
    let dir = Scratch::new("r3r6");
    // R3: unlinked after the descriptor exists. The object is still the one
    // checked and hashed; it runs, and nothing at the path matters.
    let tool = own_executable(&dir.0, "tool");
    let launch = Launch::new(&tool, &["--list", "--format", "terse"], &dir.0);
    let (exe, cwd, authorisation) = launch.open();
    fs::remove_file(&tool).unwrap();
    let id = authorisation.process_id.clone();
    let OutcomeResult::Done(done) = p.start(&authorisation, exe, cwd) else {
        panic!("the checked object runs")
    };
    let generation = done.process_start.unwrap().generation;
    let out = stdout_of(&finished(&p, &id, &generation));
    assert!(String::from_utf8_lossy(&out).contains(": test"));
    evidence("R3-executable-deleted", "checked-object-executed");
    // R6: made group-writable after the authority checked it: the broker's
    // re-proof refuses; nothing runs.
    let tool = own_executable(&dir.0, "tool2");
    let launch = Launch::new(&tool, &["--list"], &dir.0);
    let (exe, cwd, authorisation) = launch.open();
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o775)).unwrap();
    assert!(matches!(
        p.start(&authorisation, exe, cwd),
        OutcomeResult::Refused(BrokerRefusal::ExecutableUntrusted)
    ));
    evidence("R6-executable-chmod", "EXECUTABLE_UNTRUSTED-zero-exec");
}

#[test]
fn each_descriptor_must_be_its_role_and_the_object_named() {
    let _serial = serial();
    let p = processes(Duration::from_secs(60));
    let dir = Scratch::new("descriptors");
    let tool = own_executable(&dir.0, "tool");
    let launch = Launch::new(&tool, &["--list"], &dir.0);
    // Reversed: the directory where the executable belongs.
    let (exe, cwd, authorisation) = launch.open();
    assert!(matches!(
        p.start(&authorisation, cwd, exe),
        OutcomeResult::Refused(BrokerRefusal::DescriptorNotRegular)
    ));
    // Another file than the one authorised.
    let other = own_executable(&dir.0, "other");
    let (_, cwd, authorisation) = launch.open();
    let impostor: OwnedFd = fs::File::open(&other).unwrap().into();
    assert!(matches!(
        p.start(&authorisation, impostor, cwd),
        OutcomeResult::Refused(BrokerRefusal::IdentityMismatch)
    ));
    // A file where the working directory belongs.
    let (exe, _, authorisation) = launch.open();
    let not_a_dir: OwnedFd = fs::File::open(&other).unwrap().into();
    assert!(matches!(
        p.start(&authorisation, exe, not_a_dir),
        OutcomeResult::Refused(BrokerRefusal::DescriptorNotDirectory)
    ));
    // Another directory than the one authorised.
    let elsewhere = Scratch::new("elsewhere");
    let (exe, _, authorisation) = launch.open();
    let wrong_dir: OwnedFd = fs::File::open(&elsewhere.0).unwrap().into();
    assert!(matches!(
        p.start(&authorisation, exe, wrong_dir),
        OutcomeResult::Refused(BrokerRefusal::IdentityMismatch)
    ));
    // An O_PATH executable: it names the object and cannot be read or
    // proved.
    let (_, cwd, authorisation) = launch.open();
    let path_only = rustix::fs::open(
        &tool,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    assert!(matches!(
        p.start(&authorisation, path_only, cwd),
        OutcomeResult::Refused(BrokerRefusal::DescriptorNotReadable)
    ));
    assert!(p.table().is_empty(), "nothing was started");
    evidence("descriptors-reversed", "refused-zero-exec");
    evidence("executable-identity-mismatch", "refused-zero-exec");
    evidence(
        "R8-executable-descriptor-substituted",
        "IDENTITY_MISMATCH-zero-exec",
    );
    evidence("cwd-not-a-directory", "refused-zero-exec");
    evidence("cwd-identity-mismatch", "refused-zero-exec");
    evidence(
        "R9-cwd-descriptor-substituted",
        "IDENTITY_MISMATCH-zero-exec",
    );
    evidence("executable-o-path", "refused-zero-exec");
}

#[test]
fn a_working_directory_replaced_after_handoff_is_not_the_one_used() {
    let _serial = serial();
    let p = processes(Duration::from_secs(60));
    let dir = Scratch::new("cwd");
    let work = dir.0.join("work");
    fs::create_dir(&work).unwrap();
    fs::write(work.join("marker"), b"original").unwrap();
    let launch = Launch::new(
        PYTHON,
        &[
            "-I",
            "-c",
            "import sys; sys.stdout.write(open('marker').read())",
        ],
        &work,
    );
    let (exe, cwd, authorisation) = launch.open();
    fs::rename(&work, dir.0.join("moved")).unwrap();
    fs::create_dir(&work).unwrap();
    fs::write(work.join("marker"), b"replacement").unwrap();
    let id = authorisation.process_id.clone();
    let OutcomeResult::Done(done) = p.start(&authorisation, exe, cwd) else {
        panic!("launched")
    };
    let generation = done.process_start.unwrap().generation;
    assert_eq!(stdout_of(&finished(&p, &id, &generation)), b"original");
    evidence("cwd-replaced-after-handoff", "checked-directory-used");
    evidence("R7-cwd-path-replaced", "checked-directory-used");
}

/// An output case: name, program body, stream bound, stdout kept and
/// observed, stderr kept and observed.
type OutputCase<'a> = (&'a str, &'a str, u32, &'a [u8], u64, &'a [u8], u64);

#[test]
fn output_is_bounded_and_lossless() {
    let _serial = serial();
    let p = processes(Duration::from_secs(120));
    let dir = Scratch::new("output");
    let cases: [OutputCase<'_>; 8] = [
        ("none", "pass", 131_072, b"", 0, b"", 0),
        (
            "stdout-only",
            "sys.stdout.buffer.write(b'out')",
            131_072,
            b"out",
            3,
            b"",
            0,
        ),
        (
            "stderr-only",
            "sys.stderr.buffer.write(b'err')",
            131_072,
            b"",
            0,
            b"err",
            3,
        ),
        (
            "binary",
            "sys.stdout.buffer.write(bytes([0, 255, 10, 13, 0]))",
            131_072,
            &[0, 255, 10, 13, 0],
            5,
            b"",
            0,
        ),
        (
            "exact-cap",
            "sys.stdout.buffer.write(b'abcd')",
            4,
            b"abcd",
            4,
            b"",
            0,
        ),
        (
            "cap-plus-one",
            "sys.stdout.buffer.write(b'abcde')",
            4,
            b"abcd",
            5,
            b"",
            0,
        ),
        (
            "close-stdout-early",
            "os.close(1); sys.stderr.buffer.write(b'still here')",
            131_072,
            b"",
            0,
            b"still here",
            10,
        ),
        (
            "write-then-sleep",
            "sys.stdout.buffer.write(b'first'); sys.stdout.flush(); time.sleep(0.5); sys.stdout.buffer.write(b'last')",
            131_072,
            b"firstlast",
            9,
            b"",
            0,
        ),
    ];
    for (case, body, limit, out, out_n, err, err_n) in cases {
        let program = format!("import os, sys, time\n{body}");
        let mut launch = Launch::new(PYTHON, &["-I", "-c", &program], &dir.0);
        launch.stream_limit = limit;
        let (id, generation) = start(&p, &launch).unwrap();
        let done = finished(&p, &id, &generation);
        assert_eq!(done.stdout.content.to_bytes(), out, "{case}");
        assert_eq!(done.stdout.observed.get(), out_n, "{case}");
        let kept = u64::try_from(out.len()).unwrap();
        assert_eq!(done.stdout.truncated, out_n > kept, "{case}");
        assert_eq!(done.stderr.content.to_bytes(), err, "{case}");
        assert_eq!(done.stderr.observed.get(), err_n, "{case}");
        evidence(&format!("output-{case}"), "bounded-lossless");
    }
}

#[test]
fn many_mib_on_both_streams_never_deadlock() {
    let _serial = serial();
    let p = processes(Duration::from_secs(120));
    let dir = Scratch::new("output-flood");
    // Many MiB on both streams at once, into small bounds: drained to the end,
    // the first bytes kept, every byte counted, the process not blocked.
    let program = "import sys, threading\n\
        chunk = bytes(range(256)) * 4096\n\
        def spew(stream):\n    [stream.write(chunk) for _ in range(12)]\n\
        t = threading.Thread(target=spew, args=(sys.stderr.buffer,)); t.start()\n\
        spew(sys.stdout.buffer); t.join()";
    let mut launch = Launch::new(PYTHON, &["-I", "-c", program], &dir.0);
    launch.stream_limit = 1024;
    let begun = Instant::now();
    let (id, generation) = start(&p, &launch).unwrap();
    let done = finished(&p, &id, &generation);
    assert_eq!(done.state, ProcessState::Exited);
    assert_eq!(
        done.exit_code.map(ExitCode::get),
        Some(0),
        "it was never blocked"
    );
    let expected: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
    for stream in [&done.stdout, &done.stderr] {
        assert_eq!(stream.content.to_bytes(), expected);
        assert_eq!(stream.observed.get(), 12 * 256 * 4096);
        assert!(stream.truncated);
    }
    assert!(begun.elapsed() < Duration::from_secs(60));
    evidence("output-12MiB-both-streams", "drained-no-deadlock");
}

#[test]
fn status_kill_and_the_wall_clock_act_on_this_process_only() {
    let _serial = serial();
    let p = processes(Duration::from_secs(60));
    let dir = Scratch::new("kill");
    // A leader that forks a child into its own group, then sleeps.
    let program = "import os, sys, time\n\
        pid = os.fork()\n\
        if pid == 0:\n    time.sleep(120); os._exit(0)\n\
        sys.stdout.write(str(pid)); sys.stdout.flush(); time.sleep(120)";
    let (id, generation) = start(&p, &Launch::new(PYTHON, &["-I", "-c", program], &dir.0)).unwrap();
    let until = Instant::now() + Duration::from_secs(20);
    let child = loop {
        let now = status(&p, &id, &generation).unwrap();
        assert_eq!(now.state, ProcessState::Running);
        let out = stdout_of(&now);
        if !out.is_empty() {
            break String::from_utf8(out).unwrap();
        }
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(10));
    };
    evidence("status-running", "RUNNING");
    assert_eq!(kill(&p, &id, &generation), Ok(KillOutcome::Signaled));
    let done = finished(&p, &id, &generation);
    assert_eq!(done.state, ProcessState::Signaled);
    assert_eq!(done.signal.map(SignalNumber::get), Some(9));
    assert!(!done.timed_out);
    // Its group went with it.
    let gone = Instant::now() + Duration::from_secs(10);
    while Path::new(&format!("/proc/{child}")).exists() {
        assert!(Instant::now() < gone, "the group member {child} was killed");
        std::thread::sleep(Duration::from_millis(10));
    }
    // Once ended, a kill signals nothing.
    assert_eq!(kill(&p, &id, &generation), Ok(KillOutcome::AlreadyExited));
    evidence("kill-signals-process-and-group", "SIGNALED-9");
    evidence("kill-after-exit", "ALREADY_EXITED");

    // The wall clock (shortened for this test only).
    let quick = processes(Duration::from_millis(500));
    let begun = Instant::now();
    let (id, generation) = start(
        &quick,
        &Launch::new(
            PYTHON,
            &["-I", "-c", "import time; time.sleep(120)"],
            &dir.0,
        ),
    )
    .unwrap();
    let done = finished(&quick, &id, &generation);
    assert_eq!(done.state, ProcessState::Signaled);
    assert!(done.timed_out);
    assert!(begun.elapsed() < Duration::from_secs(30));
    evidence("wall-clock", "SIGNALED-timed-out");

    // A handle from another generation, one never issued, one reused.
    let stranger = processes(Duration::from_secs(5));
    assert_eq!(
        status(&stranger, &id, &generation).err(),
        Some(BrokerRefusal::StaleGeneration)
    );
    assert_eq!(
        kill(&stranger, &id, &generation).err(),
        Some(BrokerRefusal::StaleGeneration)
    );
    assert_eq!(
        status(&quick, &process_id(next()), &generation).err(),
        Some(BrokerRefusal::UnknownProcess)
    );
    let launch = Launch::new(PYTHON, &["-I", "-c", "pass"], &dir.0);
    let (exe, cwd, mut again) = launch.open();
    again.process_id = id.clone();
    assert!(matches!(
        quick.start(&again, exe, cwd),
        OutcomeResult::Refused(BrokerRefusal::ProcessIdInUse)
    ));
    evidence("stale-generation", "refused");
    evidence("R12-broker-generation-stale", "STALE_GENERATION");
    evidence("unknown-handle", "refused");
    evidence("handle-reuse", "refused");
}

#[test]
fn the_table_is_bounded_and_evicts_only_ended_processes() {
    let _serial = serial();
    let p = processes(Duration::from_secs(60));
    let dir = Scratch::new("table");
    let sleeper = Launch::new(
        PYTHON,
        &["-I", "-c", "import time; time.sleep(120)"],
        &dir.0,
    );
    let mut running = Vec::new();
    for _ in 0..MAX_PROCESSES {
        running.push(start(&p, &sleeper).unwrap());
    }
    assert_eq!(
        start(&p, &sleeper).err(),
        Some(BrokerRefusal::ProcessTableFull)
    );
    // End one: its slot can be reused.
    let (id, generation) = running.pop().unwrap();
    assert_eq!(kill(&p, &id, &generation), Ok(KillOutcome::Signaled));
    let _ = finished(&p, &id, &generation);
    running.push(start(&p, &sleeper).unwrap());
    for (id, generation) in &running {
        let _ = kill(&p, id, generation);
        let _ = finished(&p, id, generation);
    }
    evidence("table-bound", "PROCESS_TABLE_FULL-then-evict");
}

#[test]
fn an_inherited_descriptor_refuses_the_launch_rather_than_reaching_the_target() {
    let _serial = serial();
    let p = processes(Duration::from_secs(60));
    let dir = Scratch::new("inherit");
    let leaked = fs::File::create(dir.0.join("leak")).unwrap();
    // Clear FD_CLOEXEC, as a careless launcher would have.
    rustix::io::fcntl_setfd(&leaked, rustix::io::FdFlags::empty()).unwrap();
    assert!(!fdcheck::inheritable().unwrap().is_empty());
    let launch = Launch::new(PYTHON, &["-I", "-c", "pass"], &dir.0);
    assert_eq!(
        start(&p, &launch).err(),
        Some(BrokerRefusal::InheritedDescriptor)
    );
    drop(leaked);
    assert!(fdcheck::inheritable().unwrap().is_empty());
    assert!(start(&p, &launch).is_ok());
    evidence("inherited-descriptor", "refused-zero-exec");
}

#[test]
fn a_file_the_kernel_will_not_execute_is_refused_after_the_helper_tried() {
    let _serial = serial();
    let p = processes(Duration::from_secs(60));
    let dir = Scratch::new("enoexec");
    // ELF magic, and nothing a kernel can load.
    let bogus = dir.0.join("bogus");
    fs::write(&bogus, b"\x7fELF not really").unwrap();
    fs::set_permissions(&bogus, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        start(&p, &Launch::new(&bogus, &[], &dir.0)),
        Err(BrokerRefusal::ExecFailed)
    );
    assert!(p.table().is_empty());
    evidence("exec-failure", "EXEC_FAILED-zero-running");
}

#[test]
fn launches_leave_no_descriptor_or_thread_behind() {
    let _serial = serial();
    let dir = Scratch::new("leak");
    let baseline = fdcheck::launch_resources().unwrap();
    assert_eq!(baseline.1, 0, "no supervision thread before");
    {
        let p = processes(Duration::from_secs(60));
        for n in 0..(3 * MAX_PROCESSES) {
            let (id, generation) = start(
                &p,
                &Launch::new(PYTHON, &["-I", "-c", "print('x' * 1000)"], &dir.0),
            )
            .unwrap_or_else(|why| panic!("launch {n}: {why:?}"));
            let _ = finished(&p, &id, &generation);
        }
        assert_eq!(p.table().len(), MAX_PROCESSES);
    }
    // The table's pidfds went with it; every drain and reaper has ended.
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        let now = fdcheck::launch_resources().unwrap();
        if now == baseline {
            break;
        }
        assert!(
            Instant::now() < until,
            "pidfds, pipes and supervision threads returned to {baseline:?}, not {now:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    evidence("leak-24-launches", "pidfds-pipes-threads-baseline");
}

#[test]
fn the_helper_run_by_anyone_else_does_nothing() {
    let _serial = serial();
    let dir = Scratch::new("helper");
    let marker = dir.0.join("ran");
    // stderr a pipe, not a socket whose peer is the parent broker.
    let output = std::process::Command::new(helper_binary())
        .arg("exec-helper")
        .env_clear()
        .current_dir(&dir.0)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    assert!(!marker.exists());
    evidence("helper-direct-invocation", "exit-2-nothing-done");
}

/// A JSON reader just big enough for the fixtures' reports.
mod serde_like {
    #[derive(Debug, Clone, PartialEq)]
    pub(super) enum Value {
        Null,
        Bool(bool),
        Num(i64),
        Str(String),
        List(Vec<Value>),
        Map(Vec<(String, Value)>),
    }

    pub(super) fn parse(bytes: &[u8]) -> Value {
        let text = std::str::from_utf8(bytes).unwrap();
        let (value, rest) = value(text.trim_start());
        assert!(rest.trim().is_empty(), "trailing: {rest}");
        value
    }

    fn value(s: &str) -> (Value, &str) {
        let s = s.trim_start();
        match s.chars().next().unwrap() {
            '{' => {
                let mut s = s[1..].trim_start();
                let mut map = Vec::new();
                if let Some(rest) = s.strip_prefix('}') {
                    return (Value::Map(map), rest);
                }
                loop {
                    let (Value::Str(key), rest) = value(s) else {
                        panic!("a key")
                    };
                    let rest = rest.trim_start().strip_prefix(':').unwrap();
                    let (v, rest) = value(rest);
                    map.push((key, v));
                    let rest = rest.trim_start();
                    if let Some(rest) = rest.strip_prefix(',') {
                        s = rest;
                    } else {
                        return (Value::Map(map), rest.strip_prefix('}').unwrap());
                    }
                }
            }
            '[' => {
                let mut s = s[1..].trim_start();
                let mut list = Vec::new();
                if let Some(rest) = s.strip_prefix(']') {
                    return (Value::List(list), rest);
                }
                loop {
                    let (v, rest) = value(s);
                    list.push(v);
                    let rest = rest.trim_start();
                    if let Some(rest) = rest.strip_prefix(',') {
                        s = rest;
                    } else {
                        return (Value::List(list), rest.strip_prefix(']').unwrap());
                    }
                }
            }
            '"' => {
                let mut out = String::new();
                let mut chars = s[1..].char_indices();
                while let Some((i, c)) = chars.next() {
                    match c {
                        '"' => return (Value::Str(out), &s[i + 2..]),
                        '\\' => {
                            let (_, e) = chars.next().unwrap();
                            match e {
                                'n' => out.push('\n'),
                                't' => out.push('\t'),
                                'r' => out.push('\r'),
                                'u' => {
                                    let hex: String =
                                        (0..4).map(|_| chars.next().unwrap().1).collect();
                                    out.push(
                                        char::from_u32(u32::from_str_radix(&hex, 16).unwrap())
                                            .unwrap(),
                                    );
                                }
                                other => out.push(other),
                            }
                        }
                        other => out.push(other),
                    }
                }
                panic!("an unterminated string")
            }
            't' => (Value::Bool(true), &s[4..]),
            'f' => (Value::Bool(false), &s[5..]),
            'n' => (Value::Null, &s[4..]),
            _ => {
                let end = s
                    .find(|c: char| !(c.is_ascii_digit() || c == '-'))
                    .unwrap_or(s.len());
                (Value::Num(s[..end].parse().unwrap()), &s[end..])
            }
        }
    }

    impl Value {
        pub(super) fn get(&self, key: &str) -> &Value {
            let Value::Map(map) = self else {
                panic!("not a map")
            };
            &map.iter()
                .find(|(k, _)| k == key)
                .unwrap_or_else(|| panic!("no {key}"))
                .1
        }
        pub(super) fn string(&self) -> String {
            let Value::Str(s) = self else {
                panic!("not a string: {self:?}")
            };
            s.clone()
        }
        pub(super) fn boolean(&self) -> bool {
            let Value::Bool(b) = self else {
                panic!("not a bool")
            };
            *b
        }
        pub(super) fn strings(&self) -> Vec<String> {
            let Value::List(list) = self else {
                panic!("not a list")
            };
            list.iter().map(Value::string).collect()
        }
        pub(super) fn ints(&self) -> Vec<i64> {
            let Value::List(list) = self else {
                panic!("not a list")
            };
            list.iter()
                .map(|v| match v {
                    Value::Num(n) => *n,
                    other => panic!("not a number: {other:?}"),
                })
                .collect()
        }
        pub(super) fn pairs(&self) -> Vec<(String, String)> {
            let Value::Map(map) = self else {
                panic!("not a map")
            };
            let mut pairs: Vec<(String, String)> =
                map.iter().map(|(k, v)| (k.clone(), v.string())).collect();
            pairs.sort();
            pairs
        }
    }
}
