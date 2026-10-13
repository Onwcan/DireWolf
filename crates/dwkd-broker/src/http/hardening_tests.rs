//! D11 hardening's evidence (ADR-0053 §18): real exchange workers, real
//! kernel state, real observers -- and stand-ins weakened one property at a
//! time, so each of the broker's checks is shown to be the one that refuses.
//!
//! Every case prints one `D11-EVIDENCE` line after its assertions held
//! (`make d11-hardening-evidence` requires each). Cases that need a host the
//! suite cannot make for itself -- a root-owned execute-only binary, Yama
//! lowered to 0, a cgroup with no swap -- are `#[ignore]`d and run by that
//! task where the host provides them; anywhere else they report NOT
//! EXERCISED, which is never a pass.

use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use dwk_proto::brokerp::http::HttpStatus;
use dwk_proto::brokerp::{BrokerRefusal, OutcomeResult};

use super::super::confine::ATTEMPTS;
use super::super::{Client, Deadlines, Prepared, WorkerPolicy, tls, vouch};
use super::{
    Act, Hop, broker_binary, credential, done, one_worker_test, origin, pipe_with, pki, refused,
    response, run, server, test_policy, workers_of_this_process,
};
use crate::config::{SwappableWorkers, TraceableWorkers};
use crate::egress::resolve::{FixtureResolver, Shared};
use crate::posture::{Posture, Swap};

/// One evidence line.
fn d11(case: &str, outcome: &str) {
    println!(
        "D11-EVIDENCE {{\"suite\":\"d11-hardening\",\"case\":\"{case}\",\"outcome\":\"{outcome}\"}}"
    );
}

/// Yama's setting on this host, `None` without Yama.
fn yama() -> Option<u8> {
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .ok()
        .and_then(|text| text.trim().parse().ok())
}

/// Start `binary http-worker` as this test's own child, its stderr our end
/// of a socket pair: its peer check passes, exactly as for its broker.
#[allow(clippy::unwrap_used)]
fn spawn_worker(binary: &Path) -> (Child, UnixStream) {
    let (ours, theirs) = UnixStream::pair().unwrap();
    let mut command = Command::new(binary);
    command
        .arg("http-worker")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(OwnedFd::from(theirs)));
    let child = {
        let _fork = crate::process::fork_guard();
        command.spawn().unwrap()
    };
    drop(command);
    (child, ours)
}

/// A worker's ready line, read whole.
#[allow(clippy::unwrap_used)]
fn ready_line(control: &UnixStream) -> Vec<u8> {
    control
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut line = vec![0u8; vouch::ready_len(ATTEMPTS)];
    let mut reader = control;
    reader.read_exact(&mut line).unwrap();
    line
}

/// One field of `/proc/<pid>/status`.
fn status_field(pid: u32, name: &str) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key == name).then(|| value.trim().to_owned())
        })
}

/// Whether an errno says the kernel refused access, as opposed to anything
/// that happens only once access was allowed (`EFAULT`, `ESRCH`, success).
const fn refused_access(errno: i32) -> bool {
    errno == libc::EPERM || errno == libc::EACCES
}

/// What the kernel showed of the real worker, waiting for its hand-over.
#[allow(clippy::unwrap_used)]
fn confined_before_hand_over(binary: &Path) -> u8 {
    let (mut child, control) = spawn_worker(binary);
    let line = ready_line(&control);
    let ready = vouch::judge_ready(&line, ATTEMPTS).unwrap();
    let pid = child.id();
    assert_eq!(status_field(pid, "Seccomp").as_deref(), Some("2"));
    assert_ne!(status_field(pid, "Seccomp_filters").as_deref(), Some("0"));
    assert_eq!(status_field(pid, "NoNewPrivs").as_deref(), Some("1"));
    assert_eq!(status_field(pid, "TracerPid").as_deref(), Some("0"));
    let mem = PathBuf::from(format!("/proc/{pid}/mem"));
    assert_eq!(
        std::fs::metadata(&mem).unwrap().uid(),
        0,
        "root's: not dumpable"
    );
    let error = std::fs::File::open(&mem).unwrap_err();
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied,
        "not even its parent"
    );
    assert_eq!(vouch::worker(pid), Ok(()));
    // Handed nothing, it ends having done nothing.
    drop(control);
    assert_eq!(child.wait().unwrap().code(), Some(4));
    ready.at_exec
}

/// The real worker, before it is handed anything: its own proof (every
/// forbidden attempt refused with `EPERM`) and the kernel's word for it --
/// a filter, `no_new_privs`, untraced, its memory closed even to its parent.
#[test]
fn a_real_worker_is_confined_untraced_and_closed_before_it_is_handed_anything() {
    let _one = one_worker_test();
    let at_exec = confined_before_hand_over(&broker_binary());
    d11(
        "worker-confined-before-hand-over",
        "seccomp-2-nnp-1-tracer-0-mem-root-owned",
    );
    d11(
        "worker-forbidden-attempts-refused",
        &format!("{ATTEMPTS}-of-{ATTEMPTS}-EPERM"),
    );
    // A binary the broker's uid can read starts dumpable; the worker closes
    // itself before it can be handed anything, which the case above shows.
    d11(
        "worker-image-at-exec-readable-binary",
        &format!("dumpable={at_exec}"),
    );
}

/// Where `make d11-hardening-evidence`, given `DW_D11_PRIVILEGED=1`,
/// installs a root-owned, execute-only copy of the broker for one case, and
/// removes it after. A fixed path, not a variable: this module reads nothing
/// ambient (TX046).
const XONLY_BINARY: &str = "/usr/local/libexec/direwolf-d11-evidence/dwkd-broker";

/// A root-owned, execute-only copy of the broker binary: the kernel makes
/// the worker's image non-dumpable at `execve` itself, before its first
/// instruction -- no window at all.
#[test]
#[ignore = "needs a root-owned execute-only broker binary: make d11-hardening-evidence with DW_D11_PRIVILEGED=1"]
#[allow(clippy::unwrap_used)]
fn an_execute_only_binary_starts_its_worker_non_dumpable() {
    let binary = PathBuf::from(XONLY_BINARY);
    assert!(
        binary.exists(),
        "NOT EXERCISED: no execute-only broker binary at {XONLY_BINARY}"
    );
    let meta = std::fs::metadata(&binary).unwrap();
    assert_eq!(meta.uid(), 0, "root-owned");
    assert_eq!(meta.mode() & 0o044, 0, "no read bit for group or others");
    assert!(
        std::fs::File::open(&binary).is_err(),
        "unreadable by this uid"
    );
    assert!(crate::posture::read(&binary).execute_only);
    let _one = one_worker_test();
    let at_exec = confined_before_hand_over(&binary);
    assert_eq!(at_exec, 0, "non-dumpable from execve");
    d11("execute-only-image-non-dumpable-at-exec", "dumpable=0");
}

/// What an observer process made of a target: each of `open
/// /proc/<pid>/mem`, `process_vm_readv` and `PTRACE_ATTACH` -- `ok`, or the
/// errno.
#[allow(clippy::unwrap_used)]
fn observe(observer_script: &Path, targets: &[u32]) -> Vec<Vec<(String, Result<(), i32>)>> {
    let mut command = Command::new("/usr/bin/python3");
    command.arg(observer_script);
    for pid in targets {
        command.arg(pid.to_string());
    }
    let output = {
        let _fork = crate::process::fork_guard();
        command.output().unwrap()
    };
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    text.lines()
        .map(|line| {
            line.split(' ')
                .map(|item| {
                    let (name, result) = item.split_once('=').unwrap();
                    let result = if result == "ok" {
                        Ok(())
                    } else {
                        Err(result.parse::<i32>().unwrap())
                    };
                    (name.to_owned(), result)
                })
                .collect()
        })
        .collect()
}

/// The observer: a separate process of this uid -- this test's child, so a
/// sibling of each target, never its ancestor -- attempting each way into
/// another process's memory. Test-only, written for each run.
const OBSERVER: &str = r#"
import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
class IoVec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]
def errno_of(ok):
    return "ok" if ok else str(ctypes.get_errno())
for arg in sys.argv[1:]:
    pid = int(arg)
    try:
        os.close(os.open(f"/proc/{pid}/mem", os.O_RDONLY))
        opened = "ok"
    except OSError as error:
        opened = str(error.errno)
    buf = ctypes.create_string_buffer(8)
    local = IoVec(ctypes.addressof(buf), 8)
    remote = IoVec(0x10000, 8)
    read = libc.process_vm_readv(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
    vm = "ok" if read >= 0 or ctypes.get_errno() == 14 else str(ctypes.get_errno())
    attached = libc.ptrace(16, pid, None, None) == 0
    attach = errno_of(attached)
    if attached:
        os.waitpid(pid, 0x40000000)
        libc.ptrace(17, pid, None, None)
    print(f"open={opened} vm={vm} attach={attach}")
"#;

/// A hostile process of the broker's own uid, against a real worker and
/// against an ordinary process of that uid (the control): the worker is
/// closed to it whatever Yama says; the control is closed only by Yama.
/// Where the hosted job lowers Yama to 0 the counterexample is shown: the
/// control opens, the worker still does not.
#[test]
#[allow(clippy::unwrap_used)]
fn a_same_uid_observer_cannot_reach_a_worker_whatever_yama_allows() {
    let _one = one_worker_test();
    let dir = std::env::temp_dir().join(format!("dw-d11-observer-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("observer.py");
    std::fs::write(&script, OBSERVER).unwrap();
    let (mut worker, control) = spawn_worker(&broker_binary());
    let _ = ready_line(&control);
    let mut ordinary = {
        let _fork = crate::process::fork_guard();
        Command::new("/usr/bin/sleep")
            .arg("30")
            .stdin(Stdio::null())
            .spawn()
            .unwrap()
    };
    let seen = observe(&script, &[worker.id(), ordinary.id()]);
    let [at_worker, at_control] = &seen[..] else {
        panic!("two targets observed: {seen:?}");
    };
    for (way, result) in at_worker {
        assert!(
            result.is_err_and(refused_access),
            "the worker by {way}: {result:?}"
        );
    }
    // The ancestor -- this test -- may open the ordinary process's memory
    // (dumpable, a descendant) but not the worker's: non-dumpability, not
    // ancestry, is what closes the worker.
    std::fs::File::open(format!("/proc/{}/mem", ordinary.id())).unwrap();
    assert!(std::fs::File::open(format!("/proc/{}/mem", worker.id())).is_err());
    let scope = yama();
    if scope.is_some_and(|s| s >= 1) {
        for (way, result) in at_control {
            assert!(
                result.is_err_and(refused_access),
                "Yama {scope:?}: the control by {way}: {result:?}"
            );
        }
        d11(
            "same-uid-observer-refused",
            &format!(
                "worker-refused-control-refused-by-yama-{}",
                scope.unwrap_or(0)
            ),
        );
    } else {
        for (way, result) in at_control {
            assert!(
                result.is_ok(),
                "Yama {scope:?}: the control by {way}: {result:?}"
            );
        }
        d11(
            "yama-0-counterexample",
            "control-readable-by-a-sibling-worker-refused",
        );
    }
    let _ = ordinary.kill();
    let _ = ordinary.wait();
    drop(control);
    let _ = worker.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A stand-in for a worker, weakened in exactly the ways `modes` lists:
/// `nnp` sets `no_new_privs`, `filter` installs an allow-everything filter,
/// `nondumpable` clears dumpability, `traced` makes its parent its tracer
/// (`PTRACE_TRACEME`), `lies` reports one forbidden attempt as not refused.
/// It writes a ready line, then records what it is handed in `out`.
const STAND_IN: &str = r#"#!/usr/bin/python3
import ctypes, json, os, socket, struct, sys
libc = ctypes.CDLL(None, use_errno=True)
MODES = set("@MODES@".split(","))
OUT = "@OUT@"
ATTEMPTS = @ATTEMPTS@
if "traced" in MODES:
    assert libc.ptrace(0, 0, None, None) == 0
if "nnp" in MODES:
    assert libc.prctl(38, 1, 0, 0, 0) == 0
if "filter" in MODES:
    insn = ctypes.create_string_buffer(struct.pack("HBBI", 0x06, 0, 0, 0x7FFF0000))
    class Prog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]
    prog = Prog(1, ctypes.addressof(insn))
    assert libc.prctl(22, 2, ctypes.byref(prog), 0, 0) == 0
if "nondumpable" in MODES:
    assert libc.prctl(4, 0, 0, 0, 0) == 0
answers = bytearray(ATTEMPTS)
if "lies" in MODES:
    answers[0] = 1
os.write(2, bytes([0x52, 1, ATTEMPTS]) + bytes(answers))
control = socket.socket(fileno=os.dup(2))
control.settimeout(8)
message, ancillary, _, _ = control.recvmsg(1 << 16, socket.CMSG_SPACE(16))
fds = sum(len(data) // 4 for level, kind, data in ancillary
          if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS)
with open(OUT, "w") as out:
    out.write(json.dumps({"fds": fds, "bytes": len(message)}))
"#;

/// The broker's own checks, each shown to be what refuses: stand-ins that
/// lack exactly one property -- a filter, `no_new_privs`, non-dumpability,
/// an untraced state, an honest ready line -- are handed nothing at all; a
/// stand-in that lacks none is handed its connection (the harness works).
#[test]
#[allow(clippy::unwrap_used)]
fn the_broker_hands_nothing_to_a_worker_it_cannot_vouch_for() {
    let _one = one_worker_test();
    let dir = std::env::temp_dir().join(format!("dw-d11-stand-in-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let authorisation = super::authorisation_for_worker_tests();
    let case = |name: &str, modes: &str| -> Option<String> {
        let out = dir.join(format!("{name}.json"));
        let script = dir.join(format!("{name}.py"));
        let text = STAND_IN
            .replace("@MODES@", modes)
            .replace("@OUT@", out.to_str().unwrap())
            .replace("@ATTEMPTS@", &ATTEMPTS.to_string());
        std::fs::write(&script, text).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Dialled by the broker's one dialler, as every hop's connection is.
        let socket = super::super::connect::dial(
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            port,
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        let prepared = Prepared {
            socket,
            credential: None,
        };
        let result = super::super::worker::exchange(
            &script,
            &tls::Trust::Production,
            &authorisation,
            prepared,
            Instant::now() + Duration::from_secs(2),
            &test_policy(),
        );
        assert_eq!(
            result,
            OutcomeResult::Refused(BrokerRefusal::HttpWorkerFailed),
            "{name}: no stand-in answers a hop"
        );
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut heard = Vec::new();
        let _ = peer.read_to_end(&mut heard);
        assert!(heard.is_empty(), "{name}: nothing reached the origin");
        std::fs::read_to_string(&out).ok()
    };
    // The control: every property present -- vouched for, and handed its
    // connection.
    let handed = case("complete", "nnp,filter,nondumpable").unwrap_or_default();
    assert!(
        handed.contains("\"fds\": 1"),
        "the complete stand-in: {handed}"
    );
    for (name, modes, lacks) in [
        ("nothing", "", "everything"),
        ("unfiltered", "nnp,nondumpable", "a filter"),
        ("dumpable", "nnp,filter", "non-dumpability"),
        (
            "traced",
            "traced,nnp,filter,nondumpable",
            "an untraced state",
        ),
        (
            "lies",
            "nnp,filter,nondumpable,lies",
            "an honest ready line",
        ),
    ] {
        assert_eq!(
            case(name, modes),
            None,
            "{name}: lacking {lacks}, it was handed something"
        );
        d11(
            &format!("stand-in-without-{}", lacks.replace(' ', "-")),
            "handed-nothing",
        );
    }
    d11("stand-in-complete", "handed-its-connection");
    let _ = std::fs::remove_dir_all(&dir);
}

fn window_open(_: &Path) -> Posture {
    Posture {
        scope: Some(0),
        execute_only: false,
    }
}

fn swappable(_: Option<u32>) -> Swap {
    Swap::Possible
}

fn capped(_: Option<u32>) -> Swap {
    Swap::Capped("/d11.slice/broker.service".to_owned())
}

fn broker_capped_worker_not(pid: Option<u32>) -> Swap {
    if pid.is_none() {
        capped(None)
    } else {
        Swap::Possible
    }
}

/// A client whose host facts are `policy`'s.
#[allow(clippy::unwrap_used)]
fn client_under(policy: WorkerPolicy) -> Client {
    let resolver: Shared = std::sync::Arc::new(
        FixtureResolver::parse("resolve origin.test 127.0.0.1\nallow 127.0.0.1\n").unwrap(),
    );
    let trust = tls::Trust::evidence(&pki().join("ca.pem")).unwrap();
    Client::new(
        resolver,
        trust,
        Deadlines::PRODUCTION,
        broker_binary(),
        policy,
    )
}

/// An origin that answers 204, and what it heard.
fn quiet_origin() -> (u16, std::sync::mpsc::Receiver<Vec<u8>>) {
    origin(
        server("origin", &[b"http/1.1"]),
        vec![Act::Write(response("HTTP/1.1 204 No Content\n\n", b""))],
    )
}

/// The host is read before every hop: an open start-up window refuses any
/// hop, and memory that can reach swap refuses a credential hop -- before
/// the credential is read, and again for the worker before it is handed
/// anything -- unless acknowledged.
#[test]
#[allow(clippy::unwrap_used)]
fn the_host_is_read_before_every_hop_and_refuses_what_it_cannot_vouch_for() {
    const VALUE: &[u8] = b"h0st-p0sture-v4lue-0123456789";
    let _one = one_worker_test();
    let heard_nothing = |request: &std::sync::mpsc::Receiver<Vec<u8>>| {
        request
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_default()
            .is_empty()
    };
    // 1. The start-up window open: nothing dialled, no worker.
    let open = client_under(WorkerPolicy {
        startup: window_open,
        ..test_policy()
    });
    let (port, request) = quiet_origin();
    assert_eq!(
        refused(run(&open, &Hop::get(port), None)),
        BrokerRefusal::HttpWorkerFailed
    );
    assert!(heard_nothing(&request));
    assert!(workers_of_this_process().is_empty());
    d11(
        "startup-window-open-hop-refused",
        "HTTP_WORKER_FAILED-nothing-sent",
    );
    let acknowledged = client_under(WorkerPolicy {
        startup: window_open,
        traceable: TraceableWorkers::Permitted,
        ..test_policy()
    });
    let (port, _request) = quiet_origin();
    let got = done(run(&acknowledged, &Hop::get(port), None));
    assert_eq!(got.status.map(HttpStatus::get), Some(204));
    // 2. Swappable memory, a credential hop: refused before the broker reads
    // the value -- the pipe still holds all of it.
    let strict = client_under(WorkerPolicy {
        swap: swappable,
        swappable: SwappableWorkers::Refused,
        ..test_policy()
    });
    let (port, request) = quiet_origin();
    let mut hop = Hop::get(port);
    hop.credential = Some(credential());
    let secret = pipe_with(VALUE);
    let kept = rustix::io::dup(&secret).unwrap();
    assert_eq!(
        refused(run(&strict, &hop, Some(secret))),
        BrokerRefusal::HttpWorkerFailed
    );
    let mut unread = Vec::new();
    std::fs::File::from(kept).read_to_end(&mut unread).unwrap();
    assert_eq!(unread, VALUE, "the broker never read the credential");
    assert!(heard_nothing(&request));
    d11(
        "swappable-credential-hop-refused",
        "credential-unread-nothing-sent",
    );
    // The same host, a hop without a credential: performed.
    let (port, _request) = quiet_origin();
    let got = done(run(&strict, &Hop::get(port), None));
    assert_eq!(got.status.map(HttpStatus::get), Some(204));
    d11("swappable-plain-hop-performed", "204");
    // 3. The broker capped, its worker not: the worker is handed nothing.
    let split = client_under(WorkerPolicy {
        swap: broker_capped_worker_not,
        swappable: SwappableWorkers::Refused,
        ..test_policy()
    });
    let (port, request) = quiet_origin();
    let mut hop = Hop::get(port);
    hop.credential = Some(credential());
    assert_eq!(
        refused(run(&split, &hop, Some(pipe_with(VALUE)))),
        BrokerRefusal::HttpWorkerFailed
    );
    assert!(heard_nothing(&request));
    d11(
        "swappable-worker-handed-nothing",
        "HTTP_WORKER_FAILED-nothing-sent",
    );
    // 4. Both capped: the credential hop is performed.
    let protected = client_under(WorkerPolicy {
        swap: capped,
        swappable: SwappableWorkers::Refused,
        ..test_policy()
    });
    let (port, request) = quiet_origin();
    let mut hop = Hop::get(port);
    hop.credential = Some(credential());
    let got = done(run(&protected, &hop, Some(pipe_with(VALUE))));
    assert_eq!(got.status.map(HttpStatus::get), Some(204));
    let sent = String::from_utf8(request.recv().unwrap()).unwrap();
    assert!(sent.contains(&format!(
        "authorization: Bearer {}\r\n",
        std::str::from_utf8(VALUE).unwrap()
    )));
    d11("capped-credential-hop-performed", "204-credential-sent");
}

/// This process's cgroup, and the swap counters there.
fn own_cgroup() -> Option<String> {
    std::fs::read_to_string("/proc/self/cgroup")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("0::").map(str::to_owned))
}

fn cgroup_file(cgroup: &str, file: &str) -> String {
    std::fs::read_to_string(format!("/sys/fs/cgroup{cgroup}/{file}"))
        .unwrap_or_default()
        .trim()
        .to_owned()
}

/// Under a real cgroup that allows no swap (the task runs this under
/// `systemd-run --scope -p MemorySwapMax=0`), a credential hop is performed
/// by the production policy, its worker in the same capped cgroup.
#[test]
#[ignore = "needs a no-swap cgroup: make d11-hardening-evidence runs it under MemorySwapMax=0"]
#[allow(clippy::unwrap_used)]
fn a_credential_hop_runs_under_a_real_no_swap_cap() {
    const VALUE: &[u8] = b"c4pped-v4lue-0123456789";
    let Swap::Capped(cap) = crate::posture::swap_of(None) else {
        panic!(
            "NOT EXERCISED: this process's memory is not capped: {:?}",
            crate::posture::swap_of(None)
        );
    };
    assert_eq!(cgroup_file(&cap, "memory.swap.max"), "0");
    let _one = one_worker_test();
    let client = client_under(WorkerPolicy::of_host(
        TraceableWorkers::Refused,
        SwappableWorkers::Refused,
    ));
    let (port, request) = origin(
        server("origin", &[b"http/1.1"]),
        vec![
            Act::Sleep(Duration::from_secs(2)),
            Act::Write(response("HTTP/1.1 204 No Content\n\n", b"")),
        ],
    );
    let mut hop = Hop::get(port);
    hop.credential = Some(credential());
    let answer = thread::spawn(move || run(&client, &hop, Some(pipe_with(VALUE))));
    request.recv_timeout(Duration::from_secs(20)).unwrap();
    let [worker] = workers_of_this_process()[..] else {
        panic!("one worker holds the hop");
    };
    assert_eq!(
        crate::posture::swap_of(Some(worker)),
        Swap::Capped(cap.clone())
    );
    let got = done(answer.join().unwrap());
    assert_eq!(got.status.map(HttpStatus::get), Some(204));
    let own = own_cgroup().unwrap_or_default();
    d11(
        "credential-hop-under-a-real-no-swap-cap",
        &format!(
            "204-worker-capped-at-{cap}-swap-current-{}",
            cgroup_file(&own, "memory.swap.current")
        ),
    );
}

/// Outside any cap, on a host with swap, the production policy refuses a
/// credential hop -- read from the real host, not a stand-in.
#[test]
#[ignore = "reads this host's swap: make d11-hardening-evidence runs it outside any cap"]
#[allow(clippy::unwrap_used)]
fn on_a_host_with_swap_the_production_policy_refuses_a_credential_hop() {
    let swap = crate::posture::swap_of(None);
    if swap.protected() {
        d11(
            "host-swap-refusal",
            &format!("NOT-EXERCISED-{}", swap.describe()),
        );
        return;
    }
    let _one = one_worker_test();
    let client = client_under(WorkerPolicy::of_host(
        TraceableWorkers::Refused,
        SwappableWorkers::Refused,
    ));
    let (port, _request) = quiet_origin();
    let mut hop = Hop::get(port);
    hop.credential = Some(credential());
    assert_eq!(
        refused(run(&client, &hop, Some(pipe_with(b"h0st-v4lue-0123")))),
        BrokerRefusal::HttpWorkerFailed
    );
    d11("host-swap-refusal", "swap-possible-credential-hop-refused");
}

/// Memory pressure under a cap with no swap (the task runs this under
/// `MemoryMax` and `MemorySwapMax=0`): a process that outgrows the cgroup is
/// killed by the OOM killer and nothing of it is swapped.
#[test]
#[ignore = "needs a no-swap cgroup with a memory limit: make d11-hardening-evidence"]
#[allow(clippy::unwrap_used)]
fn memory_pressure_under_the_cap_ends_in_the_oom_killer_never_in_swap() {
    let Swap::Capped(_) = crate::posture::swap_of(None) else {
        panic!("NOT EXERCISED: not under a no-swap cgroup");
    };
    let cgroup = own_cgroup().unwrap();
    let limit = cgroup_file(&cgroup, "memory.max");
    assert_ne!(limit, "max", "a memory limit is set");
    let kills = |text: String| {
        text.lines()
            .find_map(|l| l.strip_prefix("oom_kill "))
            .and_then(|n| n.trim().parse::<u64>().ok())
            .unwrap_or(0)
    };
    let before = kills(cgroup_file(&cgroup, "memory.events"));
    let status = {
        let _fork = crate::process::fork_guard();
        Command::new("/usr/bin/python3")
            // Written, not merely mapped: every page of a gigabyte touched.
            .args(["-c", "x = b'x' * (1 << 30); print(len(x))"])
            .stdout(Stdio::null())
            .status()
            .unwrap()
    };
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&status),
        Some(9),
        "killed: {status:?}"
    );
    let after = kills(cgroup_file(&cgroup, "memory.events"));
    assert!(after > before, "the OOM killer acted: {before} -> {after}");
    assert_eq!(cgroup_file(&cgroup, "memory.swap.current"), "0");
    d11(
        "memory-pressure-under-cap",
        &format!(
            "oom-killed-swap-current-0-limit-{limit}-swap-events-{}",
            cgroup_file(&cgroup, "memory.swap.events").replace([' ', '\n'], "-")
        ),
    );
}

/// A hand-over cut short -- its length promised, nothing after it -- ends
/// the worker having been handed nothing, and doing nothing.
#[test]
#[allow(clippy::unwrap_used)]
fn a_worker_whose_control_channel_closes_ends_having_been_handed_nothing() {
    let _one = one_worker_test();
    let (mut child, mut control) = spawn_worker(&broker_binary());
    let _ = ready_line(&control);
    // A hand-over cut short: its length, and nothing after it.
    control.write_all(&[0, 0, 0, 64]).unwrap();
    drop(control);
    assert_eq!(child.wait().unwrap().code(), Some(4));
    d11("worker-cut-off-before-hand-over", "exit-4-handed-nothing");
}

/// The cost of a hop, measured (ADR-0053 §15): plain and credential hops,
/// each in its own hardened worker -- the filter, the proof, the vouching,
/// the host's posture read per hop -- against a local TLS origin. Run in
/// release by the checkpoint's benchmark beside the same measurement of the
/// design before it; prints `D11-BENCH` lines, asserts only that every hop
/// completed.
#[test]
#[ignore = "a measurement, not a check: run in release by the benchmark"]
#[allow(clippy::unwrap_used)]
fn d11_bench_hops() {
    const WARM: usize = 5;
    const MEASURED: usize = 60;
    let _one = one_worker_test();
    let client = client_under(test_policy());
    for carries in [false, true] {
        let mut micros = Vec::with_capacity(MEASURED);
        for round in 0..WARM + MEASURED {
            let (port, _request) = quiet_origin();
            let mut hop = Hop::get(port);
            let secret = carries.then(|| {
                hop.credential = Some(credential());
                pipe_with(b"b3nch-v4lue-0123456789")
            });
            let started = Instant::now();
            let got = done(run(&client, &hop, secret));
            let elapsed = started.elapsed();
            assert_eq!(got.status.map(HttpStatus::get), Some(204));
            if round >= WARM {
                micros.push(elapsed.as_micros());
            }
        }
        micros.sort_unstable();
        let at = |rank: usize| micros.get(rank).copied().unwrap_or(0);
        println!(
            "D11-BENCH {} n={} p50_us={} p90_us={} max_us={}",
            if carries { "credential" } else { "plain" },
            micros.len(),
            at(micros.len().checked_div(2).unwrap_or(0)),
            at((micros.len() * 9).checked_div(10).unwrap_or(0)),
            at(micros.len().saturating_sub(1))
        );
    }
}
