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

use std::collections::HashMap;
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

/// `fs.suid_dumpable` here, which must be one under which `execve` starts
/// an image its uid cannot read closed to that uid: 0 (not dumpable) or 2
/// (dumpable by root only). Under 1 the image starts dumpable by that uid,
/// as though readable -- a host whose start-up window `posture` leaves to
/// Yama alone -- and these cases have nothing to show.
fn closing_suid_dumpable() -> u8 {
    let text = std::fs::read_to_string("/proc/sys/fs/suid_dumpable").unwrap_or_default();
    match text.trim() {
        "0" => 0,
        "2" => 2,
        other => panic!(
            "NOT EXERCISED: fs.suid_dumpable is {other:?} here; an image its uid cannot read \
             starts closed to that uid only under 0 or 2"
        ),
    }
}

/// The holder: this test's child, which starts `<binary> http-worker` as its
/// own traced child -- its stderr a socket pair whose peer is the holder, so
/// the worker's peer check passes as it does for its broker -- and holds it
/// at the stop a traced `execve` raises, before the new image's first
/// instruction. There, as its tracer since before `execve`, it reads the
/// registers and peeks at the instruction they point to. Detached into a
/// stop -- untraced, still before that instruction -- it tries each way into
/// the worker's memory as its parent: an ancestor, which Yama 1 lets
/// through, so only the worker's dumpability decides. A worker it could
/// attach to is killed where it stands; any other is let go, and its ready
/// line read. Test-only, written for each run.
const HOLDER: &str = r#"
import ctypes, os, platform, signal, socket, sys
libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.restype = ctypes.c_long
TRACEME, PEEKDATA, ATTACH, DETACH, GETREGSET, NT_PRSTATUS = 0, 2, 16, 17, 0x4204, 1
PC = {"x86_64": 16 * 8, "aarch64": 32 * 8}[platform.machine()]
class IoVec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]
def ptrace(request, pid, addr=0, data=0):
    ctypes.set_errno(0)
    libc.ptrace(ctypes.c_int(request), ctypes.c_int(pid), ctypes.c_void_p(addr), ctypes.c_void_p(data))
    return "ok" if ctypes.get_errno() == 0 else str(ctypes.get_errno())
def stopped(pid, sig, flags=0):
    _, status = os.waitpid(pid, flags)
    if not (os.WIFSTOPPED(status) and os.WSTOPSIG(status) == sig):
        print(f"error=not-stopped-by-{sig}-but-{status}")
        sys.exit(1)
binary, ready_len = sys.argv[1], int(sys.argv[2])
ours, theirs = socket.socketpair()
null = os.open(os.devnull, os.O_RDWR)
pid = os.fork()
if pid == 0:
    try:
        os.dup2(null, 0)
        os.dup2(null, 1)
        os.dup2(theirs.fileno(), 2)
        if ptrace(TRACEME, 0) == "ok":
            os.execve(binary, [binary, "http-worker"], {})
    finally:
        os._exit(127)
theirs.close()
os.close(null)
seen = {}
stopped(pid, signal.SIGTRAP)
mem = os.stat(f"/proc/{pid}/mem")
seen["owner"] = mem.st_uid
seen["mode"] = oct(mem.st_mode & 0o7777)
regs = ctypes.create_string_buffer(1024)
iov = IoVec(ctypes.addressof(regs), 1024)
seen["regs"] = ptrace(GETREGSET, pid, NT_PRSTATUS, ctypes.addressof(iov))
pc = int.from_bytes(regs.raw[PC:PC + 8], "little")
seen["peek"] = ptrace(PEEKDATA, pid, pc)
seen["detach"] = ptrace(DETACH, pid, 0, signal.SIGSTOP)
stopped(pid, signal.SIGSTOP, os.WUNTRACED)
with open(f"/proc/{pid}/status") as status:
    seen["tracer"] = next(l.split()[1] for l in status if l.startswith("TracerPid:"))
try:
    os.close(os.open(f"/proc/{pid}/mem", os.O_RDONLY))
    seen["open"] = "ok"
except OSError as error:
    seen["open"] = str(error.errno)
buf = ctypes.create_string_buffer(8)
local, remote = IoVec(ctypes.addressof(buf), 8), IoVec(pc, 8)
ctypes.set_errno(0)
read = libc.process_vm_readv(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
seen["vm"] = "ok" if read == 8 else str(ctypes.get_errno())
seen["attach"] = ptrace(ATTACH, pid)
if seen["attach"] == "ok":
    os.kill(pid, signal.SIGKILL)
    while True:
        _, status = os.waitpid(pid, 0)
        if os.WIFEXITED(status) or os.WIFSIGNALED(status):
            break
    seen["ready"] = "none"
else:
    os.kill(pid, signal.SIGCONT)
    ours.settimeout(10)
    line = b""
    while len(line) < ready_len:
        chunk = ours.recv(ready_len - len(line))
        if not chunk:
            break
        line += chunk
    seen["ready"] = "R" if len(line) == ready_len and line[:1] == b"R" else "none"
    seen["at_exec"] = line[1] if len(line) > 1 else "none"
    ours.close()
    _, status = os.waitpid(pid, 0)
    seen["exit"] = os.WEXITSTATUS(status) if os.WIFEXITED(status) else f"signal-{os.WTERMSIG(status)}"
print(" ".join(f"{key}={value}" for key, value in seen.items()))
"#;

/// What `HOLDER` saw of a worker of `binary` held at its first instruction.
#[allow(clippy::unwrap_used)]
fn held_at_exec(binary: &Path) -> HashMap<String, String> {
    let dir = std::env::temp_dir().join(format!("dw-d11-holder-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("holder.py");
    std::fs::write(&script, HOLDER).unwrap();
    let mut command = Command::new("/usr/bin/python3");
    command
        .arg(&script)
        .arg(binary)
        .arg(vouch::ready_len(ATTEMPTS).to_string())
        .stdin(Stdio::null());
    let output = {
        let _fork = crate::process::fork_guard();
        command.output().unwrap()
    };
    let _ = std::fs::remove_dir_all(&dir);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        output.status.success(),
        "{text} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    text.split_whitespace()
        .filter_map(|item| item.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

/// What a held worker shows when `execve` closed it to this uid: its
/// `/proc/<pid>/mem` root's; the tracer it had since before `execve` keeps
/// the registers but reads no memory (`EIO`); untraced, its own parent --
/// the ancestor Yama allows -- refused by `open`, `process_vm_readv` and
/// `PTRACE_ATTACH`; and, let go, a worker that confined itself, handed
/// nothing, and began with `fs.suid_dumpable`'s dumpability.
fn assert_closed_at_exec(seen: &HashMap<String, String>, suid_dumpable: u8) {
    let at = |key: &str| seen.get(key).map_or("", String::as_str);
    assert_eq!(at("owner"), "0", "root's: {seen:?}");
    assert_eq!(at("mode"), "0o600", "{seen:?}");
    assert_eq!(at("regs"), "ok", "{seen:?}");
    assert_eq!(at("peek"), libc::EIO.to_string(), "{seen:?}");
    assert_eq!(at("tracer"), "0", "untraced when observed: {seen:?}");
    for way in ["open", "vm", "attach"] {
        let errno = at(way).parse::<i32>().unwrap_or(0);
        assert!(refused_access(errno), "{way}: {seen:?}");
    }
    assert_eq!(at("ready"), "R", "{seen:?}");
    assert_eq!(at("at_exec"), suid_dumpable.to_string(), "{seen:?}");
    assert_eq!(at("exit"), "4", "handed nothing, it ends: {seen:?}");
}

/// The control: a binary this uid can read starts its worker dumpable by
/// this uid -- the state `fs.suid_dumpable` 1 gives an unreadable one too
/// (`begin_new_exec`) -- and, held at its first instruction, its parent
/// reads its memory every way and attaches to it. Only the worker's own
/// hardening closes that, after the window; hence the broker requires the
/// window closed besides (`posture`).
#[test]
#[allow(clippy::unwrap_used)]
fn a_readable_binary_starts_its_worker_open_to_its_uid() {
    let scope = yama();
    assert!(
        scope.is_none_or(|s| s <= 1),
        "NOT EXERCISED: Yama {scope:?} refuses even a parent; the control needs 0 or 1"
    );
    let _one = one_worker_test();
    let seen = held_at_exec(&broker_binary());
    let own = std::fs::metadata("/proc/self").unwrap().uid();
    let at = |key: &str| seen.get(key).map_or("", String::as_str);
    assert_eq!(at("owner"), own.to_string(), "its own uid's: {seen:?}");
    assert_eq!(at("tracer"), "0", "untraced when observed: {seen:?}");
    for way in ["regs", "peek", "open", "vm", "attach"] {
        assert_eq!(at(way), "ok", "{way}: {seen:?}");
    }
    d11(
        "readable-image-open-to-its-uid-at-exec",
        "dumpable-1-mem-own-uid-peek-open-vm-attach-ok",
    );
}

/// The kernel's rule itself, without root: a copy of the broker its uid
/// cannot read (mode 0111) starts its worker with `fs.suid_dumpable`'s
/// dumpability from `execve` -- 0 or 2, each closed to that uid. Held at
/// its first instruction, even its parent is refused every way in, and the
/// tracer it had since before `execve` reads none of its memory. This uid
/// owns the copy and could give the read bit back, so no deployment rests
/// on it: `posture` never counts it execute-only; the root-owned case below
/// is the deployment's.
#[test]
#[allow(clippy::unwrap_used)]
fn an_image_its_uid_cannot_read_starts_its_worker_closed_to_that_uid() {
    let suid_dumpable = closing_suid_dumpable();
    let _one = one_worker_test();
    let dir = broker_binary()
        .parent()
        .unwrap()
        .join(format!("dw-d11-unreadable-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let copy = dir.join("dwkd-broker");
    std::fs::copy(broker_binary(), &copy).unwrap();
    std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o111)).unwrap();
    let unreadable = std::fs::File::open(&copy).is_err();
    let counted = crate::posture::read(&copy).execute_only;
    let seen = held_at_exec(&copy);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(unreadable, "unreadable by this uid");
    assert!(!counted, "this uid's own: never execute-only");
    assert_closed_at_exec(&seen, suid_dumpable);
    d11(
        "unreadable-image-closed-to-its-uid-at-exec",
        &format!(
            "suid_dumpable-{suid_dumpable}-at_exec-{suid_dumpable}-mem-root-0600-peek-eio-open-vm-attach-refused"
        ),
    );
}

/// Where `make d11-hardening-evidence`, given `DW_D11_PRIVILEGED=1`,
/// installs a root-owned, execute-only copy of the broker for one case, and
/// removes it after. A fixed path, not a variable: this module reads nothing
/// ambient (TX046).
const XONLY_BINARY: &str = "/usr/local/libexec/direwolf-d11-evidence/dwkd-broker";

/// The deployment: a root-owned, execute-only copy of the broker binary.
/// The broker's own posture counts it as closing the start-up window --
/// Yama aside -- because `fs.suid_dumpable` here is 0 or 2; held at its
/// first instruction its worker is closed to this uid as above; and run as
/// its broker runs it, it is confined before its hand-over and began with
/// that dumpability. 0 (not dumpable) and 2 (dumpable by root only) close
/// it alike: `ptrace(2)` refuses a target whose dumpable attribute is not 1
/// to every caller without `CAP_SYS_PTRACE`, and `/proc` gives its memory
/// to root. 2 differs only in a core dump, which the kernel then writes as
/// root, readable by root only -- and the worker holds nothing until it has
/// made itself not dumpable at all.
#[test]
#[ignore = "needs a root-owned execute-only broker binary: make d11-hardening-evidence with DW_D11_PRIVILEGED=1"]
#[allow(clippy::unwrap_used)]
fn an_execute_only_binary_starts_its_worker_closed_to_its_uid() {
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
    let suid_dumpable = closing_suid_dumpable();
    let posture = crate::posture::read(&binary);
    assert!(posture.execute_only, "{}", posture.describe());
    assert_eq!(
        posture.suid_dumpable,
        Some(suid_dumpable),
        "{}",
        posture.describe()
    );
    let without_yama = Posture {
        scope: Some(0),
        ..posture
    };
    assert!(
        without_yama.startup_window_closed(),
        "the binary alone closes the window: {}",
        without_yama.describe()
    );
    let _one = one_worker_test();
    assert_closed_at_exec(&held_at_exec(&binary), suid_dumpable);
    let at_exec = confined_before_hand_over(&binary);
    assert_eq!(
        at_exec, suid_dumpable,
        "began with fs.suid_dumpable's dumpability"
    );
    d11(
        "execute-only-image-closed-to-its-uid-at-exec",
        &format!(
            "suid_dumpable-{suid_dumpable}-at_exec-{suid_dumpable}-posture-closed-mem-root-0600-peek-eio-open-vm-attach-refused"
        ),
    );
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
        suid_dumpable: None,
    }
}

/// An execute-only binary where `fs.suid_dumpable` is 1: `execve` starts its
/// image dumpable by its own uid, as though readable.
fn execute_only_under_suid_dumpable_1(_: &Path) -> Posture {
    Posture {
        scope: Some(0),
        execute_only: true,
        suid_dumpable: Some(1),
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
    // An execute-only binary closes nothing where `fs.suid_dumpable` is 1.
    let unsealed = client_under(WorkerPolicy {
        startup: execute_only_under_suid_dumpable_1,
        ..test_policy()
    });
    let (port, request) = quiet_origin();
    assert_eq!(
        refused(run(&unsealed, &Hop::get(port), None)),
        BrokerRefusal::HttpWorkerFailed
    );
    assert!(heard_nothing(&request));
    assert!(workers_of_this_process().is_empty());
    d11(
        "execute-only-under-suid-dumpable-1-hop-refused",
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
