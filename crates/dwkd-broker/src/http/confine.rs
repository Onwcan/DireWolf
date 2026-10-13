//! The exchange worker's syscall filter (D11 hardening, ADR-0053 §5): what a
//! worker can still ask the kernel for once it may hold a credential.
//!
//! **Why.** A worker parses TLS and HTTP from an origin the broker does not
//! trust. A memory-safety bug in that path, in `rustls`, `ring` or the HTTP
//! framing, would run the attacker's code as the broker's uid: free to open a
//! new connection to anywhere the host can reach, to execute a program, to
//! signal or read another process of the broker's uid. The worker needs none
//! of that. It is handed a connection already made to a pinned address and a
//! pipe holding the credential; it reads, writes, allocates, and exits.
//!
//! **What.** A seccomp program, installed by the worker itself after its
//! hardening and before it can receive anything (`super::worker::serve`):
//!
//! * the architecture must be the one this broker was built for, and on
//!   `x86_64` the x32 calling convention is refused -- anything else **kills
//!   the process** (`SECCOMP_RET_KILL_PROCESS`): a second syscall table is
//!   never a way around the first;
//! * exactly the calls a hop was **measured** to make are allowed
//!   ([`ALLOWED`]), a few of them only with the arguments it was measured to
//!   pass ([`guarded`]): `fcntl` without `F_SETOWN` or `F_DUPFD` to a chosen
//!   number, `setsockopt` for the two socket timeouts, `mmap` and `mprotect`
//!   never executable, `tgkill` only of this process;
//! * every other call fails with `EPERM`: no `socket`, `connect`, `bind`,
//!   `listen` or `accept`; no `execve`, `fork`, `clone` or `vfork`; no
//!   `ptrace`, `process_vm_readv`, `pidfd_open` or `kill`; no `open`; no
//!   `setuid`, `unshare`, `setns` or `mount`; no `bpf`, `perf_event_open` or
//!   `io_uring`.
//!
//! The program is this module's, and it is what the tests evaluate
//! ([`evaluate`]): every syscall number, both architecture checks and every
//! argument rule. `seccompiler` contributes only the installation -- the one
//! call that hands the kernel a pointer, which this workspace's `unsafe`
//! policy leaves to a reviewed crate (TX051). Installation sets
//! `no_new_privs` and synchronises every thread of the process (`TSYNC`).
//!
//! **Proof, in every worker.** After installing it the worker attempts each
//! forbidden operation it can name harmlessly ([`attempt`]) and goes on only
//! if the kernel refused every one with `EPERM`; the broker then reads the
//! worker's `/proc` status itself before handing anything over
//! (`super::worker`). An unconfined process given the same attempts sees them
//! succeed or fail for another reason: the refusal is the filter's.

use std::os::fd::AsFd;

use rustix::io::Errno;
use seccompiler::sock_filter;

/// The architecture this broker was built for, as `seccomp_data.arch`
/// spells it (`AUDIT_ARCH_*`: the ELF machine, 64-bit, little-endian). Not
/// in `libc` 0.2.189; fixed ABI values from `linux/audit.h`.
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;
/// No reviewed program: [`program`] answers `None`, and no worker runs.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const AUDIT_ARCH: u32 = 0;

/// `x86_64`'s x32 convention: the same architecture value, the syscall
/// number with this bit set. Never legitimate here.
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

// Classic BPF, as `linux/filter.h` spells it.
const LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
const JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
const JGE_K: u16 = 0x35; // BPF_JMP | BPF_JGE | BPF_K
const JSET_K: u16 = 0x45; // BPF_JMP | BPF_JSET | BPF_K
const RET_K: u16 = 0x06; // BPF_RET | BPF_K

// `struct seccomp_data`: the syscall number, the architecture, then six
// 64-bit arguments; each argument's low word first (little-endian only:
// both supported architectures).
const DATA_NR: u32 = 0;
const DATA_ARCH: u32 = 4;
const fn arg_low(index: u32) -> u32 {
    16 + 8 * index
}

/// What the program answers.
const RET_ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
const RET_DENY: u32 = libc::SECCOMP_RET_ERRNO | EPERM;
const RET_KILL: u32 = libc::SECCOMP_RET_KILL_PROCESS;

/// `EPERM`, as the program's errno data.
const EPERM: u32 = 1;

/// A syscall number, for the program. Every Linux number fits; one that
/// did not would become a number no call has, which the program denies.
fn nr(number: libc::c_long) -> u32 {
    u32::try_from(number).unwrap_or(u32::MAX)
}

/// A small non-negative C constant (a command, a level, an option, a flag),
/// for the program -- `u32::MAX`, matching nothing, were it ever negative.
fn int(value: libc::c_int) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// The calls a hop makes after the filter is installed, with no argument
/// rule: measured on real workers (the `http` suites and the `net.http`
/// evidence, ADR-0053 §5). I/O on the descriptors it holds; memory; the
/// signal and exit paths of the standard library; the clock; `getrandom`.
pub(crate) const ALLOWED: &[(&str, libc::c_long)] = &[
    ("read", libc::SYS_read),
    ("write", libc::SYS_write),
    ("readv", libc::SYS_readv),
    ("writev", libc::SYS_writev),
    ("recvfrom", libc::SYS_recvfrom),
    ("sendto", libc::SYS_sendto),
    ("recvmsg", libc::SYS_recvmsg),
    ("sendmsg", libc::SYS_sendmsg),
    ("shutdown", libc::SYS_shutdown),
    ("close", libc::SYS_close),
    ("fstat", libc::SYS_fstat),
    ("getrandom", libc::SYS_getrandom),
    ("munmap", libc::SYS_munmap),
    ("mremap", libc::SYS_mremap),
    ("brk", libc::SYS_brk),
    ("madvise", libc::SYS_madvise),
    ("futex", libc::SYS_futex),
    ("sched_yield", libc::SYS_sched_yield),
    ("rt_sigprocmask", libc::SYS_rt_sigprocmask),
    ("rt_sigaction", libc::SYS_rt_sigaction),
    ("rt_sigreturn", libc::SYS_rt_sigreturn),
    ("sigaltstack", libc::SYS_sigaltstack),
    ("clock_gettime", libc::SYS_clock_gettime),
    ("getpid", libc::SYS_getpid),
    ("gettid", libc::SYS_gettid),
    ("restart_syscall", libc::SYS_restart_syscall),
    ("exit", libc::SYS_exit),
    ("exit_group", libc::SYS_exit_group),
];

/// One argument rule.
#[derive(Debug, Clone)]
enum Check {
    /// The argument's low word is one of these.
    AnyOf(u32, Vec<u32>),
    /// The argument's low word has none of these bits.
    Clear(u32, u32),
}

/// The calls allowed only with the arguments a hop passes.
fn guarded(own_pid: u32) -> Vec<(&'static str, libc::c_long, Vec<Check>)> {
    // `F_GETFD`, `F_SETFD`, `F_GETFL`, `F_SETFL`, `F_DUPFD_CLOEXEC`: never
    // `F_SETOWN` (a signal to another process), never `F_DUPFD` to a chosen
    // number.
    let fcntl = [
        libc::F_GETFD,
        libc::F_SETFD,
        libc::F_GETFL,
        libc::F_SETFL,
        libc::F_DUPFD_CLOEXEC,
    ]
    .map(int)
    .to_vec();
    let timeouts = vec![int(libc::SO_RCVTIMEO), int(libc::SO_SNDTIMEO)];
    let exec = int(libc::PROT_EXEC);
    vec![
        ("fcntl", libc::SYS_fcntl, vec![Check::AnyOf(1, fcntl)]),
        (
            "setsockopt",
            libc::SYS_setsockopt,
            vec![
                Check::AnyOf(1, vec![int(libc::SOL_SOCKET)]),
                Check::AnyOf(2, timeouts),
            ],
        ),
        ("mmap", libc::SYS_mmap, vec![Check::Clear(2, exec)]),
        ("mprotect", libc::SYS_mprotect, vec![Check::Clear(2, exec)]),
        (
            "tgkill",
            libc::SYS_tgkill,
            vec![Check::AnyOf(0, vec![own_pid])],
        ),
    ]
}

/// Where a jump goes.
#[derive(Debug, Clone, Copy)]
enum To {
    Next,
    /// Skip this many following instructions.
    Ahead(usize),
    Allow,
    Deny,
    Kill,
}

/// One instruction before its jumps are resolved.
#[derive(Debug, Clone, Copy)]
struct Op {
    code: u16,
    k: u32,
    jt: To,
    jf: To,
}

const fn load(offset: u32) -> Op {
    Op {
        code: LD_W_ABS,
        k: offset,
        jt: To::Next,
        jf: To::Next,
    }
}

const fn jump(code: u16, k: u32, jt: To, jf: To) -> Op {
    Op { code, k, jt, jf }
}

/// A guarded call: the number, then each rule in turn; any rule failing
/// denies, all holding allows. Control never falls out of the body: the
/// entry's false branch skips it, with the number still loaded.
fn block(number: u32, checks: &[Check]) -> Vec<Op> {
    let mut body = Vec::new();
    for (index, check) in checks.iter().enumerate() {
        let last = index + 1 == checks.len();
        match check {
            Check::AnyOf(arg, values) => {
                body.push(load(arg_low(*arg)));
                for (i, value) in values.iter().enumerate() {
                    let rest = values.len() - 1 - i;
                    let jt = if last { To::Allow } else { To::Ahead(rest) };
                    let jf = if rest == 0 { To::Deny } else { To::Next };
                    body.push(jump(JEQ_K, *value, jt, jf));
                }
            }
            Check::Clear(arg, mask) => {
                body.push(load(arg_low(*arg)));
                let jf = if last { To::Allow } else { To::Next };
                body.push(jump(JSET_K, *mask, To::Deny, jf));
            }
        }
    }
    let mut ops = vec![jump(JEQ_K, number, To::Next, To::Ahead(body.len()))];
    ops.extend(body);
    ops
}

/// The worker's program for this process (`own_pid` for `tgkill`), or
/// `None` on an architecture this broker has no reviewed program for.
#[must_use]
pub(crate) fn program(own_pid: u32) -> Option<Vec<sock_filter>> {
    if !cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
        return None;
    }
    let mut ops = vec![load(DATA_ARCH), jump(JEQ_K, AUDIT_ARCH, To::Next, To::Kill)];
    ops.push(load(DATA_NR));
    #[cfg(target_arch = "x86_64")]
    ops.push(jump(JGE_K, X32_SYSCALL_BIT, To::Kill, To::Next));
    for (_, number) in ALLOWED {
        ops.push(jump(JEQ_K, nr(*number), To::Allow, To::Next));
    }
    for (_, number, checks) in guarded(own_pid) {
        ops.extend(block(nr(number), &checks));
    }
    assemble(&ops)
}

/// Resolve the jumps. The program ends in `DENY` (where a call that matched
/// nothing falls), `ALLOW` and `KILL`; every jump is forward and fits a
/// byte, or there is no program.
fn assemble(ops: &[Op]) -> Option<Vec<sock_filter>> {
    let deny = ops.len();
    let allow = deny + 1;
    let kill = deny + 2;
    let resolve = |at: usize, to: To| -> Option<u8> {
        let target = match to {
            To::Next => at + 1,
            To::Ahead(skip) => at + 1 + skip,
            To::Allow => allow,
            To::Deny => deny,
            To::Kill => kill,
        };
        u8::try_from(target.checked_sub(at + 1)?).ok()
    };
    let mut out = Vec::with_capacity(ops.len() + 3);
    for (at, op) in ops.iter().enumerate() {
        out.push(sock_filter {
            code: op.code,
            jt: resolve(at, op.jt)?,
            jf: resolve(at, op.jf)?,
            k: op.k,
        });
    }
    for ret in [RET_DENY, RET_ALLOW, RET_KILL] {
        out.push(sock_filter {
            code: RET_K,
            jt: 0,
            jf: 0,
            k: ret,
        });
    }
    Some(out)
}

/// Install the worker's program on every thread of this process.
///
/// # Errors
///
/// No program for this architecture, or the kernel refused it: the worker
/// does not go on.
pub(crate) fn install() -> Result<(), &'static str> {
    let own =
        u32::try_from(rustix::process::getpid().as_raw_nonzero().get()).map_err(|_| "no pid")?;
    let program = program(own).ok_or("no reviewed syscall program for this architecture")?;
    seccompiler::apply_filter_all_threads(&program).map_err(|_| "the kernel refused the filter")
}

/// How the kernel answered one attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Answer {
    /// `EPERM`: refused, as the filter answers.
    Refused,
    /// Failed, for another reason (the errno).
    Failed(i32),
    /// It worked.
    Succeeded,
}

impl Answer {
    /// The answer, the attempt's result undone: a descriptor it made is
    /// closed here.
    fn of<T>(result: rustix::io::Result<T>) -> Self {
        match result {
            Ok(made) => {
                drop(made);
                Self::Succeeded
            }
            Err(Errno::PERM) => Self::Refused,
            Err(errno) => Self::Failed(errno.raw_os_error()),
        }
    }

    /// One byte on the worker's ready line: 0 refused, 1 succeeded, 2 failed
    /// otherwise.
    #[must_use]
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::Refused => 0,
            Self::Succeeded => 1,
            Self::Failed(_) => 2,
        }
    }
}

/// How many attempts [`attempt`] makes: the ready line carries one answer
/// for each, and the broker requires exactly this many.
pub(crate) const ATTEMPTS: usize = 14;

/// A path no attempt can find: under `/proc/self`, where nothing is created.
const NOWHERE: &str = "/proc/self/direwolf-confinement-attempt";

/// The forbidden operations a worker can attempt without effect, in order,
/// and how the kernel answered each. `control` is a connected stream
/// socket of the caller's (the worker's control channel; a test's
/// socket pair): connecting, binding, listening or accepting on it can only
/// fail. Every attempt that succeeds unconfined is undone at once (its
/// descriptor dropped); none touches another process.
///
/// Attempts that cannot be made without effect -- `fork`, `clone`, `ptrace`,
/// `process_vm_readv`, `mount`, `bpf`, `io_uring` -- are proved on the
/// program instead ([`evaluate`]).
pub(crate) fn attempt(control: &impl AsFd, ids: &Ids) -> Vec<(&'static str, Answer)> {
    let mut answers = network(control);
    answers.extend(beyond_the_network(control, ids));
    answers
}

/// The process's own identities, read **before** the filter is installed:
/// `getuid`, `geteuid` and `getppid` are not among the calls a hop makes,
/// so after it they are refused -- and `rustix` treats them as infallible.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Ids {
    own: rustix::process::Pid,
    parent: Option<rustix::process::Pid>,
    uid: rustix::process::Uid,
    euid: rustix::process::Uid,
}

impl Ids {
    /// This process's, now.
    #[must_use]
    pub(crate) fn now() -> Self {
        Self {
            own: rustix::process::getpid(),
            parent: rustix::process::getppid(),
            uid: rustix::process::getuid(),
            euid: rustix::process::geteuid(),
        }
    }
}

/// New network authority: a socket of any family, and a new peer, address
/// or listener on the one it holds.
fn network(control: &impl AsFd) -> Vec<(&'static str, Answer)> {
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
    let nowhere = SocketAddrUnix::new(NOWHERE);
    vec![
        (
            "socket-inet",
            Answer::of(rustix::net::socket(
                AddressFamily::INET,
                SocketType::STREAM,
                None,
            )),
        ),
        (
            "socket-inet6",
            Answer::of(rustix::net::socket(
                AddressFamily::INET6,
                SocketType::DGRAM,
                None,
            )),
        ),
        (
            "socket-unix",
            Answer::of(rustix::net::socket(
                AddressFamily::UNIX,
                SocketType::STREAM,
                None,
            )),
        ),
        (
            "socketpair",
            Answer::of(rustix::net::socketpair(
                AddressFamily::UNIX,
                SocketType::STREAM,
                SocketFlags::CLOEXEC,
                None,
            )),
        ),
        (
            "connect",
            Answer::of(
                nowhere
                    .as_ref()
                    .map_err(|e| *e)
                    .and_then(|addr| rustix::net::connect(control, addr)),
            ),
        ),
        (
            "bind",
            Answer::of(
                nowhere
                    .as_ref()
                    .map_err(|e| *e)
                    .and_then(|addr| rustix::net::bind(control, addr)),
            ),
        ),
        ("listen", Answer::of(rustix::net::listen(control, 1))),
        ("accept", Answer::of(rustix::net::accept(control))),
    ]
}

/// Execution, files, other processes, identity and namespaces. `unshare`
/// has no safe wrapper left (`rustix` deprecated it for `unshare_unsafe`):
/// `setns` stands for namespace changes here, and the program is proved to
/// refuse `unshare` as well ([`evaluate`]).
fn beyond_the_network(control: &impl AsFd, ids: &Ids) -> Vec<(&'static str, Answer)> {
    let own = ids.own;
    vec![
        ("execve", execute()),
        (
            "open",
            Answer::of(rustix::fs::open(
                "/proc/self/mem",
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )),
        ),
        (
            "pidfd_open",
            Answer::of(rustix::process::pidfd_open(
                own,
                rustix::process::PidfdFlags::empty(),
            )),
        ),
        (
            "kill",
            Answer::of(ids.parent.map_or(Err(Errno::SRCH), |parent| {
                rustix::process::test_kill_process(parent)
            })),
        ),
        (
            "setresuid",
            Answer::of(rustix::thread::set_thread_res_uid(
                ids.uid, ids.euid, ids.euid,
            )),
        ),
        (
            "setns",
            Answer::of(rustix::thread::move_into_link_name_space(
                control.as_fd(),
                None,
            )),
        ),
    ]
}

/// `execve` of a path that cannot exist: `ENOENT` unconfined, `EPERM` here.
fn execute() -> Answer {
    let path = c"/proc/self/direwolf-confinement-attempt";
    match nix::unistd::execv(path, &[path]) {
        Ok(never) => match never {},
        Err(nix::errno::Errno::EPERM) => Answer::Refused,
        Err(errno) => Answer::Failed(std::io::Error::from(errno).raw_os_error().unwrap_or(0)),
    }
}

// ---- the program, evaluated -------------------------------------------------

/// What the program answers for one call: the number, the architecture and
/// six arguments, by the same rules the kernel runs it by. The tests'
/// interpreter: every instruction this module emits, and nothing else.
#[cfg(test)]
pub(crate) fn evaluate(program: &[sock_filter], nr: u32, arch: u32, args: [u64; 6]) -> u32 {
    let word = |offset: u32| -> u32 {
        if offset == DATA_NR {
            return nr;
        }
        if offset == DATA_ARCH {
            return arch;
        }
        for (index, value) in (0u32..).zip(args) {
            if offset == arg_low(index) {
                return u32::try_from(value & 0xFFFF_FFFF).unwrap_or(0);
            }
            if offset == arg_low(index) + 4 {
                return u32::try_from(value >> 32).unwrap_or(0);
            }
        }
        unreachable!("an offset outside seccomp_data: {offset}")
    };
    let mut acc = 0u32;
    let mut pc = 0usize;
    loop {
        let Some(insn) = program.get(pc) else {
            unreachable!("the program ran off its end at {pc}")
        };
        let skip = |taken: bool| usize::from(if taken { insn.jt } else { insn.jf });
        match insn.code {
            LD_W_ABS => {
                acc = word(insn.k);
                pc += 1;
            }
            JEQ_K => pc += 1 + skip(acc == insn.k),
            JGE_K => pc += 1 + skip(acc >= insn.k),
            JSET_K => pc += 1 + skip(acc & insn.k != 0),
            RET_K => return insn.k,
            other => unreachable!("an instruction this module never emits: {other:#x}"),
        }
    }
}

#[cfg(test)]
#[path = "confine_tests.rs"]
mod tests;
