//! The launch helper: `dwkd-broker exec-helper` (ADR-0045 §12). One launch,
//! then it **is** the target.
//!
//! Safe Rust cannot run code between `fork` and `exec` (`pre_exec` is
//! `unsafe`), so the child-only setup a launch needs happens in a process of
//! its own, which then replaces itself with the target:
//!
//! 1. its stderr is the control channel: take a close-on-exec copy, and
//!    prove the peer is the parent broker — same uid, pid = parent pid;
//! 2. receive one launch: `argv`, `envp`, and exactly three descriptors —
//!    the executable, the working directory, the stderr pipe;
//! 3. stderr := the stderr pipe (stdin is already `/dev/null`, stdout the
//!    stdout pipe);
//! 4. the fixed resource limits; `fchdir` to the working directory; the
//!    parent-death signal (`SIGKILL`: a target does not outlive the broker
//!    that supervises it); `no_new_privs`;
//! 5. no descriptor numbered 3 or higher may survive the exec, or refuse;
//! 6. write `X`, then `execveat(executable, "", argv, envp, AT_EMPTY_PATH)`.
//!
//! It evaluates nothing, opens no path of the launch's, reads no store and
//! accepts no second request. Run by anyone else, its stderr is not a socket
//! whose peer is its parent broker, and it exits having done nothing. Run by
//! a user who arranges that, it would execute a descriptor that user handed
//! it, with that user's own privileges: nothing the user could not do.

use std::ffi::CString;
use std::io::{IoSliceMut, Read as _, Write as _};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;

use dwk_proto::brokerp::{
    BrokerRefusal, PROCESS_RLIMIT_AS, PROCESS_RLIMIT_CORE, PROCESS_RLIMIT_CPU_SECONDS,
    PROCESS_RLIMIT_FSIZE, PROCESS_RLIMIT_NOFILE,
};
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags};
use rustix::process::{Resource, Rlimit};

/// The launch message's magic and version.
const MAGIC: &[u8; 5] = b"DWXH1";

/// The largest launch message: arguments (64 KiB, the authority's bound),
/// `argv[0]` (4 KiB), the environment and framing.
const MAX_SPEC: usize = 256 * 1024;

/// The most strings one launch carries: `argv[0]`, 128 arguments, and the
/// environment.
const MAX_STRINGS: usize = 256;

/// What one launch is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Spec {
    /// `argv`, `argv[0]` first.
    pub(super) argv: Vec<Vec<u8>>,
    /// `envp`: `NAME=value`.
    pub(super) envp: Vec<Vec<u8>>,
    /// Debug builds: abort immediately before `execveat` (crash point E5).
    pub(super) crash_before_exec: bool,
}

fn put_strings(out: &mut Vec<u8>, strings: &[Vec<u8>]) {
    out.extend_from_slice(
        &u32::try_from(strings.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for string in strings {
        out.extend_from_slice(
            &u32::try_from(string.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        out.extend_from_slice(string);
    }
}

/// The launch message: its length, then `DWXH1`, a flag byte, `argv`, `envp`.
pub(super) fn encode(spec: &Spec) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(MAGIC);
    body.push(u8::from(spec.crash_before_exec));
    put_strings(&mut body, &spec.argv);
    put_strings(&mut body, &spec.envp);
    let mut out = u32::try_from(body.len())
        .unwrap_or(u32::MAX)
        .to_be_bytes()
        .to_vec();
    out.extend_from_slice(&body);
    out
}

/// Take `n` bytes from the front of `cursor`.
fn take<'a>(cursor: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    let (head, tail) = (cursor.get(..n)?, cursor.get(n..)?);
    *cursor = tail;
    Some(head)
}

fn take_u32(cursor: &mut &[u8]) -> Option<usize> {
    let bytes: [u8; 4] = take(cursor, 4)?.try_into().ok()?;
    usize::try_from(u32::from_be_bytes(bytes)).ok()
}

fn take_strings(cursor: &mut &[u8]) -> Option<Vec<Vec<u8>>> {
    let count = take_u32(cursor)?;
    if count > MAX_STRINGS {
        return None;
    }
    let mut strings = Vec::with_capacity(count);
    for _ in 0..count {
        let len = take_u32(cursor)?;
        let string = take(cursor, len)?;
        if string.contains(&0) {
            return None;
        }
        strings.push(string.to_vec());
    }
    Some(strings)
}

/// Decode a launch message's body (after its length).
pub(super) fn decode(mut body: &[u8]) -> Option<Spec> {
    if take(&mut body, MAGIC.len())? != MAGIC {
        return None;
    }
    let flags = *take(&mut body, 1)?.first()?;
    let argv = take_strings(&mut body)?;
    let envp = take_strings(&mut body)?;
    (body.is_empty() && !argv.is_empty() && flags <= 1).then_some(Spec {
        argv,
        envp,
        crash_before_exec: flags == 1,
    })
}

/// What the control channel said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Handshake {
    /// `X`, then end of file: the target was executed.
    Executed,
    /// The helper stopped at `stage`.
    Failed {
        /// Where.
        stage: u8,
        /// The kernel's answer there, if any.
        errno: i32,
    },
}

/// The stages a helper reports failing at.
pub(super) mod stage {
    /// Receiving the launch.
    pub(in crate::process) const RECEIVE: u8 = 2;
    /// Installing the stderr pipe.
    pub(in crate::process) const STDERR: u8 = 3;
    /// A resource limit.
    pub(in crate::process) const RLIMIT: u8 = 4;
    /// The working directory.
    pub(in crate::process) const FCHDIR: u8 = 5;
    /// The parent-death signal, or the parent is gone.
    pub(in crate::process) const PARENT: u8 = 6;
    /// `no_new_privs`.
    pub(in crate::process) const PRIVS: u8 = 7;
    /// A descriptor would survive the exec.
    pub(in crate::process) const DESCRIPTORS: u8 = 8;
    /// `execveat` itself.
    pub(in crate::process) const EXEC: u8 = 9;
}

impl Handshake {
    /// Parse what was read up to end of file. `None` for anything else.
    pub(super) fn parse(bytes: &[u8]) -> Option<Self> {
        match bytes {
            [b'X'] => Some(Self::Executed),
            [b'X', b'F', stage, a, b, c, d] | [b'F', stage, a, b, c, d] => Some(Self::Failed {
                stage: *stage,
                errno: i32::from_be_bytes([*a, *b, *c, *d]),
            }),
            _ => None,
        }
    }
}

/// The broker's refusal for a helper that stopped at `stage`.
pub(super) const fn refusal(stage: u8) -> BrokerRefusal {
    match stage {
        stage::DESCRIPTORS => BrokerRefusal::InheritedDescriptor,
        stage::EXEC => BrokerRefusal::ExecFailed,
        _ => BrokerRefusal::ExecSetupFailed,
    }
}

/// The fixed limits, set soft = hard: the target cannot raise them.
/// `RLIMIT_NPROC` is deliberately absent: it counts every process of the
/// broker's real uid, not this target's, so it would either starve unrelated
/// processes or bound nothing (ADR-0045 §12; pids.max is M5's).
fn limits() -> [(Resource, u64); 5] {
    [
        (Resource::Nofile, PROCESS_RLIMIT_NOFILE),
        (Resource::Core, PROCESS_RLIMIT_CORE),
        (Resource::Fsize, PROCESS_RLIMIT_FSIZE),
        (Resource::Cpu, PROCESS_RLIMIT_CPU_SECONDS),
        (Resource::As, PROCESS_RLIMIT_AS),
    ]
}

/// Tell the broker where it stopped, and stop.
fn fail(control: &mut UnixStream, stage: u8, errno: i32) -> ExitCode {
    let mut record = vec![b'F', stage];
    record.extend_from_slice(&errno.to_be_bytes());
    let _ = control.write_all(&record);
    ExitCode::from(127)
}

fn errno_of(error: &std::io::Error) -> i32 {
    error.raw_os_error().unwrap_or(0)
}

/// Receive the launch message and its three descriptors.
fn receive(control: &UnixStream) -> Option<(Spec, [OwnedFd; 3])> {
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(3))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let mut first = vec![0u8; MAX_SPEC.saturating_add(4)];
    let received = rustix::net::recvmsg(
        control,
        &mut [IoSliceMut::new(&mut first)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )
    .ok()?;
    if received.flags.contains(ReturnFlags::CTRUNC) || received.bytes < 4 {
        return None;
    }
    let mut fds: Vec<OwnedFd> = Vec::new();
    for message in ancillary.drain() {
        if let RecvAncillaryMessage::ScmRights(received) = message {
            fds.extend(received);
        }
    }
    let [executable, cwd, stderr]: [OwnedFd; 3] = fds.try_into().ok()?;
    let mut data = first.get(..received.bytes)?.to_vec();
    let length = usize::try_from(u32::from_be_bytes(data.get(..4)?.try_into().ok()?)).ok()?;
    if length > MAX_SPEC {
        return None;
    }
    let want = length.checked_add(4)?;
    let mut reader = control;
    while data.len() < want {
        let mut chunk = vec![0u8; want - data.len()];
        let n = reader.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        data.extend_from_slice(chunk.get(..n)?);
    }
    if data.len() != want {
        return None;
    }
    let spec = decode(data.get(4..)?)?;
    Some((spec, [executable, cwd, stderr]))
}

/// The helper's whole life. Returns only when it did not execute a target.
pub(crate) fn run() -> ExitCode {
    // 1. The control channel: stderr, as the broker spawned it. A
    //    close-on-exec copy is what signals the exec; fd 2 becomes the
    //    target's stderr below.
    let Ok(control) = std::io::stderr().as_fd().try_clone_to_owned() else {
        return ExitCode::from(2);
    };
    let mut control = UnixStream::from(control);
    let parent = rustix::process::getppid();
    let authentic = rustix::net::sockopt::socket_peercred(&control)
        .is_ok_and(|cred| Some(cred.pid) == parent && cred.uid == rustix::process::geteuid());
    if !authentic {
        // Not launched by a broker: nothing is written, nothing is done.
        return ExitCode::from(2);
    }

    // 2. The launch.
    let Some((spec, [executable, cwd, stderr])) = receive(&control) else {
        return fail(&mut control, stage::RECEIVE, 0);
    };

    // 3. stderr: the pipe the broker drains.
    if let Err(errno) = nix::unistd::dup2_stderr(&stderr) {
        return fail(&mut control, stage::STDERR, errno_of(&errno.into()));
    }
    drop(stderr);

    // 4. Limits, directory, parent-death signal, no new privileges.
    for (resource, value) in limits() {
        let limit = Rlimit {
            current: Some(value),
            maximum: Some(value),
        };
        if let Err(errno) = rustix::process::setrlimit(resource, limit) {
            return fail(&mut control, stage::RLIMIT, errno.raw_os_error());
        }
    }
    if let Err(errno) = rustix::process::fchdir(&cwd) {
        return fail(&mut control, stage::FCHDIR, errno.raw_os_error());
    }
    drop(cwd);
    if let Err(errno) =
        rustix::process::set_parent_process_death_signal(Some(rustix::process::Signal::KILL))
    {
        return fail(&mut control, stage::PARENT, errno.raw_os_error());
    }
    // The broker may have died before the signal was armed.
    if rustix::process::getppid() != parent {
        return fail(&mut control, stage::PARENT, 0);
    }
    if let Err(errno) = rustix::thread::set_no_new_privs(true) {
        return fail(&mut control, stage::PRIVS, errno.raw_os_error());
    }

    // 5. Nothing numbered 3 or above may reach the target.
    match super::fdcheck::inheritable() {
        Ok(found) if found.is_empty() => {}
        Ok(_) => return fail(&mut control, stage::DESCRIPTORS, 0),
        Err(error) => return fail(&mut control, stage::DESCRIPTORS, errno_of(&error)),
    }

    // 6. The exec.
    let argv: Option<Vec<CString>> = spec
        .argv
        .into_iter()
        .map(|a| CString::new(a).ok())
        .collect();
    let envp: Option<Vec<CString>> = spec
        .envp
        .into_iter()
        .map(|e| CString::new(e).ok())
        .collect();
    let (Some(argv), Some(envp)) = (argv, envp) else {
        return fail(&mut control, stage::RECEIVE, 0);
    };
    // Crash point E5 (debug builds): stop before announcing the exec, so the
    // broker's handshake shows nothing was executed.
    #[cfg(debug_assertions)]
    if spec.crash_before_exec {
        std::process::abort();
    }
    // Between this byte and `execveat` lies a window a few instructions wide:
    // a SIGKILL landing exactly there (from root or the broker's own uid) would
    // read as an exec. ADR-0045 §12 states it.
    if control.write_all(b"X").is_err() {
        return ExitCode::from(127);
    }
    let errno = match nix::unistd::execveat(
        &executable,
        c"",
        &argv,
        &envp,
        nix::fcntl::AtFlags::AT_EMPTY_PATH,
    ) {
        Err(errno) => errno_of(&errno.into()),
        Ok(never) => match never {},
    };
    fail(&mut control, stage::EXEC, errno)
}

#[cfg(test)]
mod tests {
    use super::{Handshake, Spec, decode, encode, refusal, stage};
    use dwk_proto::brokerp::BrokerRefusal;

    #[test]
    fn a_launch_message_round_trips_and_nothing_else_decodes() {
        let spec = Spec {
            argv: vec![
                b"/usr/bin/printf".to_vec(),
                b"%s".to_vec(),
                b"$HOME; |*".to_vec(),
            ],
            envp: vec![b"PATH=/usr/bin".to_vec()],
            crash_before_exec: false,
        };
        let bytes = encode(&spec);
        assert_eq!(
            decode(bytes.get(4..).unwrap_or_default()),
            Some(spec.clone())
        );
        // Truncated, trailing bytes, a NUL, no argv[0]: nothing.
        let body = bytes.get(4..).unwrap_or_default();
        assert_eq!(decode(body.get(..body.len() - 1).unwrap_or_default()), None);
        let mut longer = body.to_vec();
        longer.push(0);
        assert_eq!(decode(&longer), None);
        let nul = Spec {
            argv: vec![b"/bin/x\0y".to_vec()],
            ..spec.clone()
        };
        assert_eq!(decode(encode(&nul).get(4..).unwrap_or_default()), None);
        let empty = Spec {
            argv: Vec::new(),
            ..spec
        };
        assert_eq!(decode(encode(&empty).get(4..).unwrap_or_default()), None);
    }

    #[test]
    fn the_handshake_is_exactly_one_of_its_forms() {
        assert_eq!(Handshake::parse(b"X"), Some(Handshake::Executed));
        assert_eq!(
            Handshake::parse(&[b'X', b'F', stage::EXEC, 0, 0, 0, 2]),
            Some(Handshake::Failed {
                stage: stage::EXEC,
                errno: 2
            })
        );
        assert_eq!(Handshake::parse(b""), None);
        assert_eq!(Handshake::parse(b"XX"), None);
        assert_eq!(
            refusal(stage::DESCRIPTORS),
            BrokerRefusal::InheritedDescriptor
        );
        assert_eq!(refusal(stage::EXEC), BrokerRefusal::ExecFailed);
        assert_eq!(refusal(stage::FCHDIR), BrokerRefusal::ExecSetupFailed);
    }
}
