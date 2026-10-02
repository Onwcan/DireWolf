//! Running a checked executable to completion (M5a, ADR-0047 §4): the
//! container runtime, for one lifecycle step.
//!
//! The same launch as a `process_start`'s — the descriptor the authority
//! checked, re-proved by the caller, executed by the launch helper with an
//! empty environment but the one the caller built, its limits, its own
//! process group and no inherited descriptor — and then, instead of a table
//! entry, a wait: both streams drained to their bounds, the leader's exit
//! observed through its pidfd without reaping it, its group killed, the
//! leader reaped, and both drains joined, all before one deadline. What comes
//! back is the complete bounded output and how the process ended, or why
//! there is none.
//!
//! Nothing here chooses a program: the caller built the argv from typed
//! values, and the executable is the authority's.

use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::process::ExitStatusExt as _;
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use dwk_proto::brokerp::BrokerRefusal;
use rustix::process::{Pid, PidfdFlags, Signal, WaitId, WaitIdOptions};

use super::fdcheck;
use super::launch::{self, Program};

/// How often the wait looks for an exit and at the deadline.
const TICK: Duration = Duration::from_millis(5);

/// How long the drains may take to reach end of file after the process
/// ended, beyond the deadline.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// How much of each stream a run keeps, and when it must be over.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Bounds {
    /// The most stdout bytes kept; the rest is read and discarded.
    pub(crate) stdout: usize,
    /// The most stderr bytes kept.
    pub(crate) stderr: usize,
    /// When the process is killed if it has not ended.
    pub(crate) deadline: Instant,
}

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ended {
    /// It exited with this code.
    Exited(u8),
    /// A signal ended it.
    Signaled(u8),
    /// The deadline passed and it was killed.
    TimedOut,
}

/// A completed run.
#[derive(Debug)]
pub(crate) struct Completed {
    /// How it ended.
    pub(crate) ended: Ended,
    /// Its stdout, at most the bound.
    pub(crate) stdout: Vec<u8>,
    /// Whether stdout was longer than the bound.
    pub(crate) stdout_cut: bool,
    /// Its stderr, at most the bound.
    pub(crate) stderr: Vec<u8>,
}

/// Why a run has no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    /// Provably nothing was executed.
    Refused(BrokerRefusal),
    /// The program may have run and nothing proves what it did.
    Unconfirmed,
}

/// One stream's bounded contents.
struct Drained {
    stdout: bool,
    kept: Vec<u8>,
    cut: bool,
}

fn drain(reader: impl std::io::Read, stdout: bool, limit: usize, sent: &mpsc::Sender<Drained>) {
    let mut reader = reader;
    let mut kept = Vec::new();
    let mut cut = false;
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let read = match reader.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let bytes = chunk.get(..read).unwrap_or_default();
        let room = limit.saturating_sub(kept.len());
        if bytes.len() > room {
            cut = true;
        }
        kept.extend_from_slice(bytes.get(..room.min(bytes.len())).unwrap_or_default());
    }
    let _ = sent.send(Drained { stdout, kept, cut });
}

fn exited(pidfd: &OwnedFd) -> bool {
    matches!(
        rustix::process::waitid(
            WaitId::PidFd(pidfd.as_fd()),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        ),
        Ok(Some(_))
    )
}

fn kill_group(pidfd: &OwnedFd, pid: Pid) {
    let _ = rustix::process::pidfd_send_signal(pidfd, Signal::KILL);
    let _ = rustix::process::kill_process_group(pid, Signal::KILL);
}

/// Launch `program` from `executable` in `cwd` and wait for it, within
/// `bounds`. The caller has re-proved both descriptors.
///
/// # Errors
///
/// [`Failure::Refused`] when nothing ran; [`Failure::Unconfirmed`] when it
/// may have and its end or its output could not be observed.
pub(crate) fn run(
    helper: &Path,
    program: &Program,
    executable: OwnedFd,
    cwd: OwnedFd,
    bounds: &Bounds,
) -> Result<Completed, Failure> {
    // Nothing this process holds may reach the program.
    match fdcheck::inheritable() {
        Ok(found) if found.is_empty() => {}
        _ => return Err(Failure::Refused(BrokerRefusal::InheritedDescriptor)),
    }
    let launched = match launch::launch(helper, program, executable, cwd, None) {
        Ok(launched) => launched,
        Err(launch::Failure::Refused(refusal)) => return Err(Failure::Refused(refusal)),
        Err(launch::Failure::Unconfirmed) => return Err(Failure::Unconfirmed),
    };
    let launch::Launched {
        mut child,
        stdout,
        stderr,
    } = launched;
    let pid = Pid::from_child(&child);
    let Ok(pidfd) = rustix::process::pidfd_open(pid, PidfdFlags::empty()) else {
        // Unreaped, so its pid is still its own.
        let _ = rustix::process::kill_process_group(pid, Signal::KILL);
        let _ = child.kill();
        let _ = child.wait();
        return Err(Failure::Unconfirmed);
    };
    let (sent, received) = mpsc::channel();
    let (out_sent, err_sent) = (sent.clone(), sent);
    let (out_limit, err_limit) = (bounds.stdout, bounds.stderr);
    let drains = (
        thread::Builder::new()
            .name("run-stdout".to_owned())
            .spawn(move || drain(stdout, true, out_limit, &out_sent)),
        thread::Builder::new()
            .name("run-stderr".to_owned())
            .spawn(move || drain(stderr, false, err_limit, &err_sent)),
    );
    if drains.0.is_err() || drains.1.is_err() {
        kill_group(&pidfd, pid);
        let _ = child.wait();
        return Err(Failure::Unconfirmed);
    }

    // The leader's end, seen without reaping it: its group id is still its
    // own while it is unreaped, so the group can be killed safely.
    let mut timed_out = false;
    while !exited(&pidfd) {
        if Instant::now() >= bounds.deadline {
            kill_group(&pidfd, pid);
            timed_out = true;
            break;
        }
        thread::sleep(TICK);
    }
    kill_group(&pidfd, pid);
    let status = child.wait();

    let mut out = None;
    let mut err = None;
    let until = bounds.deadline.max(Instant::now()) + DRAIN_GRACE;
    while out.is_none() || err.is_none() {
        let left = until.saturating_duration_since(Instant::now());
        match received.recv_timeout(left) {
            Ok(drained) if drained.stdout => out = Some(drained),
            Ok(drained) => err = Some(drained),
            Err(_) => return Err(Failure::Unconfirmed),
        }
    }
    let (Some(out), Some(err)) = (out, err) else {
        return Err(Failure::Unconfirmed);
    };
    let ended = if timed_out {
        Ended::TimedOut
    } else {
        match status {
            Ok(status) => match (status.code(), status.signal()) {
                (Some(code), _) => Ended::Exited(u8::try_from(code & 0xff).unwrap_or(u8::MAX)),
                (None, Some(signal)) => Ended::Signaled(u8::try_from(signal).unwrap_or(u8::MAX)),
                (None, None) => return Err(Failure::Unconfirmed),
            },
            Err(_) => return Err(Failure::Unconfirmed),
        }
    };
    Ok(Completed {
        ended,
        stdout: out.kept,
        stdout_cut: out.cut,
        stderr: err.kept,
    })
}
