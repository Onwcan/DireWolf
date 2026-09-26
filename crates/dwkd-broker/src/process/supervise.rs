//! Supervising a launched process (ADR-0045 §13, §14): its output, its wall
//! clock, its end — and the only two ways anything signals it.
//!
//! **Identity.** The target is this broker's own child, the leader of its own
//! process group (the helper was spawned into a new one, and `execveat`
//! keeps it). A `pidfd` is taken at launch. A pid and a process-group id
//! cannot be reused while the process they name is unreaped; so every
//! signal — the wall clock's, `process.kill`'s — is sent **under the lock the
//! reaper takes**, only while the process is unreaped, and a reaped process
//! is never signalled. There is no numeric pid on the wire, and none is ever
//! taken from one.
//!
//! **Output.** stdout and stderr are drained concurrently, each by its own
//! thread, for as long as anything holds the write end: the first
//! `stream_limit` bytes are kept, every byte is counted, and the rest is read
//! and discarded — so a process that writes more than is retained neither
//! blocks on a full pipe nor changes how it runs. The output is bytes;
//! nothing decodes it.
//!
//! **The end.** When the leader exits, the rest of its process group is sent
//! `SIGKILL` (the leader still unreaped, so the group id is still its own),
//! then the leader is reaped. At the wall clock, the leader and its group
//! are sent `SIGKILL` and the process is marked timed out. **Descendants that
//! left the group** — `setsid`, `setpgid`, a double fork — are not reached:
//! without cgroups (M5) there is no containment of a process tree, and none
//! is claimed.

use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::process::ExitStatusExt as _;
use std::process::Child;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use dwk_proto::wire::id::ProcessId;
use dwk_proto::wire::scalar::{KillOutcome, ProcessState};
use rustix::process::{Pid, PidfdFlags, Signal, WaitId, WaitIdOptions};

use super::launch::Launched;

/// How often the reaper looks for an exit and at the wall clock.
const TICK: Duration = Duration::from_millis(10);

/// One stream, as far as it has been read.
#[derive(Debug, Default)]
struct Stream {
    retained: Vec<u8>,
    limit: usize,
    observed: u64,
}

/// A copy of one stream's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StreamSnapshot {
    /// The first bytes, at most the bound.
    pub(super) retained: Vec<u8>,
    /// Every byte read so far.
    pub(super) observed: u64,
}

/// How a process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Lifecycle {
    /// Not yet reaped.
    Running,
    /// Exited with this code.
    Exited(u8),
    /// Ended by this signal.
    Signaled(u8),
}

impl Lifecycle {
    /// Its wire form: state, exit code, signal.
    pub(super) fn wire(
        self,
    ) -> (
        ProcessState,
        Option<dwk_proto::wire::scalar::ExitCode>,
        Option<dwk_proto::wire::scalar::SignalNumber>,
    ) {
        match self {
            Self::Running => (ProcessState::Running, None, None),
            Self::Exited(code) => (
                ProcessState::Exited,
                dwk_proto::wire::scalar::ExitCode::new(code),
                None,
            ),
            Self::Signaled(signal) => (
                ProcessState::Signaled,
                None,
                dwk_proto::wire::scalar::SignalNumber::new(signal),
            ),
        }
    }
}

/// A copy of a process's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Snapshot {
    /// Running, exited or signalled.
    pub(super) state: Lifecycle,
    /// Whether the wall clock ended it.
    pub(super) timed_out: bool,
    /// stdout.
    pub(super) stdout: StreamSnapshot,
    /// stderr.
    pub(super) stderr: StreamSnapshot,
}

/// What the reaper and the signallers share, under one lock.
#[derive(Debug)]
struct Control {
    child: Child,
    state: Lifecycle,
    timed_out: bool,
}

/// One supervised process.
#[derive(Debug)]
pub(crate) struct Entry {
    /// The authority's handle.
    pub(crate) process_id: ProcessId,
    /// The leader's pid, which is also its process group's id.
    pid: Pid,
    pidfd: OwnedFd,
    control: Mutex<Control>,
    stdout: Arc<Mutex<Stream>>,
    stderr: Arc<Mutex<Stream>>,
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Read `reader` to end of file into `stream`: keep the first `limit` bytes,
/// count every byte.
fn drain(mut reader: impl std::io::Read, stream: &Mutex<Stream>) {
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let read = match reader.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        let Some(bytes) = chunk.get(..read) else {
            return;
        };
        let mut stream = locked(stream);
        stream.observed = stream
            .observed
            .saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        let room = stream.limit.saturating_sub(stream.retained.len());
        let keep = bytes.get(..room.min(read)).unwrap_or_default();
        stream.retained.extend_from_slice(keep);
    }
}

impl Entry {
    /// Whether it has been reaped.
    pub(super) fn reaped(&self) -> bool {
        locked(&self.control).state != Lifecycle::Running
    }

    /// A copy of its state and output.
    pub(super) fn snapshot(&self) -> Snapshot {
        let (state, timed_out) = {
            let control = locked(&self.control);
            (control.state, control.timed_out)
        };
        let copy = |stream: &Mutex<Stream>| {
            let stream = locked(stream);
            StreamSnapshot {
                retained: stream.retained.clone(),
                observed: stream.observed,
            }
        };
        Snapshot {
            state,
            timed_out,
            stdout: copy(&self.stdout),
            stderr: copy(&self.stderr),
        }
    }

    /// Whether the leader has exited, without reaping it.
    fn exited(&self) -> bool {
        matches!(
            rustix::process::waitid(
                WaitId::PidFd(self.pidfd.as_fd()),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            ),
            Ok(Some(_))
        )
    }

    /// `SIGKILL` to the leader and its process group. Call only with the
    /// control lock held and the leader unreaped.
    fn kill_group(&self) -> Result<(), ()> {
        let direct = rustix::process::pidfd_send_signal(&self.pidfd, Signal::KILL);
        let group = rustix::process::kill_process_group(self.pid, Signal::KILL);
        // A group whose leader is its only (zombie) member, or already gone:
        // nothing left to signal is not a failure.
        match (direct, group) {
            (Ok(()) | Err(rustix::io::Errno::SRCH), Ok(()) | Err(rustix::io::Errno::SRCH)) => {
                Ok(())
            }
            _ => Err(()),
        }
    }

    /// `process.kill`: `SIGKILL` to the process and its group if it has not
    /// exited, or `ALREADY_EXITED`.
    ///
    /// # Errors
    ///
    /// The signal could not be sent: whether it was is unknown.
    pub(super) fn kill(&self) -> Result<KillOutcome, ()> {
        let control = locked(&self.control);
        if control.state != Lifecycle::Running || self.exited() {
            return Ok(KillOutcome::AlreadyExited);
        }
        self.kill_group()?;
        Ok(KillOutcome::Signaled)
    }

    /// The reaper: until the leader exits, watch the wall clock; then clear
    /// its group and reap it.
    fn reap(&self, deadline: Instant) {
        loop {
            {
                let mut control = locked(&self.control);
                if self.exited() {
                    // The leader is unreaped: its group id is still its own.
                    let _ = self.kill_group();
                    let status = control.child.wait();
                    control.state = match status {
                        Ok(status) => match (status.code(), status.signal()) {
                            (Some(code), _) => {
                                Lifecycle::Exited(u8::try_from(code & 0xff).unwrap_or(u8::MAX))
                            }
                            (None, Some(signal)) => {
                                Lifecycle::Signaled(u8::try_from(signal).unwrap_or(u8::MAX))
                            }
                            (None, None) => Lifecycle::Signaled(9),
                        },
                        Err(_) => Lifecycle::Signaled(9),
                    };
                    return;
                }
                if !control.timed_out && Instant::now() >= deadline {
                    let _ = self.kill_group();
                    control.timed_out = true;
                    crate::event(&format!(
                        "process_timed_out process={}",
                        self.process_id.as_str()
                    ));
                }
            }
            thread::sleep(TICK);
        }
    }
}

/// Take a launched process under supervision: its pidfd, its drains, its
/// reaper.
///
/// # Errors
///
/// No pidfd or no thread: the process was killed and reaped, and the caller
/// cannot say what it did before that.
pub(super) fn supervise(
    process_id: ProcessId,
    launched: Launched,
    stream_limit: usize,
    wall_clock: Duration,
) -> Result<Arc<Entry>, ()> {
    let Launched {
        mut child,
        stdout,
        stderr,
    } = launched;
    let pid = Pid::from_child(&child);
    let Ok(pidfd) = rustix::process::pidfd_open(pid, PidfdFlags::empty()) else {
        // Unreaped, so its pid is still its own.
        let _ = child.kill();
        let _ = child.wait();
        return Err(());
    };
    let new_stream = || {
        Arc::new(Mutex::new(Stream {
            limit: stream_limit,
            ..Stream::default()
        }))
    };
    let entry = Arc::new(Entry {
        process_id,
        pid,
        pidfd,
        control: Mutex::new(Control {
            child,
            state: Lifecycle::Running,
            timed_out: false,
        }),
        stdout: new_stream(),
        stderr: new_stream(),
    });
    let deadline = Instant::now() + wall_clock;
    let started = [
        {
            let stream = Arc::clone(&entry.stdout);
            thread::Builder::new()
                .name("process-stdout".to_owned())
                .spawn(move || drain(stdout, &stream))
                .is_ok()
        },
        {
            let stream = Arc::clone(&entry.stderr);
            thread::Builder::new()
                .name("process-stderr".to_owned())
                .spawn(move || drain(stderr, &stream))
                .is_ok()
        },
        {
            let reaper = Arc::clone(&entry);
            thread::Builder::new()
                .name("process-reaper".to_owned())
                .spawn(move || reaper.reap(deadline))
                .is_ok()
        },
    ];
    if started.iter().all(|ok| *ok) {
        Ok(entry)
    } else {
        let mut control = locked(&entry.control);
        if control.state == Lifecycle::Running {
            let _ = entry.kill_group();
            let _ = control.child.wait();
            control.state = Lifecycle::Signaled(9);
        }
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Stream, drain};
    use std::sync::Mutex;

    #[test]
    fn a_drain_keeps_the_first_bytes_and_counts_them_all() {
        let stream = Mutex::new(Stream {
            limit: 5,
            ..Stream::default()
        });
        let input: Vec<u8> = (0..=255u8).cycle().take(300_000).collect();
        drain(input.as_slice(), &stream);
        let stream = stream
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(stream.retained, vec![0, 1, 2, 3, 4]);
        assert_eq!(stream.observed, 300_000);
        let empty = Mutex::new(Stream {
            limit: 5,
            ..Stream::default()
        });
        drain(&b""[..], &empty);
        let empty = empty
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(empty.retained.is_empty());
        assert_eq!(empty.observed, 0);
    }
}
