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
//! **A secret launch's output (M4e).** Each stream is redacted of the value
//! the launch delivered **as it is drained**, by a streaming matcher that
//! finds an occurrence split across reads: the retained bytes never hold the
//! value, so the table does not keep an echoed credential until eviction.
//! Once a stream's retention is full the rest is counted and discarded
//! unscanned. The broker's copy of the value lives exactly as long as the
//! drains -- until both streams reach end of file -- and is zeroed then.
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
use crate::secret::{Needle, Redactor};

/// How often the reaper looks for an exit and at the wall clock.
const TICK: Duration = Duration::from_millis(10);

/// One stream, as far as it has been read.
#[derive(Debug, Default)]
struct Stream {
    retained: Vec<u8>,
    limit: usize,
    observed: u64,
    /// Whether bytes were dropped at the bound.
    cut: bool,
}

impl Stream {
    /// Keep what fits of `bytes`; note a cut if anything does not.
    fn keep(&mut self, bytes: &[u8]) {
        let room = self.limit.saturating_sub(self.retained.len());
        if bytes.len() > room {
            self.cut = true;
        }
        let keep = bytes.get(..room.min(bytes.len())).unwrap_or_default();
        self.retained.extend_from_slice(keep);
    }

    fn full(&self) -> bool {
        self.retained.len() >= self.limit
    }
}

/// A copy of one stream's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StreamSnapshot {
    /// The first bytes, at most the bound.
    pub(super) retained: Vec<u8>,
    /// Every byte read so far.
    pub(super) observed: u64,
    /// Whether bytes were dropped at the bound.
    pub(super) cut: bool,
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
/// count every byte. With a `redactor` (a secret launch), the kept bytes are
/// the redacted stream's, and the read buffer is zeroed on the way out.
fn drain(mut reader: impl std::io::Read, stream: &Mutex<Stream>, redactor: Option<Redactor>) {
    let mut chunk = zeroize::Zeroizing::new(vec![0u8; 64 * 1024]);
    let mut redactor = redactor;
    loop {
        let read = match reader.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let Some(bytes) = chunk.get(..read) else {
            break;
        };
        let mut stream = locked(stream);
        stream.observed = stream
            .observed
            .saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        match redactor.as_mut() {
            // Retention full: the rest is counted, not scanned or kept.
            Some(_) if stream.full() => {
                if !bytes.is_empty() {
                    stream.cut = true;
                }
            }
            Some(redactor) => redactor.feed(bytes, &mut |out| stream.keep(out)),
            None => stream.keep(bytes),
        }
    }
    if let Some(mut redactor) = redactor {
        let mut stream = locked(stream);
        if stream.full() {
            // Whatever the matcher still holds is past the bound.
            let mut held = false;
            redactor.finish(&mut |out| held |= !out.is_empty());
            stream.cut |= held;
        } else {
            redactor.finish(&mut |out| stream.keep(out));
        }
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
                cut: stream.cut,
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
/// reaper. `needle`, for a secret launch, redacts both streams; the drains
/// hold the only references, so it is zeroed when both end.
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
    needle: Option<Arc<Needle>>,
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
    let stdout_redactor = needle.as_ref().map(|n| Redactor::new(Arc::clone(n)));
    let stderr_redactor = needle.map(Redactor::new);
    let started = [
        {
            let stream = Arc::clone(&entry.stdout);
            thread::Builder::new()
                .name("process-stdout".to_owned())
                .spawn(move || drain(stdout, &stream, stdout_redactor))
                .is_ok()
        },
        {
            let stream = Arc::clone(&entry.stderr);
            thread::Builder::new()
                .name("process-stderr".to_owned())
                .spawn(move || drain(stderr, &stream, stderr_redactor))
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
        drain(input.as_slice(), &stream, None);
        let stream = stream
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(stream.retained, vec![0, 1, 2, 3, 4]);
        assert_eq!(stream.observed, 300_000);
        assert!(stream.cut);
        let empty = Mutex::new(Stream {
            limit: 5,
            ..Stream::default()
        });
        drain(&b""[..], &empty, None);
        let empty = empty
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(empty.retained.is_empty());
        assert_eq!(empty.observed, 0);
        assert!(!empty.cut);
    }

    /// A reader that returns one byte per call: every internal read boundary
    /// falls inside the value.
    struct Trickle<'a>(&'a [u8]);

    impl std::io::Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match (self.0.split_first(), buf.first_mut()) {
                (Some((byte, rest)), Some(slot)) => {
                    *slot = *byte;
                    self.0 = rest;
                    Ok(1)
                }
                _ => Ok(0),
            }
        }
    }

    #[test]
    fn a_secret_launch_keeps_its_output_redacted_across_read_boundaries_and_at_the_bound() {
        use crate::secret::{Needle, Redactor};
        use dwk_proto::brokerp::SecretHandle;
        let handle = SecretHandle::new("deploy").unwrap_or_else(|| unreachable!());
        let value = b"v4lue-0f-the-s3cret";
        let needle = || {
            Needle::new(zeroize::Zeroizing::new(value.to_vec()), &handle)
                .unwrap_or_else(|| unreachable!())
        };
        let mut output = b"token=".to_vec();
        output.extend_from_slice(value);
        output.extend_from_slice(b"\n");
        for limit in [4096usize, 10, 6, 7] {
            let stream = Mutex::new(Stream {
                limit,
                ..Stream::default()
            });
            drain(Trickle(&output), &stream, Some(Redactor::new(needle())));
            let stream = stream
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let whole = b"token=[redacted:deploy]\n";
            let want = whole.get(..limit.min(whole.len())).unwrap_or_default();
            assert_eq!(stream.retained, want, "limit {limit}");
            assert_eq!(stream.observed, u64::try_from(output.len()).unwrap_or(0));
            assert_eq!(stream.cut, limit < whole.len(), "limit {limit}");
            // Never a byte run of the value, whole or in part past the prefix.
            assert!(!stream.retained.windows(value.len()).any(|w| w == value));
        }
    }
}
