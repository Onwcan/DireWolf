//! Process execution (M4d, [ADR-0045]): start the executable the authority
//! checked, supervise it, report on it, kill it. **Nothing here decides**: the
//! authority resolved the executable, hashed it, planned the call, passed
//! both gates and the host floor and recorded the intent before a single
//! byte reached this module.
//!
//! ```text
//! process_start   descriptors: [executable O_RDONLY, cwd O_RDONLY directory]
//!   re-prove      each descriptor's mode, kind and (st_dev, st_ino); the
//!                 executable's trust attributes, ELF magic and SHA-256,
//!                 read through the descriptor it will be executed from
//!   fd hygiene    no descriptor >= 3 survives exec (FD_CLOEXEC), or refuse
//!   helper        this binary, `exec-helper`, spawned with an empty
//!                 environment, stdin /dev/null, stdout the stdout pipe,
//!                 stderr the control socket, its own process group
//!   handoff       argv, envp and [executable, cwd, stderr pipe] by SCM_RIGHTS
//!   helper        stderr := pipe; rlimits; fchdir(cwd); death signal;
//!                 no_new_privs; fd hygiene again; "X";
//!                 execveat(executable, "", argv, envp, AT_EMPTY_PATH)
//!   handshake     the control socket is close-on-exec: EOF after "X" and no
//!                 failure record IS the exec -- until then only the helper ran
//!   supervise     pidfd; stdout and stderr drained concurrently, first N
//!                 bytes kept, every byte counted; wall clock; reap
//! process_status  no descriptor: the handle, and the generation that issued it
//! process_kill    no descriptor: SIGKILL to the process and its process group,
//!                 while it is unreaped (so neither id can be reused)
//! ```
//!
//! The table is in memory and bounded ([`MAX_PROCESSES`]). A restarted broker
//! is a new **generation**: it holds none of the previous one's processes,
//! and a handle naming the old generation is refused (`STALE_GENERATION`) —
//! never matched to a numeric pid that may have been reused. Its processes
//! received the parent-death signal when it died.
//!
//! [ADR-0045]: ../../../../docs/adr/0045-m4d-process-execution-broker.md

mod fdcheck;
pub(crate) mod helper;
mod launch;
mod supervise;
mod verify;

#[cfg(test)]
mod tests;

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher as _, Hasher as _};
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use dwk_proto::brokerp::{
    BrokerDone, BrokerGeneration, BrokerRefusal, Indeterminate, OutcomeResult,
    PROCESS_WALL_CLOCK_SECONDS, ProcessKillAuthorisation, ProcessKillDone,
    ProcessStartAuthorisation, ProcessStartDone, ProcessStatusAuthorisation, ProcessStatusDone,
};
use dwk_proto::wire::id::ProcessId;
use dwk_proto::wire::scalar::{ProcessState, StreamContent};

use supervise::Entry;

/// The most processes one broker instance holds: running, or ended and not
/// yet evicted. A launch into a full table of running processes is refused
/// (`PROCESS_TABLE_FULL`); an ended one is evicted, oldest first, to make
/// room.
pub(crate) const MAX_PROCESSES: usize = 8;

/// The process module of one broker instance.
pub(crate) struct Processes {
    generation: BrokerGeneration,
    table: Mutex<Vec<Arc<Entry>>>,
    /// The broker's own binary: the launch helper.
    helper: PathBuf,
    /// The authority's uid: with root, the only owner an executable may have.
    authority_uid: u32,
    /// How long a target may run before its process group is killed.
    wall_clock: Duration,
}

impl core::fmt::Debug for Processes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Processes")
            .field("generation", &self.generation.as_str())
            .finish_non_exhaustive()
    }
}

/// A fresh 128-bit generation: two words from the standard library's randomly
/// keyed hasher, which it keys from the operating system's random source.
fn new_generation() -> Option<BrokerGeneration> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut words = [0u64; 2];
    for (i, word) in words.iter_mut().enumerate() {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u32(std::process::id());
        hasher.write_u128(nanos);
        hasher.write_usize(i);
        *word = hasher.finish();
    }
    BrokerGeneration::new(format!("{:016x}{:016x}", words[0], words[1]))
}

impl Processes {
    /// The process module of this broker: a new generation, and the running
    /// binary as the launch helper.
    ///
    /// # Errors
    ///
    /// Why the helper binary cannot be named.
    pub(crate) fn new(authority_uid: u32) -> Result<Self, String> {
        let helper = std::env::current_exe()
            .map_err(|e| format!("cannot name the broker binary for the launch helper: {e}"))?;
        if helper.to_string_lossy().ends_with(" (deleted)") {
            return Err("the broker binary was replaced after it started".to_owned());
        }
        Self::with(
            helper,
            authority_uid,
            Duration::from_secs(PROCESS_WALL_CLOCK_SECONDS),
        )
    }

    /// The same, with an explicit helper binary and wall clock: this crate's
    /// unit tests only, whose own binary is the test harness and which must
    /// not wait ten minutes for a timeout. Unreachable from any build a user
    /// runs.
    #[cfg(test)]
    #[allow(
        clippy::panic,
        reason = "a test fixture that cannot be built is a failed test"
    )]
    pub(crate) fn for_tests(helper: PathBuf, authority_uid: u32, wall_clock: Duration) -> Self {
        Self::with(helper, authority_uid, wall_clock).unwrap_or_else(|e| panic!("{e}"))
    }

    fn with(helper: PathBuf, authority_uid: u32, wall_clock: Duration) -> Result<Self, String> {
        let generation =
            new_generation().ok_or_else(|| "a generation did not fit its type".to_owned())?;
        Ok(Self {
            generation,
            table: Mutex::new(Vec::new()),
            helper,
            authority_uid,
            wall_clock,
        })
    }

    /// This instance's generation.
    pub(crate) const fn generation(&self) -> &BrokerGeneration {
        &self.generation
    }

    fn table(&self) -> std::sync::MutexGuard<'_, Vec<Arc<Entry>>> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Room for one more: evict the oldest ended entry if the table is full.
    fn make_room(table: &mut Vec<Arc<Entry>>) -> bool {
        if table.len() < MAX_PROCESSES {
            return true;
        }
        match table.iter().position(|entry| entry.reaped()) {
            Some(index) => {
                let _ = table.remove(index);
                true
            }
            None => false,
        }
    }

    /// `broker.process_start`: re-prove, launch, confirm, supervise.
    pub(crate) fn start(
        &self,
        start: &ProcessStartAuthorisation,
        executable: OwnedFd,
        cwd: OwnedFd,
    ) -> OutcomeResult {
        {
            let mut table = self.table();
            if table
                .iter()
                .any(|entry| entry.process_id == start.process_id)
            {
                return OutcomeResult::Refused(BrokerRefusal::ProcessIdInUse);
            }
            if !Self::make_room(&mut table) {
                return OutcomeResult::Refused(BrokerRefusal::ProcessTableFull);
            }
        }
        if let Err(refusal) = verify::descriptors(start, &executable, &cwd, self.authority_uid) {
            return OutcomeResult::Refused(refusal);
        }
        // Nothing this process holds may reach the target: refuse rather than
        // leak it (a descriptor inherited without FD_CLOEXEC cannot be closed
        // without `unsafe`, so it is found, not fixed).
        match fdcheck::inheritable() {
            Ok(found) if found.is_empty() => {}
            Ok(found) => {
                crate::event(&format!("inherited_descriptors fds={found:?}"));
                return OutcomeResult::Refused(BrokerRefusal::InheritedDescriptor);
            }
            Err(_) => return OutcomeResult::Refused(BrokerRefusal::InheritedDescriptor),
        }
        crate::crash::point("process_before_helper");
        let launched = match launch::launch(&self.helper, start, executable, cwd) {
            Ok(launched) => launched,
            Err(launch::Failure::Refused(refusal)) => return OutcomeResult::Refused(refusal),
            Err(launch::Failure::Unconfirmed) => {
                return OutcomeResult::Indeterminate(Indeterminate::LaunchUnconfirmed);
            }
        };
        crate::crash::point("process_after_exec");
        let limit = usize::try_from(start.stream_limit.get()).unwrap_or(usize::MAX);
        let entry =
            supervise::supervise(start.process_id.clone(), launched, limit, self.wall_clock);
        match entry {
            Ok(entry) => {
                self.table().push(entry);
                OutcomeResult::done(BrokerDone::process_start(ProcessStartDone {
                    generation: self.generation.clone(),
                    state: ProcessState::Running,
                    exit_code: None,
                    signal: None,
                }))
            }
            // The target runs and could not be supervised: the broker cannot
            // say what it does next.
            Err(()) => OutcomeResult::Indeterminate(Indeterminate::LaunchUnconfirmed),
        }
    }

    /// The entry a handle names in this generation, or why none.
    fn find(
        &self,
        process_id: &ProcessId,
        generation: &BrokerGeneration,
    ) -> Result<Arc<Entry>, BrokerRefusal> {
        if generation != &self.generation {
            return Err(BrokerRefusal::StaleGeneration);
        }
        self.table()
            .iter()
            .find(|entry| &entry.process_id == process_id)
            .cloned()
            .ok_or(BrokerRefusal::UnknownProcess)
    }

    /// `broker.process_status`.
    pub(crate) fn status(&self, status: &ProcessStatusAuthorisation) -> OutcomeResult {
        let entry = match self.find(&status.process_id, &status.generation) {
            Ok(entry) => entry,
            Err(refusal) => return OutcomeResult::Refused(refusal),
        };
        let snapshot = entry.snapshot();
        let stream = |s: &supervise::StreamSnapshot| {
            Some(dwk_proto::brokerp::ProcessStreamSnapshot {
                content: StreamContent::from_bytes(&s.retained)?,
                observed: dwk_proto::wire::scalar::ByteCount::new(s.observed)?,
                truncated: s.observed > u64::try_from(s.retained.len()).unwrap_or(u64::MAX),
            })
        };
        let (Some(stdout), Some(stderr)) = (stream(&snapshot.stdout), stream(&snapshot.stderr))
        else {
            return OutcomeResult::Refused(BrokerRefusal::IoError);
        };
        let (state, exit_code, signal) = snapshot.state.wire();
        OutcomeResult::done(BrokerDone::process_status(ProcessStatusDone {
            state,
            exit_code,
            signal,
            timed_out: snapshot.timed_out,
            stdout,
            stderr,
        }))
    }

    /// `broker.process_kill`.
    pub(crate) fn kill(&self, kill: &ProcessKillAuthorisation) -> OutcomeResult {
        let entry = match self.find(&kill.process_id, &kill.generation) {
            Ok(entry) => entry,
            Err(refusal) => return OutcomeResult::Refused(refusal),
        };
        crate::crash::point("process_before_signal");
        match entry.kill() {
            Ok(outcome) => {
                crate::crash::point("process_after_signal");
                OutcomeResult::done(BrokerDone::process_kill(ProcessKillDone { outcome }))
            }
            Err(()) => OutcomeResult::Indeterminate(Indeterminate::SignalUnconfirmed),
        }
    }
}
