//! The workload supervisor (M5d.2, ADR-0052 §8): every workload this broker
//! generation started and has not yet forgotten, each run on its own thread.
//!
//! The broker serves one connection at a time (ADR-0050 §9 relies on it). A
//! workload's wall clock is up to ten minutes, and an exchange that waited
//! for it would hold every other brokered operation -- a measurement, a
//! destruction, a `net.http` hop, a host process's status -- behind it. So
//! a start is answered as soon as the environment is re-judged and the
//! executable proved, and the run continues here:
//!
//! | step | on | what the authority hears |
//! |---|---|---|
//! | reserve: no workload of this invocation, and no unended one of this environment, is held; room in the table | the exchange | `WORKLOAD_IN_USE`, `WORKLOAD_TABLE_FULL`: nothing ran |
//! | re-prove the runtime, re-judge the environment, prove the executable | the workload's thread | the refusal: nothing ran |
//! | the exchange says go -- or, past its deadline, never does | both | `done` with the generation; or `RUNTIME_UNAVAILABLE`: nothing ran |
//! | run, classify, `reap` | the workload's thread | `RUNNING`, to every collection until it ends |
//! | the ending is kept | the workload's thread | `ENDED` with it, to every collection after |
//!
//! **Nothing runs that a start did not answer for.** After its judgement the
//! workload's thread waits for the exchange's word, and an exchange that can
//! no longer answer in time never gives it. A start answered and lost on the
//! way is, to the authority, an indeterminate start: it records the workload
//! `UNKNOWN` and destroys the environment, which ends it (ADR-0052 §9).
//!
//! **Bounded.** At most [`MAX_SUPERVISED_WORKLOADS`] are held. A full table
//! evicts its oldest ended workload, and refuses a start when none has
//! ended. A workload's thread ends by [`WORKLOAD_SUPERVISION_SECONDS`] after
//! its start, its descriptors with it. One unended workload per environment:
//! `reap` ends every other process of an environment, a concurrent
//! workload's among them (OD-5).
//!
//! **One generation.** The table is in memory. A restarted broker holds
//! nothing of the previous one's: a collection naming another generation, or
//! a workload this one does not hold, is indeterminate -- nothing here can
//! say how it ended.
//!
//! **Spawning.** A workload's thread launches the runtime's client through
//! the launch helper, as an exchange does, under the same fork guard
//! (`crate::process::fork_guard`), so a launch from one never inherits a
//! descriptor another holds. The broker's exchange worker for `net.http` is
//! still started only by an exchange, one connection at a time: at most one
//! is alive (ADR-0050 §21, ADR-0053 D11).
//!
//! [`WORKLOAD_SUPERVISION_SECONDS`]: dwk_proto::brokerp::workload::WORKLOAD_SUPERVISION_SECONDS

use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use dwk_proto::brokerp::workload::{
    MAX_SUPERVISED_WORKLOADS, WorkloadCollectAuthorisation, WorkloadCollectDone, WorkloadProgress,
    WorkloadStartDone,
};
use dwk_proto::brokerp::{
    BrokerDone, BrokerGeneration, BrokerRefusal, Indeterminate, OutcomeResult,
};
use dwk_proto::wire::id::{EnvironmentId, InvocationId};

/// Where one held workload is.
#[derive(Debug, Clone)]
enum State {
    /// Its start is being judged: nothing runs yet.
    Judging,
    /// The start was answered and the run handed over: running, or not yet
    /// proved ended.
    Running,
    /// It ended, and this is what every collection answers.
    Ended(OutcomeResult),
}

/// One held workload.
#[derive(Debug)]
struct Slot {
    invocation: InvocationId,
    environment: EnvironmentId,
    state: Mutex<State>,
}

impl Slot {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn ended(&self) -> bool {
        matches!(*self.state(), State::Ended(_))
    }
}

type Table = Arc<Mutex<Vec<Arc<Slot>>>>;

fn lock(table: &Mutex<Vec<Arc<Slot>>>) -> MutexGuard<'_, Vec<Arc<Slot>>> {
    table.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What the workload's thread holds of its slot: it records the ending, or
/// -- when the run never began, or the thread ended without one -- forgets
/// the slot, so the environment may be used again and a collection is
/// indeterminate.
struct Held {
    table: Table,
    slot: Arc<Slot>,
}

impl Held {
    fn end(self, result: OutcomeResult) {
        *self.slot.state() = State::Ended(result);
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        if !self.slot.ended() {
            lock(&self.table).retain(|slot| !Arc::ptr_eq(slot, &self.slot));
        }
    }
}

/// The workload's side of its start: the judgement goes to the exchange, and
/// the exchange's word comes back.
#[derive(Debug)]
pub(crate) struct Gate {
    judged: SyncSender<Result<(), OutcomeResult>>,
    go: Receiver<()>,
}

impl Gate {
    /// Report the judgement. `true` only when it passed and the exchange,
    /// having answered for it, said go: the one way a workload runs.
    pub(crate) fn judged(self, judgement: Result<(), OutcomeResult>) -> bool {
        let passed = judgement.is_ok();
        if self.judged.send(judgement).is_err() || !passed {
            return false;
        }
        self.go.recv().is_ok()
    }
}

/// The workloads of one broker generation.
pub(crate) struct Workloads {
    generation: BrokerGeneration,
    table: Table,
}

impl core::fmt::Debug for Workloads {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Workloads")
            .field("generation", &self.generation.as_str())
            .field("held", &lock(&self.table).len())
            .finish()
    }
}

impl Workloads {
    /// An empty table, for the broker generation `generation`.
    pub(crate) fn new(generation: BrokerGeneration) -> Self {
        Self {
            generation,
            table: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// A slot for `invocation` in `environment`, or why there is none.
    fn reserve(
        &self,
        invocation: &InvocationId,
        environment: &EnvironmentId,
    ) -> Result<Arc<Slot>, BrokerRefusal> {
        let mut table = lock(&self.table);
        if table.iter().any(|slot| {
            &slot.invocation == invocation || (&slot.environment == environment && !slot.ended())
        }) {
            return Err(BrokerRefusal::WorkloadInUse);
        }
        if table.len() >= MAX_SUPERVISED_WORKLOADS {
            let Some(oldest) = table.iter().position(|slot| slot.ended()) else {
                return Err(BrokerRefusal::WorkloadTableFull);
            };
            let _ = table.remove(oldest);
        }
        let slot = Arc::new(Slot {
            invocation: invocation.clone(),
            environment: environment.clone(),
            state: Mutex::new(State::Judging),
        });
        table.push(Arc::clone(&slot));
        Ok(slot)
    }

    /// `broker.workload_start`'s answer: reserve a slot, hand `supervise` its
    /// own thread, and answer by `answer_by` with the judgement it reports
    /// through its [`Gate`]. `supervise` returns the ending once it ran, or
    /// `None` when it never did.
    pub(crate) fn start(
        &self,
        invocation: &InvocationId,
        environment: &EnvironmentId,
        answer_by: Instant,
        supervise: impl FnOnce(Gate) -> Option<OutcomeResult> + Send + 'static,
    ) -> OutcomeResult {
        let slot = match self.reserve(invocation, environment) {
            Ok(slot) => slot,
            Err(refusal) => return OutcomeResult::Refused(refusal),
        };
        let (judged, judgement) = mpsc::sync_channel(1);
        let (go, word) = mpsc::sync_channel(1);
        let held = Held {
            table: Arc::clone(&self.table),
            slot: Arc::clone(&slot),
        };
        let spawned = std::thread::Builder::new()
            .name("dwkd-workload".to_owned())
            .spawn(move || {
                if let Some(ended) = supervise(Gate { judged, go: word }) {
                    held.end(ended);
                }
            });
        if spawned.is_err() {
            // The closure, and the slot it held, are gone with the failure.
            return OutcomeResult::Refused(BrokerRefusal::ExecSetupFailed);
        }
        let wait = answer_by.saturating_duration_since(Instant::now());
        match judgement.recv_timeout(wait) {
            Ok(Ok(())) => {
                *slot.state() = State::Running;
                if go.send(()).is_ok() {
                    OutcomeResult::done(BrokerDone::workload_start(WorkloadStartDone {
                        generation: self.generation.clone(),
                    }))
                } else {
                    // The thread is gone without the word: it never ran.
                    OutcomeResult::Refused(BrokerRefusal::ExecSetupFailed)
                }
            }
            // Refused: nothing ran, and the environment is free at once --
            // before the thread's own clean-up, which the next start need
            // not wait for.
            Ok(Err(result)) => {
                self.forget(&slot);
                result
            }
            // Past the deadline, or the thread ended before judging: the
            // word is never given (`go` drops here), so nothing runs. A
            // judgement still under way reads, and runs nothing.
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                self.forget(&slot);
                OutcomeResult::Refused(BrokerRefusal::RuntimeUnavailable)
            }
        }
    }

    fn forget(&self, slot: &Arc<Slot>) {
        lock(&self.table).retain(|held| !Arc::ptr_eq(held, slot));
    }

    /// `broker.workload_collect`.
    pub(crate) fn collect(&self, collect: &WorkloadCollectAuthorisation) -> OutcomeResult {
        let unknown = OutcomeResult::Indeterminate(Indeterminate::WorkloadUnconfirmed);
        if collect.generation != self.generation {
            return unknown;
        }
        let Some(slot) = lock(&self.table)
            .iter()
            .find(|slot| slot.invocation == collect.invocation_id)
            .cloned()
        else {
            return unknown;
        };
        let state = slot.state().clone();
        match state {
            // A start not answered for has no workload to collect.
            State::Judging => unknown,
            State::Running => {
                OutcomeResult::done(BrokerDone::workload_collect(WorkloadCollectDone {
                    progress: WorkloadProgress::Running,
                    result: None,
                    never_ran: None,
                }))
            }
            State::Ended(result) => result,
        }
    }

    /// How many workloads are held. Unit tests only.
    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        lock(&self.table).len()
    }
}

#[cfg(test)]
#[path = "supervisor_tests.rs"]
mod tests;
