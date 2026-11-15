//! F-02's interleavings, for this crate's unit tests: another handle onto the
//! same store acts while an operation stands at one crash point -- the window
//! one server worker never opens and the store does not forbid.
//!
//! At its point the hook starts the other handle's work on a thread of its
//! own and waits, without sleeping on a guess, until either that work has
//! finished or it is held at the authority gate (ADR-0064); then the
//! operation goes on. Which of the two happened is kept: a held ending is
//! what the gate promises, a finished one is the window F-02 closed. A unit
//! test proves the authority's ordering with a fake broker; it does not
//! prove real-process concurrency, which the authority's server never has.
//!
//! [`Hold`] is the other direction: it stops one chosen thread at one crash
//! point -- an end of authority inside its section, before its transaction --
//! until the test releases it, so that what an effect does meanwhile can be
//! seen.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{JoinHandle, ThreadId};
use std::time::{Duration, Instant};

use super::gate::Gate;
use super::{CrashHook, CrashPoint, HookAction};

type Work = Box<dyn FnOnce() + Send>;

/// What another handle does once an operation reaches one point.
#[derive(Clone, Default)]
pub(crate) struct Meantime {
    work: Arc<Mutex<Option<Work>>>,
    gate: Arc<Mutex<Option<Arc<Gate>>>>,
    finished: Arc<AtomicBool>,
    held: Arc<AtomicBool>,
    thread: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl Meantime {
    /// The crash hook that interleaves at `at`, every other point passing.
    pub(crate) fn hook(&self, at: CrashPoint) -> CrashHook {
        let me = self.clone();
        Arc::new(move |point| {
            if point == at {
                me.interleave();
            }
            HookAction::Continue
        })
    }

    /// Watch `gate`: the store's, once the authority has started.
    pub(crate) fn watch(&self, gate: Arc<Gate>) {
        *self.gate.lock().unwrap() = Some(gate);
    }

    /// What the other handle does at the point, once.
    pub(crate) fn then(&self, work: impl FnOnce() + Send + 'static) {
        *self.work.lock().unwrap() = Some(Box::new(work));
    }

    /// Whether the other handle's work was held at the gate when the
    /// operation went on.
    pub(crate) fn held(&self) -> bool {
        self.held.load(Ordering::SeqCst)
    }

    /// Wait for the other handle's work to end.
    pub(crate) fn join(&self) {
        let thread = self.thread.lock().unwrap().take();
        if let Some(thread) = thread {
            thread.join().unwrap();
        }
    }

    fn interleave(&self) {
        let Some(work) = self.work.lock().unwrap().take() else {
            return;
        };
        let gate = self.gate.lock().unwrap().clone();
        let finished = Arc::clone(&self.finished);
        let thread = std::thread::spawn(move || {
            work();
            finished.store(true, Ordering::SeqCst);
        });
        *self.thread.lock().unwrap() = Some(thread);
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if self.finished.load(Ordering::SeqCst) {
                return;
            }
            if gate.as_ref().is_some_and(|gate| gate.endings_waiting() > 0) {
                self.held.store(true, Ordering::SeqCst);
                return;
            }
            assert!(
                Instant::now() < deadline,
                "the other handle neither finished nor waited at the gate"
            );
            std::thread::yield_now();
        }
    }
}

/// One thread stopped at one crash point until released.
#[derive(Default)]
pub(crate) struct Hold {
    armed: Mutex<Option<(CrashPoint, ThreadId)>>,
    reached: AtomicBool,
    go: AtomicBool,
}

impl Hold {
    /// The crash hook that stops each armed thread at its point; every other
    /// thread and point passes.
    pub(crate) fn hook(holds: Vec<Arc<Self>>) -> CrashHook {
        Arc::new(move |point| {
            for hold in &holds {
                hold.stop_if_armed(point);
            }
            HookAction::Continue
        })
    }

    /// Stop the calling thread the next time it reaches `at`.
    pub(crate) fn arm_here(&self, at: CrashPoint) {
        *self.armed.lock().unwrap() = Some((at, std::thread::current().id()));
    }

    /// Whether the armed thread stands at its point.
    pub(crate) fn reached(&self) -> bool {
        self.reached.load(Ordering::SeqCst)
    }

    /// Let it go on.
    pub(crate) fn release(&self) {
        self.go.store(true, Ordering::SeqCst);
    }

    fn stop_if_armed(&self, point: CrashPoint) {
        let mine = {
            let mut armed = self.armed.lock().unwrap();
            let here = (point, std::thread::current().id());
            if *armed == Some(here) {
                *armed = None;
                true
            } else {
                false
            }
        };
        if !mine {
            return;
        }
        self.reached.store(true, Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(60);
        while !self.go.load(Ordering::SeqCst) {
            assert!(
                Instant::now() < deadline,
                "a held thread was never released"
            );
            std::thread::yield_now();
        }
    }
}

/// Wait, without sleeping on a guess, until `condition` holds.
pub(crate) fn until(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !condition() {
        assert!(Instant::now() < deadline, "never happened: {what}");
        std::thread::yield_now();
    }
}
