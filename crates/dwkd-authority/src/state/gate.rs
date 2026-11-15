//! The authority gate (F-02, [ADR-0064], Proposed): an end of authority is
//! serialised with every effect already decided.
//!
//! # The window it closes
//!
//! An effect is decided in one transaction -- the fence, the run, the
//! subject's standing, the key, both gates -- and its intent committed; the
//! broker is handed it afterwards, with no transaction open (ADR-0039,
//! ADR-0044 §10), and its outcome is recorded in a third. One server worker
//! never lets another request in between. The store does: every
//! [`super::Authority`] handle onto one state directory shares it, and a
//! second handle could end the decision's authority -- a revocation's first
//! phase (ADR-0063 §5), a lease taken over after its expiry or released, a
//! run released -- after the intent and before the hand-off. The broker then
//! performed an effect for a run already ended, and a revocation reported
//! `COMPLETE` with an effect of the revoked subject still to come.
//!
//! # Two kinds of section
//!
//! | section | from | to | who |
//! |---|---|---|---|
//! | **effect** | the transaction that decides it and records its intent | the transaction that records its outcome; the broker's hand-off between them | a file operation, a host launch, one `net.http` hop, a sandboxed launch's start |
//! | **ending** | its one transaction | its commit | a lease acquired (it may end another tenure), a lease released, a run released, a revocation's first phase |
//!
//! The two kinds exclude each other; neither excludes its own kind -- two
//! effects, or two endings, contend through SQLite as before. So an ending
//! commits only when no effect stands between its decision and its outcome,
//! and every effect that begins after it is decided by the fence and the run
//! it left: from an ending's commit nothing it ended reaches the broker, and
//! an effect that did reach it was decided, performed and recorded before.
//!
//! A sandboxed launch's section ends when the broker has started it: what
//! the workload does after is the environment's (ADR-0052 §8), and an ending
//! meanwhile marks the environment `DESTROYING` and the broker removes it, as
//! ADR-0063's two phases always did. An environment's preparation,
//! destruction and a staging reclamation are not effect sections: each is
//! undone, or is itself a clean-up, and each settles against the run's state
//! at its outcome (`environment::end_with_its_run`).
//!
//! # Lock order and bounded waiting
//!
//! A section is entered before any SQLite transaction and never while one is
//! open, and never from inside another (a debug build asserts it); its guard
//! is not `Send`, so it ends on the thread that began it. An effect section
//! holds at most one broker exchange, each within its own deadline; an ending
//! section holds one transaction and no broker exchange -- the destructions
//! an ending leaves are performed after it. An ending that waits holds back
//! every effect that has not begun, so endings are not starved. Every wait
//! ends at [`WAIT_LIMIT`]: past it the operation is refused
//! [`AuthorityError::Busy`] with nothing written -- it fails closed, as a
//! transaction past SQLite's busy timeout does.
//!
//! # What it is not
//!
//! Not durable: a crash ends every section, and recovery settles what an
//! interrupted one left (`reconcile_open`: `UNKNOWN`, never run again). Not
//! the store's lock: the state directory's lock keeps one process, and
//! `BEGIN IMMEDIATE` one writer. Not new concurrency: one server worker
//! never waits here.
//!
//! [ADR-0064]: ../../../../../docs/adr/0064-f02-authority-endings-serialised-with-decided-effects.md

use std::cell::Cell;
use std::marker::PhantomData;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use super::error::AuthorityError;

/// The longest any section waits to begin: comfortably past one broker
/// exchange's longest deadline (an environment's, 120 s) and the busy
/// timeouts of the transactions around it.
pub(crate) const WAIT_LIMIT: Duration = Duration::from_secs(300);

/// Which kind a section is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Effect,
    Ending,
}

/// Who is inside, and who waits.
#[derive(Debug, Default)]
struct Rooms {
    effects: u32,
    effects_waiting: u32,
    endings: u32,
    endings_waiting: u32,
}

/// The gate every handle onto one store shares.
#[derive(Debug)]
pub(crate) struct Gate {
    rooms: Mutex<Rooms>,
    changed: Condvar,
    limit: Duration,
}

thread_local! {
    /// Whether this thread is inside a section: sections do not nest.
    static INSIDE: Cell<bool> = const { Cell::new(false) };
}

/// One section, ended when it is dropped.
#[must_use = "a section ends when it is dropped"]
#[derive(Debug)]
pub(crate) struct Section {
    gate: Arc<Gate>,
    kind: Kind,
    /// Not `Send`: a section ends on the thread that began it.
    _thread: PhantomData<*const ()>,
}

impl Gate {
    /// A gate whose waits end at `limit`.
    pub(crate) fn new(limit: Duration) -> Self {
        Self {
            rooms: Mutex::new(Rooms::default()),
            changed: Condvar::new(),
            limit,
        }
    }

    /// The counts, whatever a panicking holder left: each is changed by one
    /// statement, so none is ever half-written.
    fn rooms(&self) -> MutexGuard<'_, Rooms> {
        self.rooms.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Begin an effect section: once no ending is inside or waiting.
    ///
    /// # Errors
    ///
    /// [`AuthorityError::Busy`] past the limit; nothing has begun.
    pub(crate) fn effect(self: &Arc<Self>) -> Result<Section, AuthorityError> {
        self.enter(Kind::Effect)
    }

    /// Begin an ending section: once no effect is inside. Effects that have
    /// not begun wait for it.
    ///
    /// # Errors
    ///
    /// [`AuthorityError::Busy`] past the limit; nothing has begun.
    pub(crate) fn ending(self: &Arc<Self>) -> Result<Section, AuthorityError> {
        self.enter(Kind::Ending)
    }

    fn enter(self: &Arc<Self>, kind: Kind) -> Result<Section, AuthorityError> {
        debug_assert!(
            !INSIDE.get(),
            "an authority gate section was entered from inside another"
        );
        let deadline = Instant::now().checked_add(self.limit);
        let mut rooms = self.rooms();
        match kind {
            Kind::Effect => rooms.effects_waiting = rooms.effects_waiting.saturating_add(1),
            Kind::Ending => rooms.endings_waiting = rooms.endings_waiting.saturating_add(1),
        }
        loop {
            let open = match kind {
                Kind::Effect => rooms.endings == 0 && rooms.endings_waiting == 0,
                Kind::Ending => rooms.effects == 0,
            };
            if open {
                break;
            }
            let left = deadline
                .and_then(|d| d.checked_duration_since(Instant::now()))
                .filter(|left| !left.is_zero());
            let Some(left) = left else {
                match kind {
                    Kind::Effect => {
                        rooms.effects_waiting = rooms.effects_waiting.saturating_sub(1);
                    }
                    Kind::Ending => {
                        rooms.endings_waiting = rooms.endings_waiting.saturating_sub(1);
                        drop(rooms);
                        // Effects held back by this ending may begin.
                        self.changed.notify_all();
                    }
                }
                return Err(AuthorityError::Busy);
            };
            rooms = self
                .changed
                .wait_timeout(rooms, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        match kind {
            Kind::Effect => {
                rooms.effects_waiting = rooms.effects_waiting.saturating_sub(1);
                rooms.effects = rooms.effects.saturating_add(1);
            }
            Kind::Ending => {
                rooms.endings_waiting = rooms.endings_waiting.saturating_sub(1);
                rooms.endings = rooms.endings.saturating_add(1);
            }
        }
        drop(rooms);
        INSIDE.set(true);
        Ok(Section {
            gate: Arc::clone(self),
            kind,
            _thread: PhantomData,
        })
    }

    /// Endings waiting to begin (the route tests' observation point).
    #[cfg(test)]
    pub(crate) fn endings_waiting(&self) -> u32 {
        self.rooms().endings_waiting
    }

    /// Effect sections inside now.
    #[cfg(test)]
    pub(crate) fn effects_inside(&self) -> u32 {
        self.rooms().effects
    }

    /// Effects waiting to begin.
    #[cfg(test)]
    pub(crate) fn effects_waiting(&self) -> u32 {
        self.rooms().effects_waiting
    }
}

impl Drop for Section {
    fn drop(&mut self) {
        let mut rooms = self.gate.rooms();
        match self.kind {
            Kind::Effect => rooms.effects = rooms.effects.saturating_sub(1),
            Kind::Ending => rooms.endings = rooms.endings.saturating_sub(1),
        }
        drop(rooms);
        self.gate.changed.notify_all();
        INSIDE.set(false);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::sync::Arc;
    use std::sync::mpsc;
    use std::time::Duration;

    use super::{AuthorityError, Gate};

    fn gate(limit_ms: u64) -> Arc<Gate> {
        Arc::new(Gate::new(Duration::from_millis(limit_ms)))
    }

    /// Wait, without sleeping on a guess, until `condition` holds.
    fn until(condition: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while !condition() {
            assert!(std::time::Instant::now() < deadline, "never happened");
            std::thread::yield_now();
        }
    }

    #[test]
    fn effects_share_the_gate_and_endings_share_it() {
        let gate = gate(10_000);
        let one = std::thread::spawn({
            let gate = Arc::clone(&gate);
            move || {
                let _a = gate.effect().unwrap();
                let (tx, rx) = mpsc::channel();
                let other = std::thread::spawn({
                    let gate = Arc::clone(&gate);
                    move || {
                        let _b = gate.effect().unwrap();
                        tx.send(()).unwrap();
                    }
                });
                // A second effect begins while the first is inside.
                rx.recv_timeout(Duration::from_secs(30)).unwrap();
                other.join().unwrap();
            }
        });
        one.join().unwrap();
        let two = std::thread::spawn({
            let gate = Arc::clone(&gate);
            move || {
                let _a = gate.ending().unwrap();
                let (tx, rx) = mpsc::channel();
                let other = std::thread::spawn({
                    let gate = Arc::clone(&gate);
                    move || {
                        let _b = gate.ending().unwrap();
                        tx.send(()).unwrap();
                    }
                });
                rx.recv_timeout(Duration::from_secs(30)).unwrap();
                other.join().unwrap();
            }
        });
        two.join().unwrap();
    }

    #[test]
    fn an_ending_waits_for_every_effect_inside_and_holds_back_new_ones() {
        let gate = gate(30_000);
        let (inside, release) = (mpsc::channel(), mpsc::channel::<()>());
        let effect = std::thread::spawn({
            let gate = Arc::clone(&gate);
            let (entered, wait) = (inside.0, release.1);
            move || {
                let _section = gate.effect().unwrap();
                entered.send(()).unwrap();
                wait.recv().unwrap();
            }
        });
        inside.1.recv().unwrap();
        let (ended_tx, ended) = mpsc::channel();
        let ending = std::thread::spawn({
            let gate = Arc::clone(&gate);
            move || {
                let _section = gate.ending().unwrap();
                ended_tx.send(()).unwrap();
            }
        });
        until(|| gate.endings_waiting() == 1);
        assert!(
            ended.try_recv().is_err(),
            "an ending began beside an effect"
        );
        // A new effect waits behind the waiting ending: it is seen waiting,
        // never inside, until the ending has begun and ended.
        let (late_tx, late) = mpsc::channel();
        let newcomer = std::thread::spawn({
            let gate = Arc::clone(&gate);
            move || {
                let _section = gate.effect().unwrap();
                late_tx.send(()).unwrap();
            }
        });
        until(|| gate.effects_waiting() == 1 || gate.effects_inside() == 2);
        assert_eq!(
            (gate.effects_inside(), gate.effects_waiting()),
            (1, 1),
            "a new effect began while an ending waited"
        );
        assert!(late.try_recv().is_err());
        release.0.send(()).unwrap();
        effect.join().unwrap();
        ended.recv_timeout(Duration::from_secs(30)).unwrap();
        ending.join().unwrap();
        late.recv_timeout(Duration::from_secs(30)).unwrap();
        newcomer.join().unwrap();
        assert_eq!((gate.effects_inside(), gate.endings_waiting()), (0, 0));
    }

    #[test]
    fn every_wait_is_bounded_and_a_refused_ending_lets_effects_in() {
        let gate = gate(100);
        let (inside, release) = (mpsc::channel(), mpsc::channel::<()>());
        let effect = std::thread::spawn({
            let gate = Arc::clone(&gate);
            let (entered, wait) = (inside.0, release.1);
            move || {
                let _section = gate.effect().unwrap();
                entered.send(()).unwrap();
                wait.recv().unwrap();
            }
        });
        inside.1.recv().unwrap();
        // The ending gives up at the limit, refused Busy, nothing begun.
        let refused = std::thread::spawn({
            let gate = Arc::clone(&gate);
            move || gate.ending().err()
        })
        .join()
        .unwrap();
        assert!(matches!(refused, Some(AuthorityError::Busy)));
        assert_eq!(gate.endings_waiting(), 0);
        // Nothing holds effects back after it.
        std::thread::spawn({
            let gate = Arc::clone(&gate);
            move || drop(gate.effect().unwrap())
        })
        .join()
        .unwrap();
        release.0.send(()).unwrap();
        effect.join().unwrap();
        // An effect, too, gives up behind an ending that does not end.
        let (inside, release) = (mpsc::channel(), mpsc::channel::<()>());
        let ending = std::thread::spawn({
            let gate = Arc::clone(&gate);
            let (entered, wait) = (inside.0, release.1);
            move || {
                let _section = gate.ending().unwrap();
                entered.send(()).unwrap();
                wait.recv().unwrap();
            }
        });
        inside.1.recv().unwrap();
        let refused = std::thread::spawn({
            let gate = Arc::clone(&gate);
            move || gate.effect().err()
        })
        .join()
        .unwrap();
        assert!(matches!(refused, Some(AuthorityError::Busy)));
        release.0.send(()).unwrap();
        ending.join().unwrap();
    }

    #[test]
    fn a_section_ends_however_its_holder_leaves() {
        let gate = gate(10_000);
        let gave_up: Result<(), AuthorityError> = (|| {
            let _section = gate.effect()?;
            Err(AuthorityError::Busy)
        })();
        assert!(gave_up.is_err());
        assert_eq!(gate.effects_inside(), 0);
        let panicked = std::thread::spawn({
            let gate = Arc::clone(&gate);
            move || {
                let _section = gate.effect().unwrap();
                panic!("the holder fails");
            }
        })
        .join();
        assert!(panicked.is_err());
        assert_eq!(gate.effects_inside(), 0);
        // An ending begins at once after both.
        std::thread::spawn({
            let gate = Arc::clone(&gate);
            move || drop(gate.ending().unwrap())
        })
        .join()
        .unwrap();
    }

    #[test]
    #[should_panic(expected = "entered from inside another")]
    #[cfg(debug_assertions)]
    fn sections_do_not_nest() {
        let gate = gate(100);
        let _outer = gate.effect().unwrap();
        let _inner = gate.effect();
    }
}
