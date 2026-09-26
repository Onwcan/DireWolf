//! Crash points for the M4c crash campaigns (ADR-0044 §10). **Debug builds
//! only** — and, in unit tests only, race points and a trace.
//!
//! A debug broker started with `DWKD_BROKER_CRASH_AT=<point>` aborts — no
//! outcome sent, no clean-up run, no destructor — the first time an operation
//! reaches `<point>`, as a power cut or a `SIGKILL` would stop it there. The
//! campaigns then inspect the workspace, restart everything and prove what
//! the authority recorded, what became of the staging directory, and what a
//! retry does.
//!
//! In the broker's own unit tests the same points can run closures instead
//! ([`race_at`]): a change made at a chosen instant of the broker's sequence,
//! which no process outside it can place deterministically. That is how the
//! checks made immediately before a change, the checks made after it and the
//! restore paths are exercised — and [`reached`] says which points an
//! operation passed, so a test can prove that a namespace change was **never
//! attempted**, not merely that it was undone.
//!
//! The unit tests' trace also holds every namespace change the broker made
//! and every `fsync` that made one durable ([`Step`]), in order, so that the
//! durability ordering of ADR-0044 §10 is checked on every operation the unit
//! tests run — not inferred from a crash that happened to land well.
//!
//! A race here demonstrates an ordering in this code. It is not evidence of a
//! kernel guarantee: the window between the last check and the change is real
//! and is closed by the permission model, not by these tests (ADR-0044 §8).
//! Nor is the trace evidence of what survives a power cut: it proves the order
//! of the system calls durability depends on, and nothing about the device
//! under them.
//!
//! In a release build [`point`] is empty and the variable is never read: no
//! input can make a production broker stop half way on purpose.

#[cfg(debug_assertions)]
static AT: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

/// A race: the point it runs at, and what it does there.
#[cfg(test)]
type Race = (&'static str, Box<dyn Fn()>);

/// One step of an operation, as the unit tests trace it. A directory is named
/// by its `(st_dev, st_ino)`.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Step {
    /// A crash point was reached.
    Point(&'static str),
    /// One system call changed the entries of these directories.
    Changed(&'static str, Vec<(u64, u64)>),
    /// One system call undid the change just made — before it was made
    /// durable, which an unauthorised change never is.
    Undone(&'static str, Vec<(u64, u64)>),
    /// A file the broker wrote was made durable: its content and attributes.
    FileSynced(&'static str),
    /// A directory was made durable: its entries.
    Synced((u64, u64)),
}

#[cfg(test)]
thread_local! {
    /// The races registered for this test's thread.
    static RACES: std::cell::RefCell<Vec<Race>> = const { std::cell::RefCell::new(Vec::new()) };
    /// Every step this test's thread has taken, in order.
    static STEPS: std::cell::RefCell<Vec<Step>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Read the crash point, once, at start-up. Nothing in a release build.
pub(crate) fn init() {
    #[cfg(debug_assertions)]
    {
        let at = std::env::var("DWKD_BROKER_CRASH_AT").ok();
        if let Some(point) = &at {
            crate::log(&format!("DEBUG BUILD: will abort at crash point {point}"));
        }
        let _ = AT.set(at);
    }
}

/// Run `race` whenever this thread's operation reaches `name`. Unit tests
/// only.
#[cfg(test)]
pub(crate) fn race_at(name: &'static str, race: impl Fn() + 'static) {
    RACES.with(|races| races.borrow_mut().push((name, Box::new(race))));
}

/// The points this thread has reached, in order. Unit tests only.
#[cfg(test)]
pub(crate) fn reached() -> Vec<&'static str> {
    STEPS.with(|steps| {
        steps
            .borrow()
            .iter()
            .filter_map(|step| match step {
                Step::Point(name) => Some(*name),
                _ => None,
            })
            .collect()
    })
}

/// Every step this thread has taken, in order. Unit tests only.
#[cfg(test)]
pub(crate) fn steps() -> Vec<Step> {
    STEPS.with(|steps| steps.borrow().clone())
}

/// Add a step to this thread's trace. Unit tests only.
#[cfg(test)]
pub(crate) fn step(step: Step) {
    STEPS.with(|steps| steps.borrow_mut().push(step));
}

/// Whether `name` is the configured crash point (debug builds): for a point
/// another process reaches — the launch helper's, immediately before
/// `execveat`, which the broker arms through the launch message. Always
/// `false` in a release build.
pub(crate) fn armed(name: &'static str) -> bool {
    #[cfg(debug_assertions)]
    {
        AT.get().and_then(Option::as_deref) == Some(name)
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = name;
        false
    }
}

/// Abort here if this is the configured crash point (debug builds), or run
/// this thread's races registered here (unit tests).
#[cfg_attr(not(debug_assertions), allow(clippy::missing_const_for_fn))]
pub(crate) fn point(name: &'static str) {
    #[cfg(test)]
    {
        step(Step::Point(name));
        RACES.with(|races| {
            for (at, race) in races.borrow().iter() {
                if *at == name {
                    race();
                }
            }
        });
    }
    #[cfg(debug_assertions)]
    if AT.get().and_then(Option::as_deref) == Some(name) {
        crate::event(&format!("crash_point point={name}"));
        std::process::abort();
    }
    #[cfg(not(debug_assertions))]
    let _ = name;
}
