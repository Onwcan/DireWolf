//! Authority-owned time.
//!
//! Every expiry the state layer decides on — a lease's `expires_ms` — is a
//! wall-clock instant the **authority** read. No runtime-supplied timestamp
//! participates in any decision: the envelope's `ts` is advisory by
//! [`PROTOCOL.md`] §1, and nothing here reads it.
//!
//! # Clock jumps, stated honestly
//!
//! Lease expiry is persisted as an absolute Unix-epoch millisecond so that it
//! means the same thing after a restart. That makes it a wall-clock
//! comparison, and a wall clock can move:
//!
//! * **Backwards** — a lease can outlive its nominal TTL, by the size of the
//!   jump. The holder is still the only holder, and its epoch is still the
//!   only current one, so a backwards jump extends a single writer's tenure;
//!   it does not create a second writer.
//! * **Forwards** — a lease can expire early. The next acquirer receives a
//!   **new** epoch, and the old holder is fenced with `STALE_EPOCH` on its next
//!   request. Early expiry costs availability, never exclusivity.
//!
//! Neither direction can make two holders current at once, because currency is
//! decided by the epoch comparison inside one SQLite transaction, not by time.
//! What this does **not** resist is an attacker who controls the host clock:
//! such a party can expire any lease at will. That is a denial of service
//! against the runtime, and it is outside what M3d claims.
//!
//! [`RELIABILITY.md`] §10 asks for `CLOCK_BOOTTIME` for durations. A lease
//! expiry has to survive an authority restart, which a boot-relative clock does
//! not, so the persisted instant is wall-clock; the trade-off is the one
//! described above.
//!
//! [`PROTOCOL.md`]: ../../../../../docs/PROTOCOL.md
//! [`RELIABILITY.md`]: ../../../../../docs/RELIABILITY.md

use core::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of wall-clock time, in milliseconds since the Unix epoch.
///
/// Injectable so that lease expiry is testable without sleeping, and so that a
/// test can move time backwards and forwards deliberately. The authority owns
/// the choice of clock at startup; nothing on the wire can reach it.
pub trait Clock: Send + Sync + fmt::Debug {
    /// Milliseconds since 1970-01-01T00:00:00Z.
    fn now_ms(&self) -> u64;
}

/// The host's wall clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        // A clock before 1970 reads as 0: every lease then looks expired
        // relative to any later reading, which is the early-expiry direction
        // above -- availability lost, exclusivity kept.
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            })
    }
}

/// A clock that moves only when told to.
///
/// For tests and deterministic replay. It is an ordinary in-process value: the
/// code that starts the authority chooses it, and the runtime has no way to
/// name, reach or advance it.
#[derive(Debug)]
pub struct ManualClock {
    now: AtomicU64,
}

impl ManualClock {
    /// A clock reading `start_ms`.
    #[must_use]
    pub const fn new(start_ms: u64) -> Self {
        Self {
            now: AtomicU64::new(start_ms),
        }
    }

    /// Move forwards by `ms`, saturating.
    pub fn advance(&self, ms: u64) {
        let _ = self
            .now
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |now| {
                Some(now.saturating_add(ms))
            });
    }

    /// Jump to an arbitrary instant — including backwards, which is the point.
    pub fn set(&self, ms: u64) {
        self.now.store(ms, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::{Clock, ManualClock, SystemClock};

    #[test]
    fn a_manual_clock_moves_only_when_told_and_can_move_backwards() {
        let clock = ManualClock::new(1_000);
        assert_eq!(clock.now_ms(), 1_000);
        clock.advance(500);
        assert_eq!(clock.now_ms(), 1_500);
        clock.set(10);
        assert_eq!(clock.now_ms(), 10, "a backwards jump is representable");
        clock.set(u64::MAX);
        clock.advance(1);
        assert_eq!(clock.now_ms(), u64::MAX, "advancing saturates");
    }

    #[test]
    fn the_system_clock_reads_a_plausible_instant() {
        // 2020-01-01 in milliseconds. A reading below it means the conversion
        // is wrong, not that the host is old.
        assert!(SystemClock.now_ms() > 1_577_836_800_000);
    }
}
