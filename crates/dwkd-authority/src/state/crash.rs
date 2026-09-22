//! Crash points: the named instants between an authority mutation and the
//! durable audit record that makes it visible.
//!
//! There is no transaction spanning `kernel.db` and `audit.log`. Every audited
//! operation therefore crosses the same sequence of windows, and a crash in any
//! of them must leave a state recovery can resolve without ambiguity. The
//! windows are named here so that tests can stop an operation *in* one — in
//! this process, or by aborting a real child process — and prove the recovery.
//!
//! ```text
//! A  BeforeTransaction          nothing has happened
//! B  BeforeCommit               rows changed, not committed
//!    ── COMMIT ─────────────────────────────────────────────────────────
//! C  AfterCommitBeforeAudit     committed; the record is only in kernel.db
//! D  MidAuditRecord             part of the record's line is in audit.log
//! E  AfterAuditWriteBeforeSync  the whole line is written, not fsynced
//! F  AfterAuditSyncBeforeMark   durable in audit.log; kernel.db not told
//! G  AfterAuditMark             reconciled
//! ```
//!
//! # Why this is not a test-only backdoor
//!
//! A hook can only **stop** an operation. [`HookAction`] has two values, and
//! neither can make an operation do anything it would not otherwise do:
//! `Continue` is the normal path and `Stop` fails closed at that point. An
//! operation stopped at `C`–`F` has committed authority the caller never
//! receives — which is the state a real crash leaves, and the state recovery
//! exists for. The authority that ran the hook marks itself poisoned, exactly
//! as a crashed process is gone.

use core::fmt;
use std::sync::Arc;

/// One of the windows above.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CrashPoint {
    /// A — before the SQLite transaction begins.
    BeforeTransaction,
    /// B — the transaction has written its rows and not committed.
    BeforeCommit,
    /// C — committed; the pending audit record exists only in `kernel.db`.
    AfterCommitBeforeAudit,
    /// D — the first half of the record's line has been written to
    /// `audit.log`, the second half has not.
    MidAuditRecord,
    /// E — the whole line has been written, and not yet fsynced.
    AfterAuditWriteBeforeSync,
    /// F — `audit.log` is fsynced; `kernel.db` has not recorded that it is.
    AfterAuditSyncBeforeMark,
    /// G — `kernel.db` records the flush. The operation is complete.
    AfterAuditMark,
}

impl CrashPoint {
    /// Every point, in the order an operation crosses them.
    pub const ALL: [Self; 7] = [
        Self::BeforeTransaction,
        Self::BeforeCommit,
        Self::AfterCommitBeforeAudit,
        Self::MidAuditRecord,
        Self::AfterAuditWriteBeforeSync,
        Self::AfterAuditSyncBeforeMark,
        Self::AfterAuditMark,
    ];

    /// The letter the reliability documentation uses.
    #[must_use]
    pub const fn letter(self) -> char {
        match self {
            Self::BeforeTransaction => 'A',
            Self::BeforeCommit => 'B',
            Self::AfterCommitBeforeAudit => 'C',
            Self::MidAuditRecord => 'D',
            Self::AfterAuditWriteBeforeSync => 'E',
            Self::AfterAuditSyncBeforeMark => 'F',
            Self::AfterAuditMark => 'G',
        }
    }
}

impl fmt::Display for CrashPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({self:?})", self.letter())
    }
}

/// What a hook tells the operation to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookAction {
    /// Proceed normally.
    Continue,
    /// Stop here and fail closed, as if the process had died.
    Stop,
}

/// A function consulted at every crash point.
pub type CrashHook = Arc<dyn Fn(CrashPoint) -> HookAction + Send + Sync>;
