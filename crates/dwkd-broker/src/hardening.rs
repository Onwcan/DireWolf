//! Process hardening at serve start (M4e, ADR-0046 §9). The broker holds a
//! secret only for one invocation -- a mode A header it composes, the value
//! it relays to a launch -- but for that moment it is in the broker's memory,
//! so no core dump of the broker may exist and no other process of its uid may
//! read its memory.
//!
//! * `RLIMIT_CORE` = 0, soft and hard. A launched target inherits it, so no
//!   target dumps a core either -- a target holding a mode B value in its
//!   environment included.
//! * `PR_SET_DUMPABLE` = 0: no core at all, a `core_pattern` pipe handler
//!   included, and `/proc/<pid>/{mem,environ,fd,io}` become root's. A launch
//!   helper is a new image (`execve` resets the flag for it and its target);
//!   the helper holds the value only until it executes the target.
//!
//! `--allow-dumpable` (development only, logged as REDUCED ASSURANCE) leaves
//! the process dumpable for a same-uid harness that reads its `/proc`; the
//! core limit holds regardless. `mlock` and `MADV_DONTDUMP` are not
//! implemented: this build links no safe API for either.

use rustix::process::{DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit};

/// Apply the hardening. `dumpable` keeps the process dumpable (development).
///
/// # Errors
///
/// A message naming the setting that could not be applied: the broker does
/// not serve half-hardened.
pub(crate) fn apply(dumpable: bool) -> Result<(), String> {
    setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|e| format!("cannot set RLIMIT_CORE to 0: {e}"))?;
    if !dumpable {
        set_dumpable_behavior(DumpableBehavior::NotDumpable)
            .map_err(|e| format!("cannot make the process non-dumpable: {e}"))?;
    }
    Ok(())
}
