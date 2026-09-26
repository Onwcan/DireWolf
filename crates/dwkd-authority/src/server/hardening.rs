//! Process hardening at serve start (M4e, ADR-0046 §9): the authority holds
//! secret material, however briefly, so no core dump of it may exist and no
//! other process of its uid may read its memory.
//!
//! * `RLIMIT_CORE` = 0, soft and hard: a core file is never written, and the
//!   process cannot raise the limit again.
//! * `PR_SET_DUMPABLE` = 0: the kernel skips the core dump **entirely** —
//!   including a `core_pattern` pipe handler such as apport or
//!   systemd-coredump, which `RLIMIT_CORE` alone does not stop — and
//!   `/proc/<pid>/{mem,environ,fd,io,maps}` become root's, so no same-uid
//!   process can read the authority's memory.
//!
//! `--allow-dumpable` (development only, logged as REDUCED ASSURANCE) leaves
//! the process dumpable so a same-uid test harness can count its descriptors;
//! the core limit is applied regardless. `mlock` and `MADV_DONTDUMP` are not
//! implemented: this build links no safe API for either, and the workspace
//! forbids `unsafe`.
//!
//! One of the files in the authority that may name `rustix` (TX008).

use rustix::process::{DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit};

/// Apply the hardening. `dumpable` keeps the process dumpable (development).
///
/// # Errors
///
/// A message naming the setting that could not be applied: the server does
/// not start half-hardened.
pub(super) fn apply(dumpable: bool) -> Result<(), String> {
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
