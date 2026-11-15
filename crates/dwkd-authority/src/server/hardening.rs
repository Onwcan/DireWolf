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
//! [`observed`] reads both back (F-03): two reads of the process's own state,
//! so the effective posture the audit records says what the kernel reports,
//! not what `apply` was asked to do.
//!
//! One of the files in the authority that may name `rustix` (TX008).

use rustix::process::{
    DumpableBehavior, Resource, Rlimit, dumpable_behavior, getrlimit, set_dumpable_behavior,
    setrlimit,
};

/// This process's hardening as the kernel reports it now.
pub(super) fn observed() -> crate::posture::Hardened {
    let core = getrlimit(Resource::Core);
    crate::posture::Hardened {
        dumpable: dumpable_behavior()
            .ok()
            .map(|behavior| behavior != DumpableBehavior::NotDumpable),
        no_core: core.current == Some(0) && core.maximum == Some(0),
    }
}

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

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt as _;

    /// F-03: what `observed` reports is what the kernel shows another way.
    /// A dumpable process's `/proc/self/fd` is its own effective uid's, a
    /// non-dumpable one's root's; `/proc/self/limits` prints the core limit.
    /// This test process is not hardened, so whatever it is, the two must
    /// agree -- a read-back that always said "not dumpable" or "no core"
    /// would not.
    #[test]
    fn what_is_observed_is_what_proc_shows() {
        let observed = super::observed();
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let euid = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|ids| ids.split_whitespace().nth(1))
            .and_then(|id| id.parse::<u32>().ok());
        let owner = std::fs::metadata("/proc/self/fd").map(|m| m.uid()).ok();
        assert!(euid.is_some() && owner.is_some(), "{status}");
        assert_eq!(observed.dumpable, Some(owner == euid), "{owner:?} {euid:?}");
        let limits = std::fs::read_to_string("/proc/self/limits").unwrap_or_default();
        let core: Vec<&str> = limits
            .lines()
            .find_map(|line| line.strip_prefix("Max core file size"))
            .map(|rest| rest.split_whitespace().take(2).collect())
            .unwrap_or_default();
        assert_eq!(core.len(), 2, "{limits}");
        assert_eq!(
            observed.no_core,
            core.iter().all(|limit| *limit == "0"),
            "{core:?}"
        );
    }
}
