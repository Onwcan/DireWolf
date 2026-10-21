//! The workspace contract, from the authority's side (M5d.4, [ADR-0052]
//! §§6, 10; OD-3(a), OD-6).
//!
//! Before an environment is prepared or measured, and before every workload
//! starts in one, the authority holds the root it has just pinned -- by its
//! descriptor, never a path -- against what a production workspace must be:
//!
//! | what | why |
//! |---|---|
//! | owned by root or by the authority's own uid, never the workload's | an owner can change the root's mode, and so open the workspace to anyone |
//! | of the workspace group, `10001`, mode exactly `2770` | the workload reaches it through its own primary group; the authority and the broker as the group's members; nobody else at all |
//! | the authority a member of the group | it reads what the workload and the broker make there |
//! | its filesystem's capacity within the operator's quota, and no more than a quarter below it | the bound is the filesystem's own, measured -- never a number configured and believed |
//! | none of the authority's own state, and no secret file, on that filesystem | the workspace is the one thing the workload can write |
//!
//! The probe then says, from inside, what the runtime mounted -- the same
//! identity, owner, group, mode and capacity, the filesystem's own root,
//! `nosuid` and `nodev` -- and the broker judges the one against the other
//! ([`WorkspaceBound`] carries what the authority found). Either side
//! failing refuses the environment, or destroys it before a workload.
//!
//! **Nothing here repairs anything.** No `chmod`, `chown`, mount or format:
//! the operator provisions the workspace, and a workspace that is not as the
//! contract says is refused with the reason, never fixed.
//!
//! The evidence harness's [`WorkspaceSetting::UnverifiedEvidence`] has no
//! bound, and is checked for none: the broker builds it only when its
//! operator acknowledged it, and the environment is judged without the
//! contract's invariants -- so reported.
//!
//! [ADR-0052]: ../../../../../docs/adr/0052-m5d-sandboxed-process-exec.md

use std::path::Path;

use dwk_proto::brokerp::KernelNumber;
use dwk_proto::brokerp::sandbox::{
    Capacity, WORKLOAD_UID, WORKSPACE_GROUP, WORKSPACE_ROOT_MODE, WorkspaceBound, capacity,
    capacity_within_quota,
};

use crate::resource::fs::{PinnedRoot, RootMeasure};
use crate::sandbox::{SandboxConfig, WorkspaceSetting};

use super::Work;
use super::error::AuthorityError;

/// The facts the contract is judged from, besides the root's own.
pub(super) struct Context<'a> {
    /// The authority's uid: the one owner, besides root, a root may have.
    pub(super) authority_uid: u32,
    /// Whether the authority is a member of the workspace group, as the
    /// kernel says now; `None` when that cannot be read.
    pub(super) member: Option<bool>,
    /// Paths that must not be on the workspace's filesystem, each with
    /// whether a failure to look is itself a refusal.
    pub(super) private: &'a [(&'a Path, bool)],
}

/// Whether this process is a member of `gid` -- its effective group or a
/// supplementary one -- by its own `/proc/self/status`; `None` when that
/// cannot be read.
pub(super) fn member_of(gid: u32) -> Option<bool> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let field = |key: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .map(str::split_whitespace)
    };
    let effective = field("Gid:")?.nth(1)?.parse::<u32>().ok()?;
    let mut groups = field("Groups:")?;
    Some(effective == gid || groups.any(|g| g.parse::<u32>() == Ok(gid)))
}

/// Whether a workload may be running with `run`'s workspace mounted
/// (M5d.4): a workload `LAUNCHING` in any run whose workspace root is the
/// same directory, or an environment of such a run whose end nothing
/// proved -- `UNKNOWN`, or `DESTROYING` before its destruction is done.
///
/// **Why the broker's name changes wait for it.** The workload writes the
/// workspace as a member of its group, and its code is untrusted. Linux has
/// no compare-and-swap of a directory entry against an inode, so ADR-0044 §3
/// keeps the broker's change safe by keeping untrusted writers out of a
/// write-enabled workspace while it is made -- it excludes them, it does not
/// defend against them. Under OD-3(a) the workload is in the group, so it is
/// excluded in time instead: no brokered change of a name, and no
/// reclamation, while one may be running. Between workloads `reap` has
/// proved every process of the environment gone (or it was destroyed), so
/// nothing untrusted writes then. Reads are unaffected: the resolver is
/// built against concurrent renames (ADR-0042 §4).
///
/// Keyed by the root's identity, so two workspaces bound to one directory
/// are one workspace here.
///
/// # Errors
///
/// [`AuthorityError`] when the store cannot answer.
pub(super) fn in_use(work: &Work<'_>, run: &str) -> Result<bool, AuthorityError> {
    work.db(work.tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM run_policy_input p \
             JOIN workspace_root r ON r.workspace_id = p.workspace_id \
             JOIN workspace_root o ON o.root_device = r.root_device \
                                  AND o.root_inode = r.root_inode \
             JOIN run_policy_input q ON q.workspace_id = o.workspace_id \
             WHERE p.run_id = ?1 AND ( \
                 EXISTS (SELECT 1 FROM workload w \
                         WHERE w.run_id = q.run_id AND w.state = 'LAUNCHING') \
              OR EXISTS (SELECT 1 FROM environment e \
                         WHERE e.run_id = q.run_id \
                           AND e.state IN ('UNKNOWN', 'DESTROYING'))))",
        [run],
        |row| row.get(0),
    ))
}

/// The bound an environment of `config` carries for the root just pinned,
/// or why the workspace is not one: `Ok(None)` for the evidence harness's
/// unverified workspace, which carries none.
///
/// # Errors
///
/// The reason, one of `WORKSPACE_OWNER`, `WORKSPACE_GROUP`,
/// `WORKSPACE_MODE`, `WORKSPACE_GROUP_MEMBERSHIP`, `WORKSPACE_UNBOUNDED`,
/// `WORKSPACE_QUOTA_MISMATCH`, `WORKSPACE_FILESYSTEM_SHARED` or
/// `WORKSPACE_UNOBSERVABLE`. Each is a refusal; none is repaired.
pub(super) fn bound(
    config: &SandboxConfig,
    root: &PinnedRoot,
    context: &Context<'_>,
) -> Result<Option<WorkspaceBound>, &'static str> {
    let WorkspaceSetting::Bounded(quota) = config.workspace() else {
        return Ok(None);
    };
    let measured = root.measure().map_err(|_| "WORKSPACE_UNOBSERVABLE")?;
    judge(&measured, root.identity().device(), quota.get(), context)?;
    let Capacity::Bytes(capacity) = capacity(
        measured.block_size,
        measured.blocks,
        measured.blocks_available,
    ) else {
        return Err("WORKSPACE_UNOBSERVABLE");
    };
    Ok(Some(WorkspaceBound {
        quota_bytes: quota,
        capacity_bytes: KernelNumber::from_u64(capacity),
        owner: KernelNumber::from_u64(u64::from(measured.uid)),
    }))
}

/// The contract, held against what the root's descriptor said and what the
/// authority knows of itself. Pure but for the `stat` of each private path.
pub(super) fn judge(
    measured: &RootMeasure,
    device: u64,
    quota: u64,
    context: &Context<'_>,
) -> Result<(), &'static str> {
    if measured.uid == WORKLOAD_UID || (measured.uid != 0 && measured.uid != context.authority_uid)
    {
        return Err("WORKSPACE_OWNER");
    }
    if measured.gid != WORKSPACE_GROUP {
        return Err("WORKSPACE_GROUP");
    }
    if measured.mode != WORKSPACE_ROOT_MODE {
        return Err("WORKSPACE_MODE");
    }
    match context.member {
        Some(true) => {}
        Some(false) => return Err("WORKSPACE_GROUP_MEMBERSHIP"),
        None => return Err("WORKSPACE_UNOBSERVABLE"),
    }
    let bytes = match capacity(
        measured.block_size,
        measured.blocks,
        measured.blocks_available,
    ) {
        Capacity::Contradictory => return Err("WORKSPACE_UNOBSERVABLE"),
        // Too large to count is larger than any quota.
        Capacity::Uncountable => u64::MAX,
        Capacity::Bytes(bytes) => bytes,
    };
    if bytes > quota {
        return Err("WORKSPACE_UNBOUNDED");
    }
    if !capacity_within_quota(bytes, quota) {
        return Err("WORKSPACE_QUOTA_MISMATCH");
    }
    for (path, required) in context.private {
        match device_of(path) {
            Some(found) if found == device => return Err("WORKSPACE_FILESYSTEM_SHARED"),
            None if *required => return Err("WORKSPACE_UNOBSERVABLE"),
            // Elsewhere, or not looked at where it need not be.
            Some(_) | None => {}
        }
    }
    Ok(())
}

/// The device `path` is on, followed as the operator named it; `None` when
/// it cannot be looked at.
#[cfg(unix)]
fn device_of(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(path).ok().map(|meta| meta.dev())
}

/// No root is ever pinned off Unix, so nothing is judged here.
#[cfg(not(unix))]
fn device_of(_path: &Path) -> Option<u64> {
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test assertions")]
mod tests {
    use std::path::Path;

    use super::{Context, WORKSPACE_GROUP, WORKSPACE_ROOT_MODE, judge};
    use crate::resource::fs::RootMeasure;

    const MIB: u64 = 1 << 20;

    /// A 64 MiB filesystem of 4 KiB blocks, rooted as the contract says, the
    /// authority (uid 1000) its owner.
    fn root() -> RootMeasure {
        RootMeasure {
            uid: 1000,
            gid: WORKSPACE_GROUP,
            mode: WORKSPACE_ROOT_MODE,
            block_size: 4096,
            blocks: 16_384,
            blocks_available: 16_000,
        }
    }

    fn context(member: Option<bool>) -> Context<'static> {
        Context {
            authority_uid: 1000,
            member,
            private: &[],
        }
    }

    /// [`root`], changed by `change`.
    fn root_with(change: impl FnOnce(&mut RootMeasure)) -> RootMeasure {
        let mut measured = root();
        change(&mut measured);
        measured
    }

    #[test]
    fn a_workspace_is_the_contracts_or_refused_with_its_reason() {
        let quota = 64 * MIB;
        assert_eq!(judge(&root(), 7, quota, &context(Some(true))), Ok(()));
        // Root may own it too.
        let by_root = root_with(|m| m.uid = 0);
        assert_eq!(judge(&by_root, 7, quota, &context(Some(true))), Ok(()));
        for (measured, reason) in [
            (root_with(|m| m.uid = 10_001), "WORKSPACE_OWNER"),
            (root_with(|m| m.uid = 1001), "WORKSPACE_OWNER"),
            (root_with(|m| m.gid = 1000), "WORKSPACE_GROUP"),
            (root_with(|m| m.gid = 10_002), "WORKSPACE_GROUP"),
            (root_with(|m| m.mode = 0o770), "WORKSPACE_MODE"),
            (root_with(|m| m.mode = 0o2775), "WORKSPACE_MODE"),
            (root_with(|m| m.mode = 0o2777), "WORKSPACE_MODE"),
            (root_with(|m| m.mode = 0o3770), "WORKSPACE_MODE"),
            (root_with(|m| m.mode = 0o2750), "WORKSPACE_MODE"),
            // A host filesystem far larger than the quota.
            (
                root_with(|m| {
                    m.blocks = 263_940_717;
                    m.blocks_available = 222_329_436;
                }),
                "WORKSPACE_UNBOUNDED",
            ),
            // One block over.
            (root_with(|m| m.blocks = 16_385), "WORKSPACE_UNBOUNDED"),
            // Too large to count.
            (
                root_with(|m| {
                    m.block_size = 1 << 32;
                    m.blocks = 1 << 32;
                    m.blocks_available = 0;
                }),
                "WORKSPACE_UNBOUNDED",
            ),
            // Half the declared quota: the declaration is not this filesystem.
            (
                root_with(|m| {
                    m.blocks = 8_192;
                    m.blocks_available = 8_000;
                }),
                "WORKSPACE_QUOTA_MISMATCH",
            ),
            // Facts that cannot all be true.
            (root_with(|m| m.block_size = 0), "WORKSPACE_UNOBSERVABLE"),
            (
                root_with(|m| m.blocks_available = 16_385),
                "WORKSPACE_UNOBSERVABLE",
            ),
        ] {
            assert_eq!(
                judge(&measured, 7, quota, &context(Some(true))),
                Err(reason),
                "{measured:?}"
            );
        }
    }

    #[test]
    fn an_authority_outside_the_group_or_unable_to_say_is_refused() {
        let quota = 64 * MIB;
        assert_eq!(
            judge(&root(), 7, quota, &context(Some(false))),
            Err("WORKSPACE_GROUP_MEMBERSHIP")
        );
        assert_eq!(
            judge(&root(), 7, quota, &context(None)),
            Err("WORKSPACE_UNOBSERVABLE")
        );
    }

    #[cfg(unix)]
    #[test]
    fn nothing_private_may_be_on_the_workspaces_filesystem() {
        use std::os::unix::fs::MetadataExt as _;
        // `/` exists on every host; the state layer names no ambient
        // directory (TX006).
        let here = Path::new("/");
        let device = std::fs::metadata(here).unwrap().dev();
        let private: &[(&Path, bool)] = &[(here, true)];
        let context = Context {
            authority_uid: 1000,
            member: Some(true),
            private,
        };
        assert_eq!(
            judge(&root(), device, 64 * MIB, &context),
            Err("WORKSPACE_FILESYSTEM_SHARED")
        );
        assert_eq!(
            judge(&root(), device.wrapping_add(1), 64 * MIB, &context),
            Ok(())
        );
        // A private path that cannot be looked at: refused when it must be
        // looked at, passed over when it need not.
        let missing = Path::new("/nonexistent/direwolf-m5d4");
        for (required, want) in [(true, Err("WORKSPACE_UNOBSERVABLE")), (false, Ok(()))] {
            let private: &[(&Path, bool)] = &[(missing, required)];
            let context = Context {
                authority_uid: 1000,
                member: Some(true),
                private,
            };
            assert_eq!(judge(&root(), device, 64 * MIB, &context), want);
        }
    }
}
