//! What the broker verifies about its own deployment before it serves (M5d,
//! ADR-0052 §13), turning two of ADR-0050 §21's conditions into checks.
//!
//! **No identity of a sandbox.** Without user-namespace remapping, the uid a
//! workload has inside every environment (`SANDBOX_UID`) and the relay's
//! (`RELAY_UID`) are host uids too. A broker — or an authority it serves —
//! with one of them would share an identity with every workload or relay:
//! the uid's kernel keyring, its files, its signals wherever a namespace is
//! shared. The broker refuses to serve then; no flag changes that.
//!
//! **A startup window nobody can use.** A process this broker starts — an
//! exchange worker, the launch helper — is an ordinary process of the
//! broker's uid from `execve` until it hardens itself (ADR-0050 §§9, 20 (d)).
//! Nothing can take it over in that window unless a process of the same uid
//! may trace it: Yama's `ptrace_scope` at least 1 forbids that to every
//! non-ancestor, and a broker binary its uid cannot read (root-owned, no
//! read bit) makes the kernel start those processes non-dumpable from
//! `execve`. The broker reads both facts at start and refuses to serve when
//! neither holds, unless the operator acknowledged it for development
//! (`--allow-traceable-workers`, logged `REDUCED ASSURANCE`). Root and
//! `CAP_SYS_PTRACE` remain outside this boundary either way. Both facts are
//! read again before every exchange worker is started (ADR-0053 §4): a
//! posture changed after start -- by root, outside the threat model -- is
//! seen at the next hop, not only at the next start.
//!
//! **Memory that cannot reach swap** (ADR-0053 §7). A hop that carries a
//! credential holds it, for a moment, in this broker and then in its
//! exchange worker. Where swap exists, an anonymous page of either may be
//! written to it. The broker reads where its memory, and each such worker's,
//! can go -- no swap device at all, or a cgroup on the process's path whose
//! `memory.swap.max` is 0 (systemd's `MemorySwapMax=0`) -- and refuses a
//! credential hop otherwise, unless the operator acknowledged it for
//! development (`--allow-swappable-workers`, logged `REDUCED ASSURANCE`).
//! What this does not cover is stated, not implied: hibernation writes all
//! of memory regardless of cgroups and locks; pages already in swap are not
//! recalled; a hypervisor may page the guest's memory to its own storage.

use std::path::Path;

use dwk_sandbox_profile::{RELAY_UID, SANDBOX_UID};

/// Where Yama publishes its setting.
const YAMA: &str = "/proc/sys/kernel/yama/ptrace_scope";

/// Why `own_uid` or `authority_uid` may not be the broker's or its
/// authority's: it is an environment's own identity. `None` when neither is.
#[must_use]
pub(crate) fn sandbox_identity_clash(own_uid: u32, authority_uid: u32) -> Option<String> {
    for (whose, uid) in [
        ("the broker's", own_uid),
        ("the authority's", authority_uid),
    ] {
        let role = match uid {
            SANDBOX_UID => "every workload's",
            RELAY_UID => "every relay's",
            _ => continue,
        };
        return Some(format!(
            "{whose} uid {uid} is {role} uid inside its environment, which is the same host \
             uid without user-namespace remapping; run the daemons as other users"
        ));
    }
    None
}

/// The two facts the startup window depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Posture {
    /// Yama's `ptrace_scope` (0–3), or `None` without Yama or when it
    /// cannot be read.
    pub(crate) scope: Option<u8>,
    /// Whether the broker's binary is root-owned with no read bit for
    /// group or others — so no uid but root's can read it, and the kernel
    /// starts what it executes non-dumpable.
    pub(crate) execute_only: bool,
}

impl Posture {
    /// Whether no process of the broker's uid but an ancestor may trace a
    /// process it starts before that process hardens itself.
    #[must_use]
    pub(crate) fn startup_window_closed(self) -> bool {
        self.scope.is_some_and(|scope| scope >= 1) || self.execute_only
    }

    /// How the event line spells it.
    #[must_use]
    pub(crate) fn describe(self) -> String {
        format!(
            "ptrace_scope={} execute_only={} startup_window_closed={}",
            self.scope
                .map_or_else(|| "absent".to_owned(), |s| s.to_string()),
            self.execute_only,
            self.startup_window_closed()
        )
    }
}

/// Where a process's anonymous memory can go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Swap {
    /// The host has no swap device: nowhere to write it.
    NoDevice,
    /// This cgroup, on the process's own path, allows it no swap.
    Capped(String),
    /// Neither, or it could not be read: it may be written to swap.
    Possible,
}

impl Swap {
    /// Whether the process's anonymous pages cannot be written to swap.
    #[must_use]
    pub(crate) const fn protected(&self) -> bool {
        matches!(self, Self::NoDevice | Self::Capped(_))
    }

    /// How the event line spells it.
    #[must_use]
    pub(crate) fn describe(&self) -> String {
        match self {
            Self::NoDevice => "no-device".to_owned(),
            Self::Capped(path) => format!("capped:{path}"),
            Self::Possible => "possible".to_owned(),
        }
    }
}

/// `SwapTotal` from `/proc/meminfo`, in KiB.
fn swap_total_kib(meminfo: &str) -> Option<u64> {
    meminfo.lines().find_map(|line| {
        let rest = line.strip_prefix("SwapTotal:")?;
        rest.trim().strip_suffix("kB")?.trim().parse().ok()
    })
}

/// The unified-hierarchy path from `/proc/<pid>/cgroup`: its `0::` line.
fn cgroup_path(cgroup: &str) -> Option<&str> {
    cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .filter(|path| path.starts_with('/') && !path.ends_with(" (deleted)"))
}

/// The cgroup and each one above it, nearest first, the root excluded (it
/// has no `memory.swap.max`). A path with a `..` component has none.
fn ancestry(path: &str) -> Vec<&str> {
    if path.split('/').any(|part| part == "..") {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut at = path.trim_end_matches('/');
    while !at.is_empty() {
        out.push(at);
        at = at.rfind('/').map_or("", |cut| at.get(..cut).unwrap_or(""));
    }
    out
}

/// The decision, from what was read: no swap device, or the nearest cgroup
/// whose limit is exactly `0`.
fn swap_from(total_kib: Option<u64>, limits: &[(&str, Option<String>)]) -> Swap {
    if total_kib == Some(0) {
        return Swap::NoDevice;
    }
    limits
        .iter()
        .find(|(_, limit)| limit.as_deref().map(str::trim) == Some("0"))
        .map_or(Swap::Possible, |(path, _)| Swap::Capped((*path).to_owned()))
}

/// Where process `pid`'s anonymous memory can go -- this process's for
/// `None` -- as the host says now.
#[must_use]
pub(crate) fn swap_of(pid: Option<u32>) -> Swap {
    let total = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|text| swap_total_kib(&text));
    let who = pid.map_or_else(|| "self".to_owned(), |pid| pid.to_string());
    let cgroup = std::fs::read_to_string(format!("/proc/{who}/cgroup")).unwrap_or_default();
    let limits: Vec<(&str, Option<String>)> = cgroup_path(&cgroup)
        .map(ancestry)
        .unwrap_or_default()
        .into_iter()
        .map(|dir| {
            let limit =
                std::fs::read_to_string(format!("/sys/fs/cgroup{dir}/memory.swap.max")).ok();
            (dir, limit)
        })
        .collect();
    swap_from(total, &limits)
}

/// What the kernel's command line says about zeroing pages on allocation
/// and on free (`init_on_alloc=`, `init_on_free=`): reported, never
/// required -- the build's default (`CONFIG_INIT_ON_*_DEFAULT_ON`) is not
/// visible from here, so absence is `default`, not `off`.
#[must_use]
pub(crate) fn page_zeroing(cmdline: &str) -> String {
    let value = |key: &str| {
        cmdline
            .split_whitespace()
            .filter_map(|word| word.strip_prefix(key))
            .next_back()
            .map_or("default", |v| match v {
                "1" | "on" | "y" => "on",
                "0" | "off" | "n" => "off",
                _ => "unrecognised",
            })
    };
    format!(
        "init_on_alloc={} init_on_free={}",
        value("init_on_alloc="),
        value("init_on_free=")
    )
}

/// [`page_zeroing`] of this host's kernel command line, as it is now.
#[must_use]
pub(crate) fn page_zeroing_now() -> String {
    page_zeroing(&std::fs::read_to_string("/proc/cmdline").unwrap_or_default())
}

/// Yama's setting, from its text: one digit 0–3 and a newline.
fn scope_of(text: &str) -> Option<u8> {
    let digit = text.strip_suffix('\n').unwrap_or(text);
    match digit {
        "0" => Some(0),
        "1" => Some(1),
        "2" => Some(2),
        "3" => Some(3),
        _ => None,
    }
}

/// Whether `(owner, mode)` is an execute-only binary for every uid but
/// root's.
const fn execute_only(owner: u32, mode: u32) -> bool {
    owner == 0 && mode & 0o044 == 0
}

/// Read both facts: Yama's setting, and the owner and mode of `binary`, the
/// broker's own executable as it found it at start.
#[must_use]
pub(crate) fn read(binary: &Path) -> Posture {
    let scope = std::fs::read_to_string(YAMA)
        .ok()
        .and_then(|text| scope_of(&text));
    let execute_only = rustix::fs::stat(binary).is_ok_and(|st| execute_only(st.st_uid, st.st_mode));
    Posture {
        scope,
        execute_only,
    }
}

#[cfg(test)]
mod tests {
    use super::{Posture, execute_only, sandbox_identity_clash, scope_of};

    #[test]
    fn no_daemon_may_have_an_environment_identity() {
        assert_eq!(sandbox_identity_clash(1001, 1000), None);
        assert_eq!(sandbox_identity_clash(1000, 1000), None);
        for (own, authority) in [
            (10_001, 1000),
            (10_002, 1000),
            (1001, 10_001),
            (1001, 10_002),
        ] {
            let clash = sandbox_identity_clash(own, authority);
            assert!(clash.is_some(), "{own} {authority}");
            assert!(clash.unwrap_or_default().contains("uid 1000"));
        }
    }

    #[test]
    fn memory_is_protected_from_swap_only_without_a_device_or_under_a_zero_cap() {
        use super::{Swap, ancestry, cgroup_path, swap_from, swap_total_kib};
        assert_eq!(
            swap_total_kib("MemTotal: 1 kB\nSwapTotal:        8388608 kB\n"),
            Some(8_388_608)
        );
        assert_eq!(swap_total_kib("SwapTotal: 0 kB\n"), Some(0));
        assert_eq!(swap_total_kib("SwapTotal: lots\n"), None);
        assert_eq!(swap_total_kib(""), None);
        assert_eq!(
            cgroup_path("0::/system.slice/dwkd.service\n"),
            Some("/system.slice/dwkd.service")
        );
        assert_eq!(cgroup_path("1:name=systemd:/x\n0::/a\n"), Some("/a"));
        assert_eq!(cgroup_path("0::/a (deleted)\n"), None);
        assert_eq!(cgroup_path("1:memory:/a\n"), None, "a v1-only process");
        assert_eq!(ancestry("/a/b/c"), vec!["/a/b/c", "/a/b", "/a"]);
        assert_eq!(ancestry("/"), Vec::<&str>::new());
        assert_eq!(ancestry("/a/../b"), Vec::<&str>::new());
        let zero = Some("0\n".to_owned());
        let max = Some("max\n".to_owned());
        assert_eq!(swap_from(Some(0), &[]), Swap::NoDevice);
        assert_eq!(swap_from(Some(1), &[]), Swap::Possible);
        assert_eq!(swap_from(None, &[]), Swap::Possible, "unreadable: possible");
        assert_eq!(
            swap_from(Some(1), &[("/a/b", max.clone()), ("/a", zero.clone())]),
            Swap::Capped("/a".to_owned()),
            "an ancestor's cap holds for the subtree"
        );
        assert_eq!(
            swap_from(Some(1), &[("/a/b", Some("4096\n".to_owned())), ("/a", max)]),
            Swap::Possible,
            "a non-zero cap still swaps"
        );
        assert_eq!(swap_from(Some(1), &[("/a", None)]), Swap::Possible);
        assert_eq!(
            swap_from(Some(1), &[("/a", Some("00\n".to_owned()))]),
            Swap::Possible
        );
        assert!(Swap::NoDevice.protected() && Swap::Capped("/a".to_owned()).protected());
        assert!(!Swap::Possible.protected());
    }

    #[test]
    fn page_zeroing_is_reported_from_the_command_line_and_never_inferred() {
        use super::page_zeroing;
        assert_eq!(
            page_zeroing("quiet"),
            "init_on_alloc=default init_on_free=default"
        );
        assert_eq!(
            page_zeroing("init_on_free=1 init_on_alloc=0"),
            "init_on_alloc=off init_on_free=on"
        );
        assert_eq!(
            page_zeroing("init_on_free=0 init_on_free=1"),
            "init_on_alloc=default init_on_free=on",
            "the last word wins, as the kernel reads it"
        );
    }

    #[test]
    fn the_startup_window_is_closed_by_yama_or_an_execute_only_binary_and_nothing_else() {
        let posture = |scope, execute_only| Posture {
            scope,
            execute_only,
        };
        for scope in [Some(1), Some(2), Some(3)] {
            assert!(posture(scope, false).startup_window_closed());
        }
        for scope in [None, Some(0)] {
            assert!(!posture(scope, false).startup_window_closed(), "{scope:?}");
            assert!(posture(scope, true).startup_window_closed(), "{scope:?}");
        }
        assert_eq!(scope_of("1\n"), Some(1));
        assert_eq!(scope_of("0"), Some(0));
        for bad in ["", "\n", "4\n", "01\n", " 1\n", "1\n\n", "-1\n"] {
            assert_eq!(scope_of(bad), None, "{bad:?}");
        }
        // Root-owned with no group or other read bit: execute-only. A binary
        // the broker's own uid owns is never, whatever its bits: it could
        // change them.
        assert!(execute_only(0, 0o100_711));
        assert!(execute_only(0, 0o100_111));
        assert!(!execute_only(0, 0o100_755));
        assert!(!execute_only(0, 0o100_751));
        assert!(!execute_only(1001, 0o100_111));
    }
}
