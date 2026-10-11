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
//! `CAP_SYS_PTRACE` remain outside this boundary either way.

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
