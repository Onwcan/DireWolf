//! The approver endpoint (F-18 Phase 3.4, [ADR-0067], Proposed): a door of
//! its own, apart from the runtime's DWKP socket, for the people who approve.
//!
//! ```text
//!   a process on this host
//!        │  the approver socket (its own path, its own checked place)
//!        ▼
//!   accept ──▶ kernel peer credentials (SO_PEERCRED)            peer.rs
//!        ──▶ is that uid one of the operator's approvers?       this module
//!                 no  → closed before a byte is read; approver.peer_refused
//!                 yes → closed before a byte is read; approver.peer_authenticated
//! ```
//!
//! # An identity boundary, and nothing else yet
//!
//! What an approver may do -- see a request rendered from canonical data,
//! approve or deny it against a request nonce, have the approval bound,
//! burnt once and audited -- needs M6's approval registry, which does not
//! exist. An endpoint that accepted a decision before then could only
//! approve by fiat, with no binding, expiry, single use or record behind it.
//! So this endpoint reads nothing a peer sends, answers nothing, makes no
//! subject, mints no lease holder and dispatches nothing: it says who the
//! kernel reported, and closes. Every `REQUIRE_APPROVAL` still denies, and
//! every run a runtime admits is still `api` (TX062). TX065 keeps the module
//! this way until M6 changes it under a decision of its own.
//!
//! # Who is an approver
//!
//! A uid the operator listed with `--approver-uid`, and only such a uid: no
//! wildcard, no group, no user name, no exception for root. The list is
//! disjoint from every `--allow-uid` (a runtime's), the broker's uid and the
//! authority's own, with no override for any of them: a runtime that is also
//! an approver could approve its own requests. The parser refuses the first
//! two, the start the third. A uid is an operating-system identity, not a
//! person: two people who share one are one approver (ADR-0063 OD-1).
//!
//! # What a runtime can do here
//!
//! Connect, if the socket's directory lets it, and be refused: the decision
//! is the kernel's report, never a byte the peer sends, and is made before
//! one is read. A descriptor it attaches is never received -- nothing here
//! receives (TX061 covers this module as it covers the DWKP endpoint) -- and
//! is closed by the kernel with the connection. The socket's place is checked
//! as the DWKP socket's is (`socket.rs`): absolute, its final name never
//! followed, in an authority-owned directory no one else can write, under
//! ancestors only root or the authority own, a stale socket removed only if
//! it is this authority's own dead one, one lock per name. An operator who
//! wants a runtime unable even to connect gives the approver socket a
//! directory of its own, `0710` with the approvers' group; that narrows who
//! can reach it, and proves nobody's identity.
//!
//! [ADR-0067]: ../../../../../docs/adr/0067-f18-approver-endpoint-identity-boundary.md

use std::collections::BTreeSet;
use std::os::unix::net::UnixListener;

use super::peer::{self, PeerCredentials};
use super::worker::Shutdown;
use crate::state::TransportEvent;

/// The operator's approvers: a closed set of kernel-reported uids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApproverPolicy {
    uids: BTreeSet<u32>,
}

impl ApproverPolicy {
    /// A policy admitting exactly `uids` -- already checked disjoint from the
    /// runtime's, the broker's and the authority's by the parser and the
    /// start.
    pub(crate) fn new(uids: BTreeSet<u32>) -> Self {
        Self { uids }
    }

    /// Whether the kernel reported one of the operator's approvers.
    pub(crate) fn admits(&self, uid: u32) -> bool {
        self.uids.contains(&uid)
    }

    /// The approvers, in order.
    pub(crate) fn uids(&self) -> Vec<u32> {
        self.uids.iter().copied().collect()
    }
}

/// What the endpoint records about one connection, from the kernel's report
/// alone. Either way the connection is closed unread.
pub(crate) fn judge(policy: &ApproverPolicy, credentials: PeerCredentials) -> TransportEvent {
    if policy.admits(credentials.uid) {
        TransportEvent::ApproverAuthenticated {
            uid: credentials.uid,
            pid: credentials.pid,
        }
    } else {
        TransportEvent::ApproverRefused {
            uid: credentials.uid,
            pid: credentials.pid,
        }
    }
}

/// Accept connections on the approver socket until the server stops. Each
/// is judged by its kernel-reported uid, recorded through `record` (the
/// worker's rate-limited audit), and closed; none is given a thread, a
/// holder, a byte of an answer, or a read.
pub(crate) fn accept(
    listener: &UnixListener,
    policy: &ApproverPolicy,
    shutdown: &Shutdown,
    record: impl Fn(TransportEvent),
) {
    for incoming in listener.incoming() {
        if shutdown.stopping() {
            return;
        }
        let Ok(stream) = incoming else {
            // Out of descriptors, an aborted connection: nothing was read
            // and nothing is owed. Pause so a persistent condition does not
            // spin.
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        };
        let Ok(credentials) = peer::peer_credentials(&stream) else {
            super::log(
                "an approver-endpoint connection whose peer the kernel could not identify was \
                 closed",
            );
            continue;
        };
        record(judge(policy, credentials));
        drop(stream);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{ApproverPolicy, PeerCredentials, judge};
    use crate::state::TransportEvent;

    fn policy(uids: &[u32]) -> ApproverPolicy {
        ApproverPolicy::new(uids.iter().copied().collect::<BTreeSet<u32>>())
    }

    fn peer(uid: u32) -> PeerCredentials {
        PeerCredentials { uid, pid: Some(77) }
    }

    #[test]
    fn only_a_uid_the_operator_named_is_an_approver() {
        let approvers = policy(&[2001, 2002]);
        assert_eq!(
            judge(&approvers, peer(2001)),
            TransportEvent::ApproverAuthenticated {
                uid: 2001,
                pid: Some(77)
            }
        );
        assert!(approvers.admits(2002));
        // A runtime's uid, root, the uid next door: refused, by the uid the
        // kernel reported.
        for uid in [1001, 0, 2000, 2003, u32::MAX] {
            assert_eq!(
                judge(&approvers, peer(uid)),
                TransportEvent::ApproverRefused { uid, pid: Some(77) },
                "{uid}"
            );
        }
        // No configured approver: nobody is one.
        let nobody = policy(&[]);
        for uid in [0, 1001, 2001] {
            assert!(!nobody.admits(uid), "{uid}");
        }
        assert_eq!(approvers.uids(), [2001, 2002]);
    }

    #[test]
    fn the_record_is_the_kernels_uid_never_a_configured_one() {
        // Whatever the policy holds, the record names the peer the kernel
        // reported: a refusal never names an approver, an authentication
        // never names anyone else.
        let approvers = policy(&[2001]);
        for uid in [1001, 2001] {
            let recorded = match judge(&approvers, peer(uid)) {
                TransportEvent::ApproverRefused { uid, .. }
                | TransportEvent::ApproverAuthenticated { uid, .. } => uid,
                other => unreachable!("not an approver record: {other:?}"),
            };
            assert_eq!(recorded, uid);
        }
    }

    /// This module's code, without its comments or its tests.
    fn production() -> String {
        let source = include_str!("approver.rs");
        let end = source
            .find(&["#[cfg(", "test)]"].concat())
            .unwrap_or(source.len());
        source
            .get(..end)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_endpoint_reads_answers_and_dispatches_nothing() {
        // TX065's statement, checked where a mutation review can see it: no
        // way to read a peer's bytes, write an answer, make a subject or a
        // holder, decode a frame or reach the runtime's dispatch.
        let code = production();
        assert!(code.contains("fn accept("), "the scan sees the module");
        let forbidden = [
            ["std::io::", "Read"].concat(),
            ["std::io::", "Write"].concat(),
            [".", "read("].concat(),
            [".", "read_exact("].concat(),
            [".", "read_to_end("].concat(),
            [".", "peek("].concat(),
            [".", "write("].concat(),
            [".", "write_all("].concat(),
            [".", "set_read_timeout("].concat(),
            ["dis", "patch"].concat(),
            [".", "connect("].concat(),
            ["unix_", "uid"].concat(),
            ["Authenticated", "Subject"].concat(),
            ["Caller", "Context"].concat(),
            ["Lease", "Holder"].concat(),
            ["dec", "ode"].concat(),
            ["re", "cv"].concat(),
            ["connection", "::"].concat(),
        ];
        for token in &forbidden {
            assert!(
                !code.contains(token.as_str()),
                "the approver endpoint spells `{token}`: it holds no operation before M6"
            );
        }
    }
}
