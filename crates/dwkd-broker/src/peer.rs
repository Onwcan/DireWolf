//! Who is at the other end of a Unix socket, as the kernel recorded it
//! (`SO_PEERCRED`) — the broker's one reader of a peer's credentials, for
//! the private channel's listener (the authority's uid, ADR-0043) and the
//! launch helper's control socket (the parent broker, ADR-0045).
//!
//! Read through `nix`'s safe `getsockopt` ([ADR-0049]): the kernel's `ucred`
//! as it is. A peer in a pid namespace this process cannot see has a pid of
//! **0** there, with its uid still exact; [`Peer::pid`] is then `None`, and a
//! caller that needs a pid decides what its absence means. Until ADR-0049
//! this was `rustix` 1.1.5's `socket_peercred`, whose typed `UCred` holds the
//! pid as a non-zero `Pid`: for that peer, undefined behaviour.
//!
//! [ADR-0049]: ../../../../docs/adr/0049-peer-credentials-read-soundly-through-nix.md

use std::os::fd::AsFd;

/// What the kernel reports about a socket's peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Peer {
    /// The peer's effective uid when it connected or listened.
    pub(crate) uid: u32,
    /// Its pid then, when this process can name it: `None` for a peer in a
    /// pid namespace this process cannot see.
    pub(crate) pid: Option<u32>,
}

/// The kernel's record of the peer of `socket`.
///
/// # Errors
///
/// The kernel refused the query; the caller refuses the peer.
pub(crate) fn of(socket: &impl AsFd) -> std::io::Result<Peer> {
    let cred = nix::sys::socket::getsockopt(socket, nix::sys::socket::sockopt::PeerCredentials)
        .map_err(std::io::Error::from)?;
    Ok(Peer::from_kernel(cred.uid(), cred.pid()))
}

impl Peer {
    /// The kernel's `ucred` fields: a pid of 0 — a peer in a pid namespace
    /// this process cannot see — or anything else that is not a positive pid
    /// is no pid at all, never a guess.
    fn from_kernel(uid: u32, pid: i32) -> Self {
        Self {
            uid,
            pid: u32::try_from(pid).ok().filter(|pid| *pid != 0),
        }
    }
}

/// Whether `peer` is the parent that started this process as `uid`: the same
/// uid, and a pid this process can see that is its parent's. A peer whose
/// pid cannot be seen is never the parent — a broker and the helper it
/// spawned share a pid namespace — and neither is anyone when the parent
/// itself cannot be seen.
pub(crate) fn is_parent(peer: Peer, parent: Option<u32>, uid: u32) -> bool {
    peer.uid == uid && peer.pid.is_some() && peer.pid == parent
}

#[cfg(test)]
mod tests {
    use super::{Peer, is_parent, of};

    #[test]
    fn the_kernel_reports_this_process_for_a_socket_pair() {
        let Ok((ours, theirs)) = std::os::unix::net::UnixStream::pair() else {
            unreachable!("a socket pair")
        };
        let Ok(peer) = of(&theirs) else {
            unreachable!("SO_PEERCRED on Linux")
        };
        assert_eq!(peer.pid, Some(std::process::id()));
        assert_eq!(peer.uid, rustix::process::geteuid().as_raw());
        drop(ours);
    }

    #[test]
    fn a_pid_the_kernel_cannot_name_is_no_pid() {
        assert_eq!(
            Peer::from_kernel(1000, 0),
            Peer {
                uid: 1000,
                pid: None
            }
        );
        assert_eq!(Peer::from_kernel(1000, -1).pid, None);
        assert_eq!(Peer::from_kernel(1000, 4242).pid, Some(4242));
    }

    #[test]
    fn a_peer_whose_pid_cannot_be_seen_is_never_the_parent() {
        let parent = Some(41);
        let seen = Peer {
            uid: 7,
            pid: Some(41),
        };
        assert!(is_parent(seen, parent, 7));
        // Another uid, another pid: not the parent.
        assert!(!is_parent(Peer { uid: 8, ..seen }, parent, 7));
        assert!(!is_parent(
            Peer {
                pid: Some(42),
                ..seen
            },
            parent,
            7
        ));
        // A pid this process cannot see (the kernel's 0) matches nothing —
        // not even a parent this process cannot see either.
        let hidden = Peer { uid: 7, pid: None };
        assert!(!is_parent(hidden, parent, 7));
        assert!(!is_parent(hidden, None, 7));
        assert!(!is_parent(seen, None, 7));
    }
}
