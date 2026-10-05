//! FIXTURE: nix reached for outside `server/peer.rs` (TX043): a second reader
//! of peer credentials, or any other nix call, in the authority.

use nix as _;

pub fn uid_of(stream: &std::os::unix::net::UnixStream) -> u32 {
    nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
        .map_or(0, |cred| cred.uid())
}
