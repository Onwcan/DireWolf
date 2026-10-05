//! FIXTURE: the authority's one peer reader names nix (TX043) and is NOT a
//! finding: the exemption names this file.

pub fn uid_of(stream: &std::os::unix::net::UnixStream) -> u32 {
    nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
        .map_or(0, |cred| cred.uid())
}
