//! Who is on the other end of an accepted socket, as the kernel reports it.
//!
//! **The only module that may use `rustix`** (TX008), and the one place the
//! platform decision is made: [`support`] says whether this build can derive a
//! peer's identity, and the server refuses to start where it cannot.
//!
//! # Linux: `SO_PEERCRED`
//!
//! [`peer_credentials`] reads the credentials the kernel recorded for the
//! connecting socket when it called `connect(2)` — the peer's **effective**
//! uid and its pid at that moment — through `rustix`'s safe wrapper, so the
//! crate keeps `forbid(unsafe_code)` ([ADR-0035] §3). Nothing the peer sends
//! can change them: they are attached to the connection, not carried in it.
//!
//! The uid is the subject. The pid is **diagnostic only**: pids are recycled,
//! so one names a process for an audit reader and never scopes anything the
//! authority decides ([ADR-0041]).
//!
//! # macOS: unsupported, stated rather than faked
//!
//! macOS has `LOCAL_PEERCRED` and `getpeereid(3)`, a different mechanism with
//! different guarantees. Neither `rustix` 1.1.5 nor stable Rust's standard
//! library exposes either (`UnixStream::peer_cred` is still unstable), and a
//! hand-written `getsockopt` would be `unsafe` in the authority — which
//! ADR-0035 rejected. So the server does not run on macOS: it says so at
//! startup, before touching any file. Nothing substitutes the server's own
//! uid for the peer's, and nothing guesses.
//!
//! # Windows: no Unix peer credentials at all
//!
//! Native Windows has no `SO_PEERCRED`, and DireWolf has no accepted design
//! for authenticating a named-pipe client. The server is unavailable there;
//! WSL2 is the supported path ([ADR-0029]).
//!
//! [ADR-0029]: ../../../../../docs/adr/0029-packaging-runtime-first-decoupled-authority.md
//! [ADR-0035]: ../../../../../docs/adr/0035-m3-authority-dependency-set.md
//! [ADR-0041]: ../../../../../docs/adr/0041-m3e-authenticated-dwkp-transport.md

/// What the kernel reports about a connected peer.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PeerCredentials {
    /// The peer's effective uid when it connected. The subject.
    pub(crate) uid: u32,
    /// The peer's pid when it connected. Diagnostic only.
    pub(crate) pid: Option<u32>,
}

/// Whether this build can identify a peer, and if not, why not.
///
/// # Errors
///
/// A sentence naming the platform and the missing mechanism.
pub(crate) const fn support() -> Result<(), &'static str> {
    if cfg!(target_os = "linux") {
        Ok(())
    } else if cfg!(target_os = "macos") {
        Err(
            "the DWKP server is not supported on macOS: its peer credential \
             (LOCAL_PEERCRED / getpeereid) is not exposed by any safe API this build links, and \
             the authority does not serve a peer it cannot identify. audit verification still \
             works here; run the server on Linux",
        )
    } else if cfg!(windows) {
        Err(
            "the DWKP server is not available on native Windows: there is no Unix peer \
             credential and no accepted design for authenticating a named-pipe client. use WSL2",
        )
    } else {
        Err(
            "the DWKP server is supported only on Linux, where the kernel reports a \
             Unix-domain peer's uid",
        )
    }
}

/// The kernel's report about the peer of `stream`.
///
/// # Errors
///
/// The kernel refused the query. The caller refuses the connection.
#[cfg(target_os = "linux")]
pub(crate) fn peer_credentials(
    stream: &std::os::unix::net::UnixStream,
) -> std::io::Result<PeerCredentials> {
    let cred = rustix::net::sockopt::socket_peercred(stream)?;
    Ok(PeerCredentials {
        uid: cred.uid.as_raw(),
        pid: u32::try_from(cred.pid.as_raw_nonzero().get()).ok(),
    })
}

/// No safe mechanism on this platform. Unreachable in practice — the server
/// refuses to start where [`support`] fails — and fail-closed regardless.
///
/// # Errors
///
/// Always.
#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) fn peer_credentials(
    _stream: &std::os::unix::net::UnixStream,
) -> std::io::Result<PeerCredentials> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no safe peer-credential mechanism on this platform",
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::{peer_credentials, support};

    #[cfg(target_os = "linux")]
    #[test]
    fn the_kernel_reports_this_process_for_a_socket_pair() {
        let Ok((ours, theirs)) = std::os::unix::net::UnixStream::pair() else {
            unreachable!("a socket pair")
        };
        let Ok(cred) = peer_credentials(&theirs) else {
            unreachable!("SO_PEERCRED on Linux")
        };
        assert_eq!(cred.pid, Some(std::process::id()));
        // The uid is the one that owns a file this process creates.
        let Ok(meta) = std::fs::metadata("/proc/self") else {
            unreachable!("procfs")
        };
        assert_eq!(cred.uid, std::os::unix::fs::MetadataExt::uid(&meta));
        drop(ours);
        assert!(support().is_ok());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn elsewhere_the_server_is_refused_and_no_identity_is_invented() {
        assert!(support().is_err());
        let Ok((_ours, theirs)) = std::os::unix::net::UnixStream::pair() else {
            unreachable!("a socket pair")
        };
        assert!(peer_credentials(&theirs).is_err());
    }
}
