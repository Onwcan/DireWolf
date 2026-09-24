//! The DWKP server (M3e): the authority's one door, and the process boundary.
//!
//! > **The runtime cannot lie about who it is.**
//!
//! M3d built the authority as a library that trusts its caller's claims about
//! identity. This module is the caller that makes those claims true: bytes
//! from an untrusted runtime cross a real OS process boundary and acquire no
//! authority until the kernel has identified the peer ([ADR-0041]).
//!
//! ```text
//!   untrusted client process
//!        │  Unix-domain stream socket (no TCP, no HTTP, no fallback)
//!        ▼
//!   accept ──▶ kernel peer credentials (SO_PEERCRED)      peer.rs
//!        ──▶ operator's peer policy: is this uid listed?  config.rs
//!                 no  → closed before a byte is read; audited
//!        ──▶ connection limit                              (below)
//!                 full → closed before a byte is read; audited
//!        ──▶ Authority::connect(subject): one fresh holder  worker.rs
//!        ──▶ frames, strict DWKP decode, handshake first    connection.rs, protocol.rs
//!        ──▶ Authority::dispatch(caller, request)           worker.rs → crate::state
//!        ◀── the response body, in a response envelope     envelope.rs
//! ```
//!
//! # An adapter, not a second authority
//!
//! Nothing here decides anything about authority. There is no epoch
//! comparison, no idempotency lookup, no minting, no policy evaluation and no
//! run lookup in this module: a decoded request goes to
//! [`Authority::dispatch`](crate::state::Authority::dispatch) unchanged, and
//! what comes back goes to the peer unchanged. `architecture.toml` rule TX007
//! keeps the policy engine, the capability core, SQLite and every network
//! stack out of this directory.
//!
//! # Identity
//!
//! The subject is the uid the kernel reports for the connected socket — never
//! a field of any message, an environment variable, the socket's name or a
//! command line. Admission is the operator's explicit, closed list of uids.
//! Each accepted connection gets exactly one [`CallerContext`] with a fresh
//! [`LeaseHolder`], minted by the authority; two connections from one uid are
//! one subject and two holders, and a reconnect is a new holder that inherits
//! nothing.
//!
//! [`CallerContext`]: crate::state::CallerContext
//! [`LeaseHolder`]: crate::state::LeaseHolder
//!
//! # Platforms
//!
//! Linux only. macOS and native Windows have no peer-credential mechanism this
//! build can use without `unsafe`, so [`serve`] refuses there, before touching
//! a file — see `peer.rs`.
//!
//! # Stopping
//!
//! A poisoned store stops the server: the worker refuses every later request,
//! the accept loop ends, the socket is removed and [`serve`] returns
//! [`Stopped::Poisoned`]. There is no signal handling: `SIGTERM` or `SIGKILL`
//! ends the process where it stands, the socket file stays behind, and the next
//! start recognises it as this authority's own dead socket and replaces it.
//!
//! [ADR-0041]: ../../../../docs/adr/0041-m3e-authenticated-dwkp-transport.md

mod config;
mod peer;

#[cfg(unix)]
mod connection;
#[cfg(unix)]
mod envelope;
#[cfg(unix)]
mod protocol;
#[cfg(unix)]
mod socket;
#[cfg(unix)]
mod worker;

use core::fmt;

pub use config::{
    MAX_ALLOWED_UIDS, PeerPolicy, PolicyInput, SERVE_USAGE, ServeConfig, UsageError,
    parse_serve_args,
};

use crate::state::{PoisonReason, StartError};

/// Most connections served at once. An allowed peer over the limit is refused
/// and audited before a byte is read, and gets no holder.
pub const MAX_CONNECTIONS: usize = 32;

/// Why the server did not start, or stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeError {
    /// This platform has no peer-credential mechanism the server may use.
    Unsupported(&'static str),
    /// The configured policy could not be read.
    Policy(String),
    /// The socket path is not one the authority can protect.
    Socket(String),
    /// The configuration is inconsistent with the process it runs in.
    Configuration(String),
    /// The authority refused to start.
    Start(StartError),
    /// The operating system refused something the server needs.
    Io(String),
}

impl fmt::Display for ServeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(why) => f.write_str(why),
            Self::Policy(why) => write!(f, "policy: {why}"),
            Self::Socket(why) => write!(f, "socket: {why}"),
            Self::Configuration(why) => write!(f, "configuration: {why}"),
            Self::Start(error) => write!(f, "the authority did not start: {error}"),
            Self::Io(why) => write!(f, "I/O: {why}"),
        }
    }
}

impl std::error::Error for ServeError {}

/// How a server that started stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stopped {
    /// The store was poisoned. No request is answered after that.
    Poisoned(PoisonReason),
}

/// Serve DWKP on `config.socket` until the store is poisoned or the process is
/// killed.
///
/// # Errors
///
/// [`ServeError`] when the server does not start. On an unsupported platform
/// nothing is created, opened or started.
pub fn serve(config: &ServeConfig) -> Result<Stopped, ServeError> {
    peer::support().map_err(ServeError::Unsupported)?;
    run(config)
}

/// One operational log line on stderr. Bounded, and never a peer's bytes: it
/// is diagnostics for a human, not a record anything reads back. The security
/// record is `audit.log`.
#[cfg(unix)]
fn log(line: &str) {
    let bounded: String = line
        .chars()
        .take(400)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    eprintln!("dwkd-authority: {bounded}");
}

#[cfg(not(unix))]
fn run(_config: &ServeConfig) -> Result<Stopped, ServeError> {
    // `peer::support` refuses every non-Unix platform first; this is the
    // fail-closed shape of the same fact.
    Err(ServeError::Unsupported(
        "the DWKP server is not available on this platform",
    ))
}

#[cfg(unix)]
fn run(config: &ServeConfig) -> Result<Stopped, ServeError> {
    use std::sync::Arc;

    let (place, authority, report) = start(config)?;
    let bound = socket::bind(&place).map_err(|e| ServeError::Socket(e.to_string()))?;
    let path = place.path().to_path_buf();
    let shutdown = Arc::new(worker::Shutdown::default());
    let wake_path = path.clone();
    let (handle, worker_thread) = worker::spawn(authority, Arc::clone(&shutdown), move || {
        // Wake the accept loop so it sees the worker has stopped.
        let _ = std::os::unix::net::UnixStream::connect(&wake_path);
    })
    .map_err(|e| ServeError::Io(format!("starting the authority worker: {e}")))?;

    println!(
        "dwkd-authority: serving DWKP at {} (pid {}, incarnation {}, policy revision {}, \
         allowed uids {:?})",
        path.display(),
        std::process::id(),
        report.incarnation,
        report.policy_revision.to_hex(),
        config.peers.uids()
    );
    let _ = std::io::Write::flush(&mut std::io::stdout());

    accept(
        bound.listener(),
        &config.peers,
        &handle,
        &shutdown,
        connection::Limits::for_lease_ttl(config.lease_ttl_ms),
    );

    drop(handle);
    let _ = worker_thread.join();
    drop(bound);
    drop(place);
    Ok(Stopped::Poisoned(
        shutdown.reason().unwrap_or(PoisonReason::StorageIo),
    ))
}

/// Everything before the socket is bound: the policy read, the socket's place
/// checked, locked and cleared — before the authority starts, so a socket
/// path that cannot be protected costs no incarnation — the peer policy
/// checked against the authority's own uid, and the authority started.
#[cfg(unix)]
fn start(
    config: &ServeConfig,
) -> Result<
    (
        socket::SocketPlace,
        crate::state::Authority,
        crate::state::StartReport,
    ),
    ServeError,
> {
    use std::os::unix::fs::MetadataExt as _;

    use crate::state::{Authority, PolicySet, StartOptions, StartupConfig};

    let policy = match &config.policy {
        PolicyInput::Shipped(name) => PolicySet::shipped(name).ok_or_else(|| {
            ServeError::Policy(format!(
                "no shipped policy pack is called {name:?}; the packs are safe, balanced and power"
            ))
        })?,
        PolicyInput::Files { profile, files } => {
            PolicySet::from_files(profile, files).map_err(ServeError::Policy)?
        }
    };

    let (place, authority_uid, existing) =
        socket::prepare(&config.socket).map_err(|e| ServeError::Socket(e.to_string()))?;
    if existing == socket::Existing::StaleRemoved {
        log(&format!(
            "removed this authority's own dead socket at {}",
            place.path().display()
        ));
    }
    if config.peers.allows(authority_uid) {
        if !config.peers.authority_uid_permitted() {
            return Err(ServeError::Configuration(format!(
                "--allow-uid {authority_uid} is the authority's own uid; a peer with it can open \
                 kernel.db directly, so the process boundary would not constrain it. Run the \
                 runtime as its own user, or pass --allow-authority-uid for development"
            )));
        }
        log(&format!(
            "REDUCED ASSURANCE: uid {authority_uid}, the authority's own, may connect \
             (--allow-authority-uid); such a peer is not constrained by the process boundary"
        ));
    }

    let broker = match &config.broker {
        None => {
            log("no broker is configured: tool invocations are decided and never performed");
            None
        }
        Some(broker) => {
            let shared = broker.uid == authority_uid || config.peers.allows(broker.uid);
            if shared && !broker.shared_uid_permitted {
                return Err(ServeError::Configuration(format!(
                    "--broker-uid {} is the authority's own uid or an allowed DWKP peer's; the \
                     broker must be its own identity, so that neither the runtime nor the \
                     broker inherits the other's or the authority's powers. Run it as its own \
                     user, or pass --allow-shared-broker-uid for development",
                    broker.uid
                )));
            }
            if shared {
                log(&format!(
                    "REDUCED ASSURANCE: the broker uid {} is shared with the authority or a \
                     DWKP peer (--allow-shared-broker-uid)",
                    broker.uid
                ));
            }
            let link: std::sync::Arc<dyn crate::broker::EffectBroker> = std::sync::Arc::new(
                crate::broker::UnixBroker::new(broker.socket.clone(), broker.uid),
            );
            Some(link)
        }
    };
    let startup = StartupConfig {
        policy,
        mode: config.mode,
        ceiling: config.ceiling.clone(),
        flags: config.flags,
        lease_ttl_ms: config.lease_ttl_ms,
    };
    let options = StartOptions {
        broker,
        ..StartOptions::default()
    };
    let (authority, report) =
        Authority::start(&config.state_dir, &startup, options).map_err(ServeError::Start)?;
    let owner = std::fs::metadata(authority.state_dir())
        .map_err(|e| ServeError::Io(format!("inspecting the state directory: {e}")))?
        .uid();
    if owner != authority_uid {
        return Err(ServeError::Configuration(format!(
            "the state directory is owned by uid {owner}, the IPC directory's probe by uid \
             {authority_uid}; one process cannot be both"
        )));
    }
    Ok((place, authority, report))
}

/// Accept connections until the worker stops.
///
/// For each: the kernel's credentials first, then the operator's peer policy,
/// then the connection limit — all before a single byte is read from the
/// peer, so a refused peer learns nothing about DWKP, its versions or any
/// authority state. Only then does the connection get a thread, and only its
/// thread asks the authority for a holder.
#[cfg(unix)]
fn accept(
    listener: &std::os::unix::net::UnixListener,
    peers: &PeerPolicy,
    handle: &worker::WorkerHandle,
    shutdown: &worker::Shutdown,
    limits: connection::Limits,
) {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::state::TransportEvent;

    let responder = Arc::new(envelope::Responder::new());
    let active = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        if shutdown.stopping() {
            return;
        }
        let Ok(stream) = incoming else {
            // Out of descriptors, an aborted connection: nothing was read and
            // nothing is owed. Pause briefly so a persistent condition does not
            // spin.
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        };
        // 1. Who is it? The kernel says; nothing the peer sends is read yet.
        let Ok(credentials) = peer::peer_credentials(&stream) else {
            log("a connection whose peer the kernel could not identify was closed");
            continue;
        };
        // 2. May that uid speak to this authority at all?
        if !peers.allows(credentials.uid) {
            handle.audit(TransportEvent::PeerRefused {
                uid: credentials.uid,
                pid: credentials.pid,
            });
            drop(stream);
            continue;
        }
        // 3. Is there room?
        if active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
            handle.audit(TransportEvent::ConnectionRefused {
                uid: credentials.uid,
                pid: credentials.pid,
            });
            drop(stream);
            continue;
        }
        active.fetch_add(1, Ordering::SeqCst);
        let guard = ActiveGuard(Arc::clone(&active));
        let worker = handle.clone();
        let responder = Arc::clone(&responder);
        let spawned = std::thread::Builder::new()
            .name("dwkp-connection".to_owned())
            .spawn(move || {
                let _guard = guard;
                connection::serve(stream, credentials, &worker, &responder, limits);
            });
        if spawned.is_err() {
            // The guard went with the closure that never ran and has already
            // released the slot.
            handle.audit(TransportEvent::ConnectionRefused {
                uid: credentials.uid,
                pid: credentials.pid,
            });
        }
    }
}

/// Releases a connection slot when the connection's thread ends, however it
/// ends.
#[cfg(unix)]
struct ActiveGuard(std::sync::Arc<std::sync::atomic::AtomicUsize>);

#[cfg(unix)]
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}
