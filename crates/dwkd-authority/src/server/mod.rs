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
//!        ──▶ Authority::dispatch_parkable(caller, request)  worker.rs → crate::state
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
//! # The approver endpoint
//!
//! An operator may give the server a second socket, `--approver-socket`, for
//! the uids named by `--approver-uid` (F-18 Phase 3.4, [ADR-0067],
//! Proposed). It is a door of its own: none of its uids is a DWKP peer, the
//! broker or the authority, with no override; its place is checked as this
//! socket's is; its peers are judged by the kernel's report before a byte is
//! read. It holds no approval operation before M6 -- a peer it authenticates
//! is recorded and closed -- and this endpoint never takes an approver's
//! decision either. See `approver.rs`.
//!
//! [ADR-0067]: ../../../../docs/adr/0067-f18-approver-endpoint-identity-boundary.md
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

// The approver endpoint (F-18 Phase 3.4, ADR-0067): an identity boundary
// that holds no approval operation before M6 (TX065).
#[cfg(unix)]
mod approver;
mod config;
// The one reader of a peer's credentials (TX043), which the broker link
// asks too.
pub(crate) mod peer;
// The one place the operator's execution environment is attached (TX035):
// part of the Unix server's start-up, as `log` and `start` are.
#[cfg(unix)]
mod sandbox;

#[cfg(unix)]
mod connection;
#[cfg(unix)]
mod envelope;
#[cfg(target_os = "linux")]
mod hardening;
#[cfg(unix)]
mod protocol;
#[cfg(unix)]
mod socket;
#[cfg(unix)]
mod worker;

use core::fmt;

pub use config::{
    ApproverConfig, MAX_ALLOWED_UIDS, MAX_APPROVER_UIDS, PeerPolicy, PolicyInput, SERVE_USAGE,
    ServeConfig, UsageError, parse_serve_args,
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

/// A DWKP server for an authority the caller built and configured: the
/// evidence harness's door (M5d.2). Everything after the authority's start
/// is [`serve`]'s own — the socket's place checked and bound, the operator's
/// peer policy, the connection limit, the worker, the strict connection
/// protocol — so what the harness proves over it is what a peer meets.
///
/// It is the one way an authority with an execution environment attached is
/// reached over DWKP: [`serve`] has no option that attaches one (ADR-0047
/// §3), and nothing in this module names how one is attached (TX035). A
/// production deployment of the sandboxed `process.exec` needs that option,
/// which is an owner decision this milestone does not make.
#[cfg(unix)]
#[derive(Debug)]
pub struct Served {
    handle: worker::WorkerHandle,
    shutdown: std::sync::Arc<worker::Shutdown>,
    path: std::path::PathBuf,
    accept: Option<std::thread::JoinHandle<()>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

#[cfg(unix)]
impl Served {
    /// The socket it serves.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Run `work` on the served authority between requests — the harness's
    /// own in-process operations, which no peer can reach — and return what
    /// it returned. `None` once the server has stopped.
    pub fn operate<R: Send + 'static>(
        &self,
        work: impl FnOnce(&mut crate::state::Authority) -> R + Send + 'static,
    ) -> Option<R> {
        self.handle.operate(work)
    }

    /// Whether it has stopped: a poisoned store, or [`Served::stop`].
    #[must_use]
    pub fn stopped(&self) -> bool {
        self.shutdown.stopping()
    }

    /// Stop serving and wait for the server's threads: the socket is removed
    /// and the authority — every parked launch with it — is dropped.
    pub fn stop(mut self) {
        self.halt();
    }

    fn halt(&mut self) {
        self.shutdown.request_stop();
        // Wake the accept loop and the worker so both see it.
        let _ = std::os::unix::net::UnixStream::connect(&self.path);
        let _ = self.handle.operate(|_| ());
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(unix)]
impl Drop for Served {
    fn drop(&mut self) {
        self.halt();
    }
}

/// Serve DWKP on `socket` for `authority`, admitting `peers` (M5d.2): see
/// [`Served`].
///
/// # Errors
///
/// [`ServeError`] when the server does not start; nothing is bound then.
#[cfg(unix)]
pub fn serve_authority(
    authority: crate::state::Authority,
    socket: &std::path::Path,
    peers: PeerPolicy,
    lease_ttl_ms: u64,
) -> Result<Served, ServeError> {
    use std::sync::Arc;

    peer::support().map_err(ServeError::Unsupported)?;
    let (place, authority_uid, _) =
        socket::prepare(socket).map_err(|e| ServeError::Socket(e.to_string()))?;
    if peers.allows(authority_uid) && !peers.authority_uid_permitted() {
        return Err(ServeError::Configuration(format!(
            "uid {authority_uid} is the authority's own; the peer policy does not permit it"
        )));
    }
    let bound = socket::bind(&place).map_err(|e| ServeError::Socket(e.to_string()))?;
    let path = place.path().to_path_buf();
    let shutdown = Arc::new(worker::Shutdown::default());
    let wake_path = path.clone();
    let (handle, worker_thread) = worker::spawn(authority, Arc::clone(&shutdown), move || {
        let _ = std::os::unix::net::UnixStream::connect(&wake_path);
    })
    .map_err(|e| ServeError::Io(format!("starting the authority worker: {e}")))?;
    let accepting = handle.clone();
    let stopping = Arc::clone(&shutdown);
    let limits = connection::Limits::for_lease_ttl(lease_ttl_ms);
    let accept_thread = std::thread::Builder::new()
        .name("dwkp-accept".to_owned())
        .spawn(move || {
            accept(bound.listener(), &peers, &accepting, &stopping, limits);
            drop(bound);
            drop(place);
        })
        .map_err(|e| ServeError::Io(format!("starting the accept loop: {e}")))?;
    Ok(Served {
        handle,
        shutdown,
        path,
        accept: Some(accept_thread),
        worker: Some(worker_thread),
    })
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

    // Before anything is read -- the secret index reads every configured
    // value once at start -- the process can dump no core, and no other
    // process of its uid can read its memory (M4e, ADR-0046 §9).
    #[cfg(target_os = "linux")]
    {
        hardening::apply(config.dumpable_permitted).map_err(ServeError::Io)?;
        if config.dumpable_permitted {
            log(
                "REDUCED ASSURANCE: the process stays dumpable (--allow-dumpable); its memory is \
                 readable by other processes of its uid. RLIMIT_CORE is 0",
            );
        }
    }
    let (place, authority, report, approver) = start(config)?;
    let bound = socket::bind(&place).map_err(|e| ServeError::Socket(e.to_string()))?;
    let path = place.path().to_path_buf();
    let approver = match approver {
        None => None,
        Some((approver_place, policy)) => {
            let approver_bound = socket::bind(&approver_place)
                .map_err(|e| ServeError::Socket(format!("the approver endpoint: {e}")))?;
            Some((approver_place, approver_bound, policy))
        }
    };
    let approver_path = approver
        .as_ref()
        .map(|(approver_place, _, _)| approver_place.path().to_path_buf());
    let shutdown = Arc::new(worker::Shutdown::default());
    let wake_path = path.clone();
    let wake_approver = approver_path.clone();
    let (handle, worker_thread) = worker::spawn(authority, Arc::clone(&shutdown), move || {
        // Wake the accept loops so they see the worker has stopped.
        let _ = std::os::unix::net::UnixStream::connect(&wake_path);
        if let Some(approver) = &wake_approver {
            let _ = std::os::unix::net::UnixStream::connect(approver);
        }
    })
    .map_err(|e| ServeError::Io(format!("starting the authority worker: {e}")))?;
    let approver_thread = match approver {
        None => None,
        Some((approver_place, approver_bound, policy)) => {
            log(&format!(
                "approver endpoint at {} for uids {:?}: it authenticates approvers by the \
                 kernel's report and holds no approval operation before M6; every \
                 REQUIRE_APPROVAL still denies",
                approver_place.path().display(),
                policy.uids()
            ));
            let recorder = handle.clone();
            let stopping = Arc::clone(&shutdown);
            let thread = std::thread::Builder::new()
                .name("dwkp-approver-accept".to_owned())
                .spawn(move || {
                    approver::accept(approver_bound.listener(), &policy, &stopping, |event| {
                        recorder.audit(event);
                    });
                    drop(approver_bound);
                    drop(approver_place);
                })
                .map_err(|e| ServeError::Io(format!("starting the approver endpoint: {e}")))?;
            Some(thread)
        }
    };

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

    // The DWKP loop ends only once the server is stopping; wake the approver
    // loop too, and wait for it, before the worker it records through.
    if let (Some(thread), Some(approver)) = (approver_thread, approver_path) {
        let _ = std::os::unix::net::UnixStream::connect(&approver);
        let _ = thread.join();
    }
    drop(handle);
    let _ = worker_thread.join();
    drop(bound);
    drop(place);
    Ok(Stopped::Poisoned(
        shutdown.reason().unwrap_or(PoisonReason::StorageIo),
    ))
}

/// The approver endpoint's checked place and its approvers (F-18 Phase 3.4,
/// ADR-0067). Unix only, as `start` is.
#[cfg(unix)]
type Approver = (socket::SocketPlace, approver::ApproverPolicy);

/// The approver endpoint's place, if one is configured, checked, locked and
/// cleared as the DWKP socket's is, and its approvers: none the authority's
/// own uid -- the parser has already kept out the runtime's and the
/// broker's -- and never the DWKP socket's name, however it is spelled.
/// Unix only, as `start` is, its one caller.
#[cfg(unix)]
fn approver_place(
    config: &ServeConfig,
    authority_uid: u32,
    dwkp: &socket::SocketPlace,
) -> Result<Option<Approver>, ServeError> {
    let Some(approver) = &config.approver else {
        return Ok(None);
    };
    if approver.uids.contains(&authority_uid) {
        return Err(ServeError::Configuration(format!(
            "--approver-uid {authority_uid} is the authority's own uid: the authority decides \
             what an approval permits and is never the human who approves it. There is no \
             override"
        )));
    }
    let resolved = approver
        .socket
        .parent()
        .and_then(|dir| std::fs::canonicalize(dir).ok())
        .zip(approver.socket.file_name())
        .map(|(dir, name)| dir.join(name));
    if resolved.as_deref() == Some(dwkp.path()) {
        return Err(ServeError::Configuration(
            "--approver-socket names the DWKP socket: the approver endpoint is a door of its own"
                .to_owned(),
        ));
    }
    let (place, _, existing) = socket::prepare(&approver.socket)
        .map_err(|e| ServeError::Socket(format!("the approver endpoint: {e}")))?;
    if existing == socket::Existing::StaleRemoved {
        log(&format!(
            "removed this authority's own dead approver socket at {}",
            place.path().display()
        ));
    }
    Ok(Some((
        place,
        approver::ApproverPolicy::new(approver.uids.clone()),
    )))
}

/// Everything before the socket is bound: the policy read, the socket's place
/// checked, locked and cleared — before the authority starts, so a socket
/// path that cannot be protected costs no incarnation — the peer policy
/// checked against the authority's own uid, the approver endpoint's place and
/// approvers checked the same way, and the authority started.
#[cfg(unix)]
fn start(
    config: &ServeConfig,
) -> Result<
    (
        socket::SocketPlace,
        crate::state::Authority,
        crate::state::StartReport,
        Option<Approver>,
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
    let approver = approver_place(config, authority_uid, &place)?;

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
    let secrets = secret_config(config.secrets_file.as_deref(), authority_uid)?;
    let egress = egress_allowlist(config.egress_allowlist.as_deref(), authority_uid)?;
    let startup = StartupConfig {
        policy,
        mode: config.mode,
        ceiling: config.ceiling.clone(),
        flags: config.flags,
        lease_ttl_ms: config.lease_ttl_ms,
        secrets,
        net_budget: crate::state::NetBudget::default(),
        anchors: host_anchors(config),
        egress,
    };
    let options = StartOptions {
        broker,
        ..StartOptions::default()
    };
    let (mut authority, report) =
        Authority::start(&config.state_dir, &startup, options).map_err(ServeError::Start)?;
    let workspace = sandbox::attach(
        &mut authority,
        config.sandbox_config.as_deref(),
        authority_uid,
    )?;
    let owner = std::fs::metadata(authority.state_dir())
        .map_err(|e| ServeError::Io(format!("inspecting the state directory: {e}")))?
        .uid();
    if owner != authority_uid {
        return Err(ServeError::Configuration(format!(
            "the state directory is owned by uid {owner}, the IPC directory's probe by uid \
             {authority_uid}; one process cannot be both"
        )));
    }
    log_anchors(authority.host_anchors());
    record_posture(&mut authority, config, authority_uid, workspace)?;
    Ok((place, authority, report, approver))
}

/// What each host path anchor stands for (F-12, ADR-0066, Proposed): the
/// operator's `--path-anchor` directories, and the directory of every
/// configuration file this start reads -- policy files, the secret metadata,
/// the sandbox configuration -- under `${DIREWOLF_CONFIG}`. The state layer
/// adds its own state and executable directories and checks every one.
/// Unix only, as `start` is, its one caller.
#[cfg(unix)]
fn host_anchors(config: &ServeConfig) -> crate::state::HostAnchors {
    use self::config::AnchorName;
    let mut anchors = crate::state::HostAnchors::default();
    for (name, dir) in &config.path_anchors {
        let list = match name {
            AnchorName::Home => &mut anchors.home,
            AnchorName::DirewolfHome => &mut anchors.direwolf_home,
            AnchorName::DirewolfConfig => &mut anchors.direwolf_config,
            AnchorName::DirewolfInstall => &mut anchors.direwolf_install,
        };
        list.push(dir.clone());
    }
    let mut files: Vec<&std::path::Path> = Vec::new();
    if let PolicyInput::Files { files: policy, .. } = &config.policy {
        files.extend(policy.iter().map(std::path::PathBuf::as_path));
    }
    files.extend(config.secrets_file.as_deref());
    files.extend(config.sandbox_config.as_deref());
    files.extend(config.egress_allowlist.as_deref());
    for file in files {
        let directory = std::fs::canonicalize(file).ok().and_then(|real| {
            real.parent()
                .and_then(|dir| dir.to_str())
                .map(str::to_owned)
        });
        if let Some(directory) = directory
            && !anchors.direwolf_config.contains(&directory)
        {
            anchors.direwolf_config.push(directory);
        }
    }
    anchors
}

/// Say what each host path anchor stands for, once, at start: the operator
/// can see which locations the packs' hard denials are placed against, and
/// that `~` stands for nothing when no home was configured. Unix only, as
/// `log` and `start` are.
#[cfg(unix)]
fn log_anchors(anchors: &crate::state::HostAnchors) {
    for (name, list) in [
        ("~", &anchors.home),
        ("${DIREWOLF_HOME}", &anchors.direwolf_home),
        ("${DIREWOLF_CONFIG}", &anchors.direwolf_config),
        ("${DIREWOLF_INSTALL}", &anchors.direwolf_install),
    ] {
        if list.is_empty() {
            log(&format!(
                "path anchor {name} stands for nothing: every rule naming it is unresolved and \
                 denies (--path-anchor)"
            ));
        } else {
            log(&format!("path anchor {name} = {}", list.join(", ")));
        }
    }
}

/// Say the effective start-up posture on stderr and record it in
/// `audit.log` (F-03, ADR-0065, Proposed), before the socket is bound: an
/// incarnation that served weakened is never recorded as one that did not.
/// The facts are the configuration the start acted on, and this process's
/// hardening read back from the kernel.
#[cfg(unix)]
fn record_posture(
    authority: &mut crate::state::Authority,
    config: &ServeConfig,
    authority_uid: u32,
    workspace: Option<crate::sandbox::WorkspaceSetting>,
) -> Result<(), ServeError> {
    use crate::posture::Broker;

    #[cfg(target_os = "linux")]
    let hardened = Some(hardening::observed());
    #[cfg(not(target_os = "linux"))]
    let hardened = None;
    let broker = match &config.broker {
        None => Broker::None,
        Some(broker) if broker.uid == authority_uid || config.peers.allows(broker.uid) => {
            Broker::Shared
        }
        Some(_) => Broker::Own,
    };
    let controls = crate::posture::of_authority(&crate::posture::Facts {
        hardened,
        dumpable_permitted: config.dumpable_permitted,
        authority_uid_admitted: config.peers.allows(authority_uid),
        broker,
        host_execution: config.flags.security_allow_host_execution,
        workspace,
    });
    for line in crate::posture::lines(&controls) {
        log(&line);
    }
    authority
        .record_posture(&controls)
        .map_err(|error| ServeError::Io(format!("recording the effective posture: {error}")))
}

/// The operator's secret metadata (`--secrets-file`), read through the
/// trusted reader: none configured, none known.
#[cfg(unix)]
fn secret_config(
    path: Option<&std::path::Path>,
    authority_uid: u32,
) -> Result<crate::secret::metadata::SecretConfig, ServeError> {
    let Some(path) = path else {
        return Ok(crate::secret::metadata::SecretConfig::default());
    };
    let text = crate::secret::backend::read_metadata_file(&path.to_string_lossy(), authority_uid)
        .map_err(ServeError::Configuration)?;
    crate::secret::metadata::parse(&text).map_err(|error| {
        ServeError::Configuration(format!("--secrets-file {}: {error}", path.display()))
    })
}

/// The operator's egress allowlist (`--egress-allowlist`, F-06, ADR-0071):
/// read as every operator file is -- owned by root or the authority,
/// writable by nobody else, no symlink, bounded -- and parsed strictly. Said
/// at start: how many destinations, by name, or that there is none.
#[cfg(unix)]
fn egress_allowlist(
    path: Option<&std::path::Path>,
    authority_uid: u32,
) -> Result<crate::state::egress_allowlist::EgressAllowlist, ServeError> {
    let Some(path) = path else {
        log(
            "egress allowlist: none -- every network rule that requires \
             destination_allowlisted, every shipped pack's among them, grants no destination",
        );
        return Ok(crate::state::egress_allowlist::EgressAllowlist::empty());
    };
    let text = crate::secret::backend::read_operator_file(
        &path.to_string_lossy(),
        authority_uid,
        crate::state::egress_allowlist::MAX_FILE_BYTES,
        "--egress-allowlist",
    )
    .map_err(ServeError::Configuration)?;
    let allowlist =
        crate::state::egress_allowlist::EgressAllowlist::parse(&text).map_err(|error| {
            ServeError::Configuration(format!("--egress-allowlist {}: {error}", path.display()))
        })?;
    let names: Vec<&str> = allowlist
        .destinations()
        .iter()
        .map(|d| d.name.as_str())
        .collect();
    log(&format!(
        "egress allowlist {}: {} destination(s): {}",
        path.display(),
        names.len(),
        if names.is_empty() {
            "none".to_owned()
        } else {
            names.join(",")
        }
    ));
    Ok(allowlist)
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
