//! The broker's per-environment proxies (M5b, ADR-0048): one Unix socket and
//! one accepting thread per `PROXY_ONLY` environment, opened before its
//! relay starts and closed when it is destroyed.
//!
//! ```text
//! <broker socket dir>/egress/                 0700, the broker's alone
//! <broker socket dir>/egress/<environment>/   0700 + an ACL: search for the
//!                                             relay's uid only (shown 0710);
//!                                             bind-mounted read-only into
//!                                             that environment's relay
//! <broker socket dir>/egress/<environment>/proxy.sock   0666
//! ```
//!
//! **Who can connect is decided by the kernel's permission check on the
//! directory, by uid, not by asking who connected.** The root is the
//! broker's alone (0700). Each environment's directory is bind-mounted,
//! read-only, into exactly one container — that environment's relay — and
//! carries a POSIX ACL that lets the relay's uid (10002) search it and no one
//! else but the broker: not the environment's uid, not root without
//! `CAP_DAC_OVERRIDE`, not any other host user. The ACL travels with the
//! directory, so it holds wherever a runtime exposes it — Docker Desktop on
//! WSL2 re-exposes every bind source under
//! `/mnt/wsl/docker-desktop-bind-mounts/`, beneath a world-searchable
//! directory every WSL distribution shares (measured), and there the ACL is
//! what stops another uid. The socket is mode 0666 only because the ACL
//! already decides who reaches it. A filesystem that cannot keep the ACL
//! refuses the proxy (`PROXY_UNAVAILABLE`).
//!
//! `SO_PEERCRED` is **not** consulted here (ADR-0048). When M5b was built the
//! only reader was `rustix` 1.1.5's `socket_peercred`, and where the runtime
//! runs containers in a pid namespace the broker cannot see (Docker Desktop's
//! engine runs in a sibling WSL distribution) the kernel reports the relay's
//! pid as 0 — measured: uid 10002, gid 10002, pid 0 — which that read turned
//! into undefined behaviour. The ACL makes the same uid check, at path
//! resolution instead of after `accept`. A sound reader now exists
//! (`crate::peer`, ADR-0049); checking the relay's uid after `accept` as
//! well, as defence in depth, is ADR-0048's revisit, not done here.
//!
//! Each environment's grant, budgets and counters are its own.
//!
//! The listeners live in the broker process. A broker that restarts has none:
//! every `PROXY_ONLY` environment it had is unreachable through its relay,
//! measures as drift, and is destroyed — never reconnected to a proxy that
//! was not the one its grant was given to. The stale directories are removed
//! when the broker starts, and nothing else in the root ever is.

use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{
    DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, PermissionsExt as _,
};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use dwk_proto::brokerp::egress::{EgressCounters, EgressDisposition, EgressGrant};
use dwk_sandbox_profile::{EGRESS_SOCKET_NAME, RELAY_MAX_CONNECTIONS, RELAY_UID};

use super::tunnel::{self, Context};
use super::{Counters, Limits, resolve};

/// The root's mode: the broker's alone.
const ROOT_MODE: u32 = 0o700;
/// An environment's directory, once its ACL is set: the broker everything,
/// the ACL's mask (`--x`, shown as the group bits) for the relay's uid, and
/// nothing for anyone else.
const ENVIRONMENT_MODE: u32 = 0o710;
/// The socket: whoever reaches it may connect — and only the broker and the
/// relay's uid can reach it, through the directory's ACL.
const SOCKET_MODE: u32 = 0o666;
/// Where a directory's access ACL is kept.
const ACL_XATTR: &str = "system.posix_acl_access";
/// How long closing waits for the environment's connections to end.
const CLOSE_WAIT: Duration = Duration::from_secs(3);
/// How long a failed accept waits before the next.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);
/// The longest environment name a directory is made for.
const NAME_MAX: usize = 64;

/// One open proxy.
#[derive(Debug)]
struct Open {
    dir: PathBuf,
    socket: PathBuf,
    identity: (u64, u64),
    context: Arc<Context>,
    handlers: Arc<AtomicUsize>,
    accept: Option<JoinHandle<()>>,
}

/// A socket just bound, and the context its connections will share.
struct Listening {
    socket: PathBuf,
    identity: (u64, u64),
    listener: UnixListener,
    context: Arc<Context>,
}

/// Every open proxy, by environment.
#[derive(Debug)]
pub(crate) struct Proxies {
    root: PathBuf,
    owner: u32,
    resolver: resolve::Shared,
    limits: Limits,
    open: Mutex<BTreeMap<String, Open>>,
}

/// Why a proxy could not be opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProxyError(pub(crate) String);

fn io(what: &str, path: &Path, error: &std::io::Error) -> ProxyError {
    ProxyError(format!("{what} {}: {:?}", path.display(), error.kind()))
}

/// The access ACL that lets `uid` search a directory and no one but its
/// owner do anything else, in the kernel's `system.posix_acl_access`
/// encoding: version 2, then `(tag, permissions, id)` entries, little-endian,
/// in the order the kernel requires (owner, named user, group, mask, other).
pub(crate) fn relay_only_acl(uid: u32) -> Vec<u8> {
    const VERSION: u32 = 2;
    const UNDEFINED: u32 = u32::MAX;
    const USER_OBJ: u16 = 0x01;
    const USER: u16 = 0x02;
    const GROUP_OBJ: u16 = 0x04;
    const MASK: u16 = 0x10;
    const OTHER: u16 = 0x20;
    const ALL: u16 = 0o7;
    const SEARCH: u16 = 0o1;
    const NONE: u16 = 0;
    let mut acl = VERSION.to_le_bytes().to_vec();
    for (tag, permissions, id) in [
        (USER_OBJ, ALL, UNDEFINED),
        (USER, SEARCH, uid),
        (GROUP_OBJ, NONE, UNDEFINED),
        (MASK, SEARCH, UNDEFINED),
        (OTHER, NONE, UNDEFINED),
    ] {
        acl.extend_from_slice(&tag.to_le_bytes());
        acl.extend_from_slice(&permissions.to_le_bytes());
        acl.extend_from_slice(&id.to_le_bytes());
    }
    acl
}

/// Whether `dir` holds exactly the relay-only ACL, and the mode that shows
/// it: a `chmod` or an ACL edit since it was set is not.
fn holds_relay_only_acl(dir: &Path) -> bool {
    let mut held = [0u8; 64];
    let acl = rustix::fs::lgetxattr(dir, ACL_XATTR, &mut held[..])
        .is_ok_and(|length| held.get(..length) == Some(relay_only_acl(RELAY_UID).as_slice()));
    acl && fs::symlink_metadata(dir)
        .is_ok_and(|m| m.is_dir() && m.permissions().mode() & 0o777 == ENVIRONMENT_MODE)
}

/// Give `dir` the relay-only ACL, and prove the kernel holds exactly it.
fn restrict_to_relay(dir: &Path) -> Result<(), ProxyError> {
    rustix::fs::lsetxattr(
        dir,
        ACL_XATTR,
        &relay_only_acl(RELAY_UID),
        rustix::fs::XattrFlags::empty(),
    )
    .map_err(|e| io("restricting to the relay", dir, &e.into()))?;
    if !holds_relay_only_acl(dir) {
        return Err(ProxyError(format!(
            "{} did not keep the relay-only ACL",
            dir.display()
        )));
    }
    Ok(())
}

/// Whether `name` may name an environment's directory: an environment id
/// (`env_` and its encoded UUID), never a path.
fn plain(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= NAME_MAX
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

impl Proxies {
    /// The proxies, rooted at `root`, which is created if absent and must be
    /// the broker's own private directory. What a previous broker left there
    /// is removed — its own sockets and directories only.
    ///
    /// # Errors
    ///
    /// The root is not the broker's private directory.
    pub(crate) fn new(
        root: PathBuf,
        owner: u32,
        resolver: resolve::Shared,
        limits: Limits,
    ) -> Result<Self, ProxyError> {
        match fs::symlink_metadata(&root) {
            Err(error) if error.kind() == ErrorKind::NotFound => {
                fs::DirBuilder::new()
                    .mode(ROOT_MODE)
                    .create(&root)
                    .map_err(|e| io("creating", &root, &e))?;
                fs::set_permissions(&root, fs::Permissions::from_mode(ROOT_MODE))
                    .map_err(|e| io("setting the mode of", &root, &e))?;
            }
            Err(error) => return Err(io("inspecting", &root, &error)),
            Ok(_) => {}
        }
        let meta = fs::symlink_metadata(&root).map_err(|e| io("inspecting", &root, &e))?;
        if meta.file_type().is_symlink()
            || !meta.is_dir()
            || meta.uid() != owner
            || meta.permissions().mode() & 0o077 != 0
        {
            return Err(ProxyError(format!(
                "{} must be the broker's own private directory",
                root.display()
            )));
        }
        let proxies = Self {
            root,
            owner,
            resolver,
            limits,
            open: Mutex::new(BTreeMap::new()),
        };
        proxies.clear_stale();
        Ok(proxies)
    }

    /// A registry with no root on disk, for unit tests of code that holds a
    /// sandbox supervisor but prepares nothing: it touches no file, and
    /// `start` fails (the root does not exist). Not compiled into the broker.
    #[cfg(test)]
    pub(crate) fn without_root(resolver: resolve::Shared, limits: Limits) -> Self {
        Self {
            root: PathBuf::from("/nonexistent/direwolf-egress"),
            owner: u32::MAX,
            resolver,
            limits,
            open: Mutex::new(BTreeMap::new()),
        }
    }

    /// Remove what a previous broker left: an environment directory holding
    /// at most its own dead socket. Anything else is left, and said.
    fn clear_stale(&self) {
        let Ok(entries) = fs::read_dir(&self.root) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let path = entry.path();
            let ours = name.to_str().is_some_and(plain)
                && fs::symlink_metadata(&path).is_ok_and(|m| {
                    m.is_dir() && !m.file_type().is_symlink() && m.uid() == self.owner
                });
            let socket = path.join(EGRESS_SOCKET_NAME);
            if ours
                && fs::symlink_metadata(&socket)
                    .is_ok_and(|m| m.file_type().is_socket() && m.uid() == self.owner)
            {
                let _ = fs::remove_file(&socket);
            }
            if ours && fs::remove_dir(&path).is_ok() {
                crate::event("egress_stale_removed");
            } else {
                crate::event("egress_stale_left");
            }
        }
    }

    /// Open `environment`'s proxy for `grant`, and return the directory the
    /// relay is given.
    ///
    /// # Errors
    ///
    /// The name is not an environment's, it is already open, or the
    /// directory or socket could not be made.
    pub(crate) fn start(
        &self,
        environment: &str,
        grant: EgressGrant,
    ) -> Result<PathBuf, ProxyError> {
        if !plain(environment) {
            return Err(ProxyError("not an environment name".to_owned()));
        }
        let mut open = self
            .open
            .lock()
            .map_err(|_| ProxyError("the proxy table is poisoned".to_owned()))?;
        if open.contains_key(environment) {
            return Err(ProxyError("already open".to_owned()));
        }
        let dir = self.root.join(environment);
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| io("creating", &dir, &e))?;
        let Listening {
            socket,
            identity,
            listener,
            context,
        } = match self.listen(&dir, grant) {
            Ok(listening) => listening,
            Err(error) => {
                let _ = fs::remove_file(dir.join(EGRESS_SOCKET_NAME));
                let _ = fs::remove_dir(&dir);
                return Err(error);
            }
        };
        let handlers = Arc::new(AtomicUsize::new(0));
        let accept = {
            let context = Arc::clone(&context);
            let handlers = Arc::clone(&handlers);
            std::thread::Builder::new()
                .name("dw-egress-accept".to_owned())
                .spawn(move || accept(&listener, &context, &handlers))
        };
        let accept = match accept {
            Ok(accept) => accept,
            Err(error) => {
                let _ = fs::remove_file(&socket);
                let _ = fs::remove_dir(&dir);
                return Err(io("starting the proxy for", &dir, &error));
            }
        };
        open.insert(
            environment.to_owned(),
            Open {
                dir: dir.clone(),
                socket,
                identity,
                context,
                handlers,
                accept: Some(accept),
            },
        );
        Ok(dir)
    }

    /// Bind the socket in a fresh environment directory.
    fn listen(&self, dir: &Path, grant: EgressGrant) -> Result<Listening, ProxyError> {
        let socket = dir.join(EGRESS_SOCKET_NAME);
        let listener = UnixListener::bind(&socket).map_err(|e| io("binding", &socket, &e))?;
        let meta = fs::symlink_metadata(&socket).map_err(|e| io("inspecting", &socket, &e))?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(SOCKET_MODE))
            .map_err(|e| io("setting the mode of", &socket, &e))?;
        // Until now the directory was the broker's alone (0700); from here the
        // relay's uid may search it, and no one else.
        restrict_to_relay(dir)?;
        let context = Arc::new(Context::new(
            grant,
            Arc::new(Counters::default()),
            Arc::clone(&self.resolver),
            self.limits,
        ));
        Ok(Listening {
            socket,
            identity: (meta.dev(), meta.ino()),
            listener,
            context,
        })
    }

    /// Whether `environment`'s proxy is open and accepting, on the socket it
    /// bound, in a directory still the relay's alone (`HOST_PROXY_RELAY`).
    pub(crate) fn is_open(&self, environment: &str) -> bool {
        self.open.lock().is_ok_and(|open| {
            open.get(environment).is_some_and(|o| {
                o.accept.as_ref().is_some_and(|a| !a.is_finished())
                    && fs::symlink_metadata(&o.socket)
                        .is_ok_and(|m| (m.dev(), m.ino()) == o.identity)
                    && holds_relay_only_acl(&o.dir)
            })
        })
    }

    /// The directory `environment`'s relay is given, while its proxy is open.
    pub(crate) fn dir(&self, environment: &str) -> Option<PathBuf> {
        let open = self.open.lock().ok()?;
        open.get(environment).map(|o| o.dir.clone())
    }

    /// What `environment`'s proxy has done so far.
    pub(crate) fn counters(&self, environment: &str) -> Option<EgressCounters> {
        let open = self.open.lock().ok()?;
        open.get(environment)?.context.counters.snapshot()
    }

    /// Close `environment`'s proxy: refuse new connections, end the open
    /// ones (`ENVIRONMENT_CLOSED`), remove its socket and directory, and
    /// return what it did. `None` when it was not open.
    pub(crate) fn close(&self, environment: &str) -> Option<EgressCounters> {
        let mut closing = self.open.lock().ok()?.remove(environment)?;
        closing.context.closing.store(true, Ordering::SeqCst);
        // Wake the accepting thread: it sees `closing` before anything else.
        let _ = UnixStream::connect(&closing.socket);
        if let Some(accept) = closing.accept.take() {
            let _ = accept.join();
        }
        let deadline = Instant::now() + CLOSE_WAIT;
        while closing.handlers.load(Ordering::SeqCst) > 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        if fs::symlink_metadata(&closing.socket)
            .is_ok_and(|m| m.file_type().is_socket() && (m.dev(), m.ino()) == closing.identity)
        {
            let _ = fs::remove_file(&closing.socket);
        }
        let _ = fs::remove_dir(&closing.dir);
        closing.context.counters.snapshot()
    }

    /// Every open proxy's environment.
    #[cfg(test)]
    pub(crate) fn environments(&self) -> Vec<String> {
        self.open
            .lock()
            .map(|open| open.keys().cloned().collect())
            .unwrap_or_default()
    }
}

/// One connection's handler slot, given back however the handler ends — a
/// thread that could not be started, or one that unwound, included.
struct Handling(Arc<AtomicUsize>);

impl Handling {
    fn take(handlers: &Arc<AtomicUsize>) -> Option<Self> {
        handlers
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < RELAY_MAX_CONNECTIONS).then_some(n + 1)
            })
            .ok()
            .map(|_| Self(Arc::clone(handlers)))
    }
}

impl Drop for Handling {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Accept the relay's connections until the environment closes. Nothing is
/// asked of the kernel about the peer (the directory's ACL decided who could
/// reach the socket), and
/// nothing the peer sends is trusted: at most [`RELAY_MAX_CONNECTIONS`]
/// connections are handled at once whatever the relay does.
fn accept(listener: &UnixListener, context: &Arc<Context>, handlers: &Arc<AtomicUsize>) {
    for incoming in listener.incoming() {
        if context.closing.load(Ordering::SeqCst) {
            return;
        }
        let Ok(stream) = incoming else {
            // A failing accept (descriptors exhausted) is retried, not spun on.
            std::thread::sleep(ACCEPT_BACKOFF);
            continue;
        };
        let Some(handling) = Handling::take(handlers) else {
            context.counters.record(EgressDisposition::TunnelLimit);
            continue;
        };
        let context = Arc::clone(context);
        // A thread that cannot be started drops its closure, and the slot.
        let _ = std::thread::Builder::new()
            .name("dw-egress-tunnel".to_owned())
            .spawn(move || {
                let _handling = handling;
                let disposition = tunnel::serve(&stream, &context);
                crate::event(&format!(
                    "egress_tunnel disposition={}",
                    disposition.as_str()
                ));
            });
    }
}
