//! One connection from the relay (M5b, ADR-0048): a CONNECT request and, at
//! most, one opaque tunnel to a pinned address.
//!
//! The order is the policy, and nothing is connected to until every check
//! has passed: the request ([`super::request`]), the grant, the tunnel count,
//! one resolution and the whole answer's guard ([`super::guard`]), then
//! `200` — and only then the `ClientHello`'s server name ([`super::hello`]),
//! which must be the CONNECT host **before** the pinned address is dialled.
//! A refusal before `200` is answered `HTTP/1.1 4xx` with the disposition in
//! [`PROXY_DECISION_HEADER`] and nothing else; one after is the connection
//! closed. There is never a second request, a second resolution or a
//! fallback.
//!
//! The tunnel's bytes are carried, never read: each direction reads at most
//! one byte more than the environment's remaining budget, carries what is
//! left of it and, past it, closes the tunnel — so the budget holds at the
//! socket, exactly, and every later tunnel finds it spent. Every read and write wakes at least every
//! [`TICK`] to observe the environment closing, the tunnel's lifetime and
//! idleness — nothing moving either way.
//!
//! [`PROXY_DECISION_HEADER`]: dwk_sandbox_profile::PROXY_DECISION_HEADER

use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dwk_proto::brokerp::egress::{EgressDisposition, EgressGrant};
use dwk_sandbox_profile::PROXY_DECISION_HEADER;

use super::hello::Hello;
use super::request::{self, Parsed};
use super::{Counters, HELLO_MAX_BUFFERED, Limits, REQUEST_MAX_BYTES, guard, resolve};

/// The longest a read or write blocks before the tunnel's clocks and the
/// environment's closing are looked at again.
pub(crate) const TICK: Duration = Duration::from_millis(250);

/// The bytes a direction may still carry, for the whole environment.
#[derive(Debug)]
pub(crate) struct Budget(AtomicU64);

impl Budget {
    pub(crate) const fn new(bytes: u64) -> Self {
        Self(AtomicU64::new(bytes))
    }

    /// What is left.
    fn left(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }

    /// Spend `bytes`, if they are all left.
    fn spend(&self, bytes: u64) -> bool {
        self.0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(bytes)
            })
            .is_ok()
    }

    /// Spend as much of `bytes` as is left, and say how much that was.
    fn take(&self, bytes: u64) -> u64 {
        self.0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                Some(left.saturating_sub(bytes))
            })
            .map_or(0, |left| left.min(bytes))
    }
}

/// What one environment's proxy shares between its connections.
#[derive(Debug)]
pub(crate) struct Context {
    /// The destinations and the budgets.
    pub(crate) grant: EgressGrant,
    /// What has happened.
    pub(crate) counters: Arc<Counters>,
    /// Tunnels open now: granted, not yet ended.
    pub(crate) tunnels: AtomicUsize,
    /// Bytes the environment may still send.
    pub(crate) upload: Budget,
    /// Bytes the environment may still receive.
    pub(crate) download: Budget,
    /// The resolver.
    pub(crate) resolver: resolve::Shared,
    /// The deadlines.
    pub(crate) limits: Limits,
    /// Set when the environment is being destroyed.
    pub(crate) closing: AtomicBool,
}

impl Context {
    /// A context for `grant`.
    pub(crate) fn new(
        grant: EgressGrant,
        counters: Arc<Counters>,
        resolver: resolve::Shared,
        limits: Limits,
    ) -> Self {
        let upload = Budget::new(grant.max_upload_bytes.get());
        let download = Budget::new(grant.max_download_bytes.get());
        Self {
            grant,
            counters,
            tunnels: AtomicUsize::new(0),
            upload,
            download,
            resolver,
            limits,
            closing: AtomicBool::new(false),
        }
    }
}

/// A held tunnel slot, given back when the tunnel ends.
struct Held<'a>(&'a AtomicUsize);

impl<'a> Held<'a> {
    fn take(open: &'a AtomicUsize, most: usize) -> Option<Self> {
        open.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            (n < most).then_some(n + 1)
        })
        .ok()
        .map(|_| Self(open))
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Why a bounded read or write stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// Its deadline passed.
    Timeout,
    /// The environment is closing.
    Closing,
    /// The peer ended its side.
    Eof,
    /// The socket failed.
    Failed,
}

/// Whether an I/O error is only the tick passing.
fn ticked(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
    )
}

/// Read once, before `deadline`, watching the environment close.
fn read_before(
    stream: &UnixStream,
    into: &mut [u8],
    deadline: Instant,
    closing: &AtomicBool,
) -> Result<usize, Stop> {
    loop {
        if closing.load(Ordering::SeqCst) {
            return Err(Stop::Closing);
        }
        let left = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(Stop::Timeout)?;
        stream
            .set_read_timeout(Some(left.min(TICK)))
            .map_err(|_| Stop::Failed)?;
        match (&*stream).read(into) {
            Ok(0) => return Err(Stop::Eof),
            Ok(n) => return Ok(n),
            Err(e) if ticked(e.kind()) => {}
            Err(_) => return Err(Stop::Failed),
        }
    }
}

/// The reply to a refusal before `200`.
fn refusal(disposition: EgressDisposition) -> String {
    let status = match disposition {
        EgressDisposition::Malformed
        | EgressDisposition::NotConnect
        | EgressDisposition::TargetNotCanonical => "400 Bad Request",
        EgressDisposition::RequestTimeout => "408 Request Timeout",
        _ => "403 Forbidden",
    };
    format!(
        "HTTP/1.1 {status}\r\n{PROXY_DECISION_HEADER}: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        disposition.as_str()
    )
}

/// Answer a refusal, and end.
fn refuse(client: &UnixStream, disposition: EgressDisposition) -> EgressDisposition {
    let _ = client.set_write_timeout(Some(TICK));
    let _ = (&*client).write_all(refusal(disposition).as_bytes());
    let _ = client.shutdown(Shutdown::Both);
    disposition
}

/// Serve one connection from the relay, count how it ended, and say.
pub(crate) fn serve(client: &UnixStream, context: &Context) -> EgressDisposition {
    let disposition = connection(client, context);
    let _ = client.shutdown(Shutdown::Both);
    context.counters.record(disposition);
    disposition
}

/// The request, the checks, and the tunnel.
fn connection(client: &UnixStream, context: &Context) -> EgressDisposition {
    let closing = &context.closing;
    // The request, within its deadline and bound.
    let deadline = Instant::now() + context.limits.request;
    let mut buffer = Vec::with_capacity(REQUEST_MAX_BYTES);
    let mut chunk = vec![0u8; 4096];
    let (target, early) = loop {
        match request::parse(&buffer) {
            Ok(Parsed::Done { target, consumed }) => break (target, buffer.split_off(consumed)),
            Ok(Parsed::Need) => {}
            Err(disposition) => return refuse(client, disposition),
        }
        let room = REQUEST_MAX_BYTES
            .saturating_sub(buffer.len())
            .min(chunk.len());
        let Some(into) = chunk.get_mut(..room) else {
            return refuse(client, EgressDisposition::Malformed);
        };
        match read_before(client, into, deadline, closing) {
            Ok(n) => buffer.extend_from_slice(into.get(..n).unwrap_or_default()),
            Err(Stop::Timeout) => return refuse(client, EgressDisposition::RequestTimeout),
            Err(Stop::Closing) => return EgressDisposition::EnvironmentClosed,
            Err(Stop::Eof | Stop::Failed) => return EgressDisposition::Malformed,
        }
    };
    // The grant: exactly this host and port, by canonical bytes.
    if !context.grant.permits(&target.host, target.port) {
        return refuse(client, EgressDisposition::TargetNotGranted);
    }
    if guard::name_blocked(&target.host) {
        return refuse(client, EgressDisposition::AddressBlocked);
    }
    let most = usize::from(context.grant.max_tunnels.get());
    let Some(_held) = Held::take(&context.tunnels, most) else {
        return refuse(client, EgressDisposition::TunnelLimit);
    };
    // One resolution, judged whole, pinned.
    let answer = match context
        .resolver
        .resolve(&target.host, context.limits.resolve)
    {
        Ok(answer) => answer,
        Err(disposition) => return refuse(client, disposition),
    };
    let pinned = match guard::judge(&answer, context.resolver.exceptions()) {
        Ok(pinned) => pinned,
        Err(disposition) => return refuse(client, disposition),
    };
    let _ = client.set_write_timeout(Some(TICK));
    if (&*client)
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return EgressDisposition::Closed;
    }
    // The server name, before anything is dialled.
    let deadline = Instant::now() + context.limits.hello;
    let mut hello = Hello::default();
    let mut early = early;
    loop {
        match hello.feed(&early) {
            Ok(Some(name)) if name == target.host.as_bytes() => break,
            Ok(Some(_)) => return EgressDisposition::SniMismatch,
            Ok(None) => {}
            Err(disposition) => return disposition,
        }
        // One byte past the bound, so the hello parser sees it exceeded.
        let room = (HELLO_MAX_BUFFERED + 1)
            .saturating_sub(early.len())
            .min(chunk.len());
        let Some(into) = chunk.get_mut(..room) else {
            return EgressDisposition::ClientHelloMalformed;
        };
        match read_before(client, into, deadline, closing) {
            Ok(n) => early.extend_from_slice(into.get(..n).unwrap_or_default()),
            Err(Stop::Timeout) => return EgressDisposition::ClientHelloTimeout,
            Err(Stop::Closing) => return EgressDisposition::EnvironmentClosed,
            Err(Stop::Eof | Stop::Failed) => return EgressDisposition::ClientHelloMalformed,
        }
    }
    // The hello is the tunnel's first upload: a budget it would exceed is
    // never dialled for.
    let early_bytes = u64::try_from(early.len()).unwrap_or(u64::MAX);
    if context.upload.left() < early_bytes {
        return EgressDisposition::UploadBudget;
    }
    let Some(upstream) = dial(&pinned, target.port, context.limits.connect) else {
        return EgressDisposition::ConnectFailed;
    };
    if !context.upload.spend(early_bytes) {
        return EgressDisposition::UploadBudget;
    }
    let started = Instant::now();
    let _ = upstream.set_write_timeout(Some(TICK));
    if let Err((why, written)) =
        write_watching(&upstream, &early, context, started, &Activity::new(started))
    {
        context
            .counters
            .upstream(u64::try_from(written).unwrap_or(u64::MAX));
        return why;
    }
    context.counters.upstream(early_bytes);
    pump(client, &upstream, context, started)
}

/// Connect to the pinned addresses in order, within one deadline: the name
/// is never resolved again.
fn dial(pinned: &[IpAddr], port: u16, within: Duration) -> Option<TcpStream> {
    let deadline = Instant::now() + within;
    for address in pinned {
        let left = deadline.checked_duration_since(Instant::now())?;
        if left.is_zero() {
            return None;
        }
        if let Ok(stream) = TcpStream::connect_timeout(&SocketAddr::new(*address, port), left) {
            return Some(stream);
        }
    }
    None
}

/// When anything last moved, either way, in milliseconds since the start.
#[derive(Debug)]
struct Activity {
    started: Instant,
    last: AtomicU64,
}

impl Activity {
    const fn new(started: Instant) -> Self {
        Self {
            started,
            last: AtomicU64::new(0),
        }
    }

    fn now(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn touch(&self) {
        self.last.fetch_max(self.now(), Ordering::SeqCst);
    }

    fn idle(&self) -> Duration {
        Duration::from_millis(self.now().saturating_sub(self.last.load(Ordering::SeqCst)))
    }
}

/// Whether the tunnel must end now, and why.
fn expired(context: &Context, started: Instant, activity: &Activity) -> Option<EgressDisposition> {
    if context.closing.load(Ordering::SeqCst) {
        Some(EgressDisposition::EnvironmentClosed)
    } else if started.elapsed() >= context.limits.lifetime {
        Some(EgressDisposition::LifetimeExceeded)
    } else if activity.idle() >= context.limits.idle {
        Some(EgressDisposition::IdleTimeout)
    } else {
        None
    }
}

/// Write all of `bytes`, waking every tick to look at the clocks. On a
/// failure, how far it got: only bytes written are ever counted.
fn write_watching<W>(
    to: W,
    bytes: &[u8],
    context: &Context,
    started: Instant,
    activity: &Activity,
) -> Result<(), (EgressDisposition, usize)>
where
    W: std::io::Write,
{
    let mut to = to;
    let mut rest = bytes;
    let mut written = 0usize;
    while !rest.is_empty() {
        if let Some(why) = expired(context, started, activity) {
            return Err((why, written));
        }
        match to.write(rest) {
            Ok(0) => return Err((EgressDisposition::Closed, written)),
            Ok(n) => {
                rest = rest.get(n..).unwrap_or_default();
                written += n;
                activity.touch();
            }
            Err(e) if ticked(e.kind()) => {}
            Err(_) => return Err((EgressDisposition::Closed, written)),
        }
    }
    Ok(())
}

/// One direction of a tunnel.
struct Direction<'a> {
    /// The budget it spends.
    budget: &'a Budget,
    /// What spending past it is.
    exceeded: EgressDisposition,
    /// Whether it counts upstream bytes.
    upstream: bool,
}

/// How a tunnel ended, once: the first direction to end it says why.
#[derive(Debug, Default)]
struct Ending(Mutex<Option<EgressDisposition>>);

impl Ending {
    fn set(&self, disposition: EgressDisposition) {
        if let Ok(mut ending) = self.0.lock() {
            ending.get_or_insert(disposition);
        }
    }

    fn get(&self) -> Option<EgressDisposition> {
        self.0.lock().ok().and_then(|ending| *ending)
    }
}

/// What both directions of one tunnel share.
struct Tunnel<'a> {
    context: &'a Context,
    client: &'a UnixStream,
    upstream: &'a TcpStream,
    started: Instant,
    activity: Activity,
    ending: Ending,
}

impl Tunnel<'_> {
    /// End the tunnel for `why`: both sockets, both ways.
    fn fail(&self, why: EgressDisposition) {
        self.ending.set(why);
        let _ = self.client.shutdown(Shutdown::Both);
        let _ = self.upstream.shutdown(Shutdown::Both);
    }

    /// Carry `from` to `to` until `from` ends, the budget is spent or the
    /// clocks run out. A clean end half-closes `to`'s socket (`close`); any
    /// other ends the tunnel.
    fn carry<R, W>(&self, mut from: R, mut to: W, direction: &Direction<'_>, close: &dyn Fn())
    where
        R: std::io::Read,
        W: std::io::Write,
    {
        let mut buffer = vec![0u8; 16 * 1024];
        loop {
            if self.ending.get().is_some() {
                return;
            }
            if let Some(why) = expired(self.context, self.started, &self.activity) {
                return self.fail(why);
            }
            // Never read more than one byte past what may be forwarded.
            let room = usize::try_from(direction.budget.left().saturating_add(1))
                .unwrap_or(usize::MAX)
                .min(buffer.len());
            let Some(into) = buffer.get_mut(..room) else {
                return self.fail(direction.exceeded);
            };
            match from.read(into) {
                Ok(0) => return close(),
                Ok(n) => {
                    // What the budget allows is carried; past it, the rest
                    // is dropped and the tunnel ends — the budget is spent
                    // exactly, and never more.
                    let bytes = u64::try_from(n).unwrap_or(u64::MAX);
                    let allowed = direction.budget.take(bytes);
                    let carry = usize::try_from(allowed).unwrap_or(0).min(n);
                    self.activity.touch();
                    let carried = write_watching(
                        &mut to,
                        into.get(..carry).unwrap_or_default(),
                        self.context,
                        self.started,
                        &self.activity,
                    );
                    let written = match carried {
                        Ok(()) => allowed,
                        Err((_, written)) => u64::try_from(written).unwrap_or(u64::MAX),
                    };
                    if direction.upstream {
                        self.context.counters.upstream(written);
                    } else {
                        self.context.counters.downstream(written);
                    }
                    if let Err((why, _)) = carried {
                        return self.fail(why);
                    }
                    if allowed < bytes {
                        return self.fail(direction.exceeded);
                    }
                }
                Err(e) if ticked(e.kind()) => {}
                Err(_) => return self.fail(EgressDisposition::Closed),
            }
        }
    }
}

/// Carry both directions until both have ended, and say how the tunnel did.
fn pump(
    client: &UnixStream,
    upstream: &TcpStream,
    context: &Context,
    started: Instant,
) -> EgressDisposition {
    let ready = [
        client.set_read_timeout(Some(TICK)),
        client.set_write_timeout(Some(TICK)),
        upstream.set_read_timeout(Some(TICK)),
        upstream.set_write_timeout(Some(TICK)),
        upstream.set_nodelay(true),
    ];
    if ready.iter().any(Result::is_err) {
        return EgressDisposition::Closed;
    }
    let tunnel = Tunnel {
        context,
        client,
        upstream,
        started,
        activity: Activity::new(started),
        ending: Ending::default(),
    };
    tunnel.activity.touch();
    let up = Direction {
        budget: &context.upload,
        exceeded: EgressDisposition::UploadBudget,
        upstream: true,
    };
    let down = Direction {
        budget: &context.download,
        exceeded: EgressDisposition::DownloadBudget,
        upstream: false,
    };
    std::thread::scope(|scope| {
        scope.spawn(|| {
            tunnel.carry(client, upstream, &up, &|| {
                let _ = upstream.shutdown(Shutdown::Write);
            });
        });
        tunnel.carry(upstream, client, &down, &|| {
            let _ = client.shutdown(Shutdown::Write);
        });
    });
    tunnel.ending.get().unwrap_or(EgressDisposition::Closed)
}
