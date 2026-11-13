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
use dwk_proto::wire::guard::Address;
use dwk_sandbox_profile::PROXY_DECISION_HEADER;

use super::authorised::{Admitted, Cut, Root};
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
    /// The environment's workspace root's egress state (F-17): its
    /// workload's authorisation, shared with every environment on the root.
    pub(crate) root: Arc<Root>,
    /// The environment this proxy is for.
    pub(crate) environment: String,
}

impl Context {
    /// A context for `grant`, on the workspace root `root`.
    pub(crate) fn new(
        grant: EgressGrant,
        counters: Arc<Counters>,
        resolver: resolve::Shared,
        limits: Limits,
        (root, environment): (Arc<Root>, String),
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
            root,
            environment,
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
/// An address as the authorisation's lookup takes it (F-17).
const fn guard_address(ip: IpAddr) -> Address {
    match ip {
        IpAddr::V4(v4) => Address::V4(v4.octets()),
        IpAddr::V6(v6) => Address::V6(v6.octets()),
    }
}

/// A way for the root to shut the client's socket both ways.
fn unix_cut(client: &UnixStream) -> Cut {
    let held = client.try_clone().ok();
    Cut::new(move || {
        if let Some(held) = &held {
            let _ = held.shutdown(Shutdown::Both);
        }
    })
}

/// A way for the root to shut the dialled connection both ways.
fn tcp_cut(upstream: &TcpStream) -> Cut {
    let held = upstream.try_clone().ok();
    Cut::new(move || {
        if let Some(held) = &held {
            let _ = held.shutdown(Shutdown::Both);
        }
    })
}

fn refuse(client: &UnixStream, disposition: EgressDisposition) -> EgressDisposition {
    let _ = client.set_write_timeout(Some(TICK));
    let _ = (&*client).write_all(refusal(disposition).as_bytes());
    let _ = client.shutdown(Shutdown::Both);
    disposition
}

/// Serve one connection from the relay, count how it ended, and say.
pub(crate) fn serve(client: &UnixStream, context: &Context) -> EgressDisposition {
    let mut named = Named::default();
    let ended = connection(client, context, &mut named);
    // A tunnel its root stopped -- exposure, or its workload's end -- ended
    // for that, whatever its sockets said once they were shut.
    let disposition = named
        .admitted
        .as_ref()
        .and_then(|a| a.handle.stopped())
        .unwrap_or(ended);
    let _ = client.shutdown(Shutdown::Both);
    context.counters.record(disposition);
    context.root.ended(
        &context.environment,
        (named.target, named.admitted.as_ref()),
        disposition,
    );
    disposition
}

/// What a connection named of its workload's authorisation (F-17): the
/// destination, once one was found, and the tunnel it admitted.
#[derive(Debug, Default)]
struct Named {
    target: Option<usize>,
    admitted: Option<Admitted>,
}

/// The checks between the request and `200`, in order: the grant, the name,
/// the workload's authorisation before anything is resolved (F-17), the
/// tunnel limit, one resolution judged whole, and every pinned address in
/// the cell that applies now -- the tunnel registered with its root, in
/// `named`. The tunnel's slot, and the pinned addresses; or the refusal,
/// already answered.
fn checked<'a>(
    client: &UnixStream,
    context: &'a Context,
    (target, named): (&request::Target, &mut Named),
) -> Result<(Held<'a>, Vec<IpAddr>), EgressDisposition> {
    // The grant: exactly this host and port, by canonical bytes.
    if !context.grant.permits(&target.host, target.port) {
        return Err(refuse(client, EgressDisposition::TargetNotGranted));
    }
    if guard::name_blocked(&target.host) {
        return Err(refuse(client, EgressDisposition::AddressBlocked));
    }
    // The workload's authorisation (F-17): one in force, and a cell for this
    // destination that allows some address -- before anything is resolved.
    let place = context
        .root
        .consider(&context.environment, (&target.host, target.port))
        .map_err(|(disposition, place)| {
            named.target = place;
            refuse(client, disposition)
        })?;
    named.target = Some(place);
    let most = usize::from(context.grant.max_tunnels.get());
    let held = Held::take(&context.tunnels, most)
        .ok_or_else(|| refuse(client, EgressDisposition::TunnelLimit))?;
    // One resolution, judged whole, pinned.
    let answer = context
        .resolver
        .resolve(&target.host, context.limits.resolve)
        .map_err(|disposition| refuse(client, disposition))?;
    let pinned = guard::judge(&answer, context.resolver.exceptions())
        .map_err(|disposition| refuse(client, disposition))?;
    // Every pinned address in the cell that applies now, and the tunnel
    // registered with its root (F-17).
    let admitted = context
        .root
        .admit(
            &context.environment,
            place,
            (
                &pinned
                    .iter()
                    .copied()
                    .map(guard_address)
                    .collect::<Vec<_>>(),
                unix_cut(client),
            ),
        )
        .map_err(|(disposition, _)| refuse(client, disposition))?;
    named.admitted = Some(admitted);
    Ok((held, pinned))
}

/// The request, the checks, and the tunnel.
fn connection(client: &UnixStream, context: &Context, named: &mut Named) -> EgressDisposition {
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
    let (_held, pinned) = match checked(client, context, (&target, &mut *named)) {
        Ok(checked) => checked,
        Err(disposition) => return disposition,
    };
    let Some(admitted) = named.admitted.as_ref() else {
        return EgressDisposition::NotAuthorised;
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
    // Stopped since it was admitted -- the workspace exposed and its cell no
    // longer allowing it, or its workload ended: never dialled.
    if let Some(why) = admitted.handle.stopped() {
        return why;
    }
    let Some(upstream) = dial(&pinned, target.port, context.limits.connect) else {
        return EgressDisposition::ConnectFailed;
    };
    admitted.handle.hold(tcp_cut(&upstream));
    if let Some(why) = admitted.handle.stopped() {
        return why;
    }
    if !context.upload.spend(early_bytes) {
        return EgressDisposition::UploadBudget;
    }
    let started = Instant::now();
    let _ = upstream.set_write_timeout(Some(TICK));
    if let Err((why, written)) = write_watching(
        &upstream,
        &early,
        (context, Some(admitted)),
        started,
        &Activity::new(started),
    ) {
        context
            .counters
            .upstream(u64::try_from(written).unwrap_or(u64::MAX));
        return why;
    }
    context.counters.upstream(early_bytes);
    admitted.bytes.up(early_bytes);
    pump(client, &upstream, (context, admitted), started)
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
fn expired(
    (context, admitted): (&Context, Option<&Admitted>),
    started: Instant,
    activity: &Activity,
) -> Option<EgressDisposition> {
    if let Some(why) = admitted.and_then(|a| a.handle.stopped()) {
        Some(why)
    } else if context.closing.load(Ordering::SeqCst) {
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
    context: (&Context, Option<&Admitted>),
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
    /// Its admission by the workload's authorisation (F-17).
    admitted: &'a Admitted,
    /// Bytes carried back so far, against the cell's per-tunnel bound.
    carried_back: AtomicU64,
    client: &'a UnixStream,
    upstream: &'a TcpStream,
    started: Instant,
    activity: Activity,
    ending: Ending,
    /// Whether the origin has sent a byte back yet.
    origin: AtomicBool,
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
            if let Some(why) = expired(
                (self.context, Some(self.admitted)),
                self.started,
                &self.activity,
            ) {
                return self.fail(why);
            }
            // What this tunnel may still carry back (F-17): the cell's
            // per-tunnel bound; unbounded upstream.
            let bound = if direction.upstream {
                u64::MAX
            } else {
                self.admitted
                    .handle
                    .cap()
                    .saturating_sub(self.carried_back.load(Ordering::SeqCst))
            };
            // Never read more than one byte past what may be forwarded.
            let room = usize::try_from(direction.budget.left().min(bound).saturating_add(1))
                .unwrap_or(usize::MAX)
                .min(buffer.len());
            let Some(into) = buffer.get_mut(..room) else {
                return self.fail(direction.exceeded);
            };
            match from.read(into) {
                Ok(0) => return close(),
                Ok(n) => {
                    // The first byte an origin sends back is the workload's
                    // destination reached and its workspace exposed: decided
                    // under the root's lock before it is forwarded (F-17).
                    if !direction.upstream
                        && !self.origin.swap(true, Ordering::SeqCst)
                        && !self
                            .context
                            .root
                            .origin_byte(&self.context.environment, self.admitted)
                    {
                        return self.fail(
                            self.admitted
                                .handle
                                .stopped()
                                .unwrap_or(EgressDisposition::WorkloadEnded),
                        );
                    }
                    // What the budget allows is carried; past it, the rest
                    // is dropped and the tunnel ends — the budget is spent
                    // exactly, and never more. Back, the tunnel's own bound
                    // is kept the same way.
                    let bytes = u64::try_from(n).unwrap_or(u64::MAX);
                    let within = bytes.min(bound);
                    let allowed = direction.budget.take(within);
                    let carry = usize::try_from(allowed).unwrap_or(0).min(n);
                    self.activity.touch();
                    let carried = write_watching(
                        &mut to,
                        into.get(..carry).unwrap_or_default(),
                        (self.context, Some(self.admitted)),
                        self.started,
                        &self.activity,
                    );
                    let written = match carried {
                        Ok(()) => allowed,
                        Err((_, written)) => u64::try_from(written).unwrap_or(u64::MAX),
                    };
                    if direction.upstream {
                        self.context.counters.upstream(written);
                        self.admitted.bytes.up(written);
                    } else {
                        self.context.counters.downstream(written);
                        self.admitted.bytes.down(written);
                        self.carried_back.fetch_add(written, Ordering::SeqCst);
                    }
                    if let Err((why, _)) = carried {
                        return self.fail(why);
                    }
                    if allowed < within {
                        return self.fail(direction.exceeded);
                    }
                    if within < bytes {
                        return self.fail(EgressDisposition::TunnelOutputLimit);
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
    (context, admitted): (&Context, &Admitted),
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
        admitted,
        carried_back: AtomicU64::new(0),
        client,
        upstream,
        started,
        activity: Activity::new(started),
        ending: Ending::default(),
        origin: AtomicBool::new(false),
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
