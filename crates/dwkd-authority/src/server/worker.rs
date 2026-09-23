//! The authority worker: one thread owns the [`Authority`], and every
//! decision is made there, one at a time.
//!
//! # Why one worker
//!
//! `kernel.db` is a single-writer store: every M3 operation is one short
//! `BEGIN IMMEDIATE` transaction followed by an audit `fsync`. Letting each
//! connection thread hold its own handle would turn contention into SQLite's
//! busy handler, and a transaction that loses that race for longer than the
//! busy timeout is `AuthorityError::Busy` — which is not `STALE_EPOCH`, not
//! `LEASE_HELD` and not a protocol error, and so has no truthful wire answer.
//! With one owner, requests queue in a bounded channel instead, no two
//! authority transactions ever contend, and `Busy` is unreachable from the
//! server (the state directory's lock excludes any other writer). Correctness
//! still comes from the state layer — its transactions, the epoch fence,
//! idempotency — not from this serialisation, which buys predictability.
//!
//! The channel holds at most [`QUEUE_DEPTH`] jobs, and each connection has at
//! most one request in flight, so there is no unbounded writer storm and no
//! unbounded queue.
//!
//! # What the worker does not do
//!
//! It interprets nothing: a decoded request goes to [`Authority::dispatch`]
//! unchanged, and the body that comes back goes to the connection unchanged.
//! Epochs, idempotency, minting, policy and run state are the state layer's.
//!
//! # Failures
//!
//! | `Authority::dispatch` returns | the connection | the server |
//! |---|---|---|
//! | a response body | answers it | serves on |
//! | a poisoned store | is closed, unanswered | **stops**: no authority from a poisoned store |
//! | any other error (`Busy`, an invariant, an exhausted counter, …) | is closed, unanswered: no wire answer says it truthfully | serves on |
//!
//! # Transport audit, rate-limited
//!
//! A refused peer can reconnect as fast as it likes. Each [`TransportClass`]
//! may write [`AUDIT_PER_WINDOW`] records per [`AUDIT_WINDOW`]; beyond that the
//! worker counts instead of writing, and writes one `transport.audit_suppressed`
//! record with the count when the window ends — so suppression is itself on
//! the record, and the one-off events an evaluation provokes are always
//! written. Every record has a fixed field set of a few hundred bytes.

use core::fmt;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::time::{Duration, Instant};

use dwk_proto::dwkp::{DwkpBody, DwkpMessage};

use crate::state::{
    AuthenticatedSubject, Authority, AuthorityError, CallerContext, PoisonReason, TransportClass,
    TransportEvent,
};

/// Most jobs the worker's queue holds before a sender waits.
pub(crate) const QUEUE_DEPTH: usize = 64;

/// The window the transport audit rate limit counts in.
pub(crate) const AUDIT_WINDOW: Duration = Duration::from_secs(60);

/// Records each transport class may write per window.
pub(crate) const AUDIT_PER_WINDOW: u32 = 32;

/// How often an idle worker checks whether a suppression count is due.
const TICK: Duration = Duration::from_secs(1);

/// One unit of work.
enum Job {
    Connect {
        subject: AuthenticatedSubject,
        reply: SyncSender<CallerContext>,
    },
    Dispatch {
        caller: CallerContext,
        message: Box<DwkpMessage>,
        reply: SyncSender<Result<DwkpBody, Failure>>,
    },
    Audit(TransportEvent),
}

/// Why the authority gave no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The authority could not answer this request truthfully. The
    /// connection is closed; the server serves on.
    Internal,
    /// The store is poisoned, or the worker has stopped. The server stops.
    Stopped,
}

/// How the server stops, shared between the worker and the acceptor.
#[derive(Debug, Default)]
pub(crate) struct Shutdown {
    stopping: AtomicBool,
    reason: Mutex<Option<PoisonReason>>,
}

impl Shutdown {
    /// Whether the server is stopping.
    pub(crate) fn stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    /// Why, once it is.
    pub(crate) fn reason(&self) -> Option<PoisonReason> {
        self.reason.lock().ok().and_then(|slot| slot.clone())
    }

    fn stop(&self, reason: PoisonReason) {
        if let Ok(mut slot) = self.reason.lock()
            && slot.is_none()
        {
            *slot = Some(reason);
        }
        self.stopping.store(true, Ordering::SeqCst);
    }
}

/// The connections' way to the worker.
#[derive(Debug, Clone)]
pub(crate) struct WorkerHandle {
    jobs: SyncSender<Job>,
}

impl fmt::Debug for Job {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Connect { .. } => "Connect",
            Self::Dispatch { .. } => "Dispatch",
            Self::Audit(_) => "Audit",
        })
    }
}

impl WorkerHandle {
    /// A caller context for one new connection: a fresh holder, minted by the
    /// authority. `None` once the worker has stopped.
    pub(crate) fn connect(&self, subject: AuthenticatedSubject) -> Option<CallerContext> {
        let (reply, answer) = sync_channel(1);
        self.jobs.send(Job::Connect { subject, reply }).ok()?;
        answer.recv().ok()
    }

    /// Answer one decoded authority request.
    pub(crate) fn dispatch(
        &self,
        caller: CallerContext,
        message: DwkpMessage,
    ) -> Result<DwkpBody, Failure> {
        let (reply, answer) = sync_channel(1);
        self.jobs
            .send(Job::Dispatch {
                caller,
                message: Box::new(message),
                reply,
            })
            .map_err(|_| Failure::Stopped)?;
        answer.recv().unwrap_or(Err(Failure::Stopped))
    }

    /// Record a transport event, subject to the rate limit. Does not wait for
    /// the record; a stopped worker drops it, because a stopped authority is
    /// not serving the connection it describes either.
    pub(crate) fn audit(&self, event: TransportEvent) {
        let _ = self.jobs.send(Job::Audit(event));
    }
}

/// The per-class rate limit.
#[derive(Debug)]
pub(crate) struct RateLimiter {
    window: Duration,
    per_window: u32,
    buckets: BTreeMap<TransportClass, Bucket>,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    started: Instant,
    written: u32,
    suppressed: u64,
}

/// What the limiter decided about one event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Admission {
    /// A suppression record due for the window that just ended, written first.
    pub(crate) summary: Option<TransportEvent>,
    /// Whether to write the event itself.
    pub(crate) write: bool,
}

impl RateLimiter {
    pub(crate) fn new(window: Duration, per_window: u32) -> Self {
        Self {
            window,
            per_window,
            buckets: BTreeMap::new(),
        }
    }

    fn roll(
        bucket: &mut Bucket,
        class: TransportClass,
        now: Instant,
        window: Duration,
    ) -> Option<TransportEvent> {
        if now.saturating_duration_since(bucket.started) < window {
            return None;
        }
        let summary = (bucket.suppressed > 0).then_some(TransportEvent::Suppressed {
            class,
            count: bucket.suppressed,
        });
        *bucket = Bucket {
            started: now,
            written: 0,
            suppressed: 0,
        };
        summary
    }

    /// Decide about one event at `now`.
    pub(crate) fn admit(&mut self, event: &TransportEvent, now: Instant) -> Admission {
        let Some(class) = event.class() else {
            return Admission {
                summary: None,
                write: true,
            };
        };
        let window = self.window;
        let bucket = self.buckets.entry(class).or_insert(Bucket {
            started: now,
            written: 0,
            suppressed: 0,
        });
        let summary = Self::roll(bucket, class, now, window);
        let write = bucket.written < self.per_window;
        if write {
            bucket.written = bucket.written.saturating_add(1);
        } else {
            bucket.suppressed = bucket.suppressed.saturating_add(1);
        }
        Admission { summary, write }
    }

    /// Suppression records due because their window has ended.
    pub(crate) fn due(&mut self, now: Instant) -> Vec<TransportEvent> {
        let window = self.window;
        self.buckets
            .iter_mut()
            .filter_map(|(class, bucket)| Self::roll(bucket, *class, now, window))
            .collect()
    }
}

/// Start the worker thread. It owns `authority` until the server stops.
///
/// # Errors
///
/// The thread could not be spawned.
pub(crate) fn spawn(
    authority: Authority,
    shutdown: Arc<Shutdown>,
    wake: impl Fn() + Send + 'static,
) -> std::io::Result<(WorkerHandle, std::thread::JoinHandle<()>)> {
    let (jobs, queue) = sync_channel(QUEUE_DEPTH);
    let thread = std::thread::Builder::new()
        .name("dwkd-authority-worker".to_owned())
        .spawn(move || {
            let mut worker = Worker {
                authority,
                limiter: RateLimiter::new(AUDIT_WINDOW, AUDIT_PER_WINDOW),
                shutdown,
            };
            worker.run(&queue);
            wake();
        })?;
    Ok((WorkerHandle { jobs }, thread))
}

struct Worker {
    authority: Authority,
    limiter: RateLimiter,
    shutdown: Arc<Shutdown>,
}

impl Worker {
    fn run(&mut self, queue: &Receiver<Job>) {
        loop {
            match queue.recv_timeout(TICK) {
                Ok(Job::Connect { subject, reply }) => {
                    let _ = reply.send(self.authority.connect(subject));
                }
                Ok(Job::Dispatch {
                    caller,
                    message,
                    reply,
                }) => {
                    let answer = self.authority.dispatch(&caller, &message);
                    let answer = answer.map_err(|error| self.failure(&error));
                    let _ = reply.send(answer);
                }
                Ok(Job::Audit(event)) => {
                    let admission = self.limiter.admit(&event, Instant::now());
                    if let Some(summary) = admission.summary {
                        self.record(&summary);
                    }
                    if admission.write {
                        self.record(&event);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            // A window that ended is counted whether the worker is idle or
            // busy with other classes.
            for summary in self.limiter.due(Instant::now()) {
                self.record(&summary);
            }
            if self.shutdown.stopping() {
                return;
            }
        }
    }

    /// Classify a failed operation. A poisoned store stops the server.
    fn failure(&self, error: &AuthorityError) -> Failure {
        if let Some(reason) = self.authority.poisoned() {
            super::log(&format!(
                "the authority store is poisoned and will stop serving: {reason}"
            ));
            self.shutdown.stop(reason);
            return Failure::Stopped;
        }
        super::log(&format!(
            "a request could not be answered truthfully; its connection is closed: {error}"
        ));
        Failure::Internal
    }

    fn record(&mut self, event: &TransportEvent) {
        if let Err(error) = self.authority.record_transport_event(event) {
            let _ = self.failure(&error);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{RateLimiter, TransportEvent};
    use crate::state::TransportClass;

    fn refused(uid: u32) -> TransportEvent {
        TransportEvent::PeerRefused { uid, pid: None }
    }

    #[test]
    fn a_flood_is_written_up_to_the_bound_then_counted() {
        let start = Instant::now();
        let mut limiter = RateLimiter::new(Duration::from_secs(60), 3);
        let mut written = 0;
        for n in 0..1000 {
            let admission = limiter.admit(&refused(n), start);
            assert_eq!(admission.summary, None);
            written += u32::from(admission.write);
        }
        assert_eq!(written, 3);
        // The window ends: the next event carries the count of the 997 it
        // withheld, and is itself written.
        let later = start + Duration::from_secs(61);
        let admission = limiter.admit(&refused(1), later);
        assert_eq!(
            admission.summary,
            Some(TransportEvent::Suppressed {
                class: TransportClass::PeerRefused,
                count: 997
            })
        );
        assert!(admission.write);
    }

    #[test]
    fn a_count_is_written_when_the_window_ends_even_if_the_flood_stops() {
        let start = Instant::now();
        let mut limiter = RateLimiter::new(Duration::from_secs(60), 1);
        let _ = limiter.admit(&refused(1), start);
        let _ = limiter.admit(&refused(2), start);
        assert!(limiter.due(start + Duration::from_secs(30)).is_empty());
        assert_eq!(
            limiter.due(start + Duration::from_secs(60)),
            vec![TransportEvent::Suppressed {
                class: TransportClass::PeerRefused,
                count: 1
            }]
        );
        assert!(limiter.due(start + Duration::from_secs(200)).is_empty());
    }

    #[test]
    fn classes_are_limited_independently_and_a_count_is_never_suppressed() {
        let start = Instant::now();
        let mut limiter = RateLimiter::new(Duration::from_secs(60), 1);
        assert!(limiter.admit(&refused(1), start).write);
        assert!(!limiter.admit(&refused(1), start).write);
        let other = TransportEvent::ConnectionRefused { uid: 1, pid: None };
        assert!(limiter.admit(&other, start).write);
        let count = TransportEvent::Suppressed {
            class: TransportClass::PeerRefused,
            count: 9,
        };
        for _ in 0..10 {
            assert!(limiter.admit(&count, start).write);
        }
    }
}
