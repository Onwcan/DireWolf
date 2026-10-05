//! Contention, through SQLite's own locking.
//!
//! Every thread gets its own handle — its own SQLite connection onto the same
//! file — so exclusivity comes from the database's transactions, not from a
//! mutex in the test or in the authority. A barrier releases all threads at
//! once, and each scenario repeats to exercise more than one interleaving.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

#[cfg(target_os = "linux")]
use nix as _;
use proptest as _;
#[cfg(target_os = "linux")]
use rustix as _;
use sha2 as _;
use toml as _;
use unicode_normalization as _;
// M4e's secret crates (ADR-0046), reached only through the library.
use age as _;
use getrandom as _;
use hmac as _;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use keyring as _;
#[cfg(target_os = "linux")]
use linux_keyutils as _;
use zeroize as _;

mod state_support;

use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use dwk_proto::wire::scalar::RefusalReason;
use dwkd_authority::state::{Admission, AuthorityError, Reply};
use state_support::{Harness, admit_msg, count, raw, session};

const THREADS: usize = 16;
const ROUNDS: u64 = 12;

/// How long a racer may keep being told `Busy` before the test fails: four
/// of the store's 5-second busy windows. A writer that is genuinely stuck
/// fails the round in well under a minute.
const BUSY_DEADLINE: Duration = Duration::from_secs(20);
/// The pause before a racer sends a request the store answered `Busy` again.
const BUSY_BACKOFF: Duration = Duration::from_millis(10);

/// Not retried on `Busy`, unlike the admission races below: `AcquireLease`
/// has no idempotency key. A `Busy` from the audit flush after the commit can
/// mean the racer already holds the lease, and the holder acquiring again is a
/// reissue at the next epoch (`lease::acquire`), not a replay.
#[test]
fn exactly_one_of_many_racing_acquirers_wins() {
    let mut h = Harness::new("race-acquire");
    for round in 0..ROUNDS {
        let s = session(100 + round);
        let barrier = Arc::new(Barrier::new(THREADS));
        let workers: Vec<_> = (0..THREADS)
            .map(|i| {
                let mut handle = h.authority().handle().unwrap();
                // Half the racers share a subject: that must not help them.
                let caller =
                    handle.connect(state_support::subject(1000 + u32::try_from(i % 2).unwrap()));
                let (barrier, s) = (barrier.clone(), s.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    (caller, handle.acquire_lease(&caller, &s))
                })
            })
            .collect();
        let results: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
        let winners: Vec<_> = results
            .iter()
            .filter_map(|(caller, r)| match r {
                Ok(Reply::Done(e)) => Some((*caller, *e)),
                _ => None,
            })
            .collect();
        let losers = results
            .iter()
            .filter(|(_, r)| matches!(r, Ok(Reply::Refused(RefusalReason::LeaseHeld))))
            .count();
        assert_eq!(winners.len(), 1, "round {round}: {results:?}");
        assert_eq!(
            losers,
            THREADS - 1,
            "round {round}: every other racer was told LEASE_HELD"
        );
        assert_eq!(winners[0].1.get(), 1, "one acquisition, one epoch");
        let conn = raw(&h.state());
        let (epoch, holder): (i64, i64) = conn
            .query_row(
                "SELECT epoch, holder_connection FROM session_lease WHERE session_id = ?1",
                [s.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(epoch, 1);
        assert_eq!(
            u64::try_from(holder).unwrap(),
            winners[0].0.holder().connection(),
            "the stored holder is the winner"
        );
    }
}

/// One racer's final answer, and how many `Busy` answers it was given.
struct Answer {
    worker: usize,
    busy: u32,
    elapsed: Duration,
    reply: Result<Reply<Admission>, AuthorityError>,
}

/// Release one `AdmitRun` racer per message at once, each on its own handle.
/// A racer the store answered `Busy` sends **the same message** again, until
/// an answer that is not `Busy` or until [`BUSY_DEADLINE`] has passed since
/// the barrier released it.
///
/// `Busy` means a transaction waited past the store's busy timeout and did not
/// happen (`AuthorityError::Busy`, `db.rs`). That bound is a product setting,
/// not the property under test, and a runner with slow `fsync` can queue
/// sixteen serialised admissions past it. Sending the message again is safe
/// because admission is idempotent: the record is scoped by subject, session
/// and key, and the request digest leaves out `id`, `ts` and `correlation_id`
/// (`admission.rs`). So the same message gets what a later arrival would --
/// admitted if nothing is recorded, the same-response replay if its digest is
/// recorded, `IDEMPOTENCY_CONFLICT` if another is -- also when a `Busy` came
/// from the audit flush after its own transaction had committed. Only `Busy`
/// is retried; any other answer, error or not, is returned at once.
fn run_race_retrying_busy(
    h: &mut Harness,
    messages: Vec<dwk_proto::dwkp::DwkpMessage>,
    caller: dwkd_authority::state::CallerContext,
) -> Vec<Answer> {
    let barrier = Arc::new(Barrier::new(messages.len()));
    let workers: Vec<_> = messages
        .into_iter()
        .enumerate()
        .map(|(worker, message)| {
            let mut handle = h.authority().handle().unwrap();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let start = Instant::now();
                let mut busy = 0u32;
                loop {
                    let reply = handle.admit_run(&caller, &message);
                    let is_busy = matches!(reply, Err(AuthorityError::Busy));
                    busy += u32::from(is_busy);
                    let elapsed = start.elapsed();
                    if !is_busy || elapsed >= BUSY_DEADLINE {
                        return Answer {
                            worker,
                            busy,
                            elapsed,
                            reply,
                        };
                    }
                    std::thread::sleep(BUSY_BACKOFF);
                }
            })
        })
        .collect();
    workers.into_iter().map(|w| w.join().unwrap()).collect()
}

/// Each racer's final reply, failing the round loudly if one was still `Busy`
/// at the deadline.
fn settled(round: u64, answers: Vec<Answer>) -> Vec<Result<Reply<Admission>, AuthorityError>> {
    answers
        .into_iter()
        .map(|a| match a.reply {
            Err(AuthorityError::Busy) => panic!(
                "round {round}, worker {}: still Busy after {} Busy answers over {:?} (deadline {BUSY_DEADLINE:?})",
                a.worker, a.busy, a.elapsed
            ),
            reply => reply,
        })
        .collect()
}

#[test]
fn racing_identical_admissions_are_one_admission() {
    let mut h = Harness::new("race-admit");
    let caller = h.connect(1000);
    let s = session(1);
    let e = h.lease(&caller, &s);
    for round in 0..ROUNDS {
        let key = format!("k{round}");
        let messages = (0..THREADS)
            .map(|i| {
                admit_msg(
                    &s,
                    e,
                    &key,
                    "researcher",
                    &[],
                    &["model.call:*", "memory.read:*"],
                    u64::try_from(i).unwrap(),
                )
            })
            .collect();
        let results = settled(round, run_race_retrying_busy(&mut h, messages, caller));
        let admissions: Vec<Admission> = results
            .into_iter()
            .map(|r| match r {
                Ok(Reply::Done(admission)) => admission,
                other => panic!("round {round}: {other:?}"),
            })
            .collect();
        assert!(
            admissions.windows(2).all(|w| w[0] == w[1]),
            "round {round}: every retry saw the same grant"
        );
        let conn = raw(&h.state());
        let run = admissions[0].run_id().as_str();
        let records: i64 = conn
            .query_row(
                "SELECT count(*) FROM admission_idempotency WHERE idempotency_key = ?1",
                [&key],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(records, 1);
        let grants: i64 = conn
            .query_row(
                "SELECT count(*) FROM run_grant WHERE run_id = ?1",
                [run],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(grants, 2);
    }
    let conn = raw(&h.state());
    assert_eq!(
        count(&conn, "SELECT count(*) FROM run"),
        i64::try_from(ROUNDS).unwrap()
    );
}

#[test]
fn racing_conflicting_admissions_under_one_key_let_exactly_one_win() {
    let mut h = Harness::new("race-conflict");
    let caller = h.connect(1000);
    let s = session(1);
    let e = h.lease(&caller, &s);
    for round in 0..ROUNDS {
        let key = format!("c{round}");
        let messages = (0..THREADS)
            .map(|i| {
                let capability = if i % 2 == 0 {
                    "model.call:*"
                } else {
                    "memory.read:*"
                };
                admit_msg(
                    &s,
                    e,
                    &key,
                    "researcher",
                    &[],
                    &[capability],
                    u64::try_from(i).unwrap(),
                )
            })
            .collect();
        let results = settled(round, run_race_retrying_busy(&mut h, messages, caller));
        let admissions: Vec<&Admission> = results
            .iter()
            .filter_map(|r| match r {
                Ok(Reply::Done(admission)) => Some(admission),
                _ => None,
            })
            .collect();
        let conflicts = results
            .iter()
            .filter(|r| matches!(r, Ok(Reply::Refused(RefusalReason::IdempotencyConflict))))
            .count();
        assert_eq!(
            admissions.len() + conflicts,
            THREADS,
            "round {round}: {results:?}"
        );
        assert!(!admissions.is_empty());
        assert!(
            admissions.windows(2).all(|w| w[0] == w[1]),
            "one winner, replayed"
        );
        let granted: Vec<String> = admissions[0]
            .granted()
            .iter()
            .map(|g| g.capability().to_canonical_string())
            .collect();
        assert_eq!(granted.len(), 1, "no mixed grant: {granted:?}");
        assert_eq!(
            conflicts,
            THREADS >> 1,
            "the other request's half conflicted"
        );
    }
}
