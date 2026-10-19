//! The supervisor's own tests (M5d.2): the start's handshake, the table's
//! bounds and the collections, driven by a stand-in for the workload's
//! thread. No runtime is needed, and none is claimed: what runs in a real
//! environment is `make sandbox-workload-evidence`'s.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dwk_proto::brokerp::workload::{
    MAX_SUPERVISED_WORKLOADS, WorkloadCollectAuthorisation, WorkloadCollectDone, WorkloadProgress,
};
use dwk_proto::brokerp::{
    BrokerDone, BrokerGeneration, BrokerRefusal, ChannelNonce, Common, Indeterminate, OutcomeResult,
};
use dwk_proto::wire::id::{EnvironmentId, InvocationId};

use super::{Gate, Workloads};

const BODY: &str = "01M24BB8G3E0A851TRWE3M8FZ";

/// The `n`th last character: Crockford base32 has no I, L, O or U.
fn last(n: u8) -> char {
    char::from(
        b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"
            .get(usize::from(n))
            .copied()
            .unwrap(),
    )
}

fn invocation(n: u8) -> InvocationId {
    InvocationId::parse(&format!("inv_{BODY}{}", last(n))).unwrap()
}

fn environment(n: u8) -> EnvironmentId {
    EnvironmentId::parse(&format!("env_{BODY}{}", last(n))).unwrap()
}

fn generation(c: char) -> BrokerGeneration {
    BrokerGeneration::new(c.to_string().repeat(32)).unwrap()
}

fn collect(workloads: &Workloads, n: u8, generation: BrokerGeneration) -> OutcomeResult {
    workloads.collect(&WorkloadCollectAuthorisation::new(
        Common {
            channel: ChannelNonce::new("c".repeat(32)).unwrap(),
            invocation_id: invocation(n),
        },
        generation,
    ))
}

fn running() -> OutcomeResult {
    OutcomeResult::done(BrokerDone::workload_collect(WorkloadCollectDone {
        progress: WorkloadProgress::Running,
        result: None,
        never_ran: None,
    }))
}

fn unknown() -> OutcomeResult {
    OutcomeResult::Indeterminate(Indeterminate::WorkloadUnconfirmed)
}

/// What a stand-in workload ends with: any outcome serves.
fn ending() -> OutcomeResult {
    OutcomeResult::Refused(BrokerRefusal::DigestMismatch)
}

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

/// Collect `n` until it is no longer `RUNNING`, within ten seconds.
fn settled(workloads: &Workloads, n: u8, generation: &BrokerGeneration) -> OutcomeResult {
    let until = soon();
    loop {
        let answer = collect(workloads, n, generation.clone());
        if answer != running() || Instant::now() > until {
            return answer;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// A stand-in workload: judged clean, then -- told to run -- waits for
/// `release` and ends with [`ending`]. `ran` says whether it was ever told.
fn held_workload(
    release: mpsc::Receiver<()>,
    ran: Arc<AtomicBool>,
) -> impl FnOnce(Gate) -> Option<OutcomeResult> + Send + 'static {
    move |gate: Gate| {
        if !gate.judged(Ok(())) {
            return None;
        }
        ran.store(true, Ordering::SeqCst);
        let _ = release.recv();
        Some(ending())
    }
}

#[test]
fn a_passed_start_answers_its_generation_then_running_then_exactly_its_ending() {
    let workloads = Workloads::new(generation('a'));
    let (release, wait) = mpsc::channel();
    let ran = Arc::new(AtomicBool::new(false));
    let answer = workloads.start(
        &invocation(0),
        &environment(0),
        soon(),
        held_workload(wait, Arc::clone(&ran)),
    );
    let OutcomeResult::Done(done) = answer else {
        unreachable!("a passed start is done: {answer:?}")
    };
    assert_eq!(
        done.workload_start.map(|s| s.generation),
        Some(generation('a'))
    );
    assert_eq!(collect(&workloads, 0, generation('a')), running());
    release.send(()).unwrap();
    assert_eq!(settled(&workloads, 0, &generation('a')), ending());
    // Every later collection answers the same ending: a lost answer is
    // collected again, not guessed.
    assert_eq!(collect(&workloads, 0, generation('a')), ending());
    assert!(ran.load(Ordering::SeqCst));
}

#[test]
fn a_refused_judgement_is_the_answer_and_nothing_runs_or_stays_held() {
    let workloads = Workloads::new(generation('a'));
    let ran = Arc::new(AtomicBool::new(false));
    let told = Arc::clone(&ran);
    let answer = workloads.start(&invocation(0), &environment(0), soon(), move |gate| {
        if gate.judged(Err(OutcomeResult::Refused(
            BrokerRefusal::EnvironmentNotClean,
        ))) {
            told.store(true, Ordering::SeqCst);
        }
        None
    });
    assert_eq!(
        answer,
        OutcomeResult::Refused(BrokerRefusal::EnvironmentNotClean)
    );
    assert!(!ran.load(Ordering::SeqCst));
    // Freed before the answer: the environment's next start is not
    // refused for the one that never ran.
    assert_eq!(workloads.held(), 0);
    let (release, wait) = mpsc::channel();
    let next = workloads.start(
        &invocation(1),
        &environment(0),
        soon(),
        held_workload(wait, Arc::new(AtomicBool::new(false))),
    );
    assert!(matches!(next, OutcomeResult::Done(_)), "{next:?}");
    release.send(()).unwrap();
    // A refused start is never collected as a workload.
    assert_eq!(collect(&workloads, 0, generation('a')), unknown());
}

#[test]
fn a_judgement_past_the_deadline_is_refused_and_the_workload_is_never_told_to_run() {
    let workloads = Workloads::new(generation('a'));
    let (judging, judged_late) = mpsc::channel::<()>();
    let told = Arc::new(Mutex::new(None));
    let seen = Arc::clone(&told);
    let answer = workloads.start(
        &invocation(0),
        &environment(0),
        Instant::now() + Duration::from_millis(50),
        move |gate| {
            // The judgement outlasts the exchange's deadline.
            std::thread::sleep(Duration::from_millis(300));
            *seen.lock().unwrap() = Some(gate.judged(Ok(())));
            let _ = judging.send(());
            None
        },
    );
    assert_eq!(
        answer,
        OutcomeResult::Refused(BrokerRefusal::RuntimeUnavailable)
    );
    judged_late.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(*told.lock().unwrap(), Some(false));
    assert_eq!(collect(&workloads, 0, generation('a')), unknown());
}

#[test]
fn one_unended_workload_per_environment_and_one_start_per_invocation() {
    let workloads = Workloads::new(generation('a'));
    let (release, wait) = mpsc::channel();
    let first = workloads.start(
        &invocation(0),
        &environment(0),
        soon(),
        held_workload(wait, Arc::new(AtomicBool::new(false))),
    );
    assert!(matches!(first, OutcomeResult::Done(_)), "{first:?}");
    let never =
        |_: Gate| -> Option<OutcomeResult> { unreachable!("a refused start spawns nothing") };
    // `reap` ends every other process of the environment: a second
    // workload there would be ended by the first's.
    assert_eq!(
        workloads.start(&invocation(1), &environment(0), soon(), never),
        OutcomeResult::Refused(BrokerRefusal::WorkloadInUse)
    );
    // Another environment is free.
    let (other, other_wait) = mpsc::channel();
    let elsewhere = workloads.start(
        &invocation(2),
        &environment(1),
        soon(),
        held_workload(other_wait, Arc::new(AtomicBool::new(false))),
    );
    assert!(matches!(elsewhere, OutcomeResult::Done(_)), "{elsewhere:?}");
    release.send(()).unwrap();
    other.send(()).unwrap();
    assert_eq!(settled(&workloads, 0, &generation('a')), ending());
    // Ended, the environment is free; the invocation is never started twice.
    assert_eq!(
        workloads.start(&invocation(0), &environment(0), soon(), never),
        OutcomeResult::Refused(BrokerRefusal::WorkloadInUse)
    );
    let (again, again_wait) = mpsc::channel();
    let next = workloads.start(
        &invocation(3),
        &environment(0),
        soon(),
        held_workload(again_wait, Arc::new(AtomicBool::new(false))),
    );
    assert!(matches!(next, OutcomeResult::Done(_)), "{next:?}");
    again.send(()).unwrap();
}

#[test]
fn a_full_table_evicts_its_oldest_ended_workload_and_otherwise_refuses() {
    let workloads = Workloads::new(generation('a'));
    let mut releases = Vec::new();
    let count = u8::try_from(MAX_SUPERVISED_WORKLOADS).unwrap();
    for n in 0..count {
        let (release, wait) = mpsc::channel();
        let answer = workloads.start(
            &invocation(n),
            &environment(n),
            soon(),
            held_workload(wait, Arc::new(AtomicBool::new(false))),
        );
        assert!(matches!(answer, OutcomeResult::Done(_)), "{n}: {answer:?}");
        releases.push(release);
    }
    let never =
        |_: Gate| -> Option<OutcomeResult> { unreachable!("a refused start spawns nothing") };
    assert_eq!(
        workloads.start(&invocation(count), &environment(count), soon(), never),
        OutcomeResult::Refused(BrokerRefusal::WorkloadTableFull)
    );
    // The third ends: it, and only it, makes room.
    releases.get(2).unwrap().send(()).unwrap();
    assert_eq!(settled(&workloads, 2, &generation('a')), ending());
    let (last, last_wait) = mpsc::channel();
    let answer = workloads.start(
        &invocation(count),
        &environment(count),
        soon(),
        held_workload(last_wait, Arc::new(AtomicBool::new(false))),
    );
    assert!(matches!(answer, OutcomeResult::Done(_)), "{answer:?}");
    assert_eq!(workloads.held(), MAX_SUPERVISED_WORKLOADS);
    // Evicted, its ending is no longer known here: indeterminate, never a
    // guess.
    assert_eq!(collect(&workloads, 2, generation('a')), unknown());
    assert_eq!(collect(&workloads, 3, generation('a')), running());
    for release in releases {
        let _ = release.send(());
    }
    last.send(()).unwrap();
}

#[test]
fn another_generation_or_an_unknown_workload_is_indeterminate() {
    let workloads = Workloads::new(generation('a'));
    let (release, wait) = mpsc::channel();
    let answer = workloads.start(
        &invocation(0),
        &environment(0),
        soon(),
        held_workload(wait, Arc::new(AtomicBool::new(false))),
    );
    assert!(matches!(answer, OutcomeResult::Done(_)), "{answer:?}");
    // A restarted broker supervises nothing of an earlier generation.
    assert_eq!(collect(&workloads, 0, generation('b')), unknown());
    assert_eq!(collect(&workloads, 7, generation('a')), unknown());
    release.send(()).unwrap();
    assert_eq!(settled(&workloads, 0, &generation('a')), ending());
    assert_eq!(collect(&workloads, 0, generation('b')), unknown());
}

#[test]
#[allow(clippy::panic, reason = "the thread's failure is what is tested")]
fn a_workload_thread_that_fails_after_the_word_is_forgotten_never_reported_ended() {
    let workloads = Workloads::new(generation('a'));
    let answer = workloads.start(&invocation(0), &environment(0), soon(), |gate| {
        assert!(
            !gate.judged(Ok(())),
            "the supervision fails after the workload started"
        );
        None
    });
    assert!(matches!(answer, OutcomeResult::Done(_)), "{answer:?}");
    let until = soon();
    while workloads.held() != 0 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(workloads.held(), 0);
    // Nothing says how it ended: the authority hears that, and destroys the
    // environment.
    assert_eq!(collect(&workloads, 0, generation('a')), unknown());
}
