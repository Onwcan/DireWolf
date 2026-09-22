//! Fixtures for evidence that needs something this test binary cannot do by
//! itself: a second operating-system identity, and wall-clock latency.
//!
//! Both are `#[ignore]`d. They are run deliberately, by
//! `make authority-write-probe` and `make authority-state-evidence`, and their
//! output is evidence rather than a pass/fail gate on a shared machine.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]

use proptest as _;
use sha2 as _;
use toml as _;

mod state_support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use dwk_proto::wire::scalar::CapabilityText;
use dwkd_authority::capability::parse;
use dwkd_authority::policy::{CanonicalAction, Environment};
use dwkd_authority::state::{Proposal, Reply, SystemClock};
use state_support::{Harness, admit_simple, install_fixtures, session, subject};

/// Create a real authority state directory at `DW_PROBE_STATE_DIR`, with a
/// lease, an admission and a flushed audit log, and leave it there.
///
/// The runtime-user write probe (`tests/authority/runtime_write_probe.py`)
/// then attempts, as a DIFFERENT operating-system user, every write that would
/// let the runtime change the state that constrains it.
#[test]
#[ignore = "creates state for the runtime-user write probe"]
fn create_probe_state() {
    let Ok(dir) = std::env::var("DW_PROBE_STATE_DIR") else {
        return;
    };
    let options = dwkd_authority::state::StartOptions {
        clock: Arc::new(SystemClock),
        crash_hook: None,
    };
    let (mut authority, _) = dwkd_authority::state::Authority::start(
        std::path::Path::new(&dir),
        &state_support::balanced(),
        options,
    )
    .expect("the probe state starts");
    install_fixtures(&mut authority);
    let caller = authority.connect(subject(1000));
    let s = session(1);
    let Reply::Done(e) = authority.acquire_lease(&caller, &s).unwrap() else {
        panic!("leased")
    };
    let Reply::Done(_) = authority
        .admit_run(&caller, &admit_simple(&s, e, "probe", &["model.call:*"]))
        .unwrap()
    else {
        panic!("admitted")
    };
    println!("probe state ready at {dir}");
}

fn percentile(samples: &mut [Duration], p: usize) -> Duration {
    samples.sort_unstable();
    let index = (samples.len() * p).div_ceil(100).saturating_sub(1);
    samples[index.min(samples.len() - 1)]
}

fn report(name: &str, mut samples: Vec<Duration>) {
    let p50 = percentile(&mut samples, 50);
    let p95 = percentile(&mut samples, 95);
    let p99 = percentile(&mut samples, 99);
    println!(
        "{name:<28} n={:<4} p50={p50:>10.3?} p95={p95:>10.3?} p99={p99:>10.3?}",
        samples.len()
    );
}

/// Diagnostic latency of each audited operation, on real files with
/// `synchronous = FULL` and an `fsync` of `audit.log` per operation.
///
/// **Not a gate.** `fsync` latency is a property of the disk and the host
/// under it, and a threshold on a shared laptop or CI runner would be a flaky
/// check rather than a security control. The numbers say where the time goes.
#[test]
#[ignore = "diagnostic latency, run by make authority-state-evidence"]
fn state_operation_latency() {
    const N: u64 = 200;
    let mut h = Harness::new("latency");
    let mut acquire = Vec::new();
    let mut admit = Vec::new();
    let mut replay = Vec::new();
    let mut query = Vec::new();
    let mut heartbeat = Vec::new();
    let mut refused = Vec::new();
    // A decision is made only about a complete canonical action (ADR-0040);
    // this one stands in for what M4's canonicaliser will build. A wire
    // proposal is refused before any rule runs, and is timed separately.
    let action = CanonicalAction::new(
        parse("model.call:anthropic/claude")
            .unwrap()
            .resolve()
            .unwrap(),
        Environment::Sandbox,
    );
    let proposal = CapabilityText::new("model.call:anthropic/claude").unwrap();
    for n in 0..N {
        let caller = h.connect(1000);
        let s = session(1_000 + n);
        let started = Instant::now();
        let e = h.lease(&caller, &s);
        acquire.push(started.elapsed());

        let message = admit_simple(&s, e, "k", &["model.call:*"]);
        let started = Instant::now();
        let Reply::Done(admission) = h.authority().admit_run(&caller, &message).unwrap() else {
            panic!("admitted")
        };
        admit.push(started.elapsed());

        let started = Instant::now();
        let _ = h.authority().admit_run(&caller, &message).unwrap();
        replay.push(started.elapsed());

        let started = Instant::now();
        let _ = h
            .authority()
            .query_authority(
                &caller,
                &s,
                admission.run_id(),
                e,
                Some(Proposal::Action(&action)),
            )
            .unwrap();
        query.push(started.elapsed());

        let started = Instant::now();
        let _ = h
            .authority()
            .query_authority(
                &caller,
                &s,
                admission.run_id(),
                e,
                Some(Proposal::Text(&proposal)),
            )
            .unwrap();
        refused.push(started.elapsed());

        let started = Instant::now();
        let _ = h.authority().heartbeat(&caller, &s, e).unwrap();
        heartbeat.push(started.elapsed());
    }
    println!("M3d state latency (diagnostic; real files, FULL sync, one audit fsync per op)");
    report("AcquireLease", acquire);
    report("AdmitRun (first)", admit);
    report("AdmitRun (replay)", replay);
    report("QueryAuthority (decision)", query);
    report("QueryAuthority (refused)", refused);
    report("Heartbeat (no audit)", heartbeat);
}
