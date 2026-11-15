//! The broker's effective posture against every acknowledgement and every
//! host fact, on any host: what this machine's own Yama or swap says does not
//! decide what these tests prove.

#![allow(clippy::indexing_slicing)]

use super::{Condition, Control, Evidence, Facts, Requirement, lines, of_broker};
use crate::config::{self, Command, ServeConfig, parse};
use crate::hardening::Observed;
use crate::posture::{Posture, Swap};

const BROKER: u32 = 1001;
const AUTHORITY: u32 = 1000;

fn serve(authority: u32, flags: &[&str]) -> ServeConfig {
    let socket = std::env::temp_dir()
        .join("broker.sock")
        .display()
        .to_string();
    let mut args: Vec<String> = ["serve", "--socket", socket.as_str(), "--authority-uid"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    args.push(authority.to_string());
    args.extend(flags.iter().map(|s| (*s).to_owned()));
    let Ok(Command::Serve(config)) = parse(&args) else {
        unreachable!("a serve configuration: {args:?}")
    };
    config
}

const YAMA: Posture = Posture {
    scope: Some(1),
    execute_only: false,
    suid_dumpable: None,
};

const OPEN: Posture = Posture {
    scope: Some(0),
    execute_only: false,
    suid_dumpable: None,
};

/// A host that gives everything: Yama, a zero swap cap, a verified
/// architecture, the hardening read back, `init_on_free` on.
fn hardened() -> Facts {
    Facts {
        own_uid: BROKER,
        posture: YAMA,
        swap: Swap::Capped("/system.slice/dwkd-broker.service".to_owned()),
        architecture_verified: true,
        hardened: Observed {
            dumpable: Some(false),
            no_core: true,
        },
        page_zeroing: "init_on_alloc=default init_on_free=on".to_owned(),
    }
}

fn record<'a>(records: &'a [Control], id: &str) -> &'a Control {
    let found: Vec<&Control> = records.iter().filter(|r| r.id == id).collect();
    assert_eq!(found.len(), 1, "exactly one record for {id}: {records:?}");
    found[0]
}

fn summary(records: &[Control]) -> String {
    lines(records).pop().unwrap_or_default()
}

#[test]
fn a_production_broker_on_a_hardened_host_reports_every_control_enforced() {
    let records = of_broker(&serve(AUTHORITY, &[]), &hardened());
    assert_eq!(records.len(), 12);
    for r in &records {
        assert_eq!(r.condition, Condition::Enforced, "{r:?}");
        assert_eq!(r.flag, None, "{r:?}");
        assert_eq!(r.refuses, None, "{r:?}");
    }
    // The ids are distinct: one record per control.
    let mut ids: Vec<&str> = records.iter().map(|r| r.id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), records.len());
    assert_eq!(
        summary(&records),
        "posture_summary reduced=- unverified=- unsupported=- refuses=\"-\""
    );
    // What was read is said to have been read.
    for id in [
        "broker.identity.authority",
        "broker.memory.dumpable",
        "broker.memory.core_limit",
        "worker.startup_window",
        "worker.credential_swap",
    ] {
        assert_eq!(record(&records, id).evidence, Evidence::Observed, "{id}");
    }
}

#[test]
fn every_acknowledgement_reduces_exactly_the_control_it_weakens_and_names_itself() {
    let fixture = std::env::temp_dir()
        .join("fixture.txt")
        .display()
        .to_string();
    let anchor = std::env::temp_dir().join("ca.pem").display().to_string();
    for (flags, authority, id) in [
        (
            vec![config::SHARED_AUTHORITY_UID],
            BROKER,
            "broker.identity.authority",
        ),
        (vec![config::DUMPABLE], AUTHORITY, "broker.memory.dumpable"),
        (
            vec![config::TRACEABLE_WORKERS],
            AUTHORITY,
            "worker.startup_window",
        ),
        (
            vec![config::SWAPPABLE_WORKERS],
            AUTHORITY,
            "worker.credential_swap",
        ),
        (
            vec![config::EVIDENCE_TOPOLOGY],
            AUTHORITY,
            "environment.topology",
        ),
        (
            vec![config::UNVERIFIED_WORKSPACE],
            AUTHORITY,
            "environment.workspace",
        ),
        (
            vec![config::EVIDENCE_EGRESS, fixture.as_str()],
            AUTHORITY,
            "egress.resolver",
        ),
    ] {
        let records = of_broker(&serve(authority, &flags), &hardened());
        let reduced: Vec<&Control> = records
            .iter()
            .filter(|r| r.condition == Condition::Reduced)
            .collect();
        assert_eq!(reduced.len(), 1, "{flags:?}: {reduced:?}");
        assert_eq!(reduced[0].id, id, "{flags:?}");
        assert_eq!(reduced[0].flag, Some(flags[0]), "{flags:?}");
        assert!(
            !reduced[0].consequence.is_empty(),
            "{id}: the guarantee lost"
        );
        assert!(!reduced[0].remediation.is_empty(), "{id}: what to do");
        assert!(
            summary(&records).contains(&format!("reduced={id} ")),
            "{}",
            summary(&records)
        );
    }
    // The trust anchor is given only beside the fixture resolver: both
    // reduce, each its own control.
    let records = of_broker(
        &serve(
            AUTHORITY,
            &[
                config::EVIDENCE_EGRESS,
                fixture.as_str(),
                config::EVIDENCE_TRUST,
                anchor.as_str(),
            ],
        ),
        &hardened(),
    );
    assert_eq!(
        record(&records, "egress.trust_anchor").flag,
        Some(config::EVIDENCE_TRUST)
    );
    assert_eq!(
        record(&records, "egress.resolver").condition,
        Condition::Reduced
    );
}

#[test]
fn an_acknowledgement_is_reduced_even_where_the_host_is_safe_now() {
    // F-03's defect: with the window closed and swap capped at start, the
    // acknowledgements reduced nothing that was said, yet turned the per-hop
    // checks into admissions. They are reduced whatever the host says now.
    let records = of_broker(
        &serve(
            AUTHORITY,
            &[config::TRACEABLE_WORKERS, config::SWAPPABLE_WORKERS],
        ),
        &hardened(),
    );
    for id in ["worker.startup_window", "worker.credential_swap"] {
        let r = record(&records, id);
        assert_eq!(r.condition, Condition::Reduced, "{r:?}");
        assert!(r.consequence.contains("later"), "{r:?}");
        assert!(r.consequence.contains("reported"), "{r:?}");
        assert_eq!(r.refuses, None, "{r:?}");
    }
    // And on a host that is not safe, the same flags say what is lost now.
    let mut open = hardened();
    open.posture = OPEN;
    open.swap = Swap::Possible;
    let records = of_broker(
        &serve(
            AUTHORITY,
            &[config::TRACEABLE_WORKERS, config::SWAPPABLE_WORKERS],
        ),
        &open,
    );
    assert!(
        record(&records, "worker.startup_window")
            .consequence
            .contains("may trace")
    );
    assert!(
        record(&records, "worker.credential_swap")
            .consequence
            .contains("may be written to swap")
    );
}

#[test]
fn an_unknown_observation_is_never_taken_for_a_safe_one() {
    let config = serve(AUTHORITY, &[]);
    // Swap: no device and a zero cap are protected; swap with no cap is kept
    // by refusing credential hops; an unread device count is unverified --
    // and refused too.
    for (swap, condition, refused) in [
        (Swap::NoDevice, Condition::Enforced, false),
        (Swap::Capped("/a".to_owned()), Condition::Enforced, false),
        (Swap::Possible, Condition::Enforced, true),
        (Swap::Unknown, Condition::Unverified, true),
    ] {
        let mut facts = hardened();
        facts.swap = swap.clone();
        let records = of_broker(&config, &facts);
        let r = record(&records, "worker.credential_swap");
        assert_eq!(r.condition, condition, "{swap:?}");
        assert_eq!(
            r.refuses,
            refused.then_some("every net.http hop that carries a credential"),
            "{swap:?}"
        );
        assert!(r.facts.contains(&swap.describe()), "{r:?}");
    }
    // The process's own hardening, read back: unread is not enforced.
    let mut facts = hardened();
    facts.hardened = Observed {
        dumpable: None,
        no_core: false,
    };
    let records = of_broker(&config, &facts);
    let dumpable = record(&records, "broker.memory.dumpable");
    assert_eq!(dumpable.condition, Condition::Unverified);
    assert_eq!(dumpable.evidence, Evidence::Configured, "nothing was read");
    assert_eq!(
        record(&records, "broker.memory.core_limit").condition,
        Condition::Unverified
    );
    // Read as dumpable with nothing acknowledging it: contradicted, never
    // enforced.
    facts.hardened.dumpable = Some(true);
    assert_eq!(
        record(&of_broker(&config, &facts), "broker.memory.dumpable").condition,
        Condition::Unverified
    );
    let lines = lines(&of_broker(&config, &facts));
    assert!(
        lines.last().is_some_and(
            |s| s.contains("unverified=broker.memory.dumpable,broker.memory.core_limit")
        ),
        "{lines:?}"
    );
}

#[test]
fn what_this_build_cannot_give_is_unsupported_and_refused() {
    let mut facts = hardened();
    facts.architecture_verified = false;
    let records = of_broker(&serve(AUTHORITY, &[]), &facts);
    let r = record(&records, "worker.syscall_program");
    assert_eq!(r.condition, Condition::Unsupported);
    assert_eq!(r.refuses, Some("every net.http hop"));
    assert!(summary(&records).contains("unsupported=worker.syscall_program "));
    // No hop runs, so no credential is held for one: swap does not apply.
    assert_eq!(
        record(&records, "worker.credential_swap").condition,
        Condition::NotApplicable
    );
    // No acknowledgement turns it into anything else.
    let every = serve(
        BROKER,
        &[
            config::SHARED_AUTHORITY_UID,
            config::DUMPABLE,
            config::TRACEABLE_WORKERS,
            config::SWAPPABLE_WORKERS,
        ],
    );
    assert_eq!(
        record(&of_broker(&every, &facts), "worker.syscall_program").condition,
        Condition::Unsupported
    );
}

#[test]
fn what_the_start_refuses_is_said_as_refused_never_as_reduced() {
    // An open window, a shared uid, an environment's identity -- each
    // without its acknowledgement: the broker refuses to serve, and the
    // report says so rather than reporting the control weakened.
    let mut facts = hardened();
    facts.posture = OPEN;
    let r = of_broker(&serve(AUTHORITY, &[]), &facts);
    assert_eq!(record(&r, "worker.startup_window").refuses, Some("serving"));
    assert_eq!(
        record(&r, "worker.startup_window").condition,
        Condition::Enforced
    );
    let r = of_broker(&serve(BROKER, &[]), &hardened());
    assert_eq!(
        record(&r, "broker.identity.authority").refuses,
        Some("serving")
    );
    let mut sandboxed = hardened();
    sandboxed.own_uid = 10_001;
    let r = of_broker(
        &serve(AUTHORITY, &[config::SHARED_AUTHORITY_UID]),
        &sandboxed,
    );
    assert_eq!(
        record(&r, "broker.identity.sandbox").refuses,
        Some("serving")
    );
    assert!(
        summary(&r).contains("refuses=\"serving\""),
        "{}",
        summary(&r)
    );
}

#[test]
fn a_reduced_control_is_never_averaged_away_by_the_ones_that_hold() {
    // Eleven controls hold; one is reduced. The summary names the one, and
    // carries no count or score that the eleven could outweigh.
    let records = of_broker(&serve(AUTHORITY, &[config::DUMPABLE]), &hardened());
    let s = summary(&records);
    assert_eq!(
        s,
        "posture_summary reduced=broker.memory.dumpable unverified=- unsupported=- refuses=\"-\""
    );
    assert!(!s.contains("ENFORCED") && !s.contains('%') && !s.contains("score"));
}

#[test]
fn a_recommendation_is_reported_and_never_required() {
    for (cmdline, condition) in [
        ("init_on_alloc=default init_on_free=on", Condition::Enforced),
        ("init_on_alloc=default init_on_free=off", Condition::Reduced),
        (
            "init_on_alloc=default init_on_free=default",
            Condition::Unverified,
        ),
        (
            "init_on_alloc=default init_on_free=unrecognised",
            Condition::Unverified,
        ),
    ] {
        let mut facts = hardened();
        facts.page_zeroing = cmdline.to_owned();
        let records = of_broker(&serve(AUTHORITY, &[]), &facts);
        let r = record(&records, "host.page_zeroing");
        assert_eq!(r.requirement, Requirement::Recommended);
        assert_eq!(r.condition, condition, "{cmdline}");
        assert_eq!(r.refuses, None, "a recommendation refuses nothing");
        assert_eq!(
            summary(&records),
            "posture_summary reduced=- unverified=- unsupported=- refuses=\"-\"",
            "{cmdline}: a recommendation is never listed with the required"
        );
    }
}

#[test]
fn no_line_carries_a_path_or_anything_but_names_ids_and_facts() {
    let fixture = "/srv/evidence/s3cret-fixture-81f0.txt";
    let anchor = "/srv/evidence/s3cret-anchor-81f0.pem";
    let config = serve(
        BROKER,
        &[
            config::SHARED_AUTHORITY_UID,
            config::DUMPABLE,
            config::TRACEABLE_WORKERS,
            config::SWAPPABLE_WORKERS,
            config::EVIDENCE_TOPOLOGY,
            config::UNVERIFIED_WORKSPACE,
            config::EVIDENCE_EGRESS,
            fixture,
            config::EVIDENCE_TRUST,
            anchor,
        ],
    );
    let all = lines(&of_broker(&config, &hardened())).join("\n");
    assert!(!all.contains("s3cret"), "{all}");
    assert!(!all.contains(&config.socket.display().to_string()), "{all}");
    // Every record is one line; quotes only delimit values.
    for line in lines(&of_broker(&config, &hardened())) {
        assert!(!line.contains('\n'));
        assert_eq!(line.matches('"').count() % 2, 0, "{line}");
    }
}

#[test]
fn the_records_are_well_formed() {
    // No record contradicts itself: a flag only on a reduced record, a
    // reduced required record always names its flag, a refusal only where
    // the control is not weakened.
    let fixture = std::env::temp_dir().join("f.txt").display().to_string();
    let mut every_host = Vec::new();
    for posture in [YAMA, OPEN] {
        for swap in [Swap::NoDevice, Swap::Possible, Swap::Unknown] {
            for verified in [true, false] {
                let mut facts = hardened();
                facts.posture = posture;
                facts.swap = swap.clone();
                facts.architecture_verified = verified;
                every_host.push(facts);
            }
        }
    }
    for flags in [
        vec![],
        vec![config::DUMPABLE, config::TRACEABLE_WORKERS],
        vec![
            config::SWAPPABLE_WORKERS,
            config::EVIDENCE_EGRESS,
            fixture.as_str(),
        ],
    ] {
        for facts in &every_host {
            for r in of_broker(&serve(AUTHORITY, &flags), facts) {
                assert_eq!(
                    r.flag.is_some(),
                    r.condition == Condition::Reduced && r.requirement == Requirement::Required,
                    "{r:?}"
                );
                if r.refuses.is_some() {
                    assert!(
                        matches!(
                            r.condition,
                            Condition::Enforced | Condition::Unverified | Condition::Unsupported
                        ),
                        "{r:?}"
                    );
                }
                if r.condition != Condition::Enforced && r.requirement == Requirement::Required {
                    assert!(!r.consequence.is_empty(), "{r:?}");
                }
            }
        }
    }
}
