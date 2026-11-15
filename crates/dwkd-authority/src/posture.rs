//! The authority's effective start-up posture (F-03, ADR-0065, Proposed):
//! one record per control the authority owns or depends on, recorded in
//! `audit.log` once per incarnation (`authority.posture`) and said on stderr.
//! What holds, what an operator's acknowledgement reduced, what could not be
//! verified, what does not apply -- and never a score: one reduced control is
//! listed as reduced however many others hold.
//!
//! Each record says whether it was **observed** (read from the kernel now:
//! this process's own hardening, read back) or **configured** (the
//! operator's command line and files). The authority cannot observe the
//! broker's posture -- the broker's acknowledgements and the host facts it
//! reads are its own, in its own log (`event=posture`), and nothing on the
//! private channel carries them -- so a configured broker's posture is
//! recorded as **unverified**, never assumed.
//!
//! This records; it decides nothing. The refusals stay where they are -- the
//! server's start-up checks, the policy flags, the sandbox's judgement of
//! each environment -- and every record is computed from the same
//! configuration they act on. The facts are the process's own and fixed for
//! its life: a dumpable flag cleared at start is not set again, a core limit
//! of zero cannot be raised by this process, and the peer policy, the broker
//! and the attached environment do not change until the next start, which
//! records its own posture.
//!
//! No record carries a path, a secret or a peer's bytes: flags by name,
//! uids, and enumerated conditions.

use crate::sandbox::WorkspaceSetting;

/// What holds of a control now. Not an authorisation decision: what the
/// authority does about it is [`Control::refuses`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    /// The property is verified: observed or, where nothing can be observed,
    /// fixed by the operator's configuration.
    Enforced,
    /// An acknowledgement the operator gave weakens the control.
    Reduced,
    /// What would establish the property could not be read, or is not
    /// visible to the authority.
    Unverified,
    /// This platform cannot give the control.
    Unsupported,
    /// The control does not apply to this configuration.
    NotApplicable,
}

impl Condition {
    /// The stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enforced => "ENFORCED",
            Self::Reduced => "REDUCED",
            Self::Unverified => "UNVERIFIED",
            Self::Unsupported => "UNSUPPORTED",
            Self::NotApplicable => "NOT_APPLICABLE",
        }
    }
}

/// Where a record's facts come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence {
    /// Read from the kernel at start.
    Observed,
    /// The operator's configuration.
    Configured,
}

impl Evidence {
    /// The stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "OBSERVED",
            Self::Configured => "CONFIGURED",
        }
    }
}

/// One control's effective condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control {
    /// The control's stable id.
    pub id: &'static str,
    /// Whose property it is: `authority`, `broker`, `policy` or
    /// `environment`.
    pub scope: &'static str,
    /// What holds.
    pub condition: Condition,
    /// Where that comes from.
    pub evidence: Evidence,
    /// The acknowledgement that reduced it.
    pub flag: Option<&'static str>,
    /// What the condition means: the guarantee lost, or why it is not known.
    pub consequence: &'static str,
}

/// This process's own hardening as the kernel reports it, read back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hardened {
    /// Whether the process is dumpable; `None` when that could not be read.
    pub dumpable: Option<bool>,
    /// Whether `RLIMIT_CORE` is 0, soft and hard.
    pub no_core: bool,
}

/// The broker as the operator configured it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Broker {
    /// None: tool invocations are decided and never performed.
    None,
    /// Its own identity: neither the authority's nor a DWKP peer's.
    Own,
    /// The authority's uid or a peer's, acknowledged for development.
    Shared,
}

/// Everything the records are computed from, fixed at start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Facts {
    /// This process's hardening, read back; `None` where the server does
    /// not harden (off Linux).
    pub hardened: Option<Hardened>,
    /// `--allow-dumpable`.
    pub dumpable_permitted: bool,
    /// The peer policy admits the authority's own uid
    /// (`--allow-authority-uid`).
    pub authority_uid_admitted: bool,
    /// The broker.
    pub broker: Broker,
    /// `--allow-host-execution`: the `security.allow_host_execution` flag.
    pub host_execution: bool,
    /// The attached execution environment's workspace; `None` without one.
    pub workspace: Option<WorkspaceSetting>,
}

/// The authority's own command-line acknowledgements, as the effective
/// posture names them.
pub const DUMPABLE: &str = "--allow-dumpable";
/// The authority's uid may connect as a peer.
pub const AUTHORITY_UID: &str = "--allow-authority-uid";
/// The broker may share a uid with the authority or a peer.
pub const SHARED_BROKER_UID: &str = "--allow-shared-broker-uid";
/// The `security.allow_host_execution` policy flag.
pub const HOST_EXECUTION: &str = "--allow-host-execution";
/// The operator's file's evidence-only workspace.
pub const UNVERIFIED_WORKSPACE_KEY: &str = "[workspace] unverified_evidence";

const fn control(
    id: &'static str,
    scope: &'static str,
    condition: Condition,
    evidence: Evidence,
) -> Control {
    Control {
        id,
        scope,
        condition,
        evidence,
        flag: None,
        consequence: "",
    }
}

/// The process's own memory: not dumpable, and no core.
fn memory(facts: &Facts) -> [Control; 2] {
    let read = facts.hardened.and_then(|h| h.dumpable);
    let mut dumpable = control(
        "authority.memory.dumpable",
        "authority",
        match (facts.dumpable_permitted, read) {
            (true, _) => Condition::Reduced,
            (false, Some(false)) => Condition::Enforced,
            (false, _) => Condition::Unverified,
        },
        if read.is_some() {
            Evidence::Observed
        } else {
            Evidence::Configured
        },
    );
    if facts.dumpable_permitted {
        dumpable.flag = Some(DUMPABLE);
        dumpable.consequence = "the authority's memory, secret material it holds included, is \
                                readable by other processes of its uid";
    } else if read != Some(false) {
        dumpable.consequence = "the kernel did not confirm the authority is not dumpable";
    }
    let no_core = facts.hardened.is_some_and(|h| h.no_core);
    let mut core = control(
        "authority.memory.core_limit",
        "authority",
        if no_core {
            Condition::Enforced
        } else {
            Condition::Unverified
        },
        if facts.hardened.is_some() {
            Evidence::Observed
        } else {
            Evidence::Configured
        },
    );
    if !no_core {
        core.consequence = "the kernel did not confirm RLIMIT_CORE is 0";
    }
    [dumpable, core]
}

/// The two broker controls: its identity, and its own posture -- which the
/// authority cannot see.
fn broker(facts: &Facts) -> [Control; 2] {
    let mut identity = control(
        "broker.identity",
        "broker",
        match facts.broker {
            Broker::None => Condition::NotApplicable,
            Broker::Own => Condition::Enforced,
            Broker::Shared => Condition::Reduced,
        },
        Evidence::Configured,
    );
    let mut posture = control(
        "broker.posture",
        "broker",
        if facts.broker == Broker::None {
            Condition::NotApplicable
        } else {
            Condition::Unverified
        },
        Evidence::Configured,
    );
    match facts.broker {
        Broker::None => {
            let none = "no broker is configured: tool invocations are decided and never \
                        performed";
            identity.consequence = none;
            posture.consequence = none;
        }
        Broker::Own => {}
        Broker::Shared => {
            identity.flag = Some(SHARED_BROKER_UID);
            identity.consequence = "the broker shares a uid with the authority or a DWKP peer: \
                                    one inherits the other's powers";
        }
    }
    if facts.broker != Broker::None {
        posture.consequence = "the broker's acknowledgements and host facts are not visible to \
                               the authority: see the broker's own event=posture lines";
    }
    [identity, posture]
}

/// The authority's effective start-up posture for `facts`.
#[must_use]
pub fn of_authority(facts: &Facts) -> Vec<Control> {
    let mut records = Vec::with_capacity(7);
    records.extend(memory(facts));
    let mut peers = control(
        "authority.peer_boundary",
        "authority",
        if facts.authority_uid_admitted {
            Condition::Reduced
        } else {
            Condition::Enforced
        },
        Evidence::Configured,
    );
    if facts.authority_uid_admitted {
        peers.flag = Some(AUTHORITY_UID);
        peers.consequence = "a peer with the authority's own uid can open kernel.db directly: \
                             the process boundary does not constrain it";
    }
    records.push(peers);
    records.extend(broker(facts));
    let mut host = control(
        "policy.host_execution",
        "policy",
        if facts.host_execution {
            Condition::Reduced
        } else {
            Condition::Enforced
        },
        Evidence::Configured,
    );
    if facts.host_execution {
        host.flag = Some(HOST_EXECUTION);
        host.consequence = "a policy rule may admit a process on the host, outside every \
                            execution environment, with the broker's privileges, once an \
                            approval exists";
    }
    records.push(host);
    let mut workspace = control(
        "environment.workspace",
        "environment",
        match facts.workspace {
            None => Condition::NotApplicable,
            Some(WorkspaceSetting::Bounded(_)) => Condition::Enforced,
            Some(WorkspaceSetting::UnverifiedEvidence) => Condition::Reduced,
        },
        Evidence::Configured,
    );
    match facts.workspace {
        None => {
            workspace.consequence = "no execution environment is attached: process.exec runs \
                                     nowhere";
        }
        Some(WorkspaceSetting::Bounded(_)) => {}
        Some(WorkspaceSetting::UnverifiedEvidence) => {
            workspace.flag = Some(UNVERIFIED_WORKSPACE_KEY);
            workspace.consequence = "no run's workspace has its group or its bound proved, so a \
                                     workload can fill the filesystem it is on";
        }
    }
    records.push(workspace);
    records
}

/// The ids in `condition`, in record order.
#[must_use]
pub fn ids(records: &[Control], condition: Condition) -> Vec<&'static str> {
    records
        .iter()
        .filter(|r| r.condition == condition)
        .map(|r| r.id)
        .collect()
}

/// The stderr lines: one per record, then the summary -- the controls that
/// are not enforced, by condition; no count of what holds, and no score.
#[must_use]
pub fn lines(records: &[Control]) -> Vec<String> {
    let list = |condition| {
        let named = ids(records, condition);
        if named.is_empty() {
            "-".to_owned()
        } else {
            named.join(",")
        }
    };
    let mut out: Vec<String> = records
        .iter()
        .map(|r| {
            format!(
                "posture control={} scope={} condition={} evidence={} flag={}",
                r.id,
                r.scope,
                r.condition.as_str(),
                r.evidence.as_str(),
                r.flag.unwrap_or("-")
            )
        })
        .collect();
    out.push(format!(
        "posture_summary reduced={} unverified={} unsupported={}",
        list(Condition::Reduced),
        list(Condition::Unverified),
        list(Condition::Unsupported)
    ));
    out
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::{Broker, Condition, Control, Evidence, Facts, Hardened, lines, of_authority};
    use crate::sandbox::WorkspaceSetting;

    fn hardened() -> Facts {
        Facts {
            hardened: Some(Hardened {
                dumpable: Some(false),
                no_core: true,
            }),
            dumpable_permitted: false,
            authority_uid_admitted: false,
            broker: Broker::Own,
            host_execution: false,
            workspace: Some(WorkspaceSetting::Bounded(
                dwk_proto::brokerp::sandbox::WorkspaceQuota::new(64 << 20)
                    .unwrap_or_else(|| unreachable!("a quota in range")),
            )),
        }
    }

    fn record<'a>(records: &'a [Control], id: &str) -> &'a Control {
        let found: Vec<&Control> = records.iter().filter(|r| r.id == id).collect();
        assert_eq!(found.len(), 1, "{id}: {records:?}");
        found[0]
    }

    #[test]
    fn a_hardened_production_authority_is_enforced_but_for_the_broker_it_cannot_see() {
        let records = of_authority(&hardened());
        assert_eq!(records.len(), 7);
        for r in &records {
            let expected = if r.id == "broker.posture" {
                Condition::Unverified
            } else {
                Condition::Enforced
            };
            assert_eq!(r.condition, expected, "{r:?}");
            assert_eq!(r.flag, None, "{r:?}");
        }
        assert_eq!(
            record(&records, "authority.memory.dumpable").evidence,
            Evidence::Observed
        );
        assert_eq!(
            lines(&records).last().map(String::as_str),
            Some("posture_summary reduced=- unverified=broker.posture unsupported=-")
        );
    }

    #[test]
    fn every_acknowledgement_reduces_exactly_its_control_and_names_itself() {
        type Weaken = fn(&mut Facts);
        let cases: [(Weaken, &str, &str); 5] = [
            (
                |f| f.dumpable_permitted = true,
                "authority.memory.dumpable",
                "--allow-dumpable",
            ),
            (
                |f| f.authority_uid_admitted = true,
                "authority.peer_boundary",
                "--allow-authority-uid",
            ),
            (
                |f| f.broker = Broker::Shared,
                "broker.identity",
                "--allow-shared-broker-uid",
            ),
            (
                |f| f.host_execution = true,
                "policy.host_execution",
                "--allow-host-execution",
            ),
            (
                |f| f.workspace = Some(WorkspaceSetting::UnverifiedEvidence),
                "environment.workspace",
                "[workspace] unverified_evidence",
            ),
        ];
        for (weaken, id, flag) in cases {
            let mut facts = hardened();
            weaken(&mut facts);
            let records = of_authority(&facts);
            let reduced: Vec<&Control> = records
                .iter()
                .filter(|r| r.condition == Condition::Reduced)
                .collect();
            assert_eq!(reduced.len(), 1, "{id}: {reduced:?}");
            assert_eq!((reduced[0].id, reduced[0].flag), (id, Some(flag)));
            assert!(!reduced[0].consequence.is_empty(), "{id}");
            assert!(
                lines(&records)
                    .last()
                    .is_some_and(|s| s.contains(&format!("reduced={id} "))),
                "{id}"
            );
        }
    }

    #[test]
    fn what_was_not_read_is_unverified_and_what_is_absent_does_not_apply() {
        let mut facts = hardened();
        facts.hardened = Some(Hardened {
            dumpable: None,
            no_core: false,
        });
        let records = of_authority(&facts);
        for id in ["authority.memory.dumpable", "authority.memory.core_limit"] {
            assert_eq!(
                record(&records, id).condition,
                Condition::Unverified,
                "{id}"
            );
            assert!(!record(&records, id).consequence.is_empty());
        }
        facts.hardened = Some(Hardened {
            dumpable: Some(true),
            no_core: true,
        });
        assert_eq!(
            record(&of_authority(&facts), "authority.memory.dumpable").condition,
            Condition::Unverified,
            "dumpable with nothing acknowledging it is contradicted, never enforced"
        );
        facts.hardened = None;
        let records = of_authority(&facts);
        assert_eq!(
            record(&records, "authority.memory.dumpable").evidence,
            Evidence::Configured
        );
        assert_eq!(
            record(&records, "authority.memory.core_limit").condition,
            Condition::Unverified
        );
        let mut bare = hardened();
        bare.broker = Broker::None;
        bare.workspace = None;
        let records = of_authority(&bare);
        for id in ["broker.identity", "broker.posture", "environment.workspace"] {
            assert_eq!(
                record(&records, id).condition,
                Condition::NotApplicable,
                "{id}"
            );
        }
        assert_eq!(
            lines(&records).last().map(String::as_str),
            Some("posture_summary reduced=- unverified=- unsupported=-")
        );
    }

    #[test]
    fn a_reduced_control_is_never_averaged_away() {
        let mut facts = hardened();
        facts.host_execution = true;
        let summary = lines(&of_authority(&facts)).pop().unwrap_or_default();
        assert_eq!(
            summary,
            "posture_summary reduced=policy.host_execution unverified=broker.posture \
             unsupported=-"
        );
        assert!(!summary.contains("ENFORCED") && !summary.contains('%'));
    }

    #[test]
    fn the_records_are_well_formed_and_carry_no_path() {
        let mut every = Vec::new();
        for dumpable_permitted in [false, true] {
            for authority_uid_admitted in [false, true] {
                for broker in [Broker::None, Broker::Own, Broker::Shared] {
                    for host_execution in [false, true] {
                        for workspace in [
                            None,
                            hardened().workspace,
                            Some(WorkspaceSetting::UnverifiedEvidence),
                        ] {
                            every.push(Facts {
                                dumpable_permitted,
                                authority_uid_admitted,
                                broker,
                                host_execution,
                                workspace,
                                ..hardened()
                            });
                        }
                    }
                }
            }
        }
        for facts in &every {
            let records = of_authority(facts);
            for r in &records {
                assert_eq!(r.flag.is_some(), r.condition == Condition::Reduced, "{r:?}");
                if r.condition != Condition::Enforced {
                    assert!(!r.consequence.is_empty(), "{r:?}");
                }
            }
            for line in lines(&records) {
                assert!(!line.contains('/') && line.len() < 400, "{line}");
            }
        }
    }
}
