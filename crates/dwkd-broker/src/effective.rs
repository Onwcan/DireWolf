//! The broker's effective security posture, said at start (F-03, ADR-0065,
//! Proposed): one record per control the broker owns -- what holds, what an
//! acknowledgement reduced, what could not be verified, what this build or
//! platform cannot give -- and never a score. One reduced control is listed
//! as reduced however many others hold.
//!
//! Each record says whether it was **observed** (read from the kernel or the
//! host now: uids, Yama, the binary's mode, swap, this process's own
//! hardening read back) or **configured** (the operator's command line, or
//! this build), the flag that reduced it, and what it refuses because of it.
//!
//! This reports; it decides nothing. The decisions stay where they are -- the
//! start-up refusals (`admit` in `main.rs`) and `http::WorkerPolicy` before
//! every hop -- and every record is computed from the same facts and flags
//! they use, read once at start: the report and the enforcement describe one
//! host. What changes after start is the per-hop check's to see; a hop an
//! acknowledgement admitted against the facts is reported there
//! (`posture_acknowledged`), never here.
//!
//! No record carries a path, a credential or anything a hop holds: flags by
//! name, uids, and the host facts the `deployment_posture` line already
//! prints.

use core::fmt::Write as _;

use crate::config::{self, ServeConfig, SwappableWorkers, TraceableWorkers, UnverifiedWorkspace};
use crate::hardening::Observed;
use crate::posture::{Posture, Swap};

/// What holds of a control now. Not an authorisation decision: what the
/// broker does about it is [`Control::refuses`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Condition {
    /// The property is verified: observed or, where nothing can be observed,
    /// fixed by this build and the operator's configuration.
    Enforced,
    /// An acknowledgement the operator gave weakens the control.
    Reduced,
    /// What would establish the property could not be read.
    Unverified,
    /// This build or platform cannot give the control.
    Unsupported,
    /// The control does not apply to this configuration.
    NotApplicable,
}

impl Condition {
    /// The stable spelling.
    pub(crate) const fn as_str(self) -> &'static str {
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
pub(crate) enum Evidence {
    /// Read from the kernel or the host at start.
    Observed,
    /// The operator's configuration, or this build.
    Configured,
}

impl Evidence {
    /// The stable spelling.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "OBSERVED",
            Self::Configured => "CONFIGURED",
        }
    }
}

/// Whether a control is required, or only recommended: a recommendation
/// never refuses anything and is never listed with the required ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Requirement {
    /// Part of the broker's contract.
    Required,
    /// Advice the deployment guide gives; nothing depends on it.
    Recommended,
}

impl Requirement {
    /// The stable spelling.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Required => "REQUIRED",
            Self::Recommended => "RECOMMENDED",
        }
    }
}

/// One control's effective condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Control {
    /// The control's stable id.
    pub(crate) id: &'static str,
    /// Whose property it is: `broker`, `worker` (a hop's exchange worker),
    /// `egress` or `environment`, or the `host`'s.
    pub(crate) scope: &'static str,
    pub(crate) condition: Condition,
    pub(crate) evidence: Evidence,
    pub(crate) requirement: Requirement,
    /// The acknowledgement that reduced it.
    pub(crate) flag: Option<&'static str>,
    /// What was read or configured, for the operator.
    pub(crate) facts: String,
    /// What the broker refuses because of this control's condition.
    pub(crate) refuses: Option<&'static str>,
    /// What the condition means: the guarantee lost, or how it is kept.
    pub(crate) consequence: &'static str,
    /// What the operator can do about it.
    pub(crate) remediation: &'static str,
}

/// Everything the records are computed from, read once at start.
#[derive(Debug, Clone)]
pub(crate) struct Facts {
    /// The broker's own uid, as the kernel reports it.
    pub(crate) own_uid: u32,
    /// The start-up window's facts.
    pub(crate) posture: Posture,
    /// Where this broker's memory can go.
    pub(crate) swap: Swap,
    /// Whether the worker's syscall program has kernel evidence here.
    pub(crate) architecture_verified: bool,
    /// This process's hardening, read back.
    pub(crate) hardened: Observed,
    /// `posture::page_zeroing`'s report of the kernel command line.
    pub(crate) page_zeroing: String,
}

/// A record with no flag, nothing refused and no advice: the parts every
/// record has, the rest filled in by the caller.
fn control(
    id: &'static str,
    scope: &'static str,
    condition: Condition,
    evidence: Evidence,
    facts: String,
) -> Control {
    Control {
        id,
        scope,
        condition,
        evidence,
        requirement: Requirement::Required,
        flag: None,
        facts,
        refuses: None,
        consequence: "",
        remediation: "",
    }
}

/// The two identity controls: the authority's uid, and no environment's.
fn identity(config: &ServeConfig, facts: &Facts) -> [Control; 2] {
    let uids = format!(
        "broker_uid={} authority_uid={}",
        facts.own_uid, config.authority_uid
    );
    let shared = facts.own_uid == config.authority_uid;
    let mut authority = control(
        "broker.identity.authority",
        "broker",
        if shared && config.shared_uid_permitted {
            Condition::Reduced
        } else {
            Condition::Enforced
        },
        Evidence::Observed,
        uids.clone(),
    );
    if shared {
        if config.shared_uid_permitted {
            authority.flag = Some(config::SHARED_AUTHORITY_UID);
            authority.consequence = "the authority and the broker are one identity: a process \
                                     of that uid holds the powers of both";
            authority.remediation = "run the broker as its own user";
        } else {
            authority.refuses = Some("serving");
        }
    }
    let clash = crate::posture::sandbox_identity_clash(facts.own_uid, config.authority_uid);
    let mut sandbox = control(
        "broker.identity.sandbox",
        "broker",
        Condition::Enforced,
        Evidence::Observed,
        uids,
    );
    if clash.is_some() {
        sandbox.refuses = Some("serving");
        sandbox.remediation = "run neither daemon as uid 10001 or 10002";
    }
    [authority, sandbox]
}

/// The broker's own memory: not dumpable, and no core.
fn memory(config: &ServeConfig, facts: &Facts) -> [Control; 2] {
    let read = facts.hardened.dumpable;
    let mut dumpable = control(
        "broker.memory.dumpable",
        "broker",
        match (config.dumpable_permitted, read) {
            (true, _) => Condition::Reduced,
            (false, Some(false)) => Condition::Enforced,
            // Read as dumpable though nothing acknowledged it, or not read at
            // all: nothing establishes the property.
            (false, _) => Condition::Unverified,
        },
        if read.is_some() {
            Evidence::Observed
        } else {
            Evidence::Configured
        },
        format!(
            "dumpable={}",
            read.map_or("unread", |d| if d { "1" } else { "0" })
        ),
    );
    if config.dumpable_permitted {
        dumpable.flag = Some(config::DUMPABLE);
        dumpable.consequence = "the broker's memory, a credential it holds for a hop \
                                included, is readable by other processes of its uid";
        dumpable.remediation = "start the broker without --allow-dumpable";
    } else if read != Some(false) {
        dumpable.consequence = "the kernel did not confirm the broker is not dumpable";
    }
    let mut core = control(
        "broker.memory.core_limit",
        "broker",
        if facts.hardened.no_core {
            Condition::Enforced
        } else {
            Condition::Unverified
        },
        Evidence::Observed,
        format!("rlimit_core_zero={}", facts.hardened.no_core),
    );
    if !facts.hardened.no_core {
        core.consequence = "the kernel did not confirm RLIMIT_CORE is 0";
    }
    [dumpable, core]
}

/// The exchange worker's start-up window (ADR-0053 §4).
fn startup_window(config: &ServeConfig, facts: &Facts) -> Control {
    let closed = facts.posture.startup_window_closed();
    let acknowledged = config.traceable_workers == TraceableWorkers::Permitted;
    let mut record = control(
        "worker.startup_window",
        "worker",
        if acknowledged {
            Condition::Reduced
        } else {
            Condition::Enforced
        },
        Evidence::Observed,
        facts.posture.describe(),
    );
    if acknowledged {
        record.flag = Some(config::TRACEABLE_WORKERS);
        record.consequence = if closed {
            "closed now, but a hop is admitted if the window opens later: reported at that \
             hop, never refused"
        } else {
            "a process of the broker's uid may trace a worker or launch helper before it \
             hardens itself"
        };
        record.remediation = "set kernel.yama.ptrace_scope to 1 or more, or install the broker \
                              root-owned and execute-only where fs.suid_dumpable is 0 or 2; \
                              then drop the flag";
    } else if !closed {
        record.refuses = Some("serving");
    }
    record
}

/// A credential hop's memory and swap (ADR-0053 §7).
fn credential_swap(config: &ServeConfig, facts: &Facts) -> Control {
    let protected = facts.swap.protected();
    let acknowledged = config.swappable_workers == SwappableWorkers::Permitted;
    if !facts.architecture_verified {
        // No hop runs here, so no credential is read for one: nothing for
        // swap to hold, whatever was acknowledged.
        let mut record = control(
            "worker.credential_swap",
            "worker",
            Condition::NotApplicable,
            Evidence::Observed,
            format!("swap={}", facts.swap.describe()),
        );
        record.consequence = "no net.http hop runs on this architecture (worker.syscall_program)";
        return record;
    }
    let mut record = control(
        "worker.credential_swap",
        "worker",
        match (acknowledged, &facts.swap) {
            (true, _) => Condition::Reduced,
            // A failed read is not proof of anything.
            (false, Swap::Unknown) => Condition::Unverified,
            // Protected, or kept by refusing every credential hop.
            (false, _) => Condition::Enforced,
        },
        Evidence::Observed,
        format!("swap={}", facts.swap.describe()),
    );
    let remediation = "run the broker under memory.swap.max = 0 (systemd: MemorySwapMax=0) or \
                       on a host without swap";
    if acknowledged {
        record.flag = Some(config::SWAPPABLE_WORKERS);
        record.consequence = if protected {
            "protected now, but a credential hop is admitted if swap appears later: reported \
             at that hop, never refused"
        } else {
            "a credential exchange's memory, the broker's and its worker's, may be written to \
             swap"
        };
        record.remediation = remediation;
    } else if !protected {
        record.refuses = Some("every net.http hop that carries a credential");
        record.consequence = "no credential reaches swap because no credential hop is \
                              performed";
        record.remediation = remediation;
    }
    record
}

/// The worker's syscall program (ADR-0053 OD-7): this build's evidence.
fn syscall_program(facts: &Facts) -> Control {
    let mut record = control(
        "worker.syscall_program",
        "worker",
        if facts.architecture_verified {
            Condition::Enforced
        } else {
            Condition::Unsupported
        },
        Evidence::Configured,
        format!("architecture={}", std::env::consts::ARCH),
    );
    if !facts.architecture_verified {
        record.refuses = Some("every net.http hop");
        record.consequence = "no worker syscall program has kernel evidence on this \
                              architecture";
        record.remediation = "run the broker on x86_64 for net.http";
    }
    record
}

/// A control an evidence-only acknowledgement reduces, configured.
fn evidence_only(
    (id, scope): (&'static str, &'static str),
    given: bool,
    flag: &'static str,
    (production, consequence): (&'static str, &'static str),
) -> Control {
    let mut record = control(
        id,
        scope,
        if given {
            Condition::Reduced
        } else {
            Condition::Enforced
        },
        Evidence::Configured,
        production.to_owned(),
    );
    if given {
        record.flag = Some(flag);
        record.facts = format!("{flag} given");
        record.consequence = consequence;
        record.remediation = "evidence harnesses only: never pass it to a production broker";
    }
    record
}

/// The page-zeroing recommendation (ADR-0053 §7, `BROKER_HARDENING.md`):
/// reported, never required.
fn page_zeroing(facts: &Facts) -> Control {
    let free = |value: &str| {
        facts
            .page_zeroing
            .contains(&format!("init_on_free={value}"))
    };
    let mut record = control(
        "host.page_zeroing",
        "host",
        if free("on") {
            Condition::Enforced
        } else if free("off") {
            Condition::Reduced
        } else {
            // `default` or unrecognised: the build's default is not visible.
            Condition::Unverified
        },
        Evidence::Observed,
        facts.page_zeroing.clone(),
    );
    record.requirement = Requirement::Recommended;
    if !free("on") {
        record.consequence = "freed pages are not known to be zeroed at once; nothing is \
                              refused for it";
        record.remediation = "init_on_free=1 on the kernel command line (recommended)";
    }
    record
}

/// Every control's effective condition for `config` on a host with `facts`.
pub(crate) fn of_broker(config: &ServeConfig, facts: &Facts) -> Vec<Control> {
    let mut records = Vec::with_capacity(12);
    records.extend(identity(config, facts));
    records.extend(memory(config, facts));
    records.push(startup_window(config, facts));
    records.push(credential_swap(config, facts));
    records.push(syscall_program(facts));
    records.push(evidence_only(
        ("egress.resolver", "egress"),
        config.evidence_egress.is_some(),
        config::EVIDENCE_EGRESS,
        (
            "the host's resolver",
            "names resolve from a fixture file, and the loopback addresses it names are \
             reachable",
        ),
    ));
    records.push(evidence_only(
        ("egress.trust_anchor", "egress"),
        config.evidence_trust.is_some(),
        config::EVIDENCE_TRUST,
        (
            "Mozilla's roots, compiled in",
            "net.http trusts a test authority instead of Mozilla's roots",
        ),
    ));
    records.push(evidence_only(
        ("environment.topology", "environment"),
        config.evidence_topology_permitted,
        config::EVIDENCE_TOPOLOGY,
        (
            "PROXY_ONLY environments only",
            "NO_NETWORK environments, the M5a evidence topology, may be prepared",
        ),
    ));
    records.push(evidence_only(
        ("environment.workspace", "environment"),
        config.unverified_workspace == UnverifiedWorkspace::Permitted,
        config::UNVERIFIED_WORKSPACE,
        (
            "every workspace bounded and of the workspace group, measured",
            "an environment may mount a workspace whose group and bound nothing proves, so a \
             workload there can fill the host's filesystem",
        ),
    ));
    records.push(page_zeroing(facts));
    records
}

/// The ids of the required records in `condition`, comma-separated, or `-`.
fn ids(records: &[Control], condition: Condition) -> String {
    let named: Vec<&str> = records
        .iter()
        .filter(|r| r.requirement == Requirement::Required && r.condition == condition)
        .map(|r| r.id)
        .collect();
    if named.is_empty() {
        "-".to_owned()
    } else {
        named.join(",")
    }
}

/// The event lines: one per record, then the summary -- which lists the
/// required controls that are not enforced, by condition, and what is
/// refused; no count of what holds, and no score.
pub(crate) fn lines(records: &[Control]) -> Vec<String> {
    let mut out: Vec<String> = records
        .iter()
        .map(|r| {
            let mut line = format!(
                "posture control={} scope={} condition={} evidence={} requirement={} flag={} \
                 facts=\"{}\"",
                r.id,
                r.scope,
                r.condition.as_str(),
                r.evidence.as_str(),
                r.requirement.as_str(),
                r.flag.unwrap_or("-"),
                r.facts
            );
            if let Some(refuses) = r.refuses {
                let _ = write!(line, " refuses=\"{refuses}\"");
            }
            if !r.consequence.is_empty() {
                let _ = write!(line, " consequence=\"{}\"", r.consequence);
            }
            if !r.remediation.is_empty() {
                let _ = write!(line, " remediation=\"{}\"", r.remediation);
            }
            line
        })
        .collect();
    let refused: Vec<&str> = records.iter().filter_map(|r| r.refuses).collect();
    out.push(format!(
        "posture_summary reduced={} unverified={} unsupported={} refuses=\"{}\"",
        ids(records, Condition::Reduced),
        ids(records, Condition::Unverified),
        ids(records, Condition::Unsupported),
        if refused.is_empty() {
            "-".to_owned()
        } else {
            refused.join("; ")
        }
    ));
    out
}

#[cfg(test)]
#[path = "effective_tests.rs"]
mod tests;
