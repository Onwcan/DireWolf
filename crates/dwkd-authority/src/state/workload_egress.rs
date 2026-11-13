//! A sandboxed workload's egress, decided by both gates when it is launched
//! (F-17, [ADR-0061], Proposed).
//!
//! A `PROXY_ONLY` environment's grant -- the run's exact, unconstrained
//! `network.https` grants (ADR-0048 §5, ADR-0060) -- is only the ceiling. In
//! the transaction that records a workload's intent, the authority decides
//! `network.https:<host>:<port>` in `SANDBOX` for every destination of that
//! ceiling, through the same two gates `net.http` and `process.exec` use, and
//! the broker holds the result only while that workload is supervised. Policy
//! is evaluated for what a workload's tunnel can still turn on once it has
//! started, and nothing else:
//!
//! * **Novelty.** Whether the run has reached the destination: `SEEN` when a
//!   `net.http` hop of the run completed TLS with it or an earlier tunnel of
//!   the run reached it (`tunnel_reach`, certain), `NOVEL` until a tunnel of
//!   this workload reaches it -- the broker switches cells then -- and
//!   uncertain when a report was lost: both cells are then the stricter of
//!   the two. Tunnel reach is read here only; `net.http`'s novelty is its own.
//! * **Exposure.** Whether the workspace may hold what an origin sent: the
//!   exposed cells are the stricter of the decisions at every taint the run
//!   could then have, from its own up to `EXTERNAL_UNTRUSTED`. The broker
//!   switches every workload on the workspace's root to them before the first
//!   byte from any origin reaches any of them. A workload starts exposed when
//!   the root was exposed before (`workspace_exposure`), or another workload
//!   on the same root that may reach an origin has not settled. This decides
//!   no taint (F-01): the run's own taint is not changed.
//! * **The address.** Exactly, over the active policy's own ranges
//!   (`crate::policy::partition`): one evaluation per piece, by the
//!   production evaluator.
//!
//! An `ALLOW` keeps only what a tunnel can keep: `max_output_bytes` (each
//! tunnel's downstream bound, which bounds every response it carries) and
//! `audit_level`. Anything else -- `REQUIRE_APPROVAL` (no approval exists
//! before M6), `DENY`, an unevaluable input, an obligation a tunnel cannot
//! keep, a policy too fine to partition -- allows nothing.
//!
//! # Settled once, never forgotten
//!
//! The decision, its inputs' digest and the authorisation are durable with
//! the intent. How the workload's tunnels ended is settled with its outcome:
//! from the broker's report when one agrees with the authorisation, and
//! otherwise **uncertain** -- every destination it allowed is then reached
//! uncertainly and the root exposed. A restart settles an interrupted one the
//! same way. Reach and exposure rows are never updated or deleted, so no
//! recovery restores a less restrictive decision.
//!
//! [ADR-0061]: ../../../../../docs/adr/0061-policy-decides-sandbox-egress-at-workload-launch.md

use dwk_proto::brokerp::egress::{
    EgressBits, EgressByteBudget, EgressCell, EgressCounters, EgressHost, EgressPort, EgressPrefix,
    EgressPrefixes, MAX_EGRESS_AUTHORISATION_BYTES, WorkloadEgress, WorkloadEgressReport,
    WorkloadEgressTarget, WorkloadEgressTargets,
};
use dwk_proto::json::{self, Object, Value};
use dwk_proto::wire::WireType as _;
use dwk_proto::wire::guard::Address;
use dwk_proto::wire::id::{InvocationId, RunId};
use rusqlite::OptionalExtension as _;

use crate::capability::{
    Action, Capability, ConstraintSet, Endpoint, Namespace, Scope, SyntacticScope, Verb,
};
use crate::policy::partition::{NetworkPartition, TooFine};
use crate::policy::{
    CanonicalAction, Environment, IpAddress, Novelty, Obligation, PolicyContext, TaintLevel,
    Unevaluable,
};

use super::Work;
use super::admission::Admission;
use super::audit::{Field, Fields};
use super::digest;
use super::error::AuthorityError;
use super::lease::to_sql;
use super::policy_state::ActiveAuthority;
use super::query::{self, DecisionRecord};

/// What a destination's novelty is when a workload starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Reach {
    /// Never reached by the run.
    Novel,
    /// Reached.
    Seen,
    /// A report that would say was lost.
    Uncertain,
}

impl Reach {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Novel => "NOVEL",
            Self::Seen => "SEEN",
            Self::Uncertain => "UNCERTAIN",
        }
    }
}

/// One evaluation's verdict for one piece.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Verdict {
    allowed: bool,
    /// The bound `max_output_bytes` puts on each tunnel, when allowed.
    cap: Option<u64>,
    /// The rule that decided, or the reason nothing was evaluated.
    rule: String,
}

/// A decision made for a workload's launch.
#[derive(Debug, Clone)]
pub(super) struct Decided {
    /// What the broker is given.
    pub(super) egress: WorkloadEgress,
    /// The workspace root's identity, as the store records it.
    pub(super) root: (String, String),
    /// The digest of the context the decision was made in.
    pub(super) context_sha256: digest::Sha256Hash,
    /// Per destination and cell: the rules, and per piece which decided.
    decisions: Value,
    /// One line per destination, for the audit.
    summaries: Vec<Field>,
    /// How the address dimension was decided.
    partition: String,
}

/// The root of the run's workspace, as the store records it.
fn root_of(work: &Work<'_>, run: &str) -> Result<Option<(String, String)>, AuthorityError> {
    work.db(work
        .tx
        .query_row(
            "SELECT r.root_device, r.root_inode FROM run_policy_input p \
             JOIN workspace_root r ON r.workspace_id = p.workspace_id WHERE p.run_id = ?1",
            [run],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional())
}

/// Whether a workload on `root` starts exposed: the root was exposed, or a
/// workload on it that may reach an origin has not settled.
fn exposed(work: &Work<'_>, root: &(String, String)) -> Result<bool, AuthorityError> {
    work.db(work.tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM workspace_exposure \
                        WHERE root_device = ?1 AND root_inode = ?2) \
             OR EXISTS (SELECT 1 FROM workload_egress e \
                        JOIN workload w ON w.invocation_id = e.invocation_id \
                        WHERE e.root_device = ?1 AND e.root_inode = ?2 \
                        AND e.allows_anything = 1 AND w.state = 'LAUNCHING')",
        rusqlite::params![root.0, root.1],
        |row| row.get(0),
    ))
}

/// Whether the run has reached `host:port`.
fn reach(work: &Work<'_>, run: &str, host: &str, port: u16) -> Result<Reach, AuthorityError> {
    let (handshake, certain, uncertain): (bool, bool, bool) = work.db(work.tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM net_hop WHERE run_id = ?1 AND host = ?2 AND port = ?3 \
                        AND tls_established = 1), \
                EXISTS (SELECT 1 FROM tunnel_reach WHERE run_id = ?1 AND host = ?2 \
                        AND port = ?3 AND certain = 1), \
                EXISTS (SELECT 1 FROM tunnel_reach WHERE run_id = ?1 AND host = ?2 \
                        AND port = ?3 AND certain = 0)",
        rusqlite::params![run, host, i64::from(port)],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ))?;
    Ok(if handshake || certain {
        Reach::Seen
    } else if uncertain {
        Reach::Uncertain
    } else {
        Reach::Novel
    })
}

/// The digest of what a decision was made in: the policy revision and the
/// run's whole policy context. A collection that finds another is drift.
pub(super) fn context_digest(
    active: &ActiveAuthority,
    context: &PolicyContext,
) -> digest::Sha256Hash {
    digest::plain(format!("{}\n{context:?}", active.revision.to_hex()).as_bytes())
}

/// The capability a tunnel to `host:port` requires: exactly the destination,
/// unconstrained -- so a grant that carries a constraint does not cover it
/// (ADR-0060), whatever derived the ceiling.
fn required(host: &str, port: u16) -> Result<Capability, AuthorityError> {
    let verb = Verb::new(Namespace::Network, Action::Https)
        .ok_or(AuthorityError::Invariant("network.https is not a verb"))?;
    let endpoint = Endpoint::parse(&format!("{host}:{port}"))
        .map_err(|_| AuthorityError::Invariant("a granted destination is not an endpoint"))?;
    Capability::new(
        verb,
        Scope::Syntactic(SyntacticScope::Endpoint(endpoint)),
        ConstraintSet::unconstrained(),
    )
    .map_err(|_| AuthorityError::Invariant("a tunnel capability does not assemble"))
}

/// Whether a tunnel keeps every obligation, and the downstream bound they
/// put on it.
fn kept(record: &DecisionRecord) -> (bool, Option<u64>) {
    let mut cap: Option<u64> = None;
    for obligation in record.policy().obligations().as_slice() {
        match obligation {
            Obligation::MaxOutputBytes(bound) if *bound >= 1 => {
                cap = Some(cap.map_or(*bound, |c| c.min(*bound)));
            }
            Obligation::AuditLevel(_) => {}
            _ => return (false, None),
        }
    }
    (true, cap)
}

fn verdict(record: &DecisionRecord) -> Verdict {
    let (keeps, cap) = kept(record);
    let allowed = record.permits() && keeps;
    Verdict {
        allowed,
        cap: if allowed { cap } else { None },
        rule: if !record.capability_satisfied() {
            "NO_CAPABILITY".to_owned()
        } else if record.policy_satisfied() && !keeps {
            format!(
                "{}:OBLIGATION_UNENFORCEABLE",
                record.policy().rule_id().as_str()
            )
        } else {
            record.policy().rule_id().as_str().to_owned()
        },
    }
}

/// One verdict per piece, for one novelty and one taint.
fn piece_verdicts(
    (capability, novelty, context): (&Capability, Novelty, &PolicyContext),
    (admission, active): (&Admission, &ActiveAuthority),
    pieces: usize,
) -> Vec<Verdict> {
    let base = CanonicalAction::new(capability.clone(), Environment::Sandbox)
        .with_destination_novelty(novelty);
    let without = query::decide(&base, admission, context, active);
    match without.policy().unevaluable() {
        None => vec![verdict(&without); pieces],
        Some(Unevaluable::ResolvedAddress) => match &active.partition {
            Ok(partition) => (0..pieces)
                .map(|piece| match partition.representative(piece) {
                    Some(address) => verdict(&query::decide(
                        &base.clone().with_destination_ip(address),
                        admission,
                        context,
                        active,
                    )),
                    // No address is in this piece: nothing to allow.
                    None => Verdict {
                        allowed: false,
                        cap: None,
                        rule: "EMPTY_PIECE".to_owned(),
                    },
                })
                .collect(),
            Err(TooFine) => vec![
                Verdict {
                    allowed: false,
                    cap: None,
                    rule: "EGRESS_POLICY_TOO_FINE".to_owned(),
                };
                pieces
            ],
        },
        Some(_) => vec![
            Verdict {
                allowed: false,
                cap: None,
                rule: "UNRESOLVED_POLICY_INPUT".to_owned(),
            };
            pieces
        ],
    }
}

/// A cell: the meet of `parts` -- a piece allowed only where every part
/// allows it, at the tightest bound -- and per piece the rule that decided:
/// the first part that refused, or the first part.
fn meet(
    parts: &[&Vec<Verdict>],
    pieces: usize,
) -> Result<(EgressCell, Vec<String>), AuthorityError> {
    let mut allowed = Vec::with_capacity(pieces);
    let mut rules = Vec::with_capacity(pieces);
    let mut cap: Option<u64> = None;
    for piece in 0..pieces {
        let verdicts: Vec<&Verdict> = parts.iter().filter_map(|p| p.get(piece)).collect();
        let all = verdicts.len() == parts.len() && verdicts.iter().all(|v| v.allowed);
        allowed.push(all);
        let deciding = verdicts
            .iter()
            .find(|v| !v.allowed)
            .or_else(|| verdicts.first())
            .map_or_else(String::new, |v| v.rule.clone());
        rules.push(deciding);
        if all {
            for bound in verdicts.iter().filter_map(|v| v.cap) {
                cap = Some(cap.map_or(bound, |c| c.min(bound)));
            }
        }
    }
    let bits = EgressBits::from_pieces(&allowed).ok_or(AuthorityError::Invariant(
        "a cell's pieces do not make bits",
    ))?;
    let max_tunnel_download_bytes = match cap {
        None => None,
        // A bound past the protocol's largest budget is no tighter than it.
        Some(bound) => EgressByteBudget::new(bound.min(EgressByteBudget::MAX)),
    };
    Ok((
        EgressCell {
            allowed: bits,
            max_tunnel_download_bytes,
        },
        rules,
    ))
}

const fn ip(address: IpAddress) -> Address {
    match address {
        IpAddress::V4(o) => Address::V4(o),
        IpAddress::V6(o) => Address::V6(o),
    }
}

/// The ranges as the wire carries them.
fn prefixes(
    partition: &Result<NetworkPartition, TooFine>,
) -> Result<EgressPrefixes, AuthorityError> {
    let ranges: Vec<EgressPrefix> = match partition {
        Ok(partition) => partition
            .ranges()
            .iter()
            .map(|cidr| {
                u8::try_from(cidr.prefix())
                    .ok()
                    .and_then(|length| EgressPrefix::of(&ip(cidr.network()), length))
                    .ok_or(AuthorityError::Invariant(
                        "a policy range is not a canonical prefix",
                    ))
            })
            .collect::<Result<_, _>>()?,
        Err(TooFine) => Vec::new(),
    };
    EgressPrefixes::new(ranges).ok_or(AuthorityError::Invariant(
        "more ranges than a grant carries",
    ))
}

/// One cell's summary: how many non-empty pieces it allows, and the rules
/// that decided.
fn summary(cell: &EgressCell, rules: &[String], nonempty: &[bool]) -> String {
    let allowed = nonempty
        .iter()
        .enumerate()
        .filter(|(piece, there)| **there && cell.allowed.get(*piece))
        .count();
    let total = nonempty.iter().filter(|there| **there).count();
    let mut named: Vec<&str> = Vec::new();
    for (piece, rule) in rules.iter().enumerate() {
        if nonempty.get(piece).copied().unwrap_or(false) && !named.contains(&rule.as_str()) {
            named.push(rule);
        }
    }
    format!("{allowed}/{total}[{}]", named.join("+"))
}

/// What one destination's decision needs: the run's context, the policy in
/// force, and the pieces and taints it is decided over.
struct Inputs<'a> {
    admission: &'a Admission,
    context: &'a PolicyContext,
    active: &'a ActiveAuthority,
    pieces: usize,
    nonempty: &'a [bool],
    /// Every taint the run could have once exposed: its own and above.
    at_least: &'a [TaintLevel],
}

/// One destination's four cells, its record and its audit line.
fn destination(
    (host, port, reach): (&str, u16, Reach),
    inputs: &Inputs<'_>,
) -> Result<(WorkloadEgressTarget, Value, Field), AuthorityError> {
    let capability = required(host, port)?;
    // One evaluation per novelty and taint, each for every piece.
    let mut table: Vec<((bool, TaintLevel), Vec<Verdict>)> = Vec::new();
    for novel in [true, false] {
        for taint in inputs.at_least {
            let novelty = if novel { Novelty::Novel } else { Novelty::Seen };
            let taint_context = inputs.context.clone().with_taint_at_least(*taint);
            table.push((
                (novel, *taint),
                piece_verdicts(
                    (&capability, novelty, &taint_context),
                    (inputs.admission, inputs.active),
                    inputs.pieces,
                ),
            ));
        }
    }
    let pick = |novelties: &[bool], taints: &[TaintLevel]| -> Vec<&Vec<Verdict>> {
        table
            .iter()
            .filter(|((novel, taint), _)| novelties.contains(novel) && taints.contains(taint))
            .map(|(_, verdicts)| verdicts)
            .collect()
    };
    // An uncertain reach is decided both ways, and the stricter kept.
    let (novel_novelties, seen_novelties): (&[bool], &[bool]) = if reach == Reach::Uncertain {
        (&[true, false], &[true, false])
    } else {
        (&[true], &[false])
    };
    let own = [inputs.context.taint()];
    let (novel_pristine, np) = meet(&pick(novel_novelties, &own), inputs.pieces)?;
    let (novel_exposed, ne) = meet(&pick(novel_novelties, inputs.at_least), inputs.pieces)?;
    let (seen_pristine, sp) = meet(&pick(seen_novelties, &own), inputs.pieces)?;
    let (seen_exposed, se) = meet(&pick(seen_novelties, inputs.at_least), inputs.pieces)?;
    let line = Field::Text(format!(
        "{host}:{port} {} np={} ne={} sp={} se={}",
        reach.as_str(),
        summary(&novel_pristine, &np, inputs.nonempty),
        summary(&novel_exposed, &ne, inputs.nonempty),
        summary(&seen_pristine, &sp, inputs.nonempty),
        summary(&seen_exposed, &se, inputs.nonempty),
    ));
    let record = decision_record(
        (host, port, reach),
        [("np", &np), ("ne", &ne), ("sp", &sp), ("se", &se)],
    )?;
    let target = WorkloadEgressTarget {
        host: EgressHost::new(host).ok_or(AuthorityError::Invariant(
            "a granted host is not an egress host",
        ))?,
        port: EgressPort::new(port).ok_or(AuthorityError::Invariant(
            "a granted port is not an egress port",
        ))?,
        seen: reach == Reach::Seen,
        novel_pristine,
        novel_exposed,
        seen_pristine,
        seen_exposed,
    };
    Ok((target, record, line))
}

/// A destination's durable record: per cell, the rule that decided each
/// piece.
fn decision_record(
    (host, port, reach): (&str, u16, Reach),
    cells: [(&str, &Vec<String>); 4],
) -> Result<Value, AuthorityError> {
    let twice = |_| AuthorityError::Invariant("a decision is recorded twice");
    let mut by_cell = Object::new();
    for (name, rules) in cells {
        let rules: Vec<Value> = rules.iter().map(|r| Value::String(r.clone())).collect();
        by_cell
            .insert(name.to_owned(), Value::Array(rules))
            .map_err(twice)?;
    }
    let mut entry = Object::new();
    for (name, value) in [
        ("destination", Value::String(format!("{host}:{port}"))),
        ("reach", Value::String(reach.as_str().to_owned())),
        ("rules_by_piece", Value::Object(by_cell)),
    ] {
        entry.insert(name.to_owned(), value).map_err(twice)?;
    }
    Ok(Value::Object(entry))
}

/// Decide `run`'s workload egress (ADR-0061's decision 2): every destination
/// of the ceiling, four cells each. `Ok(Err(reason))` refuses the launch,
/// and nothing is recorded.
///
/// # Errors
///
/// [`AuthorityError`] when the store cannot answer, or an invariant fails.
pub(super) fn decide(
    work: &Work<'_>,
    run: &RunId,
    (admission, context, active): (&Admission, &PolicyContext, &ActiveAuthority),
) -> Result<Result<Decided, &'static str>, AuthorityError> {
    let Some(root) = root_of(work, run.as_str())? else {
        return Ok(Err("NO_WORKSPACE_ROOT"));
    };
    let ceiling = match crate::sandbox::egress_targets(
        admission
            .granted()
            .iter()
            .map(super::admission::Grant::capability),
    ) {
        Ok(ceiling) => ceiling,
        Err(reason) => return Ok(Err(reason)),
    };
    let exposed_at_start = exposed(work, &root)?;
    let prefixes = prefixes(&active.partition)?;
    let pieces = prefixes.len().saturating_add(2);
    let nonempty: Vec<bool> = match &active.partition {
        Ok(partition) => (0..pieces)
            .map(|piece| partition.representative(piece).is_some())
            .collect(),
        Err(TooFine) => vec![true; pieces],
    };
    let at_least: Vec<TaintLevel> = TaintLevel::ALL
        .iter()
        .copied()
        .filter(|t| *t >= context.taint())
        .collect();
    let inputs = Inputs {
        admission,
        context,
        active,
        pieces,
        nonempty: &nonempty,
        at_least: &at_least,
    };
    let mut targets = Vec::with_capacity(ceiling.len());
    let mut decisions = Vec::with_capacity(ceiling.len());
    let mut summaries = Vec::with_capacity(ceiling.len());
    for target in &ceiling {
        let (host, port) = (target.host.as_str(), target.port.get());
        let reach = reach(work, run.as_str(), host, port)?;
        let (cells, record, line) = destination((host, port, reach), &inputs)?;
        targets.push(cells);
        decisions.push(record);
        summaries.push(line);
    }
    let egress = WorkloadEgress {
        exposed: exposed_at_start,
        prefixes,
        targets: WorkloadEgressTargets::new(targets).ok_or(AuthorityError::Invariant(
            "more destinations than a grant carries",
        ))?,
    };
    egress
        .check()
        .map_err(|_| AuthorityError::Invariant("a decided authorisation contradicts itself"))?;
    let encoded = json::to_canonical_bytes(
        &egress
            .encode()
            .map_err(|_| AuthorityError::Invariant("an authorisation does not encode"))?,
    );
    if encoded.len() > MAX_EGRESS_AUTHORISATION_BYTES {
        return Ok(Err("EGRESS_AUTHORISATION_TOO_LARGE"));
    }
    let partition = match &active.partition {
        Ok(partition) if partition.ranges().is_empty() => "NONE".to_owned(),
        Ok(partition) => format!("RANGES:{}", partition.ranges().len()),
        Err(TooFine) => "TOO_FINE".to_owned(),
    };
    Ok(Ok(Decided {
        egress,
        root,
        context_sha256: context_digest(active, context),
        decisions: Value::Array(decisions),
        summaries,
        partition,
    }))
}

/// The egress a launch of `run` is decided with (F-17): none outside
/// `PROXY_ONLY`; otherwise both gates for every destination, or why the
/// launch is refused.
///
/// # Errors
///
/// [`AuthorityError`] when the store cannot answer, or an invariant fails.
pub(super) fn for_launch(
    work: &Work<'_>,
    run: &RunId,
    active: &ActiveAuthority,
    proxy_only: bool,
) -> Result<Result<Option<Decided>, &'static str>, AuthorityError> {
    if !proxy_only {
        return Ok(Ok(None));
    }
    let admission = super::admission::load(work, run.as_str())?;
    let context = query::policy_context(work, run.as_str(), active)?;
    Ok(decide(work, run, (&admission, &context, active))?.map(Some))
}

/// Record `decided` for the workload `invocation`, in its intent's
/// transaction, and return the intent's audit fields for it.
///
/// # Errors
///
/// [`AuthorityError`] when the store cannot record it.
pub(super) fn record(
    work: &mut Work<'_>,
    (run, invocation): (&RunId, &InvocationId),
    decided: &Decided,
) -> Result<Fields, AuthorityError> {
    let encoded = json::to_canonical_string(
        &decided
            .egress
            .encode()
            .map_err(|_| AuthorityError::Invariant("an authorisation does not encode"))?,
    );
    let sha256 = digest::plain(encoded.as_bytes());
    let decisions = json::to_canonical_string(&decided.decisions);
    work.db(work.tx.execute(
        "INSERT INTO workload_egress (invocation_id, run_id, root_device, root_inode, \
         authorisation, authorisation_sha256, decisions, context_sha256, allows_anything, \
         exposed_at_start, settled, exposed, report, recorded_ms, settled_ms) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, NULL, NULL, ?11, NULL)",
        rusqlite::params![
            invocation.as_str(),
            run.as_str(),
            decided.root.0,
            decided.root.1,
            encoded,
            sha256.to_hex(),
            decisions,
            decided.context_sha256.to_hex(),
            i64::from(decided.egress.allows_anything()),
            i64::from(decided.egress.exposed),
            to_sql(work.now)?,
        ],
    ))?;
    Ok(Fields::new()
        .text("egress_sha256", sha256.to_hex())
        .text("egress_context_sha256", decided.context_sha256.to_hex())
        .flag("egress_exposed_at_start", decided.egress.exposed)
        .text("egress_partition", decided.partition.clone())
        .list("egress_decisions", decided.summaries.clone()))
}

/// What a workload's ending says of its tunnels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Seen {
    /// The broker's report, which agrees with the authorisation.
    Reported(Box<WorkloadEgressReport>),
    /// Provably nothing ran: no tunnel can have been opened.
    NothingRan,
    /// Not known: why.
    Uncertain(&'static str),
}

fn exposure(work: &Work<'_>, invocation: &str, certain: bool) -> Result<(), AuthorityError> {
    work.db(work.tx.execute(
        "INSERT INTO workspace_exposure (root_device, root_inode, invocation_id, certain, \
         recorded_ms) SELECT root_device, root_inode, invocation_id, ?2, ?3 \
         FROM workload_egress WHERE invocation_id = ?1",
        rusqlite::params![invocation, i64::from(certain), to_sql(work.now)?],
    ))?;
    Ok(())
}

fn reached(
    work: &Work<'_>,
    (run, invocation): (&str, &str),
    target: &WorkloadEgressTarget,
    certain: bool,
) -> Result<(), AuthorityError> {
    work.db(work.tx.execute(
        "INSERT INTO tunnel_reach (run_id, host, port, invocation_id, certain, recorded_ms) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            run,
            target.host.as_str(),
            i64::from(target.port.get()),
            invocation,
            i64::from(certain),
            to_sql(work.now)?
        ],
    ))?;
    Ok(())
}

/// The recorded authorisation of `invocation`, while it is unsettled.
fn unsettled(
    work: &Work<'_>,
    invocation: &str,
) -> Result<Option<(String, WorkloadEgress)>, AuthorityError> {
    let row: Option<(String, String)> = work.db(work
        .tx
        .query_row(
            "SELECT run_id, authorisation FROM workload_egress \
             WHERE invocation_id = ?1 AND settled IS NULL",
            [invocation],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional())?;
    let Some((run, text)) = row else {
        return Ok(None);
    };
    let malformed = AuthorityError::Invariant("a stored egress authorisation is malformed");
    let value =
        json::parse(text.as_bytes(), json::ParseOptions::dwkp()).map_err(|_| malformed.clone())?;
    let egress =
        WorkloadEgress::decode(value, &mut dwk_proto::wire::Cx::new()).map_err(|_| malformed)?;
    Ok(Some((run, egress)))
}

/// Settle `invocation`'s egress from `seen`, in its outcome's transaction,
/// and return the outcome's audit fields for it. Nothing for a workload
/// started without an authorisation.
///
/// # Errors
///
/// [`AuthorityError`] when the store cannot record it.
pub(super) fn settle(
    work: &mut Work<'_>,
    invocation: &InvocationId,
    seen: &Seen,
) -> Result<Fields, AuthorityError> {
    let Some((run, egress)) = unsettled(work, invocation.as_str())? else {
        return Ok(Fields::new());
    };
    let id = invocation.as_str();
    let now = to_sql(work.now)?;
    let mut fields = Fields::new();
    let (settled, exposed_now, report_text): (&str, bool, Option<String>) = match seen {
        Seen::Reported(report) if report.consistent_with(&egress) => {
            let mut names = Vec::new();
            for (target, entry) in egress.targets.iter().zip(report.targets.iter()) {
                if entry.reached {
                    reached(work, (&run, id), target, true)?;
                }
                names.push(Field::Text(target_line(&egress, target, entry)));
            }
            if report.exposed {
                exposure(work, id, true)?;
            }
            fields = fields.list("egress_report", names).list(
                "egress_unattributed",
                report
                    .unattributed
                    .iter()
                    .map(|c| Field::Text(format!("{}={}", c.disposition.as_str(), c.count.get())))
                    .collect(),
            );
            let text = json::to_canonical_string(
                &report
                    .encode()
                    .map_err(|_| AuthorityError::Invariant("a report does not encode"))?,
            );
            ("REPORTED", report.exposed, Some(text))
        }
        Seen::NothingRan => ("NOTHING_RAN", false, None),
        Seen::Reported(_) | Seen::Uncertain(_) => {
            // Nothing says what its tunnels did: every destination it allowed
            // may have been reached, and the root may hold what came back.
            let anything = egress.allows_anything();
            if anything {
                for target in &egress.targets {
                    let allows = [
                        &target.novel_pristine,
                        &target.novel_exposed,
                        &target.seen_pristine,
                        &target.seen_exposed,
                    ]
                    .iter()
                    .any(|c| c.allowed.any());
                    if allows {
                        reached(work, (&run, id), target, false)?;
                    }
                }
                exposure(work, id, false)?;
            }
            let why = match seen {
                Seen::Uncertain(why) => *why,
                _ => "EGRESS_REPORT_INCONSISTENT",
            };
            fields = fields.text("egress_uncertain", why);
            ("UNCERTAIN", anything, None)
        }
    };
    let changed = work.db(work.tx.execute(
        "UPDATE workload_egress SET settled = ?2, exposed = ?3, report = ?4, settled_ms = ?5 \
         WHERE invocation_id = ?1 AND settled IS NULL",
        rusqlite::params![id, settled, i64::from(exposed_now), report_text, now],
    ))?;
    if changed != 1 {
        return Err(AuthorityError::Invariant(
            "an egress authorisation was settled twice",
        ));
    }
    Ok(fields
        .text("egress_settled", settled)
        .flag("egress_exposed", exposed_now))
}

/// One destination's line in the outcome: its tunnels, bytes, reach, and
/// each address judged with the piece it is in -- whose deciding rule per
/// cell the intent's `decisions` records.
fn target_line(
    egress: &WorkloadEgress,
    target: &WorkloadEgressTarget,
    entry: &dwk_proto::brokerp::egress::WorkloadEgressTargetReport,
) -> String {
    let dispositions: Vec<String> = entry
        .dispositions
        .iter()
        .map(|c| format!("{}={}", c.disposition.as_str(), c.count.get()))
        .collect();
    let addresses: Vec<String> = entry
        .addresses
        .iter()
        .map(|a| {
            let piece = dwk_proto::brokerp::egress::parse_address_text(a.address.as_str())
                .map_or_else(
                    || "?".to_owned(),
                    |address| egress.piece(&address).to_string(),
                );
            format!(
                "{}@piece{piece}:{}/{}",
                a.address.as_str(),
                a.allowed.get(),
                a.refused.get()
            )
        })
        .collect();
    format!(
        "{}:{} reached={} up={} down={} [{}] addresses=[{}]+{}",
        target.host.as_str(),
        target.port.get(),
        entry.reached,
        entry.bytes_upstream.get(),
        entry.bytes_downstream.get(),
        dispositions.join(","),
        addresses.join(","),
        entry.addresses_omitted.get()
    )
}

/// A restart's settlement of a workload it found `LAUNCHING`: uncertain.
///
/// # Errors
///
/// [`AuthorityError`] when the store cannot record it.
pub(super) fn settle_interrupted(
    work: &mut Work<'_>,
    invocation: &InvocationId,
) -> Result<Fields, AuthorityError> {
    settle(work, invocation, &Seen::Uncertain("INTERRUPTED"))
}

/// Whether the context `invocation`'s authorisation was decided in still
/// holds for `run`: the same policy revision and the same policy context.
/// `true` when it was started without one.
///
/// # Errors
///
/// [`AuthorityError`] when the store cannot answer.
pub(super) fn context_holds(
    work: &Work<'_>,
    (run, invocation): (&RunId, &InvocationId),
    active: &ActiveAuthority,
) -> Result<bool, AuthorityError> {
    let recorded: Option<String> = work.db(work
        .tx
        .query_row(
            "SELECT context_sha256 FROM workload_egress WHERE invocation_id = ?1",
            [invocation.as_str()],
            |row| row.get(0),
        )
        .optional())?;
    let Some(recorded) = recorded else {
        return Ok(true);
    };
    let context = query::policy_context(work, run.as_str(), active)?;
    Ok(context_digest(active, &context).to_hex() == recorded)
}

/// Whether `reports` -- every report an environment's workloads gave -- fit
/// within what its proxy counted (ADR-0061's A8): no disposition reported
/// more often, and no more bytes either way, than the proxy saw. The proxy
/// counts more than the workloads report (its measurement's own question,
/// and every CONNECT made while no workload held an authorisation), never
/// less.
pub(super) fn within_counters(reports: &[WorkloadEgressReport], counters: &EgressCounters) -> bool {
    let mut by_disposition: std::collections::BTreeMap<&'static str, (u64, u64)> =
        std::collections::BTreeMap::new();
    let (mut up, mut down) = (0u64, 0u64);
    for report in reports {
        let lists = report
            .targets
            .iter()
            .map(|t| &t.dispositions)
            .chain(std::iter::once(&report.unattributed));
        for list in lists {
            for count in list {
                let entry = by_disposition
                    .entry(count.disposition.as_str())
                    .or_insert((0, counters.count(count.disposition)));
                entry.0 = entry.0.saturating_add(count.count.get());
            }
        }
        for target in &report.targets {
            up = up.saturating_add(target.bytes_upstream.get());
            down = down.saturating_add(target.bytes_downstream.get());
        }
    }
    by_disposition
        .values()
        .all(|(reported, counted)| reported <= counted)
        && up <= counters.bytes_upstream.get()
        && down <= counters.bytes_downstream.get()
}

/// The reports `environment`'s workloads gave, and whether they fit within
/// its proxy's counters at its destruction (ADR-0061's A8).
///
/// # Errors
///
/// [`AuthorityError`] when the store cannot answer, or holds a report that
/// does not decode.
pub(super) fn reconciled(
    work: &Work<'_>,
    environment: &str,
    counters: &EgressCounters,
) -> Result<(u64, bool), AuthorityError> {
    let mut statement = work.db(work.tx.prepare(
        "SELECT e.report FROM workload_egress e \
         JOIN workload w ON w.invocation_id = e.invocation_id \
         WHERE w.environment_id = ?1 AND e.settled = 'REPORTED' ORDER BY e.invocation_id",
    ))?;
    let texts: Vec<String> = work.db(statement
        .query_map([environment], |row| row.get(0))
        .and_then(Iterator::collect))?;
    let malformed = AuthorityError::Invariant("a stored egress report is malformed");
    let mut reports = Vec::with_capacity(texts.len());
    for text in &texts {
        let value = json::parse(text.as_bytes(), json::ParseOptions::dwkp())
            .map_err(|_| malformed.clone())?;
        reports.push(
            WorkloadEgressReport::decode(value, &mut dwk_proto::wire::Cx::new())
                .map_err(|_| malformed.clone())?,
        );
    }
    let count = u64::try_from(reports.len()).unwrap_or(u64::MAX);
    Ok((count, within_counters(&reports, counters)))
}

#[cfg(test)]
#[path = "workload_egress_tests.rs"]
mod tests;
