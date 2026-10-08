//! `net.http`'s durable side (ADR-0050 §11): what each transaction of a
//! request reads and writes — the standing, budgets and novelty a hop is
//! decided with, the intents, the outcomes, the audit — and the start-up
//! reconciliation. Nothing here performs I/O but `kernel.db` and the audit
//! outbox.
//!
//! **Budgets are the hops.** A run's spend is read from its `net_hop` rows —
//! how many, the sum of what each was charged at its intent, how many
//! distinct origins — and a hop row is never deleted or changed after its
//! intent, so nothing refills a budget. Each hop is charged before it is
//! sent, from its own bounds, never from what it turned out to use.
//!
//! **Novelty is a fact.** An origin is `SEEN` by a run once a hop of that run
//! completed a TLS handshake with it — sent a byte of a request — and
//! `NOVEL` until then (ADR-0050 §11, ADR-0028).

use dwk_proto::dwkp::netops::{RedirectEnd, ToolFailureReasonV4, ToolRefusalReasonV4 as Refusal};
use dwk_proto::wire::guard::Address;
use dwk_proto::wire::id::InvocationId;
use rusqlite::OptionalExtension as _;

use crate::policy::{Novelty, TaintLevel};

use super::super::Work;
use super::super::admission;
use super::super::audit::{AuditEvent, Field, Fields};
use super::super::digest::{self, DomainHash};
use super::super::error::AuthorityError;
use super::super::lease::{self, to_sql};
use super::super::query::{self, TaintCause};
use super::super::secret_use::{self, Ending as SecretEnding, Prepared};
use super::super::secrets::{self, Hits};
use super::super::tool;
use super::canon::{self, Canonical};
use super::plan::{self, Facts, Gate, NetPlan};
use super::{Ctx, HopRequest, NetBudget, Unresolved};

/// What a hop's request costs, at most, besides its body and headers: the
/// request line's fixed parts, `Host`, `User-Agent`, `Accept-Encoding`,
/// `Connection` and `Content-Length`.
const REQUEST_OVERHEAD: u64 = 512;
/// What a credential header costs, at most: a 64-byte name, a 64-byte prefix
/// and the largest value the one-shot pipe carries.
const CREDENTIAL_CHARGE: u64 = 32 * 1024 + 160;
/// What a response head costs, at most (`dwk_proto::wire::http`).
const HEAD_CHARGE: u64 = 64 * 1024;
const _: () = assert!(dwk_proto::wire::http::MAX_RESPONSE_HEAD_BYTES == 64 * 1024);

/// What a hop is charged at its intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Charges {
    pub(super) out: u64,
    pub(super) inbound: u64,
}

fn charges(hop: &HopRequest, response_limit: u32) -> Charges {
    let len = |n: usize| u64::try_from(n).unwrap_or(u64::MAX);
    let headers = hop.headers.iter().fold(0u64, |sum, (name, value)| {
        sum.saturating_add(
            len(name.len())
                .saturating_add(len(value.len()))
                .saturating_add(4),
        )
    });
    let mut out = len(hop.body.len())
        .saturating_add(headers)
        .saturating_add(len(hop.url.request_target().len()))
        .saturating_add(len(hop.host().len()))
        .saturating_add(REQUEST_OVERHEAD);
    if hop.credential {
        out = out.saturating_add(CREDENTIAL_CHARGE);
    }
    Charges {
        out,
        inbound: u64::from(response_limit).saturating_add(HEAD_CHARGE),
    }
}

/// What a run has been charged, from its hops.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Spent {
    requests: u64,
    bytes_out: u64,
    bytes_in: u64,
    origins: u64,
}

fn spent(work: &Work<'_>, run: &str) -> Result<Spent, AuthorityError> {
    let (requests, out, inbound, origins): (i64, i64, i64, i64) = work.db(work.tx.query_row(
        "SELECT count(*), coalesce(sum(charge_out), 0), coalesce(sum(charge_in), 0), \
         count(DISTINCT host || ':' || port) FROM net_hop WHERE run_id = ?1",
        [run],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ))?;
    let n = |v: i64| u64::try_from(v).unwrap_or(u64::MAX);
    Ok(Spent {
        requests: n(requests),
        bytes_out: n(out),
        bytes_in: n(inbound),
        origins: n(origins),
    })
}

/// Whether the run has a hop to `host:port` — any, or one whose handshake
/// completed.
fn reached(
    work: &Work<'_>,
    run: &str,
    host: &str,
    port: u16,
    handshake: bool,
) -> Result<bool, AuthorityError> {
    let found: Option<i64> = work.db(work
        .tx
        .query_row(
            "SELECT 1 FROM net_hop WHERE run_id = ?1 AND host = ?2 AND port = ?3 \
             AND (?4 = 0 OR tls_established = 1) LIMIT 1",
            rusqlite::params![run, host, port, i64::from(handshake)],
            |row| row.get(0),
        )
        .optional())?;
    Ok(found.is_some())
}

/// Whether a hop with `charges` fits what the run has left.
const fn within(budget: NetBudget, spent: Spent, charges: Charges, new_origin: bool) -> bool {
    spent.requests < budget.requests
        && spent.bytes_out.saturating_add(charges.out) <= budget.bytes_out
        && spent.bytes_in.saturating_add(charges.inbound) <= budget.bytes_in
        && (!new_origin || spent.origins < budget.origins)
}

/// Whether an idempotency key is bound, in any of the three ledgers.
fn key_bound(work: &Work<'_>, ctx: &Ctx<'_>, key: &str) -> Result<bool, AuthorityError> {
    let asked = ctx.asked;
    let found: Option<i64> = work.db(work
        .tx
        .query_row(
            "SELECT 1 FROM net_idempotency WHERE subject = ?1 AND session_id = ?2 \
             AND idempotency_key = ?3 UNION ALL SELECT 1 FROM tool_idempotency WHERE \
             subject = ?1 AND session_id = ?2 AND idempotency_key = ?3 UNION ALL SELECT 1 \
             FROM process_idempotency WHERE subject = ?1 AND session_id = ?2 \
             AND idempotency_key = ?3 LIMIT 1",
            rusqlite::params![
                asked.caller.subject().storage_key(),
                asked.session.as_str(),
                key
            ],
            |row| row.get(0),
        )
        .optional())?;
    Ok(found.is_some())
}

/// The fence, the run and — for an invocation's first hop — the key.
fn standing(
    work: &Work<'_>,
    ctx: &Ctx<'_>,
    check_key: bool,
) -> Result<Option<Refusal>, AuthorityError> {
    let asked = ctx.asked;
    if !lease::fence(work, asked.caller, asked.session, asked.epoch)? {
        return Ok(Some(Refusal::StaleEpoch));
    }
    if !tool::run_is_held(
        work,
        asked.caller,
        asked.session,
        asked.run,
        asked.epoch,
        ctx.active,
    )? {
        return Ok(Some(Refusal::UnknownRun));
    }
    if check_key {
        let key = asked.request.key.as_ref().ok_or(AuthorityError::Invariant(
            "a version-4 invocation arrived without an idempotency key",
        ))?;
        if key_bound(work, ctx, key.as_str())? {
            return Ok(Some(Refusal::IdempotencyKeyReused));
        }
    }
    Ok(None)
}

/// Who asked, about what: the fields every `net.http` record starts with.
/// The URL is named by its digest, never its path or query (D8).
fn base_fields(ctx: &Ctx<'_>, hop: Option<&HopRequest>) -> Fields {
    let asked = ctx.asked;
    let fields = Fields::new()
        .text("operation", asked.operation.as_str())
        .text("tool", "net.http")
        .int("protocol_version", 4)
        .text("subject", asked.caller.subject().storage_key())
        .text("holder", asked.caller.holder().to_string())
        .text("session_id", asked.session.as_str())
        .text("run_id", asked.run.as_str())
        .int("epoch", asked.epoch.get())
        .maybe_text(
            "idempotency_key",
            asked.request.key.as_ref().map(|k| k.as_str().to_owned()),
        );
    match hop {
        None => fields.text("method", asked.request.call.method.as_str()),
        Some(hop) => fields
            .int("hop", u64::from(hop.number))
            .text("method", hop.method.as_str())
            .text("host", hop.host())
            .int("port", u64::from(hop.port()))
            .text("url_sha256", hop.url_sha256.to_hex())
            .int(
                "body_bytes",
                u64::try_from(hop.body.len()).unwrap_or(u64::MAX),
            )
            .flag("credential_asked", hop.credential),
    }
}

fn gate_fields(gate: &Gate, resolved: bool) -> Field {
    let record = gate.record();
    let policy = record.policy();
    let mut items = vec![
        (
            "required_capability",
            Field::Text(record.required().to_canonical_string()),
        ),
        (
            "capability_satisfied",
            Field::Flag(record.capability_satisfied()),
        ),
        (
            "policy_effect",
            Field::Text(policy.effect().as_str().to_owned()),
        ),
        ("policy_satisfied", Field::Flag(gate.policy_satisfied())),
        ("rule_id", Field::Text(policy.rule_id().as_str().to_owned())),
        (
            "reason",
            Field::Text(gate.reason(resolved).as_str().to_owned()),
        ),
        (
            "obligations",
            Field::List(
                policy
                    .obligations()
                    .as_slice()
                    .iter()
                    .map(|o| Field::Text(o.to_string()))
                    .collect(),
            ),
        ),
    ];
    if let Some(cap) = record.covering_grant() {
        items.push(("covering_cap_id", Field::Text(cap.as_str().to_owned())));
    }
    if let Some(why) = policy.unevaluable() {
        items.push(("unevaluable", Field::Text(why.to_string())));
    }
    if let Some(ip) = record.destination_ip() {
        items.push(("destination_ip", Field::Text(ip.to_string())));
    }
    Field::Object(items)
}

/// A plan's audit fields: every gate of the network action, the injection's,
/// and the effect.
pub(super) fn plan_fields(ctx: &Ctx<'_>, plan: &NetPlan) -> Fields {
    let net = &plan.net;
    let mut fields = Fields::new()
        .text("policy_revision", ctx.active.revision.to_hex())
        .list(
            "net_gates",
            net.gates
                .iter()
                .map(|g| gate_fields(g, net.resolved))
                .collect(),
        )
        .int("response_limit", u64::from(net.response_limit));
    if let Some(injection) = &plan.injection {
        fields = fields.text("handle", injection.handle.as_str()).list(
            "injection_gate",
            vec![gate_fields(&injection.gate, net.resolved)],
        );
    }
    fields.text("effect", if plan.permits() { "ALLOW" } else { "DENY" })
}

/// Record a refusal and return it.
fn refuse(
    work: &mut Work<'_>,
    ctx: &Ctx<'_>,
    hop: Option<&HopRequest>,
    reason: Refusal,
    detail: Option<&'static str>,
) -> Result<Refusal, AuthorityError> {
    work.audit(
        AuditEvent::ToolRefused,
        base_fields(ctx, hop)
            .text("refusal", reason.as_str())
            .maybe_text("detail", detail.map(str::to_owned)),
    )?;
    Ok(reason)
}

/// The secret side's view of a hop.
fn secret_asked<'a>(
    ctx: &'a Ctx<'a>,
    handle: &'a str,
    origin: &'a str,
    key: Option<&'a str>,
) -> secret_use::Asked<'a> {
    secret_use::Asked {
        caller: ctx.asked.caller,
        session: ctx.asked.session,
        run: ctx.asked.run,
        epoch: ctx.asked.epoch,
        handle,
        origin,
        key,
    }
}

/// What a hop was decided as, before anything is recorded.
struct Assessed {
    plan: NetPlan,
    prepared: Option<Prepared>,
    charges: Charges,
    exhausted: bool,
    novelty: Novelty,
}

/// Steps 3, 6 and 7 for one hop: the credential's metadata, both gates on
/// both actions — with every pinned address, or none before resolution —
/// and the budgets. `Err(detail)` is a credential the metadata does not
/// allow here.
fn assess(
    work: &mut Work<'_>,
    ctx: &Ctx<'_>,
    hop: &HopRequest,
    addresses: Option<&[Address]>,
) -> Result<Result<Assessed, &'static str>, AuthorityError> {
    let asked = ctx.asked;
    let run = asked.run.as_str();
    let origin = format!("{}:{}", hop.host(), hop.port());
    let handle = asked
        .request
        .call
        .credential_handle
        .as_ref()
        .map(|h| h.as_str().to_owned());
    let prepared = match (&handle, hop.credential) {
        (Some(handle), true) => {
            let secret = secret_asked(ctx, handle, &origin, None);
            match secret_use::prepare(work, &secret, ctx.secrets, ctx.after_metadata)? {
                Ok(prepared) => Some(prepared),
                Err(detail) => return Ok(Err(detail)),
            }
        }
        _ => None,
    };
    let admission = admission::load(work, run)?;
    let context = query::policy_context(work, run, ctx.active)?;
    let spent = spent(work, run)?;
    let novelty = if reached(work, run, hop.host(), hop.port(), true)? {
        Novelty::Seen
    } else {
        Novelty::Novel
    };
    let new_origin = !reached(work, run, hop.host(), hop.port(), false)?;
    let net = plan::decide_net(
        &Facts {
            host: hop.host(),
            port: hop.port(),
            method: hop.method,
            url_sha256: hop.url_sha256,
            body_bytes: u64::try_from(hop.body.len()).unwrap_or(u64::MAX),
            next_request: u32::try_from(spent.requests.saturating_add(1)).unwrap_or(u32::MAX),
            novelty,
            addresses,
            response_limit: ctx.limit(),
        },
        &admission,
        &context,
        ctx.active,
    )?;
    let injection = prepared
        .as_ref()
        .map(|p| {
            plan::decide_injection(
                &p.handle,
                hop.host(),
                hop.port(),
                &admission,
                &context,
                ctx.active,
            )
        })
        .transpose()?;
    let charges = charges(hop, net.response_limit);
    let exhausted = !within(ctx.budget, spent, charges, new_origin);
    Ok(Ok(Assessed {
        plan: NetPlan { net, injection },
        prepared,
        charges,
        exhausted,
        novelty,
    }))
}

/// Whether a plan decided without an address may go on to resolution: every
/// action covered by a grant, the injection allowed, and the network action
/// allowed or refused **only** for want of the address. A decision that
/// needed no address is final — first match wins, and a rule that needed one
/// would have stopped the scan as unevaluable — so nothing is resolved for a
/// request already denied.
fn resolvable(plan: &NetPlan) -> bool {
    plan.covered()
        && plan.injection.as_ref().is_none_or(|i| i.gate.permits())
        && plan
            .net
            .gates
            .iter()
            .all(|g| g.permits() || g.record().policy().unevaluable().is_some())
}

/// What the first transaction decided.
pub(super) enum Located {
    Refused(Refusal),
    Denied(NetPlan),
    Previewed(NetPlan),
    /// Go on to resolution, under a newly minted invocation id.
    Resolve {
        canonical: Box<Canonical>,
        invocation: InvocationId,
    },
}

/// Steps 1–3, 6 (without an address) and 7, and 8: the first transaction.
pub(super) fn locate(
    work: &mut Work<'_>,
    ctx: &Ctx<'_>,
    preview: bool,
) -> Result<Located, AuthorityError> {
    if let Some(reason) = standing(work, ctx, !preview)? {
        return refuse(work, ctx, None, reason, None).map(Located::Refused);
    }
    let canonical = match canon::canonicalize(
        &ctx.asked.request.call,
        &ctx.secrets.reserved_headers(),
        &|bytes| ctx.secrets.holds_value(bytes),
    ) {
        Ok(canonical) => canonical,
        Err(reason) => return refuse(work, ctx, None, reason, None).map(Located::Refused),
    };
    let hop = HopRequest::first(&canonical);
    let assessed = match assess(work, ctx, &hop, None)? {
        Ok(assessed) => assessed,
        Err(detail) => {
            return refuse(
                work,
                ctx,
                Some(&hop),
                Refusal::CredentialUnavailable,
                Some(detail),
            )
            .map(Located::Refused);
        }
    };
    let plan = assessed.plan;
    if preview {
        if assessed.exhausted && resolvable(&plan) {
            return refuse(work, ctx, Some(&hop), Refusal::BudgetExhausted, None)
                .map(Located::Refused);
        }
        let mut fields = base_fields(ctx, Some(&hop));
        fields.extend(plan_fields(ctx, &plan));
        work.audit(AuditEvent::ToolPreviewed, fields)?;
        return Ok(Located::Previewed(plan));
    }
    if !resolvable(&plan) {
        deny(work, ctx, &hop, &plan)?;
        return Ok(Located::Denied(plan));
    }
    if assessed.exhausted {
        return refuse(work, ctx, Some(&hop), Refusal::BudgetExhausted, None).map(Located::Refused);
    }
    Ok(Located::Resolve {
        canonical: Box::new(canonical),
        invocation: work.invocation_id()?,
    })
}

/// Record a first hop's denial: the injection's gates as the secret side
/// records them, then the plan.
fn deny(
    work: &mut Work<'_>,
    ctx: &Ctx<'_>,
    hop: &HopRequest,
    plan: &NetPlan,
) -> Result<(), AuthorityError> {
    if let Some(injection) = &plan.injection {
        let origin = format!("{}:{}", injection.host, injection.port);
        let secret = secret_asked(ctx, &injection.handle, &origin, None);
        secret_use::refused_by_gates(work, &secret, ctx.active, injection.gate.record())?;
    }
    let mut fields = base_fields(ctx, Some(hop));
    fields.extend(plan_fields(ctx, plan));
    work.audit(AuditEvent::ToolDenied, fields)
}

/// A later hop whose host is not pinned: whether it may be resolved. `Some`
/// is why the chain ends instead; nothing is recorded but the audit.
pub(super) fn precheck(
    work: &mut Work<'_>,
    ctx: &Ctx<'_>,
    hop: &HopRequest,
) -> Result<Option<RedirectEnd>, AuthorityError> {
    if standing(work, ctx, false)?.is_some() {
        return Ok(Some(RedirectEnd::HopDenied));
    }
    let Ok(assessed) = assess(work, ctx, hop, None)? else {
        return Ok(Some(RedirectEnd::HopDenied));
    };
    if !resolvable(&assessed.plan) {
        let mut fields = base_fields(ctx, Some(hop));
        fields.extend(plan_fields(ctx, &assessed.plan));
        work.audit(AuditEvent::ToolDenied, fields)?;
        return Ok(Some(RedirectEnd::HopDenied));
    }
    if assessed.exhausted {
        return Ok(Some(RedirectEnd::BudgetExhausted));
    }
    Ok(None)
}

/// Record what a resolution came to: the verdict and the addresses pinned.
/// A first hop's failed resolution is also the request's refusal.
pub(super) fn record_resolution(
    work: &mut Work<'_>,
    ctx: &Ctx<'_>,
    invocation: &InvocationId,
    hop: &HopRequest,
    resolution: &Result<Vec<Address>, Unresolved>,
) -> Result<(), AuthorityError> {
    let (verdict, addresses) = match resolution {
        Ok(addresses) => ("RESOLVED", addresses.as_slice()),
        Err(unresolved) => (unresolved.as_str(), &[][..]),
    };
    work.audit(
        AuditEvent::NetResolved,
        base_fields(ctx, Some(hop))
            .text("invocation_id", invocation.as_str())
            .text("verdict", verdict)
            .list(
                "addresses",
                addresses
                    .iter()
                    .map(|a| Field::Text(address_text(*a)))
                    .collect(),
            ),
    )?;
    if let Err(unresolved) = resolution
        && hop.number == 1
    {
        refuse(work, ctx, Some(hop), unresolved.refusal(), None)?;
    }
    Ok(())
}

/// An address as the policy core prints it.
fn address_text(address: Address) -> String {
    match address {
        Address::V4(octets) => crate::policy::IpAddress::V4(octets).to_string(),
        Address::V6(octets) => crate::policy::IpAddress::V6(octets).to_string(),
    }
}

/// The pinned addresses as a hop row holds them: the private spelling,
/// comma-joined.
fn address_column(addresses: &[Address]) -> String {
    addresses
        .iter()
        .take(dwk_proto::brokerp::http::MAX_PINNED_ADDRESSES)
        .map(|a| {
            dwk_proto::brokerp::http::NetAddress::from_address(*a)
                .as_str()
                .to_owned()
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// A hop the intent transaction recorded.
pub(super) struct Recorded {
    pub(super) plan: NetPlan,
    pub(super) injection: Option<secret_use::Authorised>,
}

/// What the intent transaction decided.
pub(super) enum Intent {
    Refused(Refusal),
    Denied(Box<NetPlan>),
    Exhausted,
    Recorded(Box<Recorded>),
}

/// The digest an idempotency key is bound to: the run and the canonical
/// call.
fn request_digest(ctx: &Ctx<'_>, canonical: &Canonical) -> String {
    let mut hash = DomainHash::new(digest::NET_REQUEST)
        .text(ctx.asked.run.as_str())
        .text(canonical.method.as_str())
        .text(&canonical.url.canonical())
        .int(u64::try_from(canonical.headers.len()).unwrap_or(u64::MAX));
    for (name, value) in &canonical.headers {
        hash = hash.text(name).text(value);
    }
    hash.bytes(&canonical.body)
        .text(canonical.credential.as_deref().unwrap_or(""))
        .int(u64::from(canonical.follow_redirects))
        .int(u64::from(canonical.max_response_bytes.unwrap_or(0)))
        .finish()
        .to_hex()
}

/// Steps 6–9 for one hop, with its pinned addresses: decide again — the run
/// may have changed since the first transaction — then, if every action is
/// allowed and the budgets hold, record the request (first hop), the
/// credential's intent and the hop's, in that order.
pub(super) fn record_intent(
    work: &mut Work<'_>,
    ctx: &Ctx<'_>,
    invocation: &InvocationId,
    canonical: &Canonical,
    hop: &HopRequest,
    addresses: &[Address],
) -> Result<Intent, AuthorityError> {
    let first = hop.number == 1;
    if let Some(reason) = standing(work, ctx, first)? {
        if first {
            refuse(work, ctx, Some(hop), reason, None)?;
        }
        return Ok(Intent::Refused(reason));
    }
    let assessed = match assess(work, ctx, hop, Some(addresses))? {
        Ok(assessed) => assessed,
        Err(detail) => {
            if first {
                refuse(
                    work,
                    ctx,
                    Some(hop),
                    Refusal::CredentialUnavailable,
                    Some(detail),
                )?;
            }
            return Ok(Intent::Refused(Refusal::CredentialUnavailable));
        }
    };
    let Assessed {
        plan,
        prepared,
        charges,
        exhausted,
        novelty,
    } = assessed;
    if !plan.permits() {
        deny(work, ctx, hop, &plan)?;
        return Ok(Intent::Denied(Box::new(plan)));
    }
    if exhausted {
        if first {
            refuse(work, ctx, Some(hop), Refusal::BudgetExhausted, None)?;
        }
        return Ok(Intent::Exhausted);
    }
    if first {
        record_request(work, ctx, invocation, canonical, hop)?;
    }
    // The credential's intent first: the hop row names it.
    let key = format!("{}:{}", invocation.as_str(), hop.number);
    let injection = match (prepared, &plan.injection) {
        (Some(prepared), Some(decided)) => {
            let origin = format!("{}:{}", hop.host(), hop.port());
            let handle = prepared.handle.as_str().to_owned();
            let secret = secret_asked(ctx, &handle, &origin, Some(&key));
            Some(secret_use::record_intent(
                work,
                &secret,
                prepared,
                ctx.active,
                decided.gate.record(),
            )?)
        }
        (None, None) => None,
        _ => {
            return Err(AuthorityError::Invariant(
                "a credential was prepared without its decision, or decided without preparing",
            ));
        }
    };
    record_hop(
        work,
        ctx,
        invocation,
        hop,
        addresses,
        (charges, novelty),
        injection.as_ref(),
        &plan,
    )?;
    Ok(Intent::Recorded(Box::new(Recorded { plan, injection })))
}

/// A request's own durable intent, with its first hop's: the request row
/// and the idempotency key bound to its digest.
fn record_request(
    work: &mut Work<'_>,
    ctx: &Ctx<'_>,
    invocation: &InvocationId,
    canonical: &Canonical,
    hop: &HopRequest,
) -> Result<(), AuthorityError> {
    let asked = ctx.asked;
    let now = to_sql(work.now)?;
    let incarnation = to_sql(work.incarnation())?;
    {
        work.db(work.tx.execute(
            "INSERT INTO net_request (invocation_id, run_id, method, host, port, url_sha256, \
             credential_handle, follow_redirects, incarnation, state, failure, final_status, \
             hops, redirect_ended, intent_ms, ended_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, \
             ?9, 'INTENT', NULL, NULL, NULL, NULL, ?10, NULL)",
            rusqlite::params![
                invocation.as_str(),
                asked.run.as_str(),
                hop.method.as_str(),
                hop.host(),
                hop.port(),
                hop.url_sha256.to_hex(),
                canonical.credential.as_deref(),
                i64::from(canonical.follow_redirects),
                incarnation,
                now
            ],
        ))?;
        let key = asked.request.key.as_ref().ok_or(AuthorityError::Invariant(
            "a version-4 invocation arrived without an idempotency key",
        ))?;
        work.db(work.tx.execute(
            "INSERT INTO net_idempotency (subject, session_id, idempotency_key, request_digest, \
             invocation_id, recorded_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                asked.caller.subject().storage_key(),
                asked.session.as_str(),
                key.as_str(),
                request_digest(ctx, canonical),
                invocation.as_str(),
                now
            ],
        ))?;
    }
    Ok(())
}

/// A hop's durable intent and its audit record: the pinned addresses, the
/// charges, the novelty it was decided with, its credential's use if any.
#[expect(
    clippy::too_many_arguments,
    reason = "the hop's whole decision, recorded as it was made"
)]
fn record_hop(
    work: &mut Work<'_>,
    ctx: &Ctx<'_>,
    invocation: &InvocationId,
    hop: &HopRequest,
    addresses: &[Address],
    (charges, novelty): (Charges, Novelty),
    injection: Option<&secret_use::Authorised>,
    plan: &NetPlan,
) -> Result<(), AuthorityError> {
    let asked = ctx.asked;
    let now = to_sql(work.now)?;
    let incarnation = to_sql(work.incarnation())?;
    let charge = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
    work.db(work.tx.execute(
        "INSERT INTO net_hop (invocation_id, hop, run_id, method, host, port, url_sha256, \
         addresses, injection_id, charge_out, charge_in, incarnation, state, disposition, \
         status, tls_established, bytes_sent, bytes_received, intent_ms, ended_ms) VALUES \
         (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'INTENT', NULL, NULL, 0, NULL, \
         NULL, ?13, NULL)",
        rusqlite::params![
            invocation.as_str(),
            hop.number,
            asked.run.as_str(),
            hop.method.as_str(),
            hop.host(),
            hop.port(),
            hop.url_sha256.to_hex(),
            address_column(addresses),
            injection.map(|a| a.invocation.as_str().to_owned()),
            charge(charges.out),
            charge(charges.inbound),
            incarnation,
            now
        ],
    ))?;
    let mut fields = base_fields(ctx, Some(hop))
        .text("invocation_id", invocation.as_str())
        .list(
            "addresses",
            addresses
                .iter()
                .map(|a| Field::Text(address_text(*a)))
                .collect(),
        )
        .text(
            "novelty",
            match novelty {
                Novelty::Novel => "NOVEL",
                Novelty::Seen => "SEEN",
            },
        )
        .int("charge_out", charges.out)
        .int("charge_in", charges.inbound)
        .maybe_text(
            "injection_id",
            injection.map(|a| a.invocation.as_str().to_owned()),
        );
    fields.extend(plan_fields(ctx, plan));
    work.audit(AuditEvent::NetIntentRecorded, fields)
}

/// How a hop ended, as its row records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct HopEnding {
    pub(super) state: &'static str,
    pub(super) disposition: &'static str,
    pub(super) status: Option<u16>,
    pub(super) tls: bool,
    pub(super) bytes_sent: Option<u64>,
    pub(super) bytes_received: Option<u64>,
    /// Whether the request was written: a credential with it was injected.
    pub(super) injected: bool,
    pub(super) headers_dropped: u64,
    pub(super) cookies_dropped: u64,
    pub(super) truncated: bool,
}

/// Step 11: a hop's outcome, durably; its credential's; the taint a
/// response raises — before anything of it is answered or followed.
pub(super) fn end_hop(
    work: &mut Work<'_>,
    ctx: &Ctx<'_>,
    invocation: &InvocationId,
    hop: &HopRequest,
    ending: &HopEnding,
    secret: Option<(&secret_use::Authorised, SecretEnding, bool)>,
) -> Result<(), AuthorityError> {
    let n = |v: Option<u64>| v.map(|v| i64::try_from(v).unwrap_or(i64::MAX));
    let ended = work.db(work.tx.execute(
        "UPDATE net_hop SET state = ?3, disposition = ?4, status = ?5, tls_established = ?6, \
         bytes_sent = ?7, bytes_received = ?8, ended_ms = ?9 \
         WHERE invocation_id = ?1 AND hop = ?2 AND state = 'INTENT'",
        rusqlite::params![
            invocation.as_str(),
            hop.number,
            ending.state,
            ending.disposition,
            ending.status,
            i64::from(ending.tls),
            n(ending.bytes_sent),
            n(ending.bytes_received),
            to_sql(work.now)?
        ],
    ))?;
    if ended != 1 {
        return Err(AuthorityError::Invariant("a hop was not open"));
    }
    if let Some((authorised, secret_ending, resolved)) = secret {
        secret_use::record_outcome(work, authorised, ctx.asked.run, secret_ending, resolved)?;
    }
    // A response head arrived: what the network says is untrusted from here
    // on, before any of it is followed or answered (ADR-0050 §14).
    if ending.status.is_some() {
        query::raise_taint(
            work,
            ctx.asked.run,
            TaintLevel::ExternalUntrusted,
            TaintCause::ToolResult,
        )?;
    }
    work.audit(
        AuditEvent::NetHopEnded,
        Fields::new()
            .text("invocation_id", invocation.as_str())
            .text("run_id", ctx.asked.run.as_str())
            .int("hop", u64::from(hop.number))
            .text("method", hop.method.as_str())
            .text("host", hop.host())
            .int("port", u64::from(hop.port()))
            .text("url_sha256", hop.url_sha256.to_hex())
            .text("state", ending.state)
            .text("disposition", ending.disposition)
            .maybe_int("status", ending.status.map(u64::from))
            .flag("tls_established", ending.tls)
            .maybe_int("bytes_sent", ending.bytes_sent)
            .maybe_int("bytes_received", ending.bytes_received)
            .flag("injected", secret.is_some() && ending.injected)
            .maybe_text(
                "handle",
                secret.map(|(a, _, _)| a.prepared.handle.as_str().to_owned()),
            )
            .int("headers_dropped", ending.headers_dropped)
            .int("cookies_dropped", ending.cookies_dropped)
            .flag("truncated", ending.truncated),
    )
}

/// A redirect that was not followed, and why.
pub(super) fn end_redirect(
    work: &mut Work<'_>,
    ctx: &Ctx<'_>,
    invocation: &InvocationId,
    hops: u8,
    why: RedirectEnd,
) -> Result<(), AuthorityError> {
    work.audit(
        AuditEvent::NetRedirectEnded,
        Fields::new()
            .text("invocation_id", invocation.as_str())
            .text("run_id", ctx.asked.run.as_str())
            .int("hops", u64::from(hops))
            .text("reason", why.as_str()),
    )
}

/// How a request ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RequestEnding {
    Completed {
        status: u16,
        redirect_ended: Option<RedirectEnd>,
        body_bytes: u64,
        truncated: bool,
    },
    Failed(ToolFailureReasonV4),
    Unknown,
}

/// The request's outcome, durably, with what redaction removed from its
/// answer.
pub(super) fn end_request(
    work: &mut Work<'_>,
    ctx: &Ctx<'_>,
    invocation: &InvocationId,
    ending: &RequestEnding,
    hops: u8,
    hits: &Hits,
) -> Result<(), AuthorityError> {
    let (state, failure, status, redirect) = match ending {
        RequestEnding::Completed {
            status,
            redirect_ended,
            ..
        } => (
            "COMPLETED",
            None,
            Some(*status),
            redirect_ended.map(RedirectEnd::as_str),
        ),
        RequestEnding::Failed(reason) => ("FAILED", Some(reason.as_str()), None, None),
        RequestEnding::Unknown => ("UNKNOWN", None, None, None),
    };
    let ended = work.db(work.tx.execute(
        "UPDATE net_request SET state = ?2, failure = ?3, final_status = ?4, hops = ?5, \
         redirect_ended = ?6, ended_ms = ?7 WHERE invocation_id = ?1 AND state = 'INTENT'",
        rusqlite::params![
            invocation.as_str(),
            state,
            failure,
            status,
            hops,
            redirect,
            to_sql(work.now)?
        ],
    ))?;
    if ended != 1 {
        return Err(AuthorityError::Invariant("a request was not open"));
    }
    secrets::audit_hits(
        work,
        ctx.asked.run.as_str(),
        invocation.as_str(),
        "net.http",
        hits,
    )?;
    let mut fields = Fields::new()
        .text("invocation_id", invocation.as_str())
        .text("run_id", ctx.asked.run.as_str())
        .text("state", state)
        .int("hops", u64::from(hops))
        .maybe_text("failure", failure.map(str::to_owned))
        .maybe_int("status", status.map(u64::from))
        .maybe_text("redirect_ended", redirect.map(str::to_owned));
    if let RequestEnding::Completed {
        body_bytes,
        truncated,
        ..
    } = ending
    {
        fields = fields
            .int("body_bytes", *body_bytes)
            .flag("truncated", *truncated);
    }
    work.audit(AuditEvent::NetOutcome, fields)
}

/// End every hop and request a previous incarnation left open: `UNKNOWN`,
/// never performed again. Runs in the start-up transaction; returns how many
/// requests it ended. A hop's credential is the secret side's to end.
pub(crate) fn reconcile_open(work: &mut Work<'_>) -> Result<u64, AuthorityError> {
    let now = to_sql(work.now)?;
    let hops: Vec<(String, i64, String)> = {
        let mut statement = work.db(work.tx.prepare(
            "SELECT invocation_id, hop, run_id FROM net_hop WHERE state = 'INTENT' \
             ORDER BY intent_ms, invocation_id, hop",
        ))?;
        let rows =
            work.db(statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))))?;
        work.db(rows.collect::<rusqlite::Result<_>>())?
    };
    for (invocation, hop, run) in &hops {
        let ended = work.db(work.tx.execute(
            "UPDATE net_hop SET state = 'UNKNOWN', disposition = 'OUTCOME_UNKNOWN', \
             ended_ms = ?3 WHERE invocation_id = ?1 AND hop = ?2 AND state = 'INTENT'",
            rusqlite::params![invocation, hop, now],
        ))?;
        if ended != 1 {
            return Err(AuthorityError::Invariant("an open hop could not be ended"));
        }
        work.audit(
            AuditEvent::NetHopEnded,
            Fields::new()
                .text("invocation_id", invocation.clone())
                .text("run_id", run.clone())
                .int("hop", u64::try_from(*hop).unwrap_or(0))
                .text("state", "UNKNOWN")
                .text("disposition", "OUTCOME_UNKNOWN")
                .text("cause", "restart"),
        )?;
    }
    let requests: Vec<(String, String, i64)> = {
        let mut statement = work.db(work.tx.prepare(
            "SELECT invocation_id, run_id, incarnation FROM net_request WHERE state = 'INTENT' \
             ORDER BY intent_ms, invocation_id",
        ))?;
        let rows =
            work.db(statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))))?;
        work.db(rows.collect::<rusqlite::Result<_>>())?
    };
    for (invocation, run, incarnation) in &requests {
        let hops: i64 = work.db(work.tx.query_row(
            "SELECT count(*) FROM net_hop WHERE invocation_id = ?1",
            [invocation],
            |row| row.get(0),
        ))?;
        let ended = work.db(work.tx.execute(
            "UPDATE net_request SET state = 'UNKNOWN', hops = ?2, ended_ms = ?3 \
             WHERE invocation_id = ?1 AND state = 'INTENT'",
            rusqlite::params![invocation, (hops > 0).then_some(hops), now],
        ))?;
        if ended != 1 {
            return Err(AuthorityError::Invariant(
                "an open request could not be ended",
            ));
        }
        work.audit(
            AuditEvent::NetOutcome,
            Fields::new()
                .text("invocation_id", invocation.clone())
                .text("run_id", run.clone())
                .text("state", "UNKNOWN")
                .int("hops", u64::try_from(hops).unwrap_or(0))
                .int(
                    "intent_incarnation",
                    u64::try_from(*incarnation).unwrap_or(0),
                )
                .text("cause", "restart"),
        )?;
    }
    Ok(u64::try_from(requests.len()).unwrap_or(u64::MAX))
}
