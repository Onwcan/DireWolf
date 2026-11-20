//! Steps 3 and 6 of a hop: both gates, on the complete canonical action
//! (ADR-0050 §5).
//!
//! The network action requires
//! `network.https:<host>:<port>?methods=<method>&max_requests=<n>`, where `n`
//! is one more than the hops this run has already been charged: a grant whose
//! `max_requests` is spent no longer covers the next request. Policy decides
//! on the action with its environment (`HOST`: the broker is the client), the
//! body's byte count, the destination's novelty and — once the host is
//! resolved — **each pinned address**: every one must allow, because a rule
//! that denies one address of an answer must not be escaped by its sibling.
//! Before resolution there is no address, so a rule that needs one cannot be
//! evaluated and denies (`UNRESOLVED_POLICY_INPUT`), which is what a preview
//! reports and why nothing is ever decided without the address.
//!
//! The injection action, when the call names a credential, requires
//! `secret.use:<handle>` through both gates, as M4e's mode A does.
//!
//! Every obligation must be one a hop keeps: `max_output_bytes` (the response
//! bound, never widened) and `audit_level`. Anything else denies
//! (`OBLIGATION_UNENFORCEABLE`). `REQUIRE_APPROVAL` denies: approvals arrive
//! at M6.

use dwk_proto::dwkp::netops::{HttpMethod, NetDecisionReason};
use dwk_proto::wire::guard::Address;

use crate::capability::{
    Action, Capability, ConstraintSet, Endpoint, Method, MethodSet, Namespace, Scope,
    SyntacticScope, Verb,
};
use crate::policy::{
    CanonicalAction, Effect, Environment, IpAddress, Novelty, Obligation, PolicyContext,
};

use super::super::admission::Admission;
use super::super::digest::Sha256Hash;
use super::super::error::AuthorityError;
use super::super::policy_state::ActiveAuthority;
use super::super::query::{self, DecisionRecord};

/// One evaluation of both gates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Gate {
    record: DecisionRecord,
    obligations_enforced: bool,
}

impl Gate {
    /// The record both gates produced.
    pub(crate) const fn record(&self) -> &DecisionRecord {
        &self.record
    }

    /// Whether policy is satisfied: it allows, and every obligation is kept.
    pub(crate) fn policy_satisfied(&self) -> bool {
        self.record.policy_satisfied() && self.obligations_enforced
    }

    /// Both gates.
    pub(crate) fn permits(&self) -> bool {
        self.record.capability_satisfied() && self.policy_satisfied()
    }

    /// Why it was decided as it was. Before resolution, a missing grant is
    /// the reason — nothing is resolved for a host no grant covers — even
    /// where a rule could not yet be evaluated.
    pub(crate) fn reason(&self, resolved: bool) -> NetDecisionReason {
        let policy = self.record.policy();
        if self.permits() {
            return NetDecisionReason::AllowedByRule;
        }
        if !resolved && !self.record.capability_satisfied() {
            return NetDecisionReason::NoCapability;
        }
        if policy.unevaluable().is_some() {
            return NetDecisionReason::UnresolvedPolicyInput;
        }
        match policy.effect() {
            Effect::Deny if policy.rule_id().is_default() => NetDecisionReason::DefaultDeny,
            Effect::Deny => NetDecisionReason::DeniedByRule,
            _ if !self.record.capability_satisfied() => NetDecisionReason::NoCapability,
            Effect::RequireApproval => NetDecisionReason::ApprovalRequired,
            Effect::Allow => NetDecisionReason::ObligationUnenforceable,
        }
    }
}

/// A hop's network action, decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetAction {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) method: HttpMethod,
    pub(crate) url_sha256: Sha256Hash,
    pub(crate) body_bytes: u64,
    /// One evaluation per pinned address; one, without an address, before
    /// resolution.
    pub(crate) gates: Vec<Gate>,
    /// Whether the host was resolved and the gates saw its addresses.
    pub(crate) resolved: bool,
    /// The response bound, after the obligations narrowed it.
    pub(crate) response_limit: u32,
}

impl NetAction {
    /// Every gate permits.
    pub(crate) fn permits(&self) -> bool {
        !self.gates.is_empty() && self.gates.iter().all(Gate::permits)
    }

    /// The gate the plan reports: the first that refused, or the first.
    pub(crate) fn reported(&self) -> Option<&Gate> {
        self.gates
            .iter()
            .find(|g| !g.permits())
            .or_else(|| self.gates.first())
    }
}

/// A hop's injection action, decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InjectionAction {
    pub(crate) handle: String,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) gate: Gate,
}

/// A hop's plan: the network action and, when the call names a credential and
/// the hop is at the request's own origin, the injection action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetPlan {
    pub(crate) net: NetAction,
    pub(crate) injection: Option<InjectionAction>,
}

impl NetPlan {
    /// Both actions permitted: the only condition under which anything is
    /// performed.
    pub(crate) fn permits(&self) -> bool {
        self.net.permits() && self.injection.as_ref().is_none_or(|i| i.gate.permits())
    }

    /// Whether a grant covers every action — the condition for resolving.
    pub(crate) fn covered(&self) -> bool {
        self.net
            .gates
            .iter()
            .all(|g| g.record.capability_satisfied())
            && self
                .injection
                .as_ref()
                .is_none_or(|i| i.gate.record.capability_satisfied())
    }
}

/// The capability layer's spelling of a method.
const fn method(method: HttpMethod) -> Method {
    match method {
        HttpMethod::Get => Method::Get,
        HttpMethod::Head => Method::Head,
        HttpMethod::Post => Method::Post,
        HttpMethod::Put => Method::Put,
        HttpMethod::Patch => Method::Patch,
        HttpMethod::Delete => Method::Delete,
        HttpMethod::Options => Method::Options,
    }
}

/// The capability a hop requires.
fn required(
    host: &str,
    port: u16,
    hop_method: HttpMethod,
    max_requests: u32,
) -> Result<Capability, AuthorityError> {
    let verb = Verb::new(Namespace::Network, Action::Https)
        .ok_or(AuthorityError::Invariant("network.https is not a verb"))?;
    let endpoint = Endpoint::parse(&format!("{host}:{port}"))
        .map_err(|_| AuthorityError::Invariant("a canonical origin is not an endpoint"))?;
    let methods = MethodSet::new(&[method(hop_method)])
        .ok_or(AuthorityError::Invariant("one method is a method set"))?;
    let constraints = ConstraintSet {
        methods: Some(methods),
        max_requests: Some(max_requests),
        ..ConstraintSet::unconstrained()
    };
    Capability::new(
        verb,
        Scope::Syntactic(SyntacticScope::Endpoint(endpoint)),
        constraints,
    )
    .map_err(|_| AuthorityError::Invariant("a network capability does not assemble"))
}

/// Whether every obligation is one a hop keeps, narrowing `limit` by
/// `max_output_bytes`.
fn obligations(record: &DecisionRecord, limit: &mut u32) -> bool {
    let mut enforced = true;
    for obligation in record.policy().obligations().as_slice() {
        enforced &= match obligation {
            Obligation::MaxOutputBytes(bound) if *bound >= 1 => {
                *limit = (*limit).min(u32::try_from(*bound).unwrap_or(u32::MAX));
                true
            }
            Obligation::AuditLevel(_) => true,
            _ => false,
        };
    }
    enforced
}

/// What a hop's network action is decided from.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Facts<'a> {
    pub(crate) host: &'a str,
    pub(crate) port: u16,
    pub(crate) method: HttpMethod,
    pub(crate) url_sha256: Sha256Hash,
    pub(crate) body_bytes: u64,
    /// One more than the hops this run has been charged.
    pub(crate) next_request: u32,
    /// Whether the run has completed a handshake with this origin.
    pub(crate) novelty: Novelty,
    /// The pinned addresses; none before resolution.
    pub(crate) addresses: Option<&'a [Address]>,
    /// The bound before any obligation.
    pub(crate) response_limit: u32,
}

/// Decide a hop's network action. Pure: reads what the caller loaded.
///
/// # Errors
///
/// An invariant: a canonical origin that does not assemble a capability.
pub(crate) fn decide_net(
    facts: &Facts<'_>,
    admission: &Admission,
    context: &PolicyContext,
    active: &ActiveAuthority,
) -> Result<NetAction, AuthorityError> {
    let capability = required(facts.host, facts.port, facts.method, facts.next_request)?;
    let base = CanonicalAction::new(capability, Environment::Host)
        .with_byte_count(facts.body_bytes)
        .with_destination_novelty(facts.novelty);
    let mut limit = facts.response_limit;
    let mut gates = Vec::new();
    match facts.addresses {
        None => {
            let record = query::decide(&base, admission, context, active);
            let obligations_enforced = obligations(&record, &mut limit);
            gates.push(Gate {
                record,
                obligations_enforced,
            });
        }
        Some(addresses) => {
            for address in addresses {
                let ip = match address {
                    Address::V4(octets) => IpAddress::V4(*octets),
                    Address::V6(octets) => IpAddress::V6(*octets),
                };
                let action = base.clone().with_destination_ip(ip);
                let record = query::decide(&action, admission, context, active);
                let obligations_enforced = obligations(&record, &mut limit);
                gates.push(Gate {
                    record,
                    obligations_enforced,
                });
            }
        }
    }
    Ok(NetAction {
        host: facts.host.to_owned(),
        port: facts.port,
        method: facts.method,
        url_sha256: facts.url_sha256,
        body_bytes: facts.body_bytes,
        gates,
        resolved: facts.addresses.is_some(),
        response_limit: limit,
    })
}

/// Decide a hop's injection action: `secret.use:<handle>` through both gates,
/// keeping only `audit_level`.
///
/// # Errors
///
/// An invariant: a handle that does not assemble a capability.
pub(crate) fn decide_injection(
    handle: &crate::secret::metadata::SecretHandle,
    host: &str,
    port: u16,
    admission: &Admission,
    context: &PolicyContext,
    active: &ActiveAuthority,
) -> Result<InjectionAction, AuthorityError> {
    let required = super::super::secret_use::required(handle)?;
    let record = query::decide(
        &CanonicalAction::new(required, Environment::Host),
        admission,
        context,
        active,
    );
    let obligations_enforced = super::super::secret_use::obligations_enforced(&record);
    Ok(InjectionAction {
        handle: handle.as_str().to_owned(),
        host: host.to_owned(),
        port,
        gate: Gate {
            record,
            obligations_enforced,
        },
    })
}
