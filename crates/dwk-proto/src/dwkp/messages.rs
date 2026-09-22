//! DWKP message payloads defined by M2.
//!
//! Only messages whose shape is fully determined by the architecture and whose
//! first consumer is the next milestone are defined. Everything else in the
//! inventory is reserved, with its owning milestone, and is not on the wire —
//! see [`super::registry`]. Every type here rejects unknown members.

use crate::error::{ErrorCode, ProtocolError, Violation};
use crate::json::Value;
use crate::schema::{Defs, obj, string, strings};
use crate::version::VersionRange;
use crate::wire::id::{CapId, RunId, SessionId};
use crate::wire::list::BoundedList;
use crate::wire::macros::wire_struct;
use crate::wire::scalar::{
    AgentProfileName, CapabilityText, DecisionEffect, DecisionReason, Detail, Epoch, ErrorPath,
    GateResult, PolicyRevision, ProfileName, RefusalReason, RefusedOperation, RuleId, RuleSource,
    SkillName, Version, WithheldReason,
};
use crate::wire::{Cx, WireType, expect_string};

wire_struct! {
    /// Opens a DWKP connection by offering a range of envelope versions. Always
    /// sent in envelope version 1, whatever it offers, so that any receiver can
    /// read the offer.
    Handshake: reject {
        /// Lowest envelope version the sender speaks.
        required min_version: Version,
        /// Highest envelope version the sender speaks.
        required max_version: Version,
    }
    ordered(min_version <= max_version)
}

wire_struct! {
    /// Accepts a handshake, naming the version both sides will use: the highest
    /// both support at or above the receiver's floor.
    HandshakeAccepted: reject {
        /// The negotiated envelope version.
        required version: Version,
    }
}

wire_struct! {
    /// Renews the session lease named in the envelope at the epoch named in the
    /// envelope. Carries nothing else.
    HeartbeatPayload: reject {}
}

wire_struct! {
    /// Requests the single-writer lease for the session named in the envelope.
    /// The kernel assigns the epoch; the sender cannot propose one.
    LeaseAcquire: reject {}
}

wire_struct! {
    /// The lease the kernel granted.
    LeaseGrant: reject {
        /// The session the lease is for.
        required session_id: SessionId,
        /// The epoch the kernel assigned. Every later request for the session
        /// carries it; a request carrying an older one is fenced (§3).
        required epoch: Epoch,
    }
}

wire_struct! {
    /// Surrenders the lease named in the envelope, at the epoch named in the
    /// envelope. Can only reduce authority.
    LeaseRelease: reject {}
}

wire_struct! {
    /// Acknowledges a request that has no other result.
    Ack: reject {}
}

// ---------------------------------------------------------------------------
// M3 authority primitives.
//
// Three operations get their first wire form here: AdmitRun, ReleaseRun and
// QueryAuthority. ToolInvoke deliberately does not -- see `super::registry` and
// ADR-0036 for why an operation that must name a tool cannot be designed by the
// milestone before the one that builds the first tool.
//
// The list bounds below are protocol limits, not policy: they cap what one
// frame can turn into. A run needing more than MAX_CAPABILITIES distinct
// capabilities is a design smell long before it is a protocol problem.
// ---------------------------------------------------------------------------

/// Most capabilities one run may hold or request.
pub const MAX_CAPABILITIES: usize = 64;

/// Most skills one run may be admitted with.
pub const MAX_SKILLS: usize = 32;

/// A set of capabilities as they appear on the wire.
pub type CapabilitySet = BoundedList<CapabilityText, MAX_CAPABILITIES>;

/// A set of granted capabilities, each with the id the kernel minted for it.
pub type GrantSet = BoundedList<CapabilityGrant, MAX_CAPABILITIES>;

/// The capabilities a run asked for and did not receive, with the reason.
pub type WithheldSet = BoundedList<WithheldCapability, MAX_CAPABILITIES>;

/// The skills a run is admitted with.
pub type SkillSet = BoundedList<SkillName, MAX_SKILLS>;

wire_struct! {
    /// Asks the kernel to admit a run and mint its authority.
    ///
    /// `requested_capabilities` is a request, not an assertion: the kernel
    /// intersects it with the agent profile, the skills, the parent grant and
    /// the profile ceiling, and returns what survived (`CAPABILITIES.md` §4,
    /// `mint` step 5). Asking for more is not an error, because an error
    /// invites a retry loop; it yields less, and the difference is reported.
    ///
    /// There is no `mode`, `profile`, `workspace_sensitivity`, `taint` or
    /// `privacy_class` field. Those are policy inputs, and ADR-0028 makes every
    /// policy input kernel-derived: a field here would be the runtime asserting
    /// one.
    AdmitRun: reject {
        /// Which agent profile the run is for. The kernel resolves it to the
        /// profile's declared capabilities; an unknown name is a denial, not a
        /// protocol error.
        required agent_profile: AgentProfileName,
        /// The skills to activate. Skills only ever narrow.
        required skills: SkillSet,
        /// The capabilities the run would like. May exceed what it can have.
        required requested_capabilities: CapabilitySet,
    }
}

wire_struct! {
    /// One capability the kernel granted, and the id it minted for it.
    CapabilityGrant: reject {
        /// The kernel's handle for this grant. `ToolInvoke` will name it when
        /// M4 gives that operation a wire form; the kernel resolves it against
        /// its own record, so the id proves nothing by itself.
        required cap_id: CapId,
        /// The granted capability, which may be narrower than the one asked
        /// for. Never wider: that is the ⊑ invariant the kernel enforces.
        required capability: CapabilityText,
    }
}

wire_struct! {
    /// One capability that was asked for and not granted, and which term of
    /// the minting expression removed it.
    WithheldCapability: reject {
        /// The capability as requested.
        required capability: CapabilityText,
        /// Which intersection removed it.
        required reason: WithheldReason,
    }
}

wire_struct! {
    /// The authority the kernel minted for a run.
    ///
    /// Everything here is kernel-assigned. The run id, the epoch and every
    /// `cap_id` are the kernel's; the runtime cannot propose any of them.
    RunGrant: reject {
        /// The run the kernel admitted.
        required run_id: RunId,
        /// The epoch this grant is fenced to. A request carrying an older one
        /// is rejected (`PROTOCOL.md` §3).
        required epoch: Epoch,
        /// Which policy was in force when the grant was minted.
        required policy_revision: PolicyRevision,
        /// The ceiling the run was admitted under.
        required profile: ProfileName,
        /// What the run holds.
        required granted: GrantSet,
        /// What it asked for and did not get, so it can say so coherently.
        required withheld: WithheldSet,
    }
}

wire_struct! {
    /// Ends a run's authority. The run is named by the envelope.
    ///
    /// Carries nothing: it can only surrender authority, and a field here would
    /// be a way to say something about a run while ending it.
    ReleaseRun: reject {}
}

wire_struct! {
    /// Asks what a run may do, and optionally whether one specific action is
    /// permitted.
    ///
    /// Read-only in both shapes. It reports authority and grants none, touches
    /// no resource, reserves nothing and performs no effect: it is the question
    /// M3 exists to answer, asked without doing anything about the answer.
    AuthorityQuery: reject {
        /// A proposed action, in the kernel's capability grammar. When absent
        /// the response reports effective authority only. When present, the
        /// response is a `decision` for exactly this action **only if** the
        /// authority can construct the complete canonical action it names;
        /// otherwise it is `direwolf.authority.refused` with
        /// `NO_CANONICAL_ACTION`. Through M3e that is every proposal, because
        /// capability text alone never determines one (ADR-0040).
        optional proposed: CapabilityText,
    }
}

wire_struct! {
    /// One authority decision, with everything needed to explain it.
    ///
    /// Never a bare boolean. POLICY.md §1.5 requires the matched rule, its
    /// source and the capability that was required, because a denial nobody can
    /// debug is a denial someone will route around.
    AuthorityDecision: reject {
        /// What was decided.
        required effect: DecisionEffect,
        /// Why, as a classifiable code rather than prose.
        required reason: DecisionReason,
        /// Whether a held capability covers the action (ADR-0006 gate one).
        required capability_result: GateResult,
        /// Whether policy permits it (ADR-0006 gate two). Both gates always
        /// run: an ALLOW needs both, and neither substitutes for the other.
        required policy_result: GateResult,
        /// The id of the rule that produced the effect: the matched rule, the
        /// narrowing postcondition, or the policy's own mandatory `default`
        /// rule when nothing matched before it. Never a stand-in for a rule
        /// that did not run (ADR-0040).
        required rule_id: RuleId,
        /// Where that rule is written: file and line.
        required rule_source: RuleSource,
        /// The capability the action needed. Always present: a decision is
        /// only ever made about a canonical action, and every canonical action
        /// requires one (ADR-0040; optional in version 1).
        required required_capability: CapabilityText,
    }
}

wire_struct! {
    /// What a run may do, as the kernel currently records it.
    EffectiveAuthority: reject {
        /// The run this describes.
        required run_id: RunId,
        /// The epoch the answer is current at. An answer is about a moment.
        required epoch: Epoch,
        /// Which policy produced it.
        required policy_revision: PolicyRevision,
        /// The ceiling the run was admitted under.
        required profile: ProfileName,
        /// What the run holds.
        required granted: GrantSet,
        /// What it asked for and did not get.
        required withheld: WithheldSet,
        /// The decision for the `proposed` action, present exactly when the
        /// query carried one the authority could decide. A proposal it cannot
        /// decide is refused instead (`NO_CANONICAL_ACTION`), so an
        /// `EffectiveAuthority` answering a proposal always carries its
        /// decision. A reader that asked and received none must treat the
        /// answer as unusable rather than as an allow.
        optional decision: AuthorityDecision,
    }
}

/// Which refusal reasons each M3 operation can produce.
///
/// The combination is closed, not just each field: a refusal naming a reason
/// its operation cannot produce is refused at the boundary. The table is short
/// because M3's authority state is small, and it is exhaustive because every
/// entry traces to an accepted decision —
///
/// * `STALE_EPOCH` wherever the request carries an epoch (`PROTOCOL.md` §3).
///   `AcquireLease` carries none, so it cannot be fenced; it is the operation
///   that *issues* the epoch.
/// * `LEASE_HELD` only where a lease is acquired (ADR-0011 point 2).
/// * `IDEMPOTENCY_CONFLICT`, `ADMISSION_ENDED` and `UNKNOWN_AGENT_PROFILE` only
///   on `AdmitRun`, the only operation with a key and the only one naming a
///   profile.
/// * `UNKNOWN_RUN` only on `QueryAuthority`, never on `ReleaseRun`, which is
///   idempotent by shape: releasing a run the kernel does not hold is
///   acknowledged, because a retry must not be distinguishable from success.
/// * `NO_CANONICAL_ACTION` only on `QueryAuthority`, the only operation that
///   carries a proposed action (ADR-0040).
///
/// A future milestone adding a reason adds it here and bumps
/// `direwolf.authority.refused`'s `schema_version`. ADR-0040 did: the table is
/// version 2's.
pub const REFUSALS: &[(&str, &[&str])] = &[
    ("ACQUIRE_LEASE", &["LEASE_HELD"]),
    ("RELEASE_LEASE", &["STALE_EPOCH"]),
    ("HEARTBEAT", &["STALE_EPOCH"]),
    (
        "ADMIT_RUN",
        &[
            "STALE_EPOCH",
            "IDEMPOTENCY_CONFLICT",
            "ADMISSION_ENDED",
            "UNKNOWN_AGENT_PROFILE",
        ],
    ),
    ("RELEASE_RUN", &["STALE_EPOCH"]),
    (
        "QUERY_AUTHORITY",
        &["STALE_EPOCH", "UNKNOWN_RUN", "NO_CANONICAL_ACTION"],
    ),
];

wire_struct! {
    /// The authority declined to act on a well-formed request.
    ///
    /// **Three different things a caller must be able to tell apart**, and this
    /// is the middle one:
    ///
    /// * `direwolf.protocol.error` — the bytes did not form a valid message.
    ///   Nothing was evaluated because nothing arrived. The remedy is to fix
    ///   the message.
    /// * **this** — the message was valid and the authority's own state does
    ///   not permit the operation to be attempted. No policy ran, no capability
    ///   was consulted. The remedy is named by `reason` and is usually to
    ///   re-acquire a lease, admit a run, or stop retrying.
    /// * `direwolf.authority.effective` carrying a `DENY` decision — both gates
    ///   of ADR-0006 ran against real state and refused. The remedy is to ask
    ///   for less, or to change policy.
    ///
    /// Merging any two of those to save a message type would leave a caller
    /// unable to choose between three different remedies, and the failure mode
    /// of guessing is a retry loop against a refusal that will never change.
    ///
    /// **Two fields, and no third.** There is no `detail` string, no `hint`, no
    /// map: `ProtocolErrorPayload` carries a detail because a malformed message
    /// needs a human to repair *a message*, whereas a refusal needs the caller
    /// to take one of five known actions. Every byte beyond the reason is a
    /// byte the authority tells a caller about state the caller could not
    /// otherwise see — which is how a refusal becomes an oracle. `STALE_EPOCH`
    /// in particular does **not** carry the kernel's current epoch: handing a
    /// fenced runtime the one value it needs to un-fence itself would undo the
    /// fencing.
    AuthorityRefusal: reject {
        /// Which operation was refused. Redundant with `causation_id` for a
        /// caller that still has the request; not redundant for an audit
        /// record, and it is what closes the pairing below.
        required operation: RefusedOperation,
        /// Why. Closed, and narrower still per operation.
        required reason: RefusalReason,
    }
    paired(operation -> reason, REFUSALS)
}

wire_struct! {
    /// A range of versions a receiver supports.
    VersionSpan: reject {
        /// Lowest supported version.
        required min: Version,
        /// Highest supported version.
        required max: Version,
    }
    ordered(min <= max)
}

wire_struct! {
    /// The message did not decode. This is **not** a policy denial: nothing was
    /// evaluated, because there was nothing well-formed to evaluate.
    ProtocolErrorPayload: reject {
        /// Stable error code.
        required code: ErrorCode,
        /// Finer classification for schema and version failures.
        optional violation: Violation,
        /// JSON Pointer to the failing location.
        optional path: ErrorPath,
        /// Short explanation. Informational; bounded.
        required detail: Detail,
        /// For version failures, the range the receiver supports.
        optional supported: VersionSpan,
    }
}

impl VersionSpan {
    /// Convert a range. `None` only if the range is invalid, which a
    /// `VersionRange` never is.
    #[must_use]
    pub fn from_range(range: VersionRange) -> Option<Self> {
        Some(Self {
            min: Version::new(range.min)?,
            max: Version::new(range.max)?,
        })
    }
}

impl From<&ProtocolError> for ProtocolErrorPayload {
    fn from(err: &ProtocolError) -> Self {
        Self {
            code: err.code,
            violation: err.violation,
            path: (!err.path.is_empty())
                .then(|| ErrorPath::new(err.path.clone()))
                .flatten(),
            detail: Detail::truncated(&err.detail),
            supported: err.supported.and_then(VersionSpan::from_range),
        }
    }
}

impl WireType for ErrorCode {
    fn decode(value: Value, cx: &mut Cx) -> Result<Self, ProtocolError> {
        let s = expect_string(value, cx)?;
        Self::from_wire(&s)
            .ok_or_else(|| cx.violation(Violation::UnknownVariant, "not a protocol error code"))
    }

    fn encode(&self) -> Result<Value, ProtocolError> {
        Ok(Value::String(self.as_str().to_owned()))
    }

    fn schema(_: &mut Defs) -> Value {
        let names: Vec<&str> = Self::ALL.iter().map(|c| c.as_str()).collect();
        obj(vec![
            ("type", string("string")),
            ("enum", strings(&names)),
            ("x-direwolf-type", string("ErrorCode")),
        ])
    }
}

impl WireType for Violation {
    fn decode(value: Value, cx: &mut Cx) -> Result<Self, ProtocolError> {
        let s = expect_string(value, cx)?;
        Self::from_wire(&s)
            .ok_or_else(|| cx.violation(Violation::UnknownVariant, "not a violation kind"))
    }

    fn encode(&self) -> Result<Value, ProtocolError> {
        Ok(Value::String(self.as_str().to_owned()))
    }

    fn schema(_: &mut Defs) -> Value {
        let names: Vec<&str> = Self::ALL.iter().map(|v| v.as_str()).collect();
        obj(vec![
            ("type", string("string")),
            ("enum", strings(&names)),
            ("x-direwolf-type", string("Violation")),
        ])
    }
}
