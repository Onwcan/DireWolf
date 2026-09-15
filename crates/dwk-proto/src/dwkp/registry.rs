//! The DWKP operation inventory and message registry.
//!
//! **This file is the authoritative inventory.** `docs/DWKP_OPERATIONS.md` and
//! `schemas/dwkp/operations.json` are generated from it and drift-checked.
//!
//! Every operation named anywhere in the architecture is listed, but only those
//! marked [`WireStatus::Defined`] exist on the wire. A reserved operation has no
//! message schema, and a message naming it is rejected as
//! `PROTOCOL_UNKNOWN_OPERATION` exactly like a misspelled one. Its payload is
//! designed, and its second-path argument re-examined, by its owning milestone
//! — when the kernel that will consume it exists, not before.
//!
//! # The second-path rule
//!
//! Every operation carries a written argument for why it is not a second path
//! from cognition to effect (`PROTOCOL.md` §2; `docs/adr/README.md` rule 5).
//! The test that recurs: **an operation that relays bytes the kernel does not
//! interpret cannot police what those bytes do.** If the kernel cannot state in
//! one sentence what canonical action an operation performs, it is a relay.
//!
//! Adding or changing an entry requires answering the protocol change review
//! questions in `CONTRIBUTING.md`, and a reviewer other than the author.

use crate::envelope::{EnvelopeRules, MessageType, Presence};
use crate::version::VersionRange;

/// Where an operation sits in the layering of ADR-0029.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// Connection mechanics. Carries no authority semantics at all.
    ProtocolControl,
    /// Presumes nothing about DireWolf's loop, context or orchestration.
    AuthorityPrimitive,
    /// Useful to the first-party runtime; must remain expressible in primitives.
    RuntimeConvenience,
}

impl Layer {
    /// Spelling used in generated documents.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolControl => "protocol-control",
            Self::AuthorityPrimitive => "authority-primitive",
            Self::RuntimeConvenience => "runtime-convenience",
        }
    }
}

/// Whether an operation exists on the wire in this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireStatus {
    /// Its messages are defined, decoded and schema-emitted.
    Defined,
    /// Named by the architecture; not on the wire until its owning milestone.
    Reserved,
}

impl WireStatus {
    /// Spelling used in generated documents.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Defined => "defined",
            Self::Reserved => "reserved",
        }
    }
}

/// One entry in the operation inventory.
#[derive(Debug, Clone, Copy)]
pub struct OperationSpec {
    /// The operation name used throughout the architecture.
    pub name: &'static str,
    /// ADR-0029 layer.
    pub layer: Layer,
    /// On the wire, or reserved.
    pub status: WireStatus,
    /// Request message schema, for defined operations.
    pub request: Option<&'static str>,
    /// Possible response message schemas, for defined operations.
    pub responses: &'static [&'static str],
    /// Who sends the request.
    pub initiator: &'static str,
    /// Who receives it.
    pub receiver: &'static str,
    /// The milestone that implements what the operation *means*.
    pub semantics_owner: &'static str,
    /// Whether performing it can change the world outside the kernel's own
    /// records (a file, a process, a network peer, a message delivered).
    pub effect_bearing: bool,
    /// Whether it can grant, extend or exercise authority.
    pub authority_bearing: bool,
    /// What information it carries.
    pub carries: &'static str,
    /// Which component consumes it.
    pub consumer: &'static str,
    /// Why it is not a second path from cognition to effect.
    pub second_path: &'static str,
}

/// One message on the wire.
#[derive(Debug, Clone, Copy)]
pub struct MessageSpec {
    /// The `schema` value.
    pub schema: &'static str,
    /// The `type` value.
    pub message_type: MessageType,
    /// Supported `schema_version`s.
    pub versions: VersionRange,
    /// Envelope presence rules.
    pub rules: EnvelopeRules,
    /// Rust payload type name (also its `$defs` name).
    pub payload: &'static str,
    /// One-line description.
    pub summary: &'static str,
}

const V1: VersionRange = VersionRange { min: 1, max: 1 };

const REQUEST_NO_SESSION: EnvelopeRules = EnvelopeRules {
    correlation_id: Presence::Optional,
    causation_id: Presence::Optional,
    session_id: Presence::Forbidden,
    run_id: Presence::Forbidden,
    epoch: Presence::Forbidden,
    idempotency_key: Presence::Forbidden,
};

const REQUEST_SESSION: EnvelopeRules = EnvelopeRules {
    correlation_id: Presence::Optional,
    causation_id: Presence::Optional,
    session_id: Presence::Required,
    run_id: Presence::Forbidden,
    epoch: Presence::Forbidden,
    idempotency_key: Presence::Forbidden,
};

const REQUEST_SESSION_EPOCH: EnvelopeRules = EnvelopeRules {
    correlation_id: Presence::Optional,
    causation_id: Presence::Optional,
    session_id: Presence::Required,
    run_id: Presence::Forbidden,
    epoch: Presence::Required,
    idempotency_key: Presence::Forbidden,
};

const RESPONSE: EnvelopeRules = EnvelopeRules {
    correlation_id: Presence::Optional,
    causation_id: Presence::Required,
    session_id: Presence::Forbidden,
    run_id: Presence::Forbidden,
    epoch: Presence::Forbidden,
    idempotency_key: Presence::Forbidden,
};

/// A protocol error may answer bytes that never formed a request, so it cannot
/// always name its cause.
const PROTOCOL_ERROR: EnvelopeRules = EnvelopeRules {
    causation_id: Presence::Optional,
    ..RESPONSE
};

/// Every DWKP message this build decodes.
pub const MESSAGES: &[MessageSpec] = &[
    MessageSpec {
        schema: "direwolf.handshake",
        message_type: MessageType::Request,
        versions: V1,
        rules: REQUEST_NO_SESSION,
        payload: "Handshake",
        summary: "Offer a range of envelope versions.",
    },
    MessageSpec {
        schema: "direwolf.handshake.accepted",
        message_type: MessageType::Response,
        versions: V1,
        rules: RESPONSE,
        payload: "HandshakeAccepted",
        summary: "The negotiated envelope version.",
    },
    MessageSpec {
        schema: "direwolf.heartbeat",
        message_type: MessageType::Request,
        versions: V1,
        rules: REQUEST_SESSION_EPOCH,
        payload: "HeartbeatPayload",
        summary: "Renew the session lease at the stated epoch.",
    },
    MessageSpec {
        schema: "direwolf.lease.acquire",
        message_type: MessageType::Request,
        versions: V1,
        rules: REQUEST_SESSION,
        payload: "LeaseAcquire",
        summary: "Request the single-writer lease for a session.",
    },
    MessageSpec {
        schema: "direwolf.lease.grant",
        message_type: MessageType::Response,
        versions: V1,
        rules: RESPONSE,
        payload: "LeaseGrant",
        summary: "The lease and the epoch the kernel assigned.",
    },
    MessageSpec {
        schema: "direwolf.lease.release",
        message_type: MessageType::Request,
        versions: V1,
        rules: REQUEST_SESSION_EPOCH,
        payload: "LeaseRelease",
        summary: "Surrender a lease held at the stated epoch.",
    },
    MessageSpec {
        schema: "direwolf.ack",
        message_type: MessageType::Response,
        versions: V1,
        rules: RESPONSE,
        payload: "Ack",
        summary: "Acknowledge a request with no other result.",
    },
    MessageSpec {
        schema: "direwolf.protocol.error",
        message_type: MessageType::Response,
        versions: V1,
        rules: PROTOCOL_ERROR,
        payload: "ProtocolErrorPayload",
        summary: "The message did not decode. Not a policy denial.",
    },
];

/// Look up a message by its type and schema.
#[must_use]
pub fn message(message_type: MessageType, schema: &str) -> Option<&'static MessageSpec> {
    MESSAGES
        .iter()
        .find(|m| m.message_type == message_type && m.schema == schema)
}

const ERR: &str = "direwolf.protocol.error";

/// The complete DWKP operation inventory.
pub const OPERATIONS: &[OperationSpec] = &[
    // ---- defined in M2 ----------------------------------------------------
    OperationSpec {
        name: "Handshake",
        layer: Layer::ProtocolControl,
        status: WireStatus::Defined,
        request: Some("direwolf.handshake"),
        responses: &["direwolf.handshake.accepted", ERR],
        initiator: "any DWKP client (runtime, CLI)",
        receiver: "dwkd-authority",
        semantics_owner: "M3",
        effect_bearing: false,
        authority_bearing: false,
        carries: "The envelope version range the client speaks.",
        consumer: "dwkd-authority connection setup (M3), which also enforces that it is the first message.",
        second_path: "It negotiates how later messages are encoded and nothing else. It names no resource, carries no capability and grants no authority: every later request is still individually decoded, canonicalised and policed. The receiver's version floor stops it being used to downgrade the connection.",
    },
    OperationSpec {
        name: "Heartbeat",
        layer: Layer::AuthorityPrimitive,
        status: WireStatus::Defined,
        request: Some("direwolf.heartbeat"),
        responses: &["direwolf.ack", ERR],
        initiator: "runtime",
        receiver: "dwkd-authority",
        semantics_owner: "M3 (epoch authority); M8 (lease renewal)",
        effect_bearing: false,
        authority_bearing: true,
        carries: "Envelope session_id and epoch only; an empty payload.",
        consumer: "dwkd-authority lease table in kernel.db (M3/M8).",
        second_path: "It can only extend authority the kernel already granted, by at most one lease TTL, and only while the stated epoch is the kernel's current one; a stale epoch is fenced (PROTOCOL.md section 3). It names no resource and cannot create, widen or transfer authority. The epoch it carries is one the kernel issued, compared against kernel.db, never believed.",
    },
    OperationSpec {
        name: "AcquireLease",
        layer: Layer::AuthorityPrimitive,
        status: WireStatus::Defined,
        request: Some("direwolf.lease.acquire"),
        responses: &["direwolf.lease.grant", ERR],
        initiator: "runtime",
        receiver: "dwkd-authority",
        semantics_owner: "M3 (epoch authority); M8 (session leases)",
        effect_bearing: false,
        authority_bearing: true,
        carries: "Envelope session_id; an empty payload. The response carries the kernel-assigned epoch.",
        consumer: "dwkd-authority lease table in kernel.db (M3/M8).",
        second_path: "The sender cannot propose an epoch; the kernel assigns it. A lease confers the right to write one session and nothing more: capabilities come only from AdmitRun, so holding a lease authorises no effect. Its only external consequence is fencing other writers of the same session, which is its purpose. M3 adds the policy denial for a session the caller may not lease; a protocol error is not that denial.",
    },
    OperationSpec {
        name: "ReleaseLease",
        layer: Layer::AuthorityPrimitive,
        status: WireStatus::Defined,
        request: Some("direwolf.lease.release"),
        responses: &["direwolf.ack", ERR],
        initiator: "runtime",
        receiver: "dwkd-authority",
        semantics_owner: "M3; M8",
        effect_bearing: false,
        authority_bearing: true,
        carries: "Envelope session_id and epoch; an empty payload.",
        consumer: "dwkd-authority lease table in kernel.db (M3/M8).",
        second_path: "It can only surrender authority, never gain it, and only for a lease held at the stated current epoch. It names nothing but the session.",
    },
    // ---- reserved: authority primitives -----------------------------------
    OperationSpec {
        name: "AdmitRun",
        layer: Layer::AuthorityPrimitive,
        status: WireStatus::Reserved,
        request: None,
        responses: &[],
        initiator: "runtime",
        receiver: "dwkd-authority",
        semantics_owner: "M3",
        effect_bearing: false,
        authority_bearing: true,
        carries: "Agent profile and requested skills; response RunGrant{run_id, capability_tokens[], budget_lease, epoch}.",
        consumer: "Capability Broker and Budget Ledger (M3, M6).",
        second_path: "When defined: the grant is minted kernel-side from agent profile, kernel-verified skills, parent grant and profile ceiling; nothing the runtime asserts is a term in that expression (ADR-0028, invariant I9). Payload deferred to M3 because the capability token format does not exist yet.",
    },
    OperationSpec {
        name: "ReleaseRun",
        layer: Layer::AuthorityPrimitive,
        status: WireStatus::Reserved,
        request: None,
        responses: &[],
        initiator: "runtime",
        receiver: "dwkd-authority",
        semantics_owner: "M3",
        effect_bearing: false,
        authority_bearing: true,
        carries: "run_id; response Ack.",
        consumer: "Capability Broker (M3).",
        second_path: "When defined: can only end authority, never extend it.",
    },
    OperationSpec {
        name: "ToolInvoke",
        layer: Layer::AuthorityPrimitive,
        status: WireStatus::Reserved,
        request: None,
        responses: &[],
        initiator: "runtime",
        receiver: "dwkd-authority",
        semantics_owner: "M3 (pipeline); M4, M5, M10 (tools)",
        effect_bearing: true,
        authority_bearing: true,
        carries: "A typed tool invocation and capability token; responses ToolResult, Denial or ApprovalPending.",
        consumer: "Canonicaliser, policy, capabilities, approvals, budget, audit; then a per-invocation authorisation to dwkd-broker.",
        second_path: "This IS the path from cognition to effect; there must be no other. When defined it must name a tool from the canonical inventory with typed arguments the kernel canonicalises itself; it must never accept an opaque command, script or frame.",
    },
    OperationSpec {
        name: "ToolCancel",
        layer: Layer::AuthorityPrimitive,
        status: WireStatus::Reserved,
        request: None,
        responses: &[],
        initiator: "runtime",
        receiver: "dwkd-authority",
        semantics_owner: "M9",
        effect_bearing: false,
        authority_bearing: false,
        carries: "Invocation id; response Ack.",
        consumer: "Invocation tracking (M9).",
        second_path: "When defined: can only stop an effect already authorised, never start one.",
    },
    OperationSpec {
        name: "ModelCall",
        layer: Layer::AuthorityPrimitive,
        status: WireStatus::Reserved,
        request: None,
        responses: &[],
        initiator: "runtime",
        receiver: "dwkd-authority",
        semantics_owner: "M7",
        effect_bearing: true,
        authority_bearing: true,
        carries: "Typed ModelCall{provider_profile_id, model, messages[], tool_schemas[], sampling_params} (ADR-0020); streamed deltas or Denial.",
        consumer: "Authority (origin, privacy class, credential, budget); dwkd-broker renders the HTTP request from a declarative provider profile.",
        second_path: "When defined it must carry semantics only: no URL, header, credential, raw body or endpoint, which is how ADR-0002's HttpRequestSpec became an unpoliced network capability. Open for M7: ADR-0020 lists privacy_class in the request while ADR-0028 makes privacy_class a kernel-derived policy input; M7 must either drop it from the request or accept it only as a request to narrow.",
    },
    OperationSpec {
        name: "CanonicalPreview",
        layer: Layer::AuthorityPrimitive,
        status: WireStatus::Reserved,
        request: None,
        responses: &[],
        initiator: "runtime, CLI",
        receiver: "dwkd-authority",
        semantics_owner: "M3/M4",
        effect_bearing: false,
        authority_bearing: false,
        carries: "A proposed tool invocation; response CanonicalAction.",
        consumer: "direwolf policy simulate; the approval [w]hy branch.",
        second_path: "When defined: resolves what an action would mean without performing it, so the untrusted side never duplicates canonicalisation. It must not reserve, lock or touch the resource.",
    },
    OperationSpec {
        name: "CreateArtifact",
        layer: Layer::AuthorityPrimitive,
        status: WireStatus::Reserved,
        request: None,
        responses: &[],
        initiator: "runtime",
        receiver: "dwkd-authority",
        semantics_owner: "M12",
        effect_bearing: true,
        authority_bearing: false,
        carries: "Streamed content; response ArtifactId.",
        consumer: "Kernel-side content-addressed store with kernel-assigned provenance.",
        second_path: "When defined: writes only into the kernel-owned CAS, quota-bounded, with trust assigned by the kernel. It must never accept a destination path or a provenance label from the runtime.",
    },
    OperationSpec {
        name: "ReadArtifact",
        layer: Layer::AuthorityPrimitive,
        status: WireStatus::Reserved,
        request: None,
        responses: &[],
        initiator: "runtime",
        receiver: "dwkd-authority",
        semantics_owner: "M12",
        effect_bearing: false,
        authority_bearing: false,
        carries: "ArtifactId; streamed bytes.",
        consumer: "Artifact store (M12).",
        second_path: "When defined: reads by content id from the kernel's store only; never a path.",
    },
    OperationSpec {
        name: "QueryBudget",
        layer: Layer::AuthorityPrimitive,
        status: WireStatus::Reserved,
        request: None,
        responses: &[],
        initiator: "runtime, CLI",
        receiver: "dwkd-authority",
        semantics_owner: "M6",
        effect_bearing: false,
        authority_bearing: false,
        carries: "Run id; response BudgetSnapshot.",
        consumer: "Budget Ledger (M6).",
        second_path: "When defined: read-only.",
    },
    OperationSpec {
        name: "QueryAuthority",
        layer: Layer::AuthorityPrimitive,
        status: WireStatus::Reserved,
        request: None,
        responses: &[],
        initiator: "runtime, CLI",
        receiver: "dwkd-authority",
        semantics_owner: "M3",
        effect_bearing: false,
        authority_bearing: false,
        carries: "Run id; response EffectiveAuthority.",
        consumer: "direwolf run authority.",
        second_path: "When defined: read-only; reports authority, grants none.",
    },
    OperationSpec {
        name: "QueryInvocationStatus",
        layer: Layer::AuthorityPrimitive,
        status: WireStatus::Reserved,
        request: None,
        responses: &[],
        initiator: "runtime",
        receiver: "dwkd-authority",
        semantics_owner: "M9",
        effect_bearing: false,
        authority_bearing: false,
        carries: "Idempotency key; response the audited outcome (RELIABILITY.md section 1).",
        consumer: "Crash recovery (M9), answering from the audit chain.",
        second_path: "When defined: read-only. It answers whether an effect happened; it never re-performs one.",
    },
    // ---- reserved: runtime-shaped conveniences ----------------------------
    OperationSpec {
        name: "ListVisibleTools",
        layer: Layer::RuntimeConvenience,
        status: WireStatus::Reserved,
        request: None,
        responses: &[],
        initiator: "runtime",
        receiver: "dwkd-authority",
        semantics_owner: "M10",
        effect_bearing: false,
        authority_bearing: false,
        carries: "Run id; response ToolDefinition[] fixed at admission (ADR-0026).",
        consumer: "Context engine.",
        second_path: "When defined: read-only; visibility can only narrow after admission.",
    },
    OperationSpec {
        name: "SpawnSubagent",
        layer: Layer::RuntimeConvenience,
        status: WireStatus::Reserved,
        request: None,
        responses: &[],
        initiator: "runtime",
        receiver: "dwkd-authority",
        semantics_owner: "M14",
        effect_bearing: false,
        authority_bearing: true,
        carries: "Parent run and requested attenuation; response RunGrant.",
        consumer: "Capability Broker.",
        second_path: "When defined it must remain expressible as AdmitRun plus an attenuation request (ADR-0029); if it ever needs more, the primitive layer has leaked.",
    },
    OperationSpec {
        name: "McpOpen",
        layer: Layer::RuntimeConvenience,
        status: WireStatus::Reserved,
        request: None,
        responses: &[],
        initiator: "runtime",
        receiver: "dwkd-authority",
        semantics_owner: "M16",
        effect_bearing: true,
        authority_bearing: true,
        carries: "MCP server identity; response McpServerHandle and ToolDefinition[].",
        consumer: "Kernel-owned MCP client; dwkd-broker spawns the server sandboxed.",
        second_path: "The kernel owns the MCP protocol, not merely the process. There is no operation that relays a frame; invoking a discovered tool is an ordinary ToolInvoke. McpSend/McpRecv were a second path found in Phase 0 and must never return.",
    },
    OperationSpec {
        name: "McpClose",
        layer: Layer::RuntimeConvenience,
        status: WireStatus::Reserved,
        request: None,
        responses: &[],
        initiator: "runtime",
        receiver: "dwkd-authority",
        semantics_owner: "M16",
        effect_bearing: true,
        authority_bearing: false,
        carries: "McpServerHandle; response Ack.",
        consumer: "Kernel-owned MCP client.",
        second_path: "When defined: can only stop a server.",
    },
    OperationSpec {
        name: "ChannelSend",
        layer: Layer::RuntimeConvenience,
        status: WireStatus::Reserved,
        request: None,
        responses: &[],
        initiator: "runtime",
        receiver: "dwkd-authority",
        semantics_owner: "M20",
        effect_bearing: true,
        authority_bearing: true,
        carries: "Typed outbound message; response DeliveryReceipt.",
        consumer: "Secret broker (channel credential) and egress policy.",
        second_path: "Outbound delivery goes through the kernel because the channel token is a credential and outbound content is an egress surface. When defined, the destination is a configured channel reference, never a URL or token supplied by the runtime.",
    },
];

#[cfg(test)]
mod tests {
    use super::{MESSAGES, OPERATIONS, WireStatus, message};

    #[test]
    fn every_defined_operation_names_registered_messages() {
        for op in OPERATIONS
            .iter()
            .filter(|o| o.status == WireStatus::Defined)
        {
            let request = op.request.unwrap_or_default();
            assert!(
                MESSAGES.iter().any(|m| m.schema == request),
                "{} request",
                op.name
            );
            for response in op.responses {
                assert!(
                    MESSAGES.iter().any(|m| m.schema == *response),
                    "{} -> {response}",
                    op.name
                );
            }
        }
    }

    #[test]
    fn reserved_operations_have_no_wire_messages() {
        for op in OPERATIONS
            .iter()
            .filter(|o| o.status == WireStatus::Reserved)
        {
            assert!(
                op.request.is_none() && op.responses.is_empty(),
                "{}",
                op.name
            );
        }
    }

    #[test]
    fn every_registered_message_is_used_by_a_defined_operation() {
        for m in MESSAGES {
            let used = OPERATIONS
                .iter()
                .any(|o| o.request == Some(m.schema) || o.responses.contains(&m.schema));
            assert!(used, "{} is registered but no operation uses it", m.schema);
        }
    }

    #[test]
    fn every_operation_carries_a_second_path_argument() {
        for op in OPERATIONS {
            assert!(
                op.second_path.len() > 20,
                "{} has no second-path argument",
                op.name
            );
            assert!(
                !op.semantics_owner.is_empty() && !op.consumer.is_empty(),
                "{}",
                op.name
            );
        }
    }

    #[test]
    fn inventory_contains_every_operation_the_architecture_names() {
        // PROTOCOL.md section 2 plus QueryInvocationStatus (RELIABILITY.md section 1,
        // ADR-0029), plus the M2 Handshake.
        let expected = [
            "Handshake",
            "AcquireLease",
            "ReleaseLease",
            "AdmitRun",
            "ReleaseRun",
            "ToolInvoke",
            "ToolCancel",
            "ModelCall",
            "CanonicalPreview",
            "ListVisibleTools",
            "SpawnSubagent",
            "CreateArtifact",
            "ReadArtifact",
            "McpOpen",
            "McpClose",
            "ChannelSend",
            "QueryBudget",
            "QueryAuthority",
            "QueryInvocationStatus",
            "Heartbeat",
        ];
        for name in expected {
            assert!(OPERATIONS.iter().any(|o| o.name == name), "{name} missing");
        }
        assert_eq!(OPERATIONS.len(), expected.len());
    }

    /// Names that would make an authority protocol a relay. The test is
    /// crude on purpose: a reviewer adding one of these must delete a line
    /// here, in the same diff, and explain why.
    #[test]
    fn no_generic_or_relay_operation_exists() {
        let banned = [
            "Execute",
            "Raw",
            "Relay",
            "Opaque",
            "Arbitrary",
            "Passthrough",
            "Send",
            "Recv",
        ];
        for op in OPERATIONS {
            for word in banned {
                let allowed = op.name == "ChannelSend" && word == "Send";
                assert!(
                    allowed || !op.name.contains(word),
                    "{} looks generic",
                    op.name
                );
            }
            assert_ne!(op.name, "Invoke");
        }
        for m in MESSAGES {
            for word in ["raw", "relay", "exec", "http", "opaque", "passthrough"] {
                assert!(!m.schema.contains(word), "{} looks generic", m.schema);
            }
        }
    }

    #[test]
    fn lookup_is_by_type_and_schema() {
        use crate::envelope::MessageType;
        assert!(message(MessageType::Request, "direwolf.heartbeat").is_some());
        assert!(message(MessageType::Response, "direwolf.heartbeat").is_none());
        assert!(message(MessageType::Request, "direwolf.tool.invoke").is_none());
    }
}
