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

/// Messages whose payload changed incompatibly in ADR-0040. DWKP's two peers
/// ship together (ADR-0023) and no DWKP version has been released, so a bumped
/// message supports exactly its new version: a version-1 instance is
/// `PROTOCOL_VERSION_UNSUPPORTED`, never decoded under rules it predates.
const V2: VersionRange = VersionRange { min: 2, max: 2 };

/// The tool messages' third version (M4d, ADR-0045): the process tools. Beside
/// versions 1 and 2, never instead of them.
const V3: VersionRange = VersionRange { min: 3, max: 3 };

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

/// The admission request. Like `REQUEST_SESSION_EPOCH`, plus the key that
/// makes a retry one admission rather than two.
///
/// The key is *required*, not optional. An optional key leaves the kernel two
/// paths -- one deduplicated, one not -- and the undeduplicated path is
/// precisely the one a retry takes, so the safe behaviour would exist and be
/// unused. It costs a caller one generated string; it costs the kernel the
/// difference between one grant and an unbounded number (ADR-0036 section 8).
const REQUEST_ADMIT: EnvelopeRules = EnvelopeRules {
    correlation_id: Presence::Optional,
    causation_id: Presence::Optional,
    session_id: Presence::Required,
    run_id: Presence::Forbidden,
    epoch: Presence::Required,
    idempotency_key: Presence::Required,
};

/// A version-2 tool invocation (M4c, ADR-0044 §§2, 7): a run request that also
/// carries the key naming this one invocation. Required, for the reason
/// `REQUEST_ADMIT`'s is: `fs.move` and `fs.delete` are not retry-safe, a lost
/// response is the ordinary failure of a socket, and a key the kernel records
/// is what lets the caller later ask what happened instead of trying again.
const REQUEST_RUN_KEYED: EnvelopeRules = EnvelopeRules {
    correlation_id: Presence::Optional,
    causation_id: Presence::Optional,
    session_id: Presence::Required,
    run_id: Presence::Required,
    epoch: Presence::Required,
    idempotency_key: Presence::Required,
};

/// A request about an existing run: it names the session it belongs to, the
/// epoch it is fenced to, and the run itself.
const REQUEST_RUN: EnvelopeRules = EnvelopeRules {
    correlation_id: Presence::Optional,
    causation_id: Presence::Optional,
    session_id: Presence::Required,
    run_id: Presence::Required,
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

/// Every DWKP message this build decodes. A schema may appear more than once,
/// with disjoint version ranges and its own rules and payload for each: the
/// tool messages keep version 1 exactly as M4b defined it (ADR-0043) and add
/// version 2 beside it (ADR-0044). A version is never decoded under another
/// version's rules.
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
        schema: "direwolf.run.admit",
        message_type: MessageType::Request,
        versions: V1,
        rules: REQUEST_ADMIT,
        payload: "AdmitRun",
        summary: "Ask the kernel to admit a run and mint its authority.",
    },
    MessageSpec {
        schema: "direwolf.run.grant",
        message_type: MessageType::Response,
        versions: V2,
        rules: RESPONSE,
        payload: "RunGrant",
        summary: "The run, the epoch and the capabilities the kernel minted.",
    },
    MessageSpec {
        schema: "direwolf.run.release",
        message_type: MessageType::Request,
        versions: V1,
        rules: REQUEST_RUN,
        payload: "ReleaseRun",
        summary: "End a run's authority.",
    },
    MessageSpec {
        schema: "direwolf.authority.query",
        message_type: MessageType::Request,
        versions: V1,
        rules: REQUEST_RUN,
        payload: "AuthorityQuery",
        summary: "Ask what a run may do, and optionally decide one action.",
    },
    MessageSpec {
        schema: "direwolf.authority.effective",
        message_type: MessageType::Response,
        versions: V2,
        rules: RESPONSE,
        payload: "EffectiveAuthority",
        summary: "A run's effective authority, and a decision if one was asked for.",
    },
    MessageSpec {
        schema: "direwolf.authority.refused",
        message_type: MessageType::Response,
        versions: V2,
        rules: RESPONSE,
        payload: "AuthorityRefusal",
        summary: "The request was well-formed; the authority's state refused it.",
    },
    MessageSpec {
        schema: "direwolf.tool.invoke",
        message_type: MessageType::Request,
        versions: V1,
        rules: REQUEST_RUN,
        payload: "ToolInvoke",
        summary: "Perform one typed tool call for a run; this build has one tool, fs.read.",
    },
    MessageSpec {
        schema: "direwolf.tool.preview",
        message_type: MessageType::Request,
        versions: V1,
        rules: REQUEST_RUN,
        payload: "CanonicalPreview",
        summary: "Ask what a tool call would mean, without performing it.",
    },
    MessageSpec {
        schema: "direwolf.tool.result",
        message_type: MessageType::Response,
        versions: V1,
        rules: RESPONSE,
        payload: "ToolResult",
        summary: "An invocation allowed, performed on the checked object, and recorded.",
    },
    MessageSpec {
        schema: "direwolf.tool.denied",
        message_type: MessageType::Response,
        versions: V1,
        rules: RESPONSE,
        payload: "ToolDenial",
        summary: "The two gates refused a tool action; nothing was performed.",
    },
    MessageSpec {
        schema: "direwolf.tool.previewed",
        message_type: MessageType::Response,
        versions: V1,
        rules: RESPONSE,
        payload: "CanonicalPreviewResult",
        summary: "The canonical action and decision a tool call would receive.",
    },
    MessageSpec {
        schema: "direwolf.tool.refused",
        message_type: MessageType::Response,
        versions: V1,
        rules: RESPONSE,
        payload: "ToolRefusal",
        summary: "A tool operation refused before any effect was authorised.",
    },
    MessageSpec {
        schema: "direwolf.tool.failed",
        message_type: MessageType::Response,
        versions: V1,
        rules: RESPONSE,
        payload: "ToolFailure",
        summary: "An authorised invocation produced no result.",
    },
    MessageSpec {
        schema: "direwolf.tool.invoke",
        message_type: MessageType::Request,
        versions: V2,
        rules: REQUEST_RUN_KEYED,
        payload: "ToolCall",
        summary: "Perform one typed filesystem tool call for a run, under an idempotency key.",
    },
    MessageSpec {
        schema: "direwolf.tool.preview",
        message_type: MessageType::Request,
        versions: V2,
        rules: REQUEST_RUN,
        payload: "ToolCall",
        summary: "Ask what a filesystem tool call's complete plan would be, without performing it.",
    },
    MessageSpec {
        schema: "direwolf.tool.result",
        message_type: MessageType::Response,
        versions: V2,
        rules: RESPONSE,
        payload: "ToolResultV2",
        summary: "An invocation whose whole plan was allowed, performed on the checked objects, and recorded.",
    },
    MessageSpec {
        schema: "direwolf.tool.denied",
        message_type: MessageType::Response,
        versions: V2,
        rules: RESPONSE,
        payload: "ToolDenialV2",
        summary: "An action of the plan was refused; nothing was performed.",
    },
    MessageSpec {
        schema: "direwolf.tool.previewed",
        message_type: MessageType::Response,
        versions: V2,
        rules: RESPONSE,
        payload: "CanonicalPreviewResultV2",
        summary: "The complete canonical plan and decisions a tool call would receive.",
    },
    MessageSpec {
        schema: "direwolf.tool.refused",
        message_type: MessageType::Response,
        versions: V2,
        rules: RESPONSE,
        payload: "ToolRefusalV2",
        summary: "A version-2 tool operation refused before any effect was authorised.",
    },
    MessageSpec {
        schema: "direwolf.tool.failed",
        message_type: MessageType::Response,
        versions: V2,
        rules: RESPONSE,
        payload: "ToolFailureV2",
        summary: "An authorised version-2 invocation produced no result, or its outcome is unknown.",
    },
    MessageSpec {
        schema: "direwolf.tool.invoke",
        message_type: MessageType::Request,
        versions: V3,
        rules: REQUEST_RUN_KEYED,
        payload: "ToolCallV3",
        summary: "Perform one typed filesystem or process tool call for a run, under an idempotency key.",
    },
    MessageSpec {
        schema: "direwolf.tool.preview",
        message_type: MessageType::Request,
        versions: V3,
        rules: REQUEST_RUN,
        payload: "ToolCallV3",
        summary: "Ask what a filesystem or process tool call's complete plan would be, without performing it.",
    },
    MessageSpec {
        schema: "direwolf.tool.result",
        message_type: MessageType::Response,
        versions: V3,
        rules: RESPONSE,
        payload: "ToolResultV3",
        summary: "A version-3 invocation whose whole plan was allowed, performed, and recorded.",
    },
    MessageSpec {
        schema: "direwolf.tool.denied",
        message_type: MessageType::Response,
        versions: V3,
        rules: RESPONSE,
        payload: "ToolDenialV3",
        summary: "An action of a version-3 plan was refused; nothing was performed.",
    },
    MessageSpec {
        schema: "direwolf.tool.previewed",
        message_type: MessageType::Response,
        versions: V3,
        rules: RESPONSE,
        payload: "CanonicalPreviewResultV3",
        summary: "The complete canonical plan and decisions a version-3 tool call would receive.",
    },
    MessageSpec {
        schema: "direwolf.tool.refused",
        message_type: MessageType::Response,
        versions: V3,
        rules: RESPONSE,
        payload: "ToolRefusalV3",
        summary: "A version-3 tool operation refused before any effect was authorised.",
    },
    MessageSpec {
        schema: "direwolf.tool.failed",
        message_type: MessageType::Response,
        versions: V3,
        rules: RESPONSE,
        payload: "ToolFailureV3",
        summary: "An authorised version-3 invocation produced no result, or its outcome is unknown.",
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

/// Look up a message by its type, schema and version.
#[must_use]
pub fn message(
    message_type: MessageType,
    schema: &str,
    version: u16,
) -> Option<&'static MessageSpec> {
    MESSAGES.iter().find(|m| {
        m.message_type == message_type && m.schema == schema && m.versions.contains(version)
    })
}

/// Every version of a message this build decodes, as one range, or `None` if
/// it knows no message of that type and schema. The ranges of one schema are
/// contiguous (a test holds them to it), so their union is a range.
#[must_use]
pub fn versions(message_type: MessageType, schema: &str) -> Option<VersionRange> {
    MESSAGES
        .iter()
        .filter(|m| m.message_type == message_type && m.schema == schema)
        .map(|m| m.versions)
        .reduce(|a, b| VersionRange {
            min: a.min.min(b.min),
            max: a.max.max(b.max),
        })
}

const ERR: &str = "direwolf.protocol.error";

/// The typed authority refusal. Distinct from `ERR`: that one says the message
/// was not valid, this one says the message was valid and the authority's state
/// said no (ADR-0036 section 10).
const REFUSED: &str = "direwolf.authority.refused";

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
        responses: &["direwolf.ack", REFUSED, ERR],
        initiator: "runtime",
        receiver: "dwkd-authority",
        semantics_owner: "M3 (epoch authority); M8 (lease renewal)",
        effect_bearing: false,
        authority_bearing: true,
        carries: "Envelope session_id and epoch only; an empty payload.",
        consumer: "dwkd-authority lease table in kernel.db (M3/M8).",
        second_path: "It can only extend authority the kernel already granted, by at most one lease TTL, and only while the stated epoch is the kernel's current one; a stale epoch is fenced (PROTOCOL.md section 3). It names no resource and cannot create, widen or transfer authority. The epoch it carries is one the kernel issued, compared against kernel.db, never believed; an epoch that is not current is refused with STALE_EPOCH rather than silently renewing nothing.",
    },
    OperationSpec {
        name: "AcquireLease",
        layer: Layer::AuthorityPrimitive,
        status: WireStatus::Defined,
        request: Some("direwolf.lease.acquire"),
        responses: &["direwolf.lease.grant", REFUSED, ERR],
        initiator: "runtime",
        receiver: "dwkd-authority",
        semantics_owner: "M3 (epoch authority); M8 (session leases)",
        effect_bearing: false,
        authority_bearing: true,
        carries: "Envelope session_id; an empty payload. The response carries the kernel-assigned epoch.",
        consumer: "dwkd-authority lease table in kernel.db (M3/M8).",
        second_path: "The sender cannot propose an epoch; the kernel assigns it. A lease confers the right to write one session and nothing more: capabilities come only from AdmitRun, so holding a lease authorises no effect. Its only external consequence is fencing other writers of the same session, which is its purpose. Exactly one process wins the conditional acquire (ADR-0011 point 2); the others are refused with LEASE_HELD on direwolf.authority.refused, which is why that refusal exists. It is the one operation that cannot be fenced, because it is the operation that issues the epoch.",
    },
    OperationSpec {
        name: "ReleaseLease",
        layer: Layer::AuthorityPrimitive,
        status: WireStatus::Defined,
        request: Some("direwolf.lease.release"),
        responses: &["direwolf.ack", REFUSED, ERR],
        initiator: "runtime",
        receiver: "dwkd-authority",
        semantics_owner: "M3; M8",
        effect_bearing: false,
        authority_bearing: true,
        carries: "Envelope session_id and epoch; an empty payload.",
        consumer: "dwkd-authority lease table in kernel.db (M3/M8).",
        second_path: "It can only surrender authority, never gain it, and only for a lease held at the stated current epoch; a stale epoch is refused with STALE_EPOCH. It names nothing but the session. Releasing a lease the kernel no longer records is acknowledged rather than refused, for the same reason ReleaseRun is: a retry must not be distinguishable from success, and there is no UNKNOWN_LEASE reason because inventing one would turn a harmless retry into an error and make the refusal a probe for which sessions exist.",
    },
    // ---- reserved: authority primitives -----------------------------------
    OperationSpec {
        name: "AdmitRun",
        layer: Layer::AuthorityPrimitive,
        status: WireStatus::Defined,
        request: Some("direwolf.run.admit"),
        responses: &["direwolf.run.grant", REFUSED, ERR],
        initiator: "runtime",
        receiver: "dwkd-authority",
        semantics_owner: "M3",
        effect_bearing: false,
        authority_bearing: true,
        carries: "Agent profile name, requested skills and requested capabilities, under a mandatory envelope idempotency_key; response RunGrant{run_id, epoch, policy_revision, profile, granted[], withheld[]}.",
        consumer: "Capability Broker (M3); the Budget Ledger will amend the grant at M6.",
        second_path: "The grant is minted kernel-side by intersecting the agent profile, the kernel-verified skills, the parent grant and the profile ceiling; nothing the runtime asserts is a term in that expression (ADR-0028, invariant I9). requested_capabilities is a request and not an assertion -- asking for more yields less, never more, and the difference is returned as withheld[] so the agent can say what it lacks. There is no mode, workspace-sensitivity, taint or privacy-class field: each would be the runtime supplying a policy input. The run id, the epoch and every cap_id are assigned by the kernel. It is the one operation that carries an idempotency_key, and carries it mandatorily: admission mints authority, so one key can never produce a second admission. The key names an admission attempt and not a run, and is scoped kernel-side to (authenticated peer, session_id), so it cannot be guessed across subjects. A retry of the same canonical request (the epoch is not part of it) receives the recorded grant while the run it admitted is active under the caller's current lease; once that run has ended -- released, or reaped by a lease rotation, expiry or authority restart -- the key is refused with ADMISSION_ENDED for ever, because returning a grant for a run that no longer exists would be a success that authorises nothing. The same key with a different canonical request is refused with IDEMPOTENCY_CONFLICT, and an agent profile the kernel does not hold with UNKNOWN_AGENT_PROFILE -- all on direwolf.authority.refused, because the message was well-formed and a protocol error would be a lie. Epoch fencing is checked before the key is looked at, so presenting a key is never a way past the fence (ADR-0036 sections 8 and 10, as amended by ADR-0040).",
    },
    OperationSpec {
        name: "ReleaseRun",
        layer: Layer::AuthorityPrimitive,
        status: WireStatus::Defined,
        request: Some("direwolf.run.release"),
        responses: &["direwolf.ack", REFUSED, ERR],
        initiator: "runtime",
        receiver: "dwkd-authority",
        semantics_owner: "M3",
        effect_bearing: false,
        authority_bearing: true,
        carries: "Envelope session_id, run_id and epoch; an empty payload. Response Ack.",
        consumer: "Capability Broker (M3).",
        second_path: "It can only end authority, never extend it, and only for a run the caller holds at the stated current epoch. The payload is empty by design: a field here would be a way to say something about a run while ending it. Releasing an already-released run is acknowledged rather than refused, so a retry cannot be distinguished from success and cannot resurrect anything -- idempotent by shape, which is why it carries no idempotency_key and why UNKNOWN_RUN is not one of its refusals. The only way it can be refused is STALE_EPOCH, because ending a run at an epoch you no longer hold is an act by a fenced caller.",
    },
    OperationSpec {
        name: "ToolInvoke",
        layer: Layer::AuthorityPrimitive,
        status: WireStatus::Defined,
        request: Some("direwolf.tool.invoke"),
        responses: &[
            "direwolf.tool.result",
            "direwolf.tool.denied",
            "direwolf.tool.refused",
            "direwolf.tool.failed",
            ERR,
        ],
        initiator: "runtime",
        receiver: "dwkd-authority",
        semantics_owner: "M4b (fs.read, version 1); M4c (the eight filesystem tools, version 2); M4d (the three process tools, version 3); M4e, M5, M10 (further tools)",
        effect_bearing: true,
        authority_bearing: true,
        carries: "Envelope session_id, run_id and epoch. Version 1: one typed fs_read{path, max_bytes}; responses ToolResult{invocation_id, action, decision, fs_read}, ToolDenial, ToolRefusal or ToolFailure -- unchanged since M4b. Version 2: exactly one of eight typed members (fs_read, fs_list, fs_search, fs_stat, fs_write, fs_patch, fs_move, fs_delete) and a mandatory envelope idempotency_key; responses ToolResultV2{invocation_id, plan, output}, ToolDenialV2{plan}, ToolRefusalV2 or ToolFailureV2, each in the version of the request. Version 3: exactly one of eleven typed members -- the eight filesystem calls and process_exec{executable, args[], cwd?}, process_status{process_id}, process_kill{process_id} -- under the same mandatory key; responses ToolResultV3{invocation_id, plan, output}, ToolDenialV3{plan}, ToolRefusalV3 or ToolFailureV3. No capability, cap_id, environment, taint, existence claim or retry class -- and for a process call no argv[0], environment variable, executable digest, argv classification or numeric process id: each would be the runtime asserting something the authority decides.",
        consumer: "dwkd-authority: fence, run and key; the canonical resolver for every target, existing or vacant, beneath the run's pinned root (ADR-0042, ADR-0044); the canonical plan and both gates for every action of it; the durable intent and the bound key; only then the descriptors the operation needs -- the file opened for reading, the directory opened for listing, the parent directories whose names change -- and one channel-bound authorisation to dwkd-broker over the private channel; then the durable outcome -- completed, failed, or UNKNOWN when an effect is not proved -- and, for a read-family result, the run's taint (ADR-0043, ADR-0044).",
        second_path: "This IS the path from cognition to effect, and there is no other. A call names one tool from a closed inventory with typed arguments the authority canonicalises itself: a tool this build lacks is an undeclared member and fails to decode, so nothing dispatches on a string or an argument map. The authority resolves every path beneath the run's pinned workspace root so that the filesystem, not the spelling, supplies its meaning -- a vacant target as a checked parent directory and one validated name -- and derives the complete plan itself: the capability verbs each tool needs (a creating write needs fs.write and fs.create; a move fs.delete on its source and fs.create on its destination; a patch fs.read and fs.write), each with its canonical path and byte bound, environment HOST. Every action must be covered by a held grant and allowed by policy, with every obligation enforceable, or nothing happens. The intent and the idempotency key are recorded durably before any descriptor that could perform the effect exists. The broker receives exactly the operation's descriptors and at most one validated leaf name, re-proves every identity, checks the name immediately before and after changing it atomically (exchange or no-replace rename of a new file, never in place), undoes a change that reached an object it did not prove -- Linux has no compare-and-swap of a name against an inode, so the permission model keeps untrusted writers out of a write-enabled workspace -- and reports an outcome or an undo it cannot prove as indeterminate; the authority records that as UNKNOWN and never performs the invocation again. Every staging directory the broker may make is recorded with the intent and settled afterwards, removed only when it provably holds the broker's own uncommitted data. A key names one invocation for ever: a reuse is refused before anything is resolved. Because resolution precedes the gates, a refusal can say whether a workspace path exists or is vacant even where policy would deny the action; it never says what a file holds. A process call names its executable by an absolute host path, which the authority's executable resolver turns into an identity -- a bounded chain of symlinks followed to one regular native file, that file opened, required to be changeable only by root or the authority, and hashed -- decided as process.exec on that identity, with argv[0] its canonical path and every argument passed as exactly its bytes, no shell anywhere; the broker re-proves the descriptor the authority opened and executes that descriptor (execveat), never a path. process.status and process.kill name only a process this run launched, by the opaque handle its launch returned, and are decided as process.inspect and process.signal on the identity it was launched as. A host launch also needs the operator's host-execution opt-in and a per-invocation approval (SANDBOX.md section 4); approvals arrive at M6, so until then every launch is decided, audited and denied, with no invocation recorded and no broker contact (ADR-0045). The broker is not addressable from cognition, never opens a path, and never decides (ADR-0043, ADR-0044, ADR-0045).",
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
        status: WireStatus::Defined,
        request: Some("direwolf.tool.preview"),
        responses: &["direwolf.tool.previewed", "direwolf.tool.refused", ERR],
        initiator: "runtime, CLI",
        receiver: "dwkd-authority",
        semantics_owner: "M4b (version 1); M4c (version 2); M4d (version 3)",
        effect_bearing: false,
        authority_bearing: false,
        carries: "Envelope session_id, run_id and epoch; the same typed call ToolInvoke carries in the same version, and never an idempotency_key. Response CanonicalPreviewResult{action, decision} or ToolRefusal (version 1), CanonicalPreviewResultV2{plan} or ToolRefusalV2 (version 2), CanonicalPreviewResultV3{plan} or ToolRefusalV3 (version 3).",
        consumer: "direwolf policy simulate; the approval [w]hy branch (M6); a runtime asking what it lacks.",
        second_path: "It resolves every target, builds the complete plan and runs every gate of every action through the same code ToolInvoke uses, so the untrusted side never duplicates canonicalisation, and it performs nothing: it opens nothing for an effect, contacts no broker, mints no invocation id or process id, binds no key, records no intent, issues no authorisation, launches and signals nothing and reserves nothing. A process preview resolves and hashes the executable now; the identity it names is not frozen, and an invocation resolves and hashes it again. Its resolution is the same lookup ToolInvoke performs first, and a differential test holds each invocation to the plan its preview named. Its answer authorises nothing: it is information, stale the moment it is sent, and a later ToolInvoke fences, canonicalises and decides again from scratch.",
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
        status: WireStatus::Defined,
        request: Some("direwolf.authority.query"),
        responses: &["direwolf.authority.effective", REFUSED, ERR],
        initiator: "runtime, CLI",
        receiver: "dwkd-authority",
        semantics_owner: "M3",
        effect_bearing: false,
        authority_bearing: false,
        carries: "Envelope session_id, run_id and epoch; an optional proposed capability. Response EffectiveAuthority{granted[], withheld[], profile, policy_revision, epoch}, plus a decision for a proposal the authority can express as a complete canonical action; any other proposal is refused with NO_CANONICAL_ACTION, which through M3e is every proposal.",
        consumer: "direwolf run authority; the runtime, to learn what it lacks before asking a human.",
        second_path: "Read-only in both shapes: it reports authority and grants none, names no tool, touches no resource, reserves nothing and produces no side effect. A proposal is decided only when the authority can construct the complete canonical action policy decides on, and is never performed -- the answer is a decision record, and obtaining an ALLOW from it authorises nothing on its own, because the effect path is ToolInvoke and ToolInvoke checks again. Capability text alone does not determine where an action runs, the address it reaches or the resource it names, so until M4's canonicaliser exists every proposal is refused with NO_CANONICAL_ACTION rather than decided on facts the kernel would have to invent, and no policy rule is attributed to an evaluation that did not run (ADR-0040). Repeating the same query against the same state returns the same decision, so it needs no idempotency_key: there is nothing for a replay to duplicate. A run the kernel does not hold is refused with UNKNOWN_RUN rather than answered with a denial -- there is no grant, no profile and no policy revision to report, so an EffectiveAuthority could not be filled in, and a DENY would claim an evaluation that never ran.",
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
    use super::{MESSAGES, OPERATIONS, WireStatus, message, versions};

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
    fn lookup_is_by_type_schema_and_version() {
        use crate::envelope::MessageType;
        assert!(message(MessageType::Request, "direwolf.heartbeat", 1).is_some());
        assert!(message(MessageType::Request, "direwolf.heartbeat", 2).is_none());
        assert!(message(MessageType::Response, "direwolf.heartbeat", 1).is_none());
        assert!(message(MessageType::Request, "direwolf.tool.cancel", 1).is_none());
        // The tool messages carry three versions, each with its own payload.
        let v1 = message(MessageType::Request, "direwolf.tool.invoke", 1).map(|m| m.payload);
        let v2 = message(MessageType::Request, "direwolf.tool.invoke", 2).map(|m| m.payload);
        let v3 = message(MessageType::Request, "direwolf.tool.invoke", 3).map(|m| m.payload);
        assert_eq!(v1, Some("ToolInvoke"));
        assert_eq!(v2, Some("ToolCall"));
        assert_eq!(v3, Some("ToolCallV3"));
        assert!(message(MessageType::Request, "direwolf.tool.invoke", 4).is_none());
        assert_eq!(
            versions(MessageType::Request, "direwolf.tool.invoke").map(|r| (r.min, r.max)),
            Some((1, 3))
        );
        // A version-3 invocation carries the key version 2's does.
        let v3_rules = message(MessageType::Request, "direwolf.tool.invoke", 3).map(|m| m.rules);
        assert_eq!(
            v3_rules.map(|r| r.idempotency_key),
            Some(crate::envelope::Presence::Required)
        );
        assert_eq!(
            versions(MessageType::Response, "direwolf.tool.invoke"),
            None
        );
    }

    #[test]
    fn a_schemas_versions_are_disjoint_and_contiguous() {
        let mut keys: Vec<(&str, &str)> = MESSAGES
            .iter()
            .map(|m| (m.message_type.as_str(), m.schema))
            .collect();
        keys.sort_unstable();
        keys.dedup();
        for (message_type, schema) in keys {
            let mut ranges: Vec<(u16, u16)> = MESSAGES
                .iter()
                .filter(|m| m.message_type.as_str() == message_type && m.schema == schema)
                .map(|m| (m.versions.min, m.versions.max))
                .collect();
            ranges.sort_unstable();
            for pair in ranges.windows(2) {
                if let [(_, high), (low, _)] = pair {
                    assert_eq!(
                        high.checked_add(1),
                        Some(*low),
                        "{schema}: versions must be disjoint and contiguous"
                    );
                }
            }
        }
    }

    #[test]
    fn a_version_two_invocation_requires_an_idempotency_key() {
        use crate::envelope::{MessageType, Presence};
        let v1 = message(MessageType::Request, "direwolf.tool.invoke", 1).map(|m| m.rules);
        let v2 = message(MessageType::Request, "direwolf.tool.invoke", 2).map(|m| m.rules);
        assert_eq!(v1.map(|r| r.idempotency_key), Some(Presence::Forbidden));
        assert_eq!(v2.map(|r| r.idempotency_key), Some(Presence::Required));
        // A preview performs nothing, so it names no invocation.
        let preview = message(MessageType::Request, "direwolf.tool.preview", 2).map(|m| m.rules);
        assert_eq!(
            preview.map(|r| r.idempotency_key),
            Some(Presence::Forbidden)
        );
    }
}
