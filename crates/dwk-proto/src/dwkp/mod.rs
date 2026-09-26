//! DWKP — the DireWolf Kernel Protocol. **Strict.**
//!
//! The authority boundary. Every message is a request for authority or an
//! answer to one, so ambiguity here is authorisation ambiguity later
//! (ADR-0023). Decoding a DWKP frame body, in order:
//!
//! 1. [`crate::json::parse`] with the DWKP profile: UTF-8, RFC 8259 grammar,
//!    depth ≤ 32, no duplicate keys, safe integers only.
//! 2. [`crate::envelope::read_preamble`]: `v` supported, then `type`, `schema`,
//!    `schema_version`.
//! 3. Registry lookup of `(type, schema)`. Unregistered — including every
//!    reserved operation — is `PROTOCOL_UNKNOWN_OPERATION`.
//! 4. `schema_version` within the registered range, else
//!    `PROTOCOL_VERSION_UNSUPPORTED`.
//! 5. The envelope against the message's presence rules; unknown envelope
//!    members rejected.
//! 6. The payload into its type; unknown payload members rejected.
//!
//! Nothing is silently discarded at any step. There is no lenient mode, and no
//! flag that would make one.

pub mod fsops;
pub mod messages;
pub mod procops;
pub mod registry;

use crate::envelope::{Header, MessageType, decode_header, read_preamble};
use crate::error::{ErrorCode, ProtocolError, Violation};
use crate::frame::{self, ContentType};
use crate::json::{self, ParseOptions, Value};
use crate::version::SUPPORTED_ENVELOPE;
use crate::wire::{Cx, UnknownFields, WireType};
use fsops::{
    CanonicalPreviewResultV2, ToolCall, ToolDenialV2, ToolFailureV2, ToolRefusalV2, ToolResultV2,
};
use messages::{
    Ack, AdmitRun, AuthorityQuery, AuthorityRefusal, CanonicalPreview, CanonicalPreviewResult,
    EffectiveAuthority, Handshake, HandshakeAccepted, HeartbeatPayload, LeaseAcquire, LeaseGrant,
    LeaseRelease, ProtocolErrorPayload, ReleaseRun, RunGrant, ToolDenial, ToolFailure, ToolInvoke,
    ToolRefusal, ToolResult,
};
use procops::{
    CanonicalPreviewResultV3, ToolCallV3, ToolDenialV3, ToolFailureV3, ToolRefusalV3, ToolResultV3,
};

/// A decoded DWKP message body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DwkpBody {
    /// `direwolf.handshake`
    Handshake(Handshake),
    /// `direwolf.handshake.accepted`
    HandshakeAccepted(HandshakeAccepted),
    /// `direwolf.heartbeat`
    Heartbeat(HeartbeatPayload),
    /// `direwolf.lease.acquire`
    LeaseAcquire(LeaseAcquire),
    /// `direwolf.lease.grant`
    LeaseGrant(LeaseGrant),
    /// `direwolf.lease.release`
    LeaseRelease(LeaseRelease),
    /// `direwolf.run.admit`
    AdmitRun(AdmitRun),
    /// `direwolf.run.grant`
    RunGrant(RunGrant),
    /// `direwolf.run.release`
    ReleaseRun(ReleaseRun),
    /// `direwolf.authority.query`
    AuthorityQuery(AuthorityQuery),
    /// `direwolf.authority.effective`
    EffectiveAuthority(EffectiveAuthority),
    /// `direwolf.authority.refused`
    AuthorityRefused(AuthorityRefusal),
    /// `direwolf.tool.invoke`
    ToolInvoke(ToolInvoke),
    /// `direwolf.tool.preview`
    CanonicalPreview(CanonicalPreview),
    /// `direwolf.tool.result`
    ToolResult(ToolResult),
    /// `direwolf.tool.denied`
    ToolDenied(ToolDenial),
    /// `direwolf.tool.previewed`
    ToolPreviewed(CanonicalPreviewResult),
    /// `direwolf.tool.refused`
    ToolRefused(ToolRefusal),
    /// `direwolf.tool.failed`
    ToolFailed(ToolFailure),
    /// `direwolf.tool.invoke` version 2 (ADR-0044).
    ToolInvokeV2(ToolCall),
    /// `direwolf.tool.preview` version 2.
    CanonicalPreviewV2(ToolCall),
    /// `direwolf.tool.result` version 2.
    ToolResultV2(ToolResultV2),
    /// `direwolf.tool.denied` version 2.
    ToolDeniedV2(ToolDenialV2),
    /// `direwolf.tool.previewed` version 2.
    ToolPreviewedV2(CanonicalPreviewResultV2),
    /// `direwolf.tool.refused` version 2.
    ToolRefusedV2(ToolRefusalV2),
    /// `direwolf.tool.failed` version 2.
    ToolFailedV2(ToolFailureV2),
    /// `direwolf.tool.invoke` version 3 (ADR-0045).
    ToolInvokeV3(ToolCallV3),
    /// `direwolf.tool.preview` version 3.
    CanonicalPreviewV3(ToolCallV3),
    /// `direwolf.tool.result` version 3.
    ToolResultV3(ToolResultV3),
    /// `direwolf.tool.denied` version 3.
    ToolDeniedV3(ToolDenialV3),
    /// `direwolf.tool.previewed` version 3.
    ToolPreviewedV3(CanonicalPreviewResultV3),
    /// `direwolf.tool.refused` version 3.
    ToolRefusedV3(ToolRefusalV3),
    /// `direwolf.tool.failed` version 3.
    ToolFailedV3(ToolFailureV3),
    /// `direwolf.ack`
    Ack(Ack),
    /// `direwolf.protocol.error`
    ProtocolError(ProtocolErrorPayload),
}

impl DwkpBody {
    /// The `(type, schema)` this body is sent as.
    #[must_use]
    pub const fn identity(&self) -> (MessageType, &'static str) {
        let (message_type, schema, _) = self.versioned_identity();
        (message_type, schema)
    }

    /// The `(type, schema, schema_version)` this body is sent as. A body type
    /// belongs to exactly one version: the tool messages' version-1 and
    /// version-2 payloads are different Rust types.
    #[must_use]
    pub const fn versioned_identity(&self) -> (MessageType, &'static str, u16) {
        match self {
            Self::Handshake(_) => (MessageType::Request, "direwolf.handshake", 1),
            Self::HandshakeAccepted(_) => (MessageType::Response, "direwolf.handshake.accepted", 1),
            Self::Heartbeat(_) => (MessageType::Request, "direwolf.heartbeat", 1),
            Self::LeaseAcquire(_) => (MessageType::Request, "direwolf.lease.acquire", 1),
            Self::LeaseGrant(_) => (MessageType::Response, "direwolf.lease.grant", 1),
            Self::LeaseRelease(_) => (MessageType::Request, "direwolf.lease.release", 1),
            Self::AdmitRun(_) => (MessageType::Request, "direwolf.run.admit", 1),
            Self::RunGrant(_) => (MessageType::Response, "direwolf.run.grant", 2),
            Self::ReleaseRun(_) => (MessageType::Request, "direwolf.run.release", 1),
            Self::AuthorityQuery(_) => (MessageType::Request, "direwolf.authority.query", 1),
            Self::EffectiveAuthority(_) => {
                (MessageType::Response, "direwolf.authority.effective", 2)
            }
            Self::AuthorityRefused(_) => (MessageType::Response, "direwolf.authority.refused", 2),
            Self::ToolInvoke(_) => (MessageType::Request, "direwolf.tool.invoke", 1),
            Self::CanonicalPreview(_) => (MessageType::Request, "direwolf.tool.preview", 1),
            Self::ToolResult(_) => (MessageType::Response, "direwolf.tool.result", 1),
            Self::ToolDenied(_) => (MessageType::Response, "direwolf.tool.denied", 1),
            Self::ToolPreviewed(_) => (MessageType::Response, "direwolf.tool.previewed", 1),
            Self::ToolRefused(_) => (MessageType::Response, "direwolf.tool.refused", 1),
            Self::ToolFailed(_) => (MessageType::Response, "direwolf.tool.failed", 1),
            Self::ToolInvokeV2(_) => (MessageType::Request, "direwolf.tool.invoke", 2),
            Self::CanonicalPreviewV2(_) => (MessageType::Request, "direwolf.tool.preview", 2),
            Self::ToolResultV2(_) => (MessageType::Response, "direwolf.tool.result", 2),
            Self::ToolDeniedV2(_) => (MessageType::Response, "direwolf.tool.denied", 2),
            Self::ToolPreviewedV2(_) => (MessageType::Response, "direwolf.tool.previewed", 2),
            Self::ToolRefusedV2(_) => (MessageType::Response, "direwolf.tool.refused", 2),
            Self::ToolFailedV2(_) => (MessageType::Response, "direwolf.tool.failed", 2),
            Self::ToolInvokeV3(_) => (MessageType::Request, "direwolf.tool.invoke", 3),
            Self::CanonicalPreviewV3(_) => (MessageType::Request, "direwolf.tool.preview", 3),
            Self::ToolResultV3(_) => (MessageType::Response, "direwolf.tool.result", 3),
            Self::ToolDeniedV3(_) => (MessageType::Response, "direwolf.tool.denied", 3),
            Self::ToolPreviewedV3(_) => (MessageType::Response, "direwolf.tool.previewed", 3),
            Self::ToolRefusedV3(_) => (MessageType::Response, "direwolf.tool.refused", 3),
            Self::ToolFailedV3(_) => (MessageType::Response, "direwolf.tool.failed", 3),
            Self::Ack(_) => (MessageType::Response, "direwolf.ack", 1),
            Self::ProtocolError(_) => (MessageType::Response, "direwolf.protocol.error", 1),
        }
    }

    fn decode(
        schema: &str,
        version: u16,
        payload: Value,
        cx: &mut Cx,
    ) -> Result<Self, ProtocolError> {
        Ok(match (schema, version) {
            ("direwolf.tool.invoke", 2) => Self::ToolInvokeV2(WireType::decode(payload, cx)?),
            ("direwolf.tool.preview", 2) => {
                Self::CanonicalPreviewV2(WireType::decode(payload, cx)?)
            }
            ("direwolf.tool.result", 2) => Self::ToolResultV2(WireType::decode(payload, cx)?),
            ("direwolf.tool.denied", 2) => Self::ToolDeniedV2(WireType::decode(payload, cx)?),
            ("direwolf.tool.previewed", 2) => Self::ToolPreviewedV2(WireType::decode(payload, cx)?),
            ("direwolf.tool.refused", 2) => Self::ToolRefusedV2(WireType::decode(payload, cx)?),
            ("direwolf.tool.failed", 2) => Self::ToolFailedV2(WireType::decode(payload, cx)?),
            ("direwolf.tool.invoke", 3) => Self::ToolInvokeV3(WireType::decode(payload, cx)?),
            ("direwolf.tool.preview", 3) => {
                Self::CanonicalPreviewV3(WireType::decode(payload, cx)?)
            }
            ("direwolf.tool.result", 3) => Self::ToolResultV3(WireType::decode(payload, cx)?),
            ("direwolf.tool.denied", 3) => Self::ToolDeniedV3(WireType::decode(payload, cx)?),
            ("direwolf.tool.previewed", 3) => Self::ToolPreviewedV3(WireType::decode(payload, cx)?),
            ("direwolf.tool.refused", 3) => Self::ToolRefusedV3(WireType::decode(payload, cx)?),
            ("direwolf.tool.failed", 3) => Self::ToolFailedV3(WireType::decode(payload, cx)?),
            (schema, _) => Self::decode_single_version(schema, payload, cx)?,
        })
    }

    /// Messages with one payload type for every version they support.
    fn decode_single_version(
        schema: &str,
        payload: Value,
        cx: &mut Cx,
    ) -> Result<Self, ProtocolError> {
        Ok(match schema {
            "direwolf.handshake" => Self::Handshake(WireType::decode(payload, cx)?),
            "direwolf.handshake.accepted" => {
                Self::HandshakeAccepted(WireType::decode(payload, cx)?)
            }
            "direwolf.heartbeat" => Self::Heartbeat(WireType::decode(payload, cx)?),
            "direwolf.lease.acquire" => Self::LeaseAcquire(WireType::decode(payload, cx)?),
            "direwolf.lease.grant" => Self::LeaseGrant(WireType::decode(payload, cx)?),
            "direwolf.lease.release" => Self::LeaseRelease(WireType::decode(payload, cx)?),
            "direwolf.run.admit" => Self::AdmitRun(WireType::decode(payload, cx)?),
            "direwolf.run.grant" => Self::RunGrant(WireType::decode(payload, cx)?),
            "direwolf.run.release" => Self::ReleaseRun(WireType::decode(payload, cx)?),
            "direwolf.authority.query" => Self::AuthorityQuery(WireType::decode(payload, cx)?),
            "direwolf.authority.effective" => {
                Self::EffectiveAuthority(WireType::decode(payload, cx)?)
            }
            "direwolf.authority.refused" => Self::AuthorityRefused(WireType::decode(payload, cx)?),
            "direwolf.tool.invoke" => Self::ToolInvoke(WireType::decode(payload, cx)?),
            "direwolf.tool.preview" => Self::CanonicalPreview(WireType::decode(payload, cx)?),
            "direwolf.tool.result" => Self::ToolResult(WireType::decode(payload, cx)?),
            "direwolf.tool.denied" => Self::ToolDenied(WireType::decode(payload, cx)?),
            "direwolf.tool.previewed" => Self::ToolPreviewed(WireType::decode(payload, cx)?),
            "direwolf.tool.refused" => Self::ToolRefused(WireType::decode(payload, cx)?),
            "direwolf.tool.failed" => Self::ToolFailed(WireType::decode(payload, cx)?),
            "direwolf.ack" => Self::Ack(WireType::decode(payload, cx)?),
            "direwolf.protocol.error" => Self::ProtocolError(WireType::decode(payload, cx)?),
            other => {
                // Unreachable after registry lookup; kept total and fail-closed.
                return Err(ProtocolError::new(
                    ErrorCode::UnknownOperation,
                    format!("no decoder for {other}"),
                ));
            }
        })
    }

    fn encode(&self) -> Result<Value, ProtocolError> {
        match self {
            Self::Handshake(p) => p.encode(),
            Self::HandshakeAccepted(p) => p.encode(),
            Self::Heartbeat(p) => p.encode(),
            Self::LeaseAcquire(p) => p.encode(),
            Self::LeaseGrant(p) => p.encode(),
            Self::LeaseRelease(p) => p.encode(),
            Self::AdmitRun(p) => p.encode(),
            Self::RunGrant(p) => p.encode(),
            Self::ReleaseRun(p) => p.encode(),
            Self::AuthorityQuery(p) => p.encode(),
            Self::EffectiveAuthority(p) => p.encode(),
            Self::AuthorityRefused(p) => p.encode(),
            Self::ToolInvoke(p) => p.encode(),
            Self::CanonicalPreview(p) => p.encode(),
            Self::ToolResult(p) => p.encode(),
            Self::ToolDenied(p) => p.encode(),
            Self::ToolPreviewed(p) => p.encode(),
            Self::ToolRefused(p) => p.encode(),
            Self::ToolFailed(p) => p.encode(),
            Self::ToolInvokeV2(p) | Self::CanonicalPreviewV2(p) => p.encode(),
            Self::ToolResultV2(p) => p.encode(),
            Self::ToolDeniedV2(p) => p.encode(),
            Self::ToolPreviewedV2(p) => p.encode(),
            Self::ToolRefusedV2(p) => p.encode(),
            Self::ToolFailedV2(p) => p.encode(),
            Self::ToolInvokeV3(p) | Self::CanonicalPreviewV3(p) => p.encode(),
            Self::ToolResultV3(p) => p.encode(),
            Self::ToolDeniedV3(p) => p.encode(),
            Self::ToolPreviewedV3(p) => p.encode(),
            Self::ToolRefusedV3(p) => p.encode(),
            Self::ToolFailedV3(p) => p.encode(),
            Self::Ack(p) => p.encode(),
            Self::ProtocolError(p) => p.encode(),
        }
    }
}

/// A complete, decoded DWKP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DwkpMessage {
    /// The envelope.
    pub header: Header,
    /// The payload.
    pub body: DwkpBody,
}

/// Decode a DWKP frame body.
pub fn decode_body(bytes: &[u8]) -> Result<DwkpMessage, ProtocolError> {
    decode_value(json::parse(bytes, ParseOptions::dwkp())?)
}

/// Decode a frame: content type, then body.
pub fn decode_frame(frame: &frame::Frame) -> Result<DwkpMessage, ProtocolError> {
    match frame.content_type {
        ContentType::Json => decode_body(&frame.body),
    }
}

/// Decode an already-parsed value (produced by the DWKP lexer profile).
pub fn decode_value(value: Value) -> Result<DwkpMessage, ProtocolError> {
    let preamble = read_preamble(&value, SUPPORTED_ENVELOPE)?;
    let versions =
        registry::versions(preamble.message_type, preamble.schema.as_str()).ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::UnknownOperation,
                format!(
                    "no DWKP {} named {} exists in this build",
                    preamble.message_type.as_str(),
                    preamble.schema.as_str()
                ),
            )
            .with_path("/schema")
        })?;
    let version = preamble.schema_version.get();
    let spec = registry::message(preamble.message_type, preamble.schema.as_str(), version)
        .ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::VersionUnsupported,
                format!(
                    "{} schema_version {version} is not supported",
                    preamble.schema.as_str()
                ),
            )
            .with_violation(Violation::OutOfRange)
            .with_path("/schema_version")
            .with_supported(versions)
        })?;
    let schema = spec.schema;
    let (header, payload, _) = decode_header(value, preamble, spec.rules, UnknownFields::Reject)?;
    let mut cx = Cx::new();
    cx.push("payload");
    let body = DwkpBody::decode(schema, version, Value::Object(payload), &mut cx)?;
    Ok(DwkpMessage { header, body })
}

impl DwkpMessage {
    /// Encode to a JSON value.
    ///
    /// The result is **re-decoded before it is returned**. A message this
    /// crate would reject is a message it must never emit, and checking by
    /// round trip means the encoder cannot drift from the decoder.
    pub fn to_value(&self) -> Result<Value, ProtocolError> {
        let (message_type, schema, version) = self.body.versioned_identity();
        if self.header.message_type != message_type
            || self.header.schema.as_str() != schema
            || self.header.schema_version.get() != version
        {
            return Err(ProtocolError::schema(
                Violation::Inconsistent,
                "/schema",
                "the header's type, schema and version do not match the body",
            ));
        }
        let value = self
            .header
            .encode(self.body.encode()?, &json::Object::new())?;
        let reparsed = decode_value(value.clone())?;
        if &reparsed != self {
            return Err(ProtocolError::schema(
                Violation::Inconsistent,
                "",
                "message does not survive its own round trip",
            ));
        }
        Ok(value)
    }

    /// Canonical (RFC 8785) bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        Ok(json::to_canonical_bytes(&self.to_value()?))
    }

    /// A complete frame: header plus canonical body.
    pub fn to_frame(&self) -> Result<Vec<u8>, ProtocolError> {
        frame::encode(ContentType::Json, &self.to_canonical_bytes()?)
    }
}
