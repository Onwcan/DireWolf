//! DWKP — the DireWolf Kernel Protocol. **Strict.**
//!
//! The authority boundary. Every message is a request for authority or an
//! answer to one, so ambiguity here is authorisation ambiguity later
//! (ADR-0023). Decoding a DWKP frame body, in order:
//!
//! 1. [`crate::json::parse`] with the DWKP profile: UTF-8, RFC 8259 grammar,
//!    depth ≤ 32, no duplicate or NFC-colliding keys, safe integers only.
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

pub mod messages;
pub mod registry;

use crate::envelope::{Header, MessageType, decode_header, read_preamble};
use crate::error::{ErrorCode, ProtocolError, Violation};
use crate::frame::{self, ContentType};
use crate::json::{self, ParseOptions, Value};
use crate::version::SUPPORTED_ENVELOPE;
use crate::wire::{Cx, UnknownFields, WireType};
use messages::{
    Ack, Handshake, HandshakeAccepted, HeartbeatPayload, LeaseAcquire, LeaseGrant, LeaseRelease,
    ProtocolErrorPayload,
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
    /// `direwolf.ack`
    Ack(Ack),
    /// `direwolf.protocol.error`
    ProtocolError(ProtocolErrorPayload),
}

impl DwkpBody {
    /// The `(type, schema)` this body is sent as.
    #[must_use]
    pub const fn identity(&self) -> (MessageType, &'static str) {
        match self {
            Self::Handshake(_) => (MessageType::Request, "direwolf.handshake"),
            Self::HandshakeAccepted(_) => (MessageType::Response, "direwolf.handshake.accepted"),
            Self::Heartbeat(_) => (MessageType::Request, "direwolf.heartbeat"),
            Self::LeaseAcquire(_) => (MessageType::Request, "direwolf.lease.acquire"),
            Self::LeaseGrant(_) => (MessageType::Response, "direwolf.lease.grant"),
            Self::LeaseRelease(_) => (MessageType::Request, "direwolf.lease.release"),
            Self::Ack(_) => (MessageType::Response, "direwolf.ack"),
            Self::ProtocolError(_) => (MessageType::Response, "direwolf.protocol.error"),
        }
    }

    fn decode(schema: &str, payload: Value, cx: &mut Cx) -> Result<Self, ProtocolError> {
        Ok(match schema {
            "direwolf.handshake" => Self::Handshake(WireType::decode(payload, cx)?),
            "direwolf.handshake.accepted" => {
                Self::HandshakeAccepted(WireType::decode(payload, cx)?)
            }
            "direwolf.heartbeat" => Self::Heartbeat(WireType::decode(payload, cx)?),
            "direwolf.lease.acquire" => Self::LeaseAcquire(WireType::decode(payload, cx)?),
            "direwolf.lease.grant" => Self::LeaseGrant(WireType::decode(payload, cx)?),
            "direwolf.lease.release" => Self::LeaseRelease(WireType::decode(payload, cx)?),
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
    let spec =
        registry::message(preamble.message_type, preamble.schema.as_str()).ok_or_else(|| {
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
    if !spec.versions.contains(preamble.schema_version.get()) {
        return Err(ProtocolError::new(
            ErrorCode::VersionUnsupported,
            format!(
                "{} schema_version {} is not supported",
                spec.schema,
                preamble.schema_version.get()
            ),
        )
        .with_violation(Violation::OutOfRange)
        .with_path("/schema_version")
        .with_supported(spec.versions));
    }
    let schema = spec.schema;
    let (header, payload, _) = decode_header(value, preamble, spec.rules, UnknownFields::Reject)?;
    let mut cx = Cx::new();
    cx.push("payload");
    let body = DwkpBody::decode(schema, Value::Object(payload), &mut cx)?;
    Ok(DwkpMessage { header, body })
}

impl DwkpMessage {
    /// Encode to a JSON value.
    ///
    /// The result is **re-decoded before it is returned**. A message this
    /// crate would reject is a message it must never emit, and checking by
    /// round trip means the encoder cannot drift from the decoder.
    pub fn to_value(&self) -> Result<Value, ProtocolError> {
        let (message_type, schema) = self.body.identity();
        if self.header.message_type != message_type || self.header.schema.as_str() != schema {
            return Err(ProtocolError::schema(
                Violation::Inconsistent,
                "/schema",
                "the header's type and schema do not match the body",
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
