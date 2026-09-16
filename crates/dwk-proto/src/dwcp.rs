//! DWCP — the DireWolf Client Protocol. **Forward-compatible.**
//!
//! Clients ⇄ gateway. Third-party and older clients are real, so version skew
//! is expected (ADR-0023): unknown members are **preserved** and re-emitted,
//! and unknown messages are returned to the caller as [`DwcpBody::Unknown`] to
//! be logged and skipped, not treated as fatal.
//!
//! What is *not* relaxed: lexical strictness (UTF-8, grammar, depth, duplicate
//! keys), envelope version support, and validation of every
//! field this version does declare. Forward compatibility means tolerating what
//! a newer peer adds, not accepting what no peer could mean.
//!
//! M2 defines only the DWCP envelope policy and one message, `direwolf.error`,
//! which is enough to prove preservation end to end. The client message set is
//! M19's, designed with the gateway it belongs to. DWCP carries no authority:
//! an approval travels it only as a kernel-rendered request and a
//! device-authenticated response (ADR-0022, M6/M20).

use crate::envelope::{EnvelopeRules, Header, MessageType, Presence, decode_header, read_preamble};
use crate::error::ProtocolError;
use crate::json::{self, Object, ParseOptions, Value};
use crate::limits::MAX_MESSAGE_BYTES;
use crate::version::{SUPPORTED_ENVELOPE, VersionRange};
use crate::wire::macros::wire_struct;
use crate::wire::scalar::{ClientErrorCode, Detail};
use crate::wire::{Cx, UnknownFields, WireType};

wire_struct! {
    /// A request failed, or the gateway is reporting a problem.
    ClientError: preserve {
        /// An open-ended error code; clients must accept codes newer than they are.
        required code: ClientErrorCode,
        /// Human-readable explanation.
        required detail: Detail,
        /// Whether retrying the same request may succeed.
        required retryable: bool,
    }
}

/// A DWCP message this build knows.
#[derive(Debug, Clone, Copy)]
pub struct DwcpMessageSpec {
    /// `schema`
    pub schema: &'static str,
    /// `type`
    pub message_type: MessageType,
    /// Supported `schema_version`s.
    pub versions: VersionRange,
    /// Envelope presence rules.
    pub rules: EnvelopeRules,
    /// Payload type name.
    pub payload: &'static str,
    /// One-line description.
    pub summary: &'static str,
}

/// DWCP messages defined by M2.
pub const MESSAGES: &[DwcpMessageSpec] = &[DwcpMessageSpec {
    schema: "direwolf.error",
    message_type: MessageType::Response,
    versions: VersionRange { min: 1, max: 1 },
    rules: EnvelopeRules {
        correlation_id: Presence::Optional,
        causation_id: Presence::Optional,
        session_id: Presence::Optional,
        run_id: Presence::Optional,
        epoch: Presence::Forbidden,
        idempotency_key: Presence::Forbidden,
    },
    payload: "ClientError",
    summary: "A request failed or the gateway reports a problem.",
}];

/// A decoded DWCP body.
#[derive(Debug, Clone, PartialEq)]
pub enum DwcpBody {
    /// `direwolf.error`
    Error(ClientError),
    /// A message this build does not know, or a known schema at a
    /// `schema_version` it does not know. Retained so it can be logged,
    /// skipped and, if relayed, re-emitted without loss.
    Unknown {
        /// The payload, as received.
        payload: Object,
    },
}

/// A decoded DWCP message.
#[derive(Debug, Clone, PartialEq)]
pub struct DwcpMessage {
    /// The envelope.
    pub header: Header,
    /// Envelope members this build does not declare, preserved.
    pub header_extensions: Object,
    /// The payload.
    pub body: DwcpBody,
}

/// Decode a DWCP message.
pub fn decode(bytes: &[u8]) -> Result<DwcpMessage, ProtocolError> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::new(
            crate::error::ErrorCode::FrameTooLarge,
            format!(
                "message of {} bytes exceeds {MAX_MESSAGE_BYTES}",
                bytes.len()
            ),
        ));
    }
    let value = json::parse(bytes, ParseOptions::ijson())?;
    let preamble = read_preamble(&value, SUPPORTED_ENVELOPE)?;
    let known = MESSAGES.iter().find(|m| {
        m.message_type == preamble.message_type
            && m.schema == preamble.schema.as_str()
            && m.versions.contains(preamble.schema_version.get())
    });
    if let Some(spec) = known {
        let (header, payload, header_extensions) =
            decode_header(value, preamble, spec.rules, UnknownFields::Preserve)?;
        let mut cx = Cx::new();
        cx.push("payload");
        let body = DwcpBody::Error(ClientError::decode(Value::Object(payload), &mut cx)?);
        return Ok(DwcpMessage {
            header,
            header_extensions,
            body,
        });
    }
    let (header, payload, header_extensions) = decode_header(
        value,
        preamble,
        EnvelopeRules::PERMISSIVE,
        UnknownFields::Preserve,
    )?;
    Ok(DwcpMessage {
        header,
        header_extensions,
        body: DwcpBody::Unknown { payload },
    })
}

impl DwcpMessage {
    /// Encode to a JSON value, re-emitting every preserved member.
    pub fn to_value(&self) -> Result<Value, ProtocolError> {
        let payload = match &self.body {
            DwcpBody::Error(e) => e.encode()?,
            DwcpBody::Unknown { payload } => Value::Object(payload.clone()),
        };
        self.header.encode(payload, &self.header_extensions)
    }

    /// Canonical (RFC 8785) bytes. Preserved extension values are re-emitted as
    /// values: I-JSON numbers keep their double-precision value, which is the
    /// only value any conforming DWCP peer (including a browser) could have
    /// meant.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        Ok(json::to_canonical_bytes(&self.to_value()?))
    }
}
