//! Event-log records. **Retained verbatim.**
//!
//! Events outlive the code that wrote them (`PROTOCOL.md` §6). The guarantee
//! here is not "an old reader does not crash on a new event" — it is **an old
//! reader that reads and re-writes a log loses nothing**. So a record is kept
//! as its original bytes, always, and the typed view is a projection over those
//! bytes rather than a replacement for them.
//!
//! [`EventRecord::read`] fails only when the bytes are not a record at all:
//! oversized, not UTF-8, not grammatical JSON, a duplicate or NFC-colliding
//! key, too deep, or not an object. Those are corruption, and M8 quarantines
//! them. Every other outcome — a known event, an unknown schema, an unknown
//! schema version, an unsupported envelope version, even a known event whose
//! fields fail validation — produces a record whose bytes are intact and whose
//! [`EventView`] says how far interpretation got.
//!
//! Security-relevant events (`tool.*`, `approval.*`, `grant.*`, `secret.*`,
//! `policy.*`, `budget.*`) are written by the kernel to the audit chain, not by
//! the runtime to this log (`PROTOCOL.md` §5). A record here is never evidence
//! that an effect was authorised.

use crate::envelope::{EnvelopeRules, Header, MessageType, Presence, decode_header, read_preamble};
use crate::error::{ErrorCode, ProtocolError};
use crate::json::{self, Object, ParseOptions, Value};
use crate::limits::MAX_MESSAGE_BYTES;
use crate::version::{SUPPORTED_ENVELOPE, VersionRange};
use crate::wire::macros::wire_struct;
use crate::wire::scalar::Epoch;
use crate::wire::{Cx, UnknownFields, WireType};

wire_struct! {
    /// The runtime acquired the lease for the session in the envelope.
    ///
    /// A **cache** of a kernel fact: the kernel assigned the epoch and holds
    /// the authoritative value in `kernel.db` (ADR-0028). Where this record and
    /// the kernel disagree, the kernel is right.
    LeaseAcquired: preserve {
        /// The epoch the kernel granted.
        required epoch: Epoch,
    }
}

/// An event schema this build knows.
#[derive(Debug, Clone, Copy)]
pub struct EventSpec {
    /// `schema`
    pub schema: &'static str,
    /// Supported `schema_version`s.
    pub versions: VersionRange,
    /// Envelope presence rules.
    pub rules: EnvelopeRules,
    /// Payload type name.
    pub payload: &'static str,
    /// One-line description.
    pub summary: &'static str,
}

/// Event schemas defined by M2. The rest of the event catalogue
/// (`PROTOCOL.md` §5) is defined with the subsystems that emit it.
pub const EVENTS: &[EventSpec] = &[EventSpec {
    schema: "direwolf.session.lease_acquired",
    versions: VersionRange { min: 1, max: 1 },
    rules: EnvelopeRules {
        correlation_id: Presence::Optional,
        causation_id: Presence::Optional,
        session_id: Presence::Required,
        run_id: Presence::Forbidden,
        epoch: Presence::Forbidden,
        idempotency_key: Presence::Forbidden,
    },
    payload: "LeaseAcquired",
    summary: "The runtime acquired a session lease (a cache of a kernel fact).",
}];

/// A typed event.
#[derive(Debug, Clone, PartialEq)]
pub enum KnownEvent {
    /// `direwolf.session.lease_acquired`
    LeaseAcquired(LeaseAcquired),
}

/// How far a record was interpreted.
#[derive(Debug, Clone, PartialEq)]
pub enum EventView {
    /// A known schema at a known version, fully decoded.
    Known {
        /// The envelope.
        header: Header,
        /// Envelope members this build does not declare.
        header_extensions: Object,
        /// The event.
        event: KnownEvent,
    },
    /// A schema or version this build does not know. Skipped by projectors,
    /// retained by the log.
    Unknown {
        /// The `schema` value, if it was a well-formed schema name.
        schema: Option<String>,
        /// The `schema_version`, if it was a well-formed version.
        schema_version: Option<u16>,
        /// Why the record could not be interpreted further.
        reason: ProtocolError,
    },
    /// A known schema whose fields fail validation. Retained, surfaced, never
    /// silently repaired.
    Invalid {
        /// What failed.
        error: ProtocolError,
    },
}

/// One event-log record: its exact bytes and its interpretation.
#[derive(Debug, Clone, PartialEq)]
pub struct EventRecord {
    raw: Vec<u8>,
    view: EventView,
}

impl EventRecord {
    /// Read a record.
    pub fn read(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(ProtocolError::new(
                ErrorCode::FrameTooLarge,
                format!(
                    "record of {} bytes exceeds {MAX_MESSAGE_BYTES}",
                    bytes.len()
                ),
            ));
        }
        let value = json::parse(bytes, ParseOptions::ijson())?;
        let Value::Object(object) = &value else {
            return Err(ProtocolError::schema(
                crate::error::Violation::WrongType,
                "",
                "an event record is an object",
            ));
        };
        let view = interpret(object, value.clone());
        Ok(Self {
            raw: bytes.to_vec(),
            view,
        })
    }

    /// The exact bytes that were read. Re-writing a log writes these.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// The interpretation.
    #[must_use]
    pub const fn view(&self) -> &EventView {
        &self.view
    }

    /// Create a new record from a known event, in canonical form.
    pub fn create(header: &Header, event: &KnownEvent) -> Result<Self, ProtocolError> {
        let payload = match event {
            KnownEvent::LeaseAcquired(e) => e.encode()?,
        };
        let bytes = json::to_canonical_bytes(&header.encode(payload, &Object::new())?);
        let record = Self::read(&bytes)?;
        match record.view {
            EventView::Known { .. } => Ok(record),
            EventView::Unknown { reason, .. } | EventView::Invalid { error: reason } => Err(reason),
        }
    }
}

fn interpret(object: &Object, value: Value) -> EventView {
    let schema = match object.get("schema") {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    };
    let schema_version = match object.get("schema_version") {
        Some(Value::Number(json::Number::Int(i))) => u16::try_from(*i).ok(),
        _ => None,
    };
    let preamble = match read_preamble(&value, SUPPORTED_ENVELOPE) {
        Ok(p) => p,
        Err(reason) => {
            return EventView::Unknown {
                schema,
                schema_version,
                reason,
            };
        }
    };
    if preamble.message_type != MessageType::Event {
        return EventView::Invalid {
            error: ProtocolError::schema(
                crate::error::Violation::UnknownVariant,
                "/type",
                "an event record has type \"event\"",
            ),
        };
    }
    let Some(spec) = EVENTS.iter().find(|e| {
        e.schema == preamble.schema.as_str() && e.versions.contains(preamble.schema_version.get())
    }) else {
        return EventView::Unknown {
            schema,
            schema_version,
            reason: ProtocolError::new(
                ErrorCode::UnknownOperation,
                "this build does not know that event schema and version",
            )
            .with_path("/schema"),
        };
    };
    let decoded = decode_header(value, preamble, spec.rules, UnknownFields::Preserve).and_then(
        |(header, payload, header_extensions)| {
            let mut cx = Cx::new();
            cx.push("payload");
            let event =
                KnownEvent::LeaseAcquired(LeaseAcquired::decode(Value::Object(payload), &mut cx)?);
            Ok(EventView::Known {
                header,
                header_extensions,
                event,
            })
        },
    );
    decoded.unwrap_or_else(|error| EventView::Invalid { error })
}
