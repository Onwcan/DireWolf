//! The common envelope (`PROTOCOL.md` §1).
//!
//! Every message in every family — DWKP, DWCP and event records — has the same
//! envelope. What differs between families is the policy applied to it
//! (ADR-0023); what differs between operations is which optional envelope
//! fields are required, permitted or forbidden, declared per message in
//! [`EnvelopeRules`].
//!
//! # Decode order
//!
//! Fixed, so that every implementation reports the same failure for the same
//! input:
//!
//! 1. The document is an object.
//! 2. `v` — present, an integer, in range, and **supported**. Checked before
//!    anything else because a newer envelope may legitimately contain fields
//!    this receiver does not know; the right answer to such a message is
//!    `PROTOCOL_VERSION_UNSUPPORTED`, not `UNKNOWN_FIELD`.
//! 3. `type`, then `schema`, then `schema_version` — enough to identify the
//!    message. The family then looks it up.
//! 4. Undeclared envelope members (rejected or preserved by family).
//! 5. `id`, `ts`, `correlation_id`, `causation_id`, `session_id`, `run_id`,
//!    `epoch`, `idempotency_key`, each against the message's presence rule.
//! 6. Cross-field rules: an `epoch` requires a `session_id`; the `id` prefix
//!    matches the message type.
//! 7. `payload` — present and an object. Its contents are the family's concern.
//!
//! # Ownership of envelope fields
//!
//! The envelope carries **claims, not facts**. `ts` is the sender's clock.
//! `session_id`, `run_id` and `epoch` name authority the kernel issued; the
//! kernel checks them against `kernel.db` and never believes them
//! (ADR-0028, `PROTOCOL.md` §3). No envelope field is a policy input.

use crate::error::{ProtocolError, Violation, quote_key};
use crate::json::{Object, Value};
use crate::schema::Defs;
use crate::version::VersionRange;
use crate::wire::id::{AnyId, RunId, SessionId};
use crate::wire::scalar::{Epoch, IdempotencyKey, SchemaName, Timestamp, Version, wire_enum};
use crate::wire::{Cx, UnknownFields, WireType, partition_members, take_optional, take_required};

wire_enum! {
    /// What kind of message this is.
    MessageType {
        /// Sent by an initiator, expecting a response.
        Request = "request",
        /// Answers a request; carries the request id as `causation_id`.
        Response = "response",
        /// Records that something happened.
        Event = "event",
    }
}

impl MessageType {
    /// The identifier prefix messages of this type use for `id`.
    #[must_use]
    pub const fn id_prefix(self) -> &'static str {
        match self {
            Self::Request | Self::Response => "msg",
            Self::Event => "evt",
        }
    }
}

/// Whether an optional envelope field may appear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// Must be present.
    Required,
    /// May be present.
    Optional,
    /// Must be absent. A field with no meaning for an operation is a field that
    /// could carry an ambiguous meaning, so it is refused.
    Forbidden,
}

impl Presence {
    /// Wire spelling, as used in schema annotations.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Optional => "optional",
            Self::Forbidden => "forbidden",
        }
    }
}

/// Per-message presence rules for the optional envelope fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeRules {
    /// `correlation_id`
    pub correlation_id: Presence,
    /// `causation_id`
    pub causation_id: Presence,
    /// `session_id`
    pub session_id: Presence,
    /// `run_id`
    pub run_id: Presence,
    /// `epoch`
    pub epoch: Presence,
    /// `idempotency_key` — mandatory on any request with a side effect
    /// (`PROTOCOL.md` §1); no M2 operation has one.
    pub idempotency_key: Presence,
}

impl EnvelopeRules {
    /// Every optional field permitted, none required. Used to inspect messages
    /// whose schema the receiver does not know (DWCP, events).
    pub const PERMISSIVE: Self = Self {
        correlation_id: Presence::Optional,
        causation_id: Presence::Optional,
        session_id: Presence::Optional,
        run_id: Presence::Optional,
        epoch: Presence::Optional,
        idempotency_key: Presence::Optional,
    };

    /// The rules as `(field name, presence)` pairs, in decode order.
    #[must_use]
    pub const fn fields(&self) -> [(&'static str, Presence); 6] {
        [
            ("correlation_id", self.correlation_id),
            ("causation_id", self.causation_id),
            ("session_id", self.session_id),
            ("run_id", self.run_id),
            ("epoch", self.epoch),
            ("idempotency_key", self.idempotency_key),
        ]
    }
}

/// Every key the envelope declares.
pub const ENVELOPE_KEYS: [&str; 13] = [
    "v",
    "id",
    "type",
    "schema",
    "schema_version",
    "ts",
    "correlation_id",
    "causation_id",
    "session_id",
    "run_id",
    "epoch",
    "idempotency_key",
    "payload",
];

/// Enough of the envelope to identify a message: steps 1–3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preamble {
    /// Envelope version, already checked against the receiver's support.
    pub v: Version,
    /// Message type.
    pub message_type: MessageType,
    /// Message schema name.
    pub schema: SchemaName,
    /// Schema version (not yet checked against a registry).
    pub schema_version: Version,
}

/// The decoded envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Envelope version.
    pub v: Version,
    /// Message id; prefix `msg` for requests and responses, `evt` for events.
    pub id: AnyId,
    /// Message type.
    pub message_type: MessageType,
    /// Message schema name.
    pub schema: SchemaName,
    /// Schema version.
    pub schema_version: Version,
    /// Sender's timestamp. Advisory.
    pub ts: Timestamp,
    /// Groups the messages of one logical operation.
    pub correlation_id: Option<AnyId>,
    /// The message or event that directly caused this one.
    pub causation_id: Option<AnyId>,
    /// Session the message concerns. A claim the kernel verifies.
    pub session_id: Option<SessionId>,
    /// Run the message concerns. A claim the kernel verifies.
    pub run_id: Option<RunId>,
    /// Lease epoch the sender believes it holds. The kernel fences on it.
    pub epoch: Option<Epoch>,
    /// Idempotency key for side-effecting requests.
    pub idempotency_key: Option<IdempotencyKey>,
}

/// Steps 1–3: identify the message without interpreting anything else.
pub fn read_preamble(value: &Value, supported: VersionRange) -> Result<Preamble, ProtocolError> {
    let Value::Object(object) = value else {
        return Err(ProtocolError::schema(
            Violation::WrongType,
            "",
            format!("a message is an object, found {}", value.type_name()),
        ));
    };
    let mut cx = Cx::new();

    let v: Version = peek_required(object, "v", &mut cx)?;
    if !supported.contains(v.get()) {
        return Err(ProtocolError::new(
            crate::error::ErrorCode::VersionUnsupported,
            format!(
                "envelope version {} is not supported; supported {}..={}",
                v.get(),
                supported.min,
                supported.max
            ),
        )
        .with_violation(Violation::OutOfRange)
        .with_path("/v")
        .with_supported(supported));
    }
    let message_type: MessageType = peek_required(object, "type", &mut cx)?;
    let schema: SchemaName = peek_required(object, "schema", &mut cx)?;
    let schema_version: Version = peek_required(object, "schema_version", &mut cx)?;
    Ok(Preamble {
        v,
        message_type,
        schema,
        schema_version,
    })
}

fn peek_required<T: WireType>(
    object: &Object,
    name: &str,
    cx: &mut Cx,
) -> Result<T, ProtocolError> {
    cx.push(name);
    let result = match object.get(name) {
        None => {
            cx.pop();
            return Err(ProtocolError::schema(
                Violation::MissingField,
                "",
                format!("missing envelope field {}", quote_key(name)),
            )
            .with_path(&format!("/{name}")));
        }
        Some(Value::Null) => Err(cx.violation(Violation::NullNotAllowed, "null is not a value")),
        Some(value) => T::decode(value.clone(), cx),
    };
    cx.pop();
    result
}

/// Steps 4–7: decode the rest of the envelope against `rules`.
///
/// Returns the header, the raw payload object, and any preserved undeclared
/// envelope members (always empty under [`UnknownFields::Reject`]).
pub fn decode_header(
    value: Value,
    preamble: Preamble,
    rules: EnvelopeRules,
    unknown: UnknownFields,
) -> Result<(Header, Object, Object), ProtocolError> {
    let Value::Object(object) = value else {
        return Err(ProtocolError::schema(
            Violation::WrongType,
            "",
            "a message is an object",
        ));
    };
    let mut cx = Cx::new();
    let (mut members, extensions) = partition_members(object, &ENVELOPE_KEYS, unknown, &cx)?;

    let id: AnyId = take_required(&mut members, "id", &mut cx)?;
    let ts: Timestamp = take_required(&mut members, "ts", &mut cx)?;
    let correlation_id = take_ruled(
        &mut members,
        "correlation_id",
        rules.correlation_id,
        &mut cx,
    )?;
    let causation_id = take_ruled(&mut members, "causation_id", rules.causation_id, &mut cx)?;
    let session_id = take_ruled(&mut members, "session_id", rules.session_id, &mut cx)?;
    let run_id = take_ruled(&mut members, "run_id", rules.run_id, &mut cx)?;
    let epoch: Option<Epoch> = take_ruled(&mut members, "epoch", rules.epoch, &mut cx)?;
    let idempotency_key = take_ruled(
        &mut members,
        "idempotency_key",
        rules.idempotency_key,
        &mut cx,
    )?;

    if epoch.is_some() && session_id.is_none() {
        return Err(ProtocolError::schema(
            Violation::Inconsistent,
            "/epoch",
            "an epoch is meaningful only for a session; session_id is required with epoch",
        ));
    }
    let expected_prefix = preamble.message_type.id_prefix();
    if id.prefix() != expected_prefix {
        return Err(ProtocolError::schema(
            Violation::InvalidFormat,
            "/id",
            format!(
                "a {} uses a {expected_prefix}_ id",
                preamble.message_type.as_str()
            ),
        ));
    }

    let payload = match members.iter().position(|(k, _)| k == "payload") {
        None => {
            return Err(ProtocolError::schema(
                Violation::MissingField,
                "/payload",
                "missing envelope field \"payload\"",
            ));
        }
        Some(index) => members.remove(index).1,
    };
    let payload = match payload {
        Value::Object(object) => object,
        Value::Null => {
            return Err(ProtocolError::schema(
                Violation::NullNotAllowed,
                "/payload",
                "null is not a value",
            ));
        }
        other => {
            return Err(ProtocolError::schema(
                Violation::WrongType,
                "/payload",
                format!("expected object, found {}", other.type_name()),
            ));
        }
    };

    let header = Header {
        v: preamble.v,
        id,
        message_type: preamble.message_type,
        schema: preamble.schema,
        schema_version: preamble.schema_version,
        ts,
        correlation_id,
        causation_id,
        session_id,
        run_id,
        epoch,
        idempotency_key,
    };
    Ok((header, payload, extensions))
}

fn take_ruled<T: WireType>(
    members: &mut Vec<(String, Value)>,
    name: &str,
    presence: Presence,
    cx: &mut Cx,
) -> Result<Option<T>, ProtocolError> {
    let present = members.iter().any(|(k, _)| k == name);
    match (presence, present) {
        (Presence::Forbidden, true) => Err(ProtocolError::schema(
            Violation::ForbiddenField,
            &format!("/{name}"),
            format!(
                "envelope field {} is not permitted for this operation",
                quote_key(name)
            ),
        )),
        (Presence::Forbidden, false) => Ok(None),
        (Presence::Required, _) => take_required(members, name, cx).map(Some),
        (Presence::Optional, _) => take_optional(members, name, cx),
    }
}

impl Header {
    /// Encode the envelope around `payload`, re-emitting preserved members.
    pub fn encode(&self, payload: Value, extensions: &Object) -> Result<Value, ProtocolError> {
        let mut object = Object::new();
        object.insert("v".to_owned(), self.v.encode()?)?;
        object.insert("id".to_owned(), self.id.encode()?)?;
        object.insert("type".to_owned(), self.message_type.encode()?)?;
        object.insert("schema".to_owned(), self.schema.encode()?)?;
        object.insert("schema_version".to_owned(), self.schema_version.encode()?)?;
        object.insert("ts".to_owned(), self.ts.encode()?)?;
        put_optional(&mut object, "correlation_id", self.correlation_id.as_ref())?;
        put_optional(&mut object, "causation_id", self.causation_id.as_ref())?;
        put_optional(&mut object, "session_id", self.session_id.as_ref())?;
        put_optional(&mut object, "run_id", self.run_id.as_ref())?;
        put_optional(&mut object, "epoch", self.epoch.as_ref())?;
        put_optional(
            &mut object,
            "idempotency_key",
            self.idempotency_key.as_ref(),
        )?;
        object.insert("payload".to_owned(), payload)?;
        for (key, value) in extensions.iter() {
            object.insert(key.to_owned(), value.clone())?;
        }
        Ok(Value::Object(object))
    }
}

fn put_optional<T: WireType>(
    object: &mut Object,
    name: &str,
    value: Option<&T>,
) -> Result<(), ProtocolError> {
    match value {
        Some(v) => object.insert(name.to_owned(), v.encode()?),
        None => Ok(()),
    }
}

/// Schema nodes for the envelope fields, keyed by field name.
pub fn field_schema(name: &str, defs: &mut Defs) -> Option<Value> {
    Some(match name {
        "id" | "correlation_id" | "causation_id" => AnyId::schema(defs),
        "ts" => Timestamp::schema(defs),
        "session_id" => SessionId::schema(defs),
        "run_id" => RunId::schema(defs),
        "epoch" => Epoch::schema(defs),
        "idempotency_key" => IdempotencyKey::schema(defs),
        _ => return None,
    })
}
