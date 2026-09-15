//! Assemble every schema this build emits.
//!
//! Pure: returns `(relative path, document)` pairs and touches no filesystem.
//! `tools/protogen` writes them; the drift check regenerates and compares.
//!
//! Each message gets one **self-contained** document: the whole envelope with
//! this message's presence rules, and its payload under `$defs`. A reader can
//! validate a message against one file without resolving anything else, and a
//! reviewer can read one file to see everything a message may contain.

use crate::dwcp;
use crate::dwkp::messages::{
    Ack, Handshake, HandshakeAccepted, HeartbeatPayload, LeaseAcquire, LeaseGrant, LeaseRelease,
    ProtocolErrorPayload,
};
use crate::dwkp::registry::{self, OPERATIONS};
use crate::envelope::{EnvelopeRules, MessageType, Presence, field_schema};
use crate::events::{self, LeaseAcquired};
use crate::json::{Object, Value};
use crate::schema::{DIALECT, Defs, description, int, obj, string, strings};
use crate::version::{SUPPORTED_ENVELOPE, VersionRange};
use crate::wire::id::{EventId, MessageId};
use crate::wire::scalar::Timestamp;
use crate::wire::{UnknownFields, WireType};

/// A protocol family, as it appears in schema paths and annotations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// Kernel protocol.
    Dwkp,
    /// Client protocol.
    Dwcp,
    /// Event-log records.
    Events,
}

impl Family {
    /// Directory name under `schemas/`.
    #[must_use]
    pub const fn dir(self) -> &'static str {
        match self {
            Self::Dwkp => "dwkp",
            Self::Dwcp => "dwcp",
            Self::Events => "events",
        }
    }

    const fn unknown(self) -> UnknownFields {
        match self {
            Self::Dwkp => UnknownFields::Reject,
            Self::Dwcp | Self::Events => UnknownFields::Preserve,
        }
    }
}

/// Resolve a payload type name to its schema. `None` for a name no type has.
#[must_use]
pub fn payload_schema(name: &str, defs: &mut Defs) -> Option<Value> {
    Some(match name {
        "Handshake" => Handshake::schema(defs),
        "HandshakeAccepted" => HandshakeAccepted::schema(defs),
        "HeartbeatPayload" => HeartbeatPayload::schema(defs),
        "LeaseAcquire" => LeaseAcquire::schema(defs),
        "LeaseGrant" => LeaseGrant::schema(defs),
        "LeaseRelease" => LeaseRelease::schema(defs),
        "Ack" => Ack::schema(defs),
        "ProtocolErrorPayload" => ProtocolErrorPayload::schema(defs),
        "ClientError" => dwcp::ClientError::schema(defs),
        "LeaseAcquired" => LeaseAcquired::schema(defs),
        _ => return None,
    })
}

/// Every emitted document, sorted by path.
#[must_use]
pub fn all() -> Vec<(String, Value)> {
    let mut out = Vec::new();
    for m in registry::MESSAGES {
        push_versions(
            &mut out,
            Family::Dwkp,
            m.schema,
            m.message_type,
            m.versions,
            m.rules,
            m.payload,
            m.summary,
        );
    }
    for m in dwcp::MESSAGES {
        push_versions(
            &mut out,
            Family::Dwcp,
            m.schema,
            m.message_type,
            m.versions,
            m.rules,
            m.payload,
            m.summary,
        );
    }
    for e in events::EVENTS {
        push_versions(
            &mut out,
            Family::Events,
            e.schema,
            MessageType::Event,
            e.versions,
            e.rules,
            e.payload,
            e.summary,
        );
    }
    out.push(("dwkp/operations.json".to_owned(), operations()));
    out.push(("common/envelope.v1.schema.json".to_owned(), envelope()));
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[allow(clippy::too_many_arguments)]
fn push_versions(
    out: &mut Vec<(String, Value)>,
    family: Family,
    schema: &str,
    message_type: MessageType,
    versions: VersionRange,
    rules: EnvelopeRules,
    payload: &str,
    summary: &str,
) {
    for version in versions.min..=versions.max {
        let path = format!("{}/{schema}.v{version}.schema.json", family.dir());
        out.push((
            path,
            message(
                family,
                schema,
                message_type,
                version,
                versions,
                rules,
                payload,
                summary,
            ),
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn message(
    family: Family,
    schema: &str,
    message_type: MessageType,
    version: u16,
    versions: VersionRange,
    rules: EnvelopeRules,
    payload: &str,
    summary: &str,
) -> Value {
    let mut defs = Defs::new();
    let mut properties = fixed_properties(&mut defs, message_type, schema, version);
    let mut required = vec!["v", "id", "type", "schema", "schema_version", "ts"];

    let mut forbidden = Vec::new();
    let mut presence = Object::new();
    for (name, rule) in rules.fields() {
        let _ = presence.insert(name.to_owned(), string(rule.as_str()));
        match rule {
            Presence::Forbidden => forbidden.push(name),
            Presence::Required | Presence::Optional => {
                if let Some(s) = field_schema(name, &mut defs) {
                    let _ = properties.insert(name.to_owned(), s);
                }
                if rule == Presence::Required {
                    required.push(name);
                }
            }
        }
    }
    let payload_ref = payload_schema(payload, &mut defs).unwrap_or(Value::Null);
    let _ = properties.insert("payload".to_owned(), payload_ref);
    required.push("payload");

    let mut members: Vec<(&str, Value)> = vec![
        ("$schema", string(DIALECT)),
        (
            "$id",
            string(&format!(
                "urn:direwolf:schema:{}:{schema}:{version}",
                family.dir()
            )),
        ),
        ("title", string(&format!("{schema} v{version}"))),
        ("description", description(summary)),
        ("type", string("object")),
        ("properties", Value::Object(properties)),
        ("required", strings(&required)),
    ];
    if family.unknown() == UnknownFields::Reject {
        members.push(("additionalProperties", Value::Bool(false)));
    }
    if !forbidden.is_empty() {
        let any_of = forbidden
            .iter()
            .map(|f| obj(vec![("required", strings(&[f]))]))
            .collect();
        members.push(("not", obj(vec![("anyOf", Value::Array(any_of))])));
    }
    if rules.epoch != Presence::Forbidden {
        members.push((
            "dependentRequired",
            obj(vec![("epoch", strings(&["session_id"]))]),
        ));
    }
    members.extend(annotations(
        family,
        schema,
        message_type,
        versions,
        presence,
        payload,
    ));
    members.push(("$defs", defs.into_value()));
    obj(members)
}

/// The envelope members every message has, in emission order.
fn fixed_properties(
    defs: &mut Defs,
    message_type: MessageType,
    schema: &str,
    version: u16,
) -> Object {
    let mut properties = Object::new();

    let _ = properties.insert(
        "v".to_owned(),
        obj(vec![
            ("type", string("integer")),
            ("minimum", int(i64::from(SUPPORTED_ENVELOPE.min))),
            ("maximum", int(i64::from(SUPPORTED_ENVELOPE.max))),
            ("x-direwolf-type", string("Version")),
        ]),
    );
    let id_schema = match message_type {
        MessageType::Event => EventId::schema(defs),
        MessageType::Request | MessageType::Response => MessageId::schema(defs),
    };
    let _ = properties.insert("id".to_owned(), id_schema);
    let _ = properties.insert(
        "type".to_owned(),
        obj(vec![
            ("const", string(message_type.as_str())),
            ("x-direwolf-type", string("MessageType")),
        ]),
    );
    let _ = properties.insert(
        "schema".to_owned(),
        obj(vec![
            ("const", string(schema)),
            ("x-direwolf-type", string("SchemaName")),
        ]),
    );
    let _ = properties.insert(
        "schema_version".to_owned(),
        obj(vec![
            ("type", string("integer")),
            ("minimum", int(i64::from(version))),
            ("maximum", int(i64::from(version))),
            ("x-direwolf-type", string("Version")),
        ]),
    );
    let _ = properties.insert("ts".to_owned(), Timestamp::schema(defs));
    properties
}

fn annotations(
    family: Family,
    schema: &str,
    message_type: MessageType,
    versions: VersionRange,
    presence: Object,
    payload: &str,
) -> [(&'static str, Value); 9] {
    [
        ("x-direwolf-family", string(family.dir())),
        ("x-direwolf-message-type", string(message_type.as_str())),
        ("x-direwolf-schema", string(schema)),
        (
            "x-direwolf-schema-versions",
            obj(vec![
                ("min", int(i64::from(versions.min))),
                ("max", int(i64::from(versions.max))),
            ]),
        ),
        (
            "x-direwolf-envelope-versions",
            obj(vec![
                ("min", int(i64::from(SUPPORTED_ENVELOPE.min))),
                ("max", int(i64::from(SUPPORTED_ENVELOPE.max))),
            ]),
        ),
        ("x-direwolf-envelope", Value::Object(presence)),
        ("x-direwolf-id-prefix", string(message_type.id_prefix())),
        (
            "x-direwolf-unknown-fields",
            string(match family.unknown() {
                UnknownFields::Reject => "reject",
                UnknownFields::Preserve => "preserve",
            }),
        ),
        ("x-direwolf-payload", string(payload)),
    ]
}

/// The envelope on its own, with every optional field permitted: the reference
/// for field formats that no single message schema shows (an operation that
/// forbids a field omits it). Implementations in other languages check their
/// envelope constants against this document.
fn envelope() -> Value {
    let mut defs = Defs::new();
    let mut properties = Object::new();
    let _ = properties.insert(
        "v".to_owned(),
        obj(vec![
            ("type", string("integer")),
            ("minimum", int(1)),
            ("maximum", int(i64::from(u16::MAX))),
            ("x-direwolf-type", string("Version")),
        ]),
    );
    let _ = properties.insert("id".to_owned(), crate::wire::id::AnyId::schema(&mut defs));
    let _ = properties.insert("type".to_owned(), MessageType::schema(&mut defs));
    let _ = properties.insert(
        "schema".to_owned(),
        crate::wire::scalar::SchemaName::schema(&mut defs),
    );
    let _ = properties.insert(
        "schema_version".to_owned(),
        obj(vec![
            ("type", string("integer")),
            ("minimum", int(1)),
            ("maximum", int(i64::from(u16::MAX))),
            ("x-direwolf-type", string("Version")),
        ]),
    );
    let _ = properties.insert("ts".to_owned(), Timestamp::schema(&mut defs));
    for (name, _) in EnvelopeRules::PERMISSIVE.fields() {
        if let Some(s) = field_schema(name, &mut defs) {
            let _ = properties.insert(name.to_owned(), s);
        }
    }
    let _ = properties.insert("payload".to_owned(), obj(vec![("type", string("object"))]));
    obj(vec![
        ("$schema", string(DIALECT)),
        ("$id", string("urn:direwolf:schema:common:envelope:1")),
        ("title", string("DireWolf envelope v1")),
        (
            "description",
            string(
                "The common envelope with every optional field permitted. Each message \
                 schema narrows it; this document is the reference for field formats.",
            ),
        ),
        ("type", string("object")),
        ("properties", Value::Object(properties)),
        (
            "required",
            strings(&[
                "v",
                "id",
                "type",
                "schema",
                "schema_version",
                "ts",
                "payload",
            ]),
        ),
        (
            "dependentRequired",
            obj(vec![("epoch", strings(&["session_id"]))]),
        ),
        (
            "x-direwolf-envelope-versions",
            obj(vec![
                ("min", int(i64::from(SUPPORTED_ENVELOPE.min))),
                ("max", int(i64::from(SUPPORTED_ENVELOPE.max))),
            ]),
        ),
        (
            "x-direwolf-id-prefixes",
            obj(vec![
                ("request", string("msg")),
                ("response", string("msg")),
                ("event", string("evt")),
            ]),
        ),
        ("$defs", defs.into_value()),
    ])
}

fn operations() -> Value {
    let rows = OPERATIONS
        .iter()
        .map(|op| {
            obj(vec![
                ("name", string(op.name)),
                ("layer", string(op.layer.as_str())),
                ("status", string(op.status.as_str())),
                ("request", op.request.map_or(Value::Null, string)),
                ("responses", strings(op.responses)),
                ("initiator", string(op.initiator)),
                ("receiver", string(op.receiver)),
                ("semantics_owner", string(op.semantics_owner)),
                ("effect_bearing", Value::Bool(op.effect_bearing)),
                ("authority_bearing", Value::Bool(op.authority_bearing)),
                ("carries", string(op.carries)),
                ("consumer", string(op.consumer)),
                ("second_path", string(op.second_path)),
            ])
        })
        .collect();
    obj(vec![
        (
            "$comment",
            string(
                "GENERATED from crates/dwk-proto/src/dwkp/registry.rs by tools/protogen. Do not edit.",
            ),
        ),
        ("operations", Value::Array(rows)),
    ])
}

#[cfg(test)]
mod tests {
    use super::{all, payload_schema};
    use crate::dwkp::registry::MESSAGES;
    use crate::json::{self, Value};
    use crate::schema::Defs;

    #[test]
    fn every_registered_payload_type_resolves() {
        let names = MESSAGES
            .iter()
            .map(|m| m.payload)
            .chain(crate::dwcp::MESSAGES.iter().map(|m| m.payload))
            .chain(crate::events::EVENTS.iter().map(|e| e.payload));
        for name in names {
            assert!(payload_schema(name, &mut Defs::new()).is_some(), "{name}");
        }
    }

    #[test]
    fn emission_is_deterministic() {
        let a: Vec<(String, Vec<u8>)> = all()
            .into_iter()
            .map(|(p, v)| (p, json::to_canonical_bytes(&v)))
            .collect();
        let b: Vec<(String, Vec<u8>)> = all()
            .into_iter()
            .map(|(p, v)| (p, json::to_canonical_bytes(&v)))
            .collect();
        assert_eq!(a, b);
    }

    #[test]
    fn no_emitted_document_contains_a_null_placeholder_schema() {
        for (path, doc) in all() {
            if let Value::Object(o) = &doc
                && let Some(Value::Object(props)) = o.get("properties")
            {
                assert!(props.get("payload") != Some(&Value::Null), "{path}");
            }
        }
    }
}
