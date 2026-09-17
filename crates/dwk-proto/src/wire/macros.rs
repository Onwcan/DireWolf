//! `wire_struct!` — one declaration, three consistent artefacts.
//!
//! ```ignore
//! wire_struct! {
//!     /// Documentation becomes the schema `description`.
//!     Handshake: reject {
//!         /// Lowest envelope version the sender speaks.
//!         required min_version: Version,
//!         required max_version: Version,
//!     }
//!     ordered(min_version <= max_version)
//! }
//! ```
//!
//! generates the struct, a strict decoder, an encoder, and its JSON Schema.
//!
//! * `reject` types fail on any undeclared member (DWKP).
//! * `preserve` types gain `pub extensions: Object` and keep undeclared members
//!   for re-emission (DWCP, events).
//!
//! The policy is part of the **type**, not of the call: a DWKP payload cannot be
//! decoded leniently by passing the wrong flag, because there is no flag.
//!
//! `ordered(a <= b)` is the only cross-field check. The closed set is deliberate:
//! every check must be mirrored by the Python generator, and an open-ended
//! "validate with this function" hook is a place for the two to diverge.

/// Map a field kind to its Rust type.
macro_rules! field_type {
    (required, $ty:ty) => { $ty };
    (optional, $ty:ty) => { Option<$ty> };
}

/// Decode a field of a given kind.
macro_rules! field_take {
    (required, $ty:ty, $members:expr, $name:expr, $cx:expr) => {
        $crate::wire::take_required::<$ty>($members, $name, $cx)
    };
    (optional, $ty:ty, $members:expr, $name:expr, $cx:expr) => {
        $crate::wire::take_optional::<$ty>($members, $name, $cx)
    };
}

/// Encode a field of a given kind into an object.
macro_rules! field_put {
    (required, $object:expr, $name:expr, $value:expr) => {
        $object.insert($name.to_owned(), $crate::wire::WireType::encode($value)?)
    };
    (optional, $object:expr, $name:expr, $value:expr) => {
        match $value {
            Some(v) => $object.insert($name.to_owned(), $crate::wire::WireType::encode(v)?),
            None => Ok(()),
        }
    };
}

/// Whether a field kind is required.
macro_rules! field_required {
    (required) => {
        true
    };
    (optional) => {
        false
    };
}

/// Declare a wire struct. See the module documentation.
macro_rules! wire_struct {
    // ---- reject: DWKP ------------------------------------------------------
    (
        $(#[doc = $doc:literal])*
        $name:ident: reject {
            $( $(#[doc = $fdoc:literal])* $kind:ident $field:ident: $ty:ty ),* $(,)?
        }
        $( ordered($lo:ident <= $hi:ident) )?
        $( paired($left:ident -> $right:ident, $table:expr) )?
    ) => {
        $(#[doc = $doc])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            $( $(#[doc = $fdoc])* pub $field: $crate::wire::macros::field_type!($kind, $ty), )*
        }

        impl $crate::wire::WireType for $name {
            #[allow(unused_mut, unused_variables)]
            fn decode(
                value: $crate::json::Value,
                cx: &mut $crate::wire::Cx,
            ) -> Result<Self, $crate::error::ProtocolError> {
                let object = match value {
                    $crate::json::Value::Object(object) => object,
                    other => return Err(cx.wrong_type("object", &other)),
                };
                let (mut members, _) = $crate::wire::partition_members(
                    object,
                    &[$(stringify!($field)),*],
                    $crate::wire::UnknownFields::Reject,
                    cx,
                )?;
                $( let $field = $crate::wire::macros::field_take!(
                    $kind, $ty, &mut members, stringify!($field), cx
                )?; )*
                let decoded = Self { $($field),* };
                $( $crate::wire::macros::check_ordered(
                    &decoded.$lo, &decoded.$hi, stringify!($lo), stringify!($hi), cx
                )?; )?
                $( $crate::wire::macros::check_paired(
                    decoded.$left.as_str(), decoded.$right.as_str(),
                    stringify!($left), stringify!($right), $table, cx
                )?; )?
                Ok(decoded)
            }

            #[allow(unused_mut)]
            fn encode(&self) -> Result<$crate::json::Value, $crate::error::ProtocolError> {
                let mut object = $crate::json::Object::new();
                $( $crate::wire::macros::field_put!(
                    $kind, object, stringify!($field), &self.$field
                )?; )*
                Ok($crate::json::Value::Object(object))
            }

            #[allow(unused_variables)]
            fn schema(defs: &mut $crate::schema::Defs) -> $crate::json::Value {
                defs.reference(stringify!($name), |defs| {
                    let check: Option<$crate::json::Value> = None
                        $( .or(Some($crate::wire::macros::ordered_schema(
                            stringify!($lo), stringify!($hi)
                        ))) )?
                        $( .or(Some($crate::wire::macros::paired_schema(
                            stringify!($left), stringify!($right), $table
                        ))) )?;
                    $crate::wire::macros::struct_schema(
                        concat!($($doc, "\n"),*),
                        vec![$( (
                            stringify!($field),
                            concat!($($fdoc, "\n"),*),
                            $crate::wire::macros::field_required!($kind),
                            <$ty as $crate::wire::WireType>::schema(defs),
                        ) ),*],
                        $crate::wire::UnknownFields::Reject,
                        check,
                    )
                })
            }
        }
    };

    // ---- preserve: DWCP, events -------------------------------------------
    (
        $(#[doc = $doc:literal])*
        $name:ident: preserve {
            $( $(#[doc = $fdoc:literal])* $kind:ident $field:ident: $ty:ty ),* $(,)?
        }
        $( ordered($lo:ident <= $hi:ident) )?
        $( paired($left:ident -> $right:ident, $table:expr) )?
    ) => {
        $(#[doc = $doc])*
        #[derive(Debug, Clone, PartialEq)]
        pub struct $name {
            $( $(#[doc = $fdoc])* pub $field: $crate::wire::macros::field_type!($kind, $ty), )*
            /// Members this version does not declare, kept verbatim (as values)
            /// so re-emission does not destroy data a newer peer added.
            pub extensions: $crate::json::Object,
        }

        impl $crate::wire::WireType for $name {
            #[allow(unused_mut, unused_variables)]
            fn decode(
                value: $crate::json::Value,
                cx: &mut $crate::wire::Cx,
            ) -> Result<Self, $crate::error::ProtocolError> {
                let object = match value {
                    $crate::json::Value::Object(object) => object,
                    other => return Err(cx.wrong_type("object", &other)),
                };
                let (mut members, extensions) = $crate::wire::partition_members(
                    object,
                    &[$(stringify!($field)),*],
                    $crate::wire::UnknownFields::Preserve,
                    cx,
                )?;
                $( let $field = $crate::wire::macros::field_take!(
                    $kind, $ty, &mut members, stringify!($field), cx
                )?; )*
                let decoded = Self { $($field,)* extensions };
                $( $crate::wire::macros::check_ordered(
                    &decoded.$lo, &decoded.$hi, stringify!($lo), stringify!($hi), cx
                )?; )?
                $( $crate::wire::macros::check_paired(
                    decoded.$left.as_str(), decoded.$right.as_str(),
                    stringify!($left), stringify!($right), $table, cx
                )?; )?
                Ok(decoded)
            }

            #[allow(unused_mut)]
            fn encode(&self) -> Result<$crate::json::Value, $crate::error::ProtocolError> {
                let mut object = $crate::json::Object::new();
                $( $crate::wire::macros::field_put!(
                    $kind, object, stringify!($field), &self.$field
                )?; )*
                for (key, value) in self.extensions.iter() {
                    object.insert(key.to_owned(), value.clone())?;
                }
                Ok($crate::json::Value::Object(object))
            }

            #[allow(unused_variables)]
            fn schema(defs: &mut $crate::schema::Defs) -> $crate::json::Value {
                defs.reference(stringify!($name), |defs| {
                    let check: Option<$crate::json::Value> = None
                        $( .or(Some($crate::wire::macros::ordered_schema(
                            stringify!($lo), stringify!($hi)
                        ))) )?
                        $( .or(Some($crate::wire::macros::paired_schema(
                            stringify!($left), stringify!($right), $table
                        ))) )?;
                    $crate::wire::macros::struct_schema(
                        concat!($($doc, "\n"),*),
                        vec![$( (
                            stringify!($field),
                            concat!($($fdoc, "\n"),*),
                            $crate::wire::macros::field_required!($kind),
                            <$ty as $crate::wire::WireType>::schema(defs),
                        ) ),*],
                        $crate::wire::UnknownFields::Preserve,
                        check,
                    )
                })
            }
        }
    };
}

pub(crate) use {field_put, field_required, field_take, field_type, wire_struct};

use crate::error::{ProtocolError, Violation};
use crate::json::{Object, Value};
use crate::schema::{description, obj, string, strings};
use crate::wire::{Cx, UnknownFields};

/// The `ordered(lo <= hi)` cross-field check.
pub fn check_ordered<T: PartialOrd>(
    lo: &T,
    hi: &T,
    lo_name: &str,
    hi_name: &str,
    cx: &mut Cx,
) -> Result<(), ProtocolError> {
    if lo <= hi {
        return Ok(());
    }
    cx.push(hi_name);
    let err = cx.violation(
        Violation::Inconsistent,
        format!("{lo_name} must not exceed {hi_name}"),
    );
    cx.pop();
    Err(err)
}

/// The `paired(left -> right, table)` cross-field check.
///
/// Two closed enums whose *combination* is also closed: the table lists, for
/// each `left` value, the `right` values that can accompany it. A pair the
/// table does not list is refused at the boundary rather than carried inwards,
/// which is what makes "this refusal reason cannot arise from that operation"
/// a wire property instead of a convention.
pub fn check_paired(
    left: &str,
    right: &str,
    left_name: &str,
    right_name: &str,
    table: &[(&str, &[&str])],
    cx: &mut Cx,
) -> Result<(), ProtocolError> {
    const NONE: &[&str] = &[];
    let permitted = table
        .iter()
        .find(|(key, _)| *key == left)
        .map_or(NONE, |(_, values)| *values);
    if permitted.contains(&right) {
        return Ok(());
    }
    cx.push(right_name);
    let err = cx.violation(
        Violation::Inconsistent,
        format!("{left_name} {left} cannot produce {right_name} {right}"),
    );
    cx.pop();
    Err(err)
}

/// The schema annotation for an `ordered` check.
#[must_use]
pub fn ordered_schema(low: &str, high: &str) -> Value {
    obj(vec![
        ("kind", string("ordered")),
        ("low", string(low)),
        ("high", string(high)),
    ])
}

/// The schema annotation for a `paired` check.
#[must_use]
pub fn paired_schema(left: &str, right: &str, table: &[(&str, &[&str])]) -> Value {
    let mut allowed = Object::new();
    for (key, values) in table {
        let _ = allowed.insert((*key).to_owned(), strings(values));
    }
    obj(vec![
        ("kind", string("paired")),
        ("left", string(left)),
        ("right", string(right)),
        ("allowed", Value::Object(allowed)),
    ])
}

/// Assemble an object schema from field descriptions.
#[must_use]
pub fn struct_schema(
    doc: &str,
    fields: Vec<(&str, &str, bool, Value)>,
    unknown: UnknownFields,
    check: Option<Value>,
) -> Value {
    let mut properties = Object::new();
    let mut required = Vec::new();
    for (name, field_doc, is_required, schema) in fields {
        let schema = with_description(schema, field_doc);
        let _ = properties.insert(name.to_owned(), schema);
        if is_required {
            required.push(name);
        }
    }
    let mut members = vec![("type", string("object"))];
    if !doc.trim().is_empty() {
        members.push(("description", description(doc)));
    }
    members.push(("properties", Value::Object(properties)));
    members.push(("required", strings(&required)));
    match unknown {
        UnknownFields::Reject => {
            members.push(("additionalProperties", Value::Bool(false)));
            members.push(("x-direwolf-unknown-fields", string("reject")));
        }
        UnknownFields::Preserve => {
            members.push(("x-direwolf-unknown-fields", string("preserve")));
        }
    }
    if let Some(check) = check {
        members.push(("x-direwolf-check", check));
    }
    obj(members)
}

/// Attach a description to a schema node.
#[must_use]
pub fn with_description(schema: Value, doc: &str) -> Value {
    if doc.trim().is_empty() {
        return schema;
    }
    match schema {
        Value::Object(object) => {
            let mut out = Object::new();
            let mut members = object.into_members();
            members.retain(|(k, _)| k != "description");
            for (k, v) in members {
                let _ = out.insert(k, v);
            }
            let _ = out.insert("description".to_owned(), description(doc));
            Value::Object(out)
        }
        other => other,
    }
}
