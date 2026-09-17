//! `BoundedList` — an array field with a maximum length fixed by its type.
//!
//! M2 had no array-shaped field, so the wire layer had none. M3's authority
//! answers carry sets — the capabilities a run was granted, the ones it asked
//! for and did not get — and a set is an array. This is the whole of that
//! addition: one type, one schema shape, one Python counterpart.
//!
//! Two properties matter, and both are why this is a type rather than a
//! `Vec<T>` with a check bolted on afterwards:
//!
//! * **The bound is part of the type**, like [`UnknownFields`] policy in
//!   [`super::macros`]. A field declared `BoundedList<CapabilityText, 64>`
//!   cannot be decoded with a different bound by passing a flag, because there
//!   is no flag.
//! * **The bound is enforced before the elements are decoded**, not after, so a
//!   message declaring a million items costs one length check rather than a
//!   million allocations. The parser already bounds the frame; this bounds what
//!   one frame can turn into.
//!
//! [`UnknownFields`]: super::UnknownFields

use crate::error::{ProtocolError, Violation};
use crate::json::Value;
use crate::schema::{Defs, int, obj, string};
use crate::wire::{Cx, WireType};

/// An ordered list of at most `MAX` wire values.
///
/// Order is preserved exactly as received: the kernel may treat a list as a set,
/// but the wire form is an array and re-encoding must round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedList<T, const MAX: usize>(Vec<T>);

impl<T, const MAX: usize> BoundedList<T, MAX> {
    /// The declared maximum number of items.
    pub const MAX_ITEMS: usize = MAX;

    /// Build from items, or `None` if there are more than [`Self::MAX_ITEMS`].
    #[must_use]
    pub fn new(items: Vec<T>) -> Option<Self> {
        (items.len() <= MAX).then_some(Self(items))
    }

    /// An empty list. Always valid: every bound admits zero items.
    #[must_use]
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    /// The items.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// The number of items.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Borrow the items in order.
    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.0.iter()
    }
}

impl<T, const MAX: usize> IntoIterator for BoundedList<T, MAX> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T, const MAX: usize> IntoIterator for &'a BoundedList<T, MAX> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T: WireType, const MAX: usize> WireType for BoundedList<T, MAX> {
    fn decode(value: Value, cx: &mut Cx) -> Result<Self, ProtocolError> {
        let items = match value {
            Value::Array(items) => items,
            other => return Err(cx.wrong_type("array", &other)),
        };
        // Length first: a rejected message must not have cost one decode per
        // item on the way to being rejected.
        if items.len() > MAX {
            return Err(cx.violation(
                Violation::TooManyItems,
                format!("expected at most {MAX} items, found {}", items.len()),
            ));
        }
        let mut out = Vec::with_capacity(items.len());
        for (index, item) in items.into_iter().enumerate() {
            cx.push(&index.to_string());
            // `null` is not a value here either: an absent item is a shorter
            // array, exactly as an absent field is an omitted key.
            let decoded = if item == Value::Null {
                Err(cx.violation(
                    Violation::NullNotAllowed,
                    "null is not a value; a shorter array is how an item is omitted",
                ))
            } else {
                T::decode(item, cx)
            };
            cx.pop();
            out.push(decoded?);
        }
        Ok(Self(out))
    }

    fn encode(&self) -> Result<Value, ProtocolError> {
        let mut out = Vec::with_capacity(self.0.len());
        for item in &self.0 {
            out.push(item.encode()?);
        }
        Ok(Value::Array(out))
    }

    fn schema(defs: &mut Defs) -> Value {
        obj(vec![
            ("type", string("array")),
            ("items", T::schema(defs)),
            ("maxItems", int(i64::try_from(MAX).unwrap_or(i64::MAX))),
            ("x-direwolf-type", string("BoundedList")),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::BoundedList;
    use crate::error::{ErrorCode, ProtocolError, Violation};
    use crate::json::{Number, ParseOptions, Value, parse};
    use crate::schema::Defs;
    use crate::wire::scalar::Version;
    use crate::wire::{Cx, WireType};

    type Three = BoundedList<Version, 3>;

    /// Decode, or `None`. The lib's tests avoid `expect` for the same reason
    /// the lib does: the lint is only meaningful if it is not switched off.
    fn ok(text: &str) -> Option<Three> {
        decode(text).ok()
    }

    fn err(text: &str) -> Option<ProtocolError> {
        decode(text).err()
    }

    fn decode(text: &str) -> Result<Three, ProtocolError> {
        match parse(text.as_bytes(), ParseOptions::dwkp()) {
            Ok(value) => Three::decode(value, &mut Cx::new()),
            Err(e) => Err(e),
        }
    }

    fn violation(text: &str) -> Option<Violation> {
        err(text).and_then(|e| e.violation)
    }

    #[test]
    fn an_empty_list_is_valid_at_every_bound() {
        assert_eq!(ok("[]").map(|l| l.len()), Some(0));
        assert!(Three::empty().is_empty());
    }

    #[test]
    fn a_list_at_the_bound_is_accepted_and_round_trips() {
        let Some(list) = ok("[1,2,3]") else {
            unreachable!("three items is at the bound")
        };
        assert_eq!(list.len(), 3);
        let round_tripped = list
            .encode()
            .ok()
            .and_then(|v| Three::decode(v, &mut Cx::new()).ok());
        assert_eq!(round_tripped.as_ref(), Some(&list));
    }

    #[test]
    fn order_is_preserved_because_the_wire_form_is_an_array() {
        let seen: Option<Vec<u16>> = ok("[3,1,2]").map(|l| l.iter().map(|v| v.get()).collect());
        assert_eq!(seen, Some(vec![3, 1, 2]));
    }

    #[test]
    fn one_item_past_the_bound_is_rejected() {
        assert_eq!(
            err("[1,2,3,4]").map(|e| e.code),
            Some(ErrorCode::SchemaViolation)
        );
        assert_eq!(violation("[1,2,3,4]"), Some(Violation::TooManyItems));
    }

    #[test]
    fn the_bound_is_checked_before_any_item_is_decoded() {
        // Every item is invalid *and* there are too many. The length check runs
        // first, so the reported violation is the cheap one -- which is the
        // property that keeps a hostile message cheap to reject.
        assert_eq!(
            violation(r#"["a","b","c","d"]"#),
            Some(Violation::TooManyItems)
        );
    }

    #[test]
    fn a_bad_item_names_its_index_in_the_path() {
        let bad = err(r#"[1,"two",3]"#);
        assert_eq!(
            bad.as_ref().map(|e| e.path.as_str()),
            Some("/1"),
            "the path must locate the failing item"
        );
        assert_eq!(bad.and_then(|e| e.violation), Some(Violation::WrongType));
    }

    #[test]
    fn a_null_item_is_not_an_omitted_item() {
        let bad = err("[1,null]");
        assert_eq!(
            bad.as_ref().and_then(|e| e.violation),
            Some(Violation::NullNotAllowed)
        );
        assert_eq!(bad.map(|e| e.path), Some("/1".to_owned()));
    }

    #[test]
    fn a_non_array_is_a_wrong_type_not_a_one_item_list() {
        for text in ["1", r#""x""#, "{}", "true"] {
            assert_eq!(violation(text), Some(Violation::WrongType), "{text}");
        }
    }

    #[test]
    fn the_schema_states_the_bound() {
        let mut defs = Defs::new();
        let Value::Object(object) = Three::schema(&mut defs) else {
            unreachable!("a schema is an object")
        };
        assert_eq!(object.get("type"), Some(&Value::String("array".into())));
        assert!(object.get("items").is_some(), "items is mandatory");
        assert_eq!(
            object.get("maxItems"),
            Number::from_i64(3).map(Value::Number).as_ref()
        );
    }

    #[test]
    fn construction_refuses_more_items_than_the_bound() {
        let four: Vec<Version> = (1..=4).filter_map(Version::new).collect();
        assert!(Three::new(four).is_none());
        let three: Vec<Version> = (1..=3).filter_map(Version::new).collect();
        assert!(Three::new(three).is_some());
    }
}
