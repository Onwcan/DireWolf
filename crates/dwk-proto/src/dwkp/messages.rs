//! DWKP message payloads defined by M2.
//!
//! Only messages whose shape is fully determined by the architecture and whose
//! first consumer is the next milestone are defined. Everything else in the
//! inventory is reserved, with its owning milestone, and is not on the wire —
//! see [`super::registry`]. Every type here rejects unknown members.

use crate::error::{ErrorCode, ProtocolError, Violation};
use crate::json::Value;
use crate::schema::{Defs, obj, string, strings};
use crate::version::VersionRange;
use crate::wire::id::SessionId;
use crate::wire::macros::wire_struct;
use crate::wire::scalar::{Detail, Epoch, ErrorPath, Version};
use crate::wire::{Cx, WireType, expect_string};

wire_struct! {
    /// Opens a DWKP connection by offering a range of envelope versions. Always
    /// sent in envelope version 1, whatever it offers, so that any receiver can
    /// read the offer.
    Handshake: reject {
        /// Lowest envelope version the sender speaks.
        required min_version: Version,
        /// Highest envelope version the sender speaks.
        required max_version: Version,
    }
    ordered(min_version <= max_version)
}

wire_struct! {
    /// Accepts a handshake, naming the version both sides will use: the highest
    /// both support at or above the receiver's floor.
    HandshakeAccepted: reject {
        /// The negotiated envelope version.
        required version: Version,
    }
}

wire_struct! {
    /// Renews the session lease named in the envelope at the epoch named in the
    /// envelope. Carries nothing else.
    HeartbeatPayload: reject {}
}

wire_struct! {
    /// Requests the single-writer lease for the session named in the envelope.
    /// The kernel assigns the epoch; the sender cannot propose one.
    LeaseAcquire: reject {}
}

wire_struct! {
    /// The lease the kernel granted.
    LeaseGrant: reject {
        /// The session the lease is for.
        required session_id: SessionId,
        /// The epoch the kernel assigned. Every later request for the session
        /// carries it; a request carrying an older one is fenced (§3).
        required epoch: Epoch,
    }
}

wire_struct! {
    /// Surrenders the lease named in the envelope, at the epoch named in the
    /// envelope. Can only reduce authority.
    LeaseRelease: reject {}
}

wire_struct! {
    /// Acknowledges a request that has no other result.
    Ack: reject {}
}

wire_struct! {
    /// A range of versions a receiver supports.
    VersionSpan: reject {
        /// Lowest supported version.
        required min: Version,
        /// Highest supported version.
        required max: Version,
    }
    ordered(min <= max)
}

wire_struct! {
    /// The message did not decode. This is **not** a policy denial: nothing was
    /// evaluated, because there was nothing well-formed to evaluate.
    ProtocolErrorPayload: reject {
        /// Stable error code.
        required code: ErrorCode,
        /// Finer classification for schema and version failures.
        optional violation: Violation,
        /// JSON Pointer to the failing location.
        optional path: ErrorPath,
        /// Short explanation. Informational; bounded.
        required detail: Detail,
        /// For version failures, the range the receiver supports.
        optional supported: VersionSpan,
    }
}

impl VersionSpan {
    /// Convert a range. `None` only if the range is invalid, which a
    /// `VersionRange` never is.
    #[must_use]
    pub fn from_range(range: VersionRange) -> Option<Self> {
        Some(Self {
            min: Version::new(range.min)?,
            max: Version::new(range.max)?,
        })
    }
}

impl From<&ProtocolError> for ProtocolErrorPayload {
    fn from(err: &ProtocolError) -> Self {
        Self {
            code: err.code,
            violation: err.violation,
            path: (!err.path.is_empty())
                .then(|| ErrorPath::new(err.path.clone()))
                .flatten(),
            detail: Detail::truncated(&err.detail),
            supported: err.supported.and_then(VersionSpan::from_range),
        }
    }
}

impl WireType for ErrorCode {
    fn decode(value: Value, cx: &mut Cx) -> Result<Self, ProtocolError> {
        let s = expect_string(value, cx)?;
        Self::from_wire(&s)
            .ok_or_else(|| cx.violation(Violation::UnknownVariant, "not a protocol error code"))
    }

    fn encode(&self) -> Result<Value, ProtocolError> {
        Ok(Value::String(self.as_str().to_owned()))
    }

    fn schema(_: &mut Defs) -> Value {
        let names: Vec<&str> = Self::ALL.iter().map(|c| c.as_str()).collect();
        obj(vec![
            ("type", string("string")),
            ("enum", strings(&names)),
            ("x-direwolf-type", string("ErrorCode")),
        ])
    }
}

impl WireType for Violation {
    fn decode(value: Value, cx: &mut Cx) -> Result<Self, ProtocolError> {
        let s = expect_string(value, cx)?;
        Self::from_wire(&s)
            .ok_or_else(|| cx.violation(Violation::UnknownVariant, "not a violation kind"))
    }

    fn encode(&self) -> Result<Value, ProtocolError> {
        Ok(Value::String(self.as_str().to_owned()))
    }

    fn schema(_: &mut Defs) -> Value {
        let names: Vec<&str> = Self::ALL.iter().map(|v| v.as_str()).collect();
        obj(vec![
            ("type", string("string")),
            ("enum", strings(&names)),
            ("x-direwolf-type", string("Violation")),
        ])
    }
}
