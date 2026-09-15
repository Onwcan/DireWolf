//! Protocol versions and negotiation.
//!
//! Two version numbers exist, with different jobs (`PROTOCOL.md` §1):
//!
//! * the envelope version `v`, negotiated once per connection by the
//!   `Handshake` operation;
//! * each message's `schema_version`, which bumps only on a breaking payload
//!   change and is checked per message against the receiver's registry.
//!
//! An unsupported version is never silently treated as the current one. The
//! receiver answers `PROTOCOL_VERSION_UNSUPPORTED` naming the range it does
//! support.

use crate::error::{ErrorCode, ProtocolError, Violation};

/// An inclusive range of protocol versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VersionRange {
    /// Lowest supported version, inclusive.
    pub min: u16,
    /// Highest supported version, inclusive.
    pub max: u16,
}

impl VersionRange {
    /// A range. Returns `None` when `min > max` or `min == 0`: version 0 does
    /// not exist, so a range containing it is malformed rather than old.
    #[must_use]
    pub const fn new(min: u16, max: u16) -> Option<Self> {
        if min == 0 || min > max {
            None
        } else {
            Some(Self { min, max })
        }
    }

    /// Whether `v` is inside the range.
    #[must_use]
    pub const fn contains(self, v: u16) -> bool {
        self.min <= v && v <= self.max
    }
}

/// Envelope versions this build understands. M2 defines exactly version 1.
pub const SUPPORTED_ENVELOPE: VersionRange = VersionRange { min: 1, max: 1 };

/// The envelope version every `Handshake` message is sent in, regardless of
/// what it offers. The handshake is the one message whose envelope shape can
/// never change, otherwise a peer could not read the offer that tells it which
/// version to read.
pub const HANDSHAKE_ENVELOPE_VERSION: u16 = 1;

/// Choose the highest version both peers support that is at least `minimum`.
///
/// `minimum` is the receiver's configured floor. Without one, a man in the
/// middle — or a compromised runtime — could offer only an old version and pull
/// the connection down to it; `PROTOCOL.md` §8 requires the floor to be
/// enforced, not merely preferred.
pub fn negotiate(
    offered: VersionRange,
    supported: VersionRange,
    minimum: u16,
) -> Result<u16, ProtocolError> {
    let low = offered.min.max(supported.min).max(minimum);
    let high = offered.max.min(supported.max);
    if low <= high {
        Ok(high)
    } else {
        let floor = supported.min.max(minimum);
        let advertised = VersionRange::new(floor, supported.max).unwrap_or(supported);
        Err(ProtocolError::new(
            ErrorCode::VersionUnsupported,
            format!(
                "offered versions {}..={} share no version with supported {}..={}",
                offered.min, offered.max, advertised.min, advertised.max
            ),
        )
        .with_violation(Violation::OutOfRange)
        .with_path("/payload")
        .with_supported(advertised))
    }
}

#[cfg(test)]
mod tests {
    use super::{SUPPORTED_ENVELOPE, VersionRange, negotiate};
    use crate::error::ErrorCode;

    fn r(min: u16, max: u16) -> VersionRange {
        VersionRange::new(min, max).unwrap_or(SUPPORTED_ENVELOPE)
    }

    #[test]
    fn picks_the_highest_mutual_version() {
        assert_eq!(negotiate(r(1, 5), r(2, 3), 1), Ok(3));
        assert_eq!(negotiate(r(1, 1), SUPPORTED_ENVELOPE, 1), Ok(1));
    }

    #[test]
    fn disjoint_ranges_fail_naming_the_supported_range() {
        let older = negotiate(r(1, 1), r(2, 4), 1);
        let newer = negotiate(r(5, 9), r(2, 4), 1);
        for result in [older, newer] {
            let err = result.err();
            assert_eq!(
                err.as_ref().map(|e| e.code),
                Some(ErrorCode::VersionUnsupported)
            );
            assert_eq!(err.and_then(|e| e.supported), Some(r(2, 4)));
        }
    }

    #[test]
    fn the_floor_prevents_a_downgrade_the_ranges_would_allow() {
        // Both peers speak version 2, but the receiver's floor is 3.
        let err = negotiate(r(1, 2), r(1, 4), 3).err();
        assert_eq!(
            err.as_ref().map(|e| e.code),
            Some(ErrorCode::VersionUnsupported)
        );
        assert_eq!(err.and_then(|e| e.supported), Some(r(3, 4)));
    }

    #[test]
    fn version_zero_and_inverted_ranges_are_malformed_not_old() {
        assert_eq!(VersionRange::new(0, 1), None);
        assert_eq!(VersionRange::new(3, 2), None);
    }
}
