//! The connection protocol: what one decoded message does to one connection.
//!
//! A pure function of the connection's phase and the message's kind. It knows
//! no socket, no clock and no authority state, so every transition is unit-
//! and property-tested without either, and the socket code only carries out
//! what it decides.
//!
//! ```text
//!   AwaitingHandshake ──Handshake, a common version──▶ Established(v)
//!         │                                               │
//!         ├─Handshake, no common version ─▶ answer PROTOCOL_VERSION_UNSUPPORTED, close
//!         └─anything else ───────────────▶ close, no answer
//!                                                         │
//!   Established(v) ──one of the six authority requests──▶ dispatch, stay
//!         ├─request in another envelope version ─▶ answer PROTOCOL_VERSION_UNSUPPORTED, close
//!         ├─a second Handshake ──────────────────▶ close, no answer
//!         └─a response or an event ──────────────▶ close, no answer
//! ```
//!
//! **Nothing is dispatched before a handshake has been answered**, by
//! construction: [`step`] returns [`Step::Dispatch`] only from
//! `Established`, and the only way into `Established` is
//! [`Step::Accept`].
//!
//! # Why an ordering violation gets no answer
//!
//! `direwolf.protocol.error` says the bytes did not form a valid message, and
//! the protocol reserves it for that (`PROTOCOL.md` §2.1). A request sent
//! before the handshake, a second handshake, or a response sent *to* the
//! authority all decoded perfectly. No wire code says "out of order", and
//! borrowing `PROTOCOL_UNKNOWN_OPERATION` or `PROTOCOL_SCHEMA_VIOLATION` would
//! tell the peer to repair a message that is not broken. So the authority
//! closes the connection and records why in `audit.log`, and the peer learns
//! exactly one thing: it broke the connection protocol.

use dwk_proto::dwkp::{DwkpBody, DwkpMessage};
use dwk_proto::envelope::MessageType;
use dwk_proto::error::{ErrorCode, ProtocolError, Violation as FieldViolation};
use dwk_proto::version::{HANDSHAKE_ENVELOPE_VERSION, SUPPORTED_ENVELOPE, VersionRange, negotiate};

use crate::state::Violation;

/// The lowest envelope version this authority will negotiate. The floor
/// `negotiate` enforces, so an offer cannot pull the connection below it
/// (`PROTOCOL.md` §8). This build speaks exactly version 1.
pub(crate) const ENVELOPE_FLOOR: u16 = SUPPORTED_ENVELOPE.min;

/// Where a connection is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Accepted and identified; no handshake yet. Nothing is dispatched.
    AwaitingHandshake,
    /// A handshake was answered with this envelope version.
    Established(u16),
}

/// What a message is, as far as the connection protocol cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// `direwolf.handshake`, in envelope version `v`, offering `offered`.
    Handshake {
        /// The envelope version the handshake itself was sent in.
        v: u16,
        /// The versions it offers.
        offered: VersionRange,
    },
    /// One of the eight authority requests, in envelope version `v`.
    AuthorityRequest {
        /// Its envelope version.
        v: u16,
    },
    /// A response or an event: something the authority never receives.
    NotARequest,
}

/// Classify a decoded message. Total over the decoder's output: a request
/// body the connection protocol does not know is [`Kind::NotARequest`], so a
/// future message cannot become dispatchable by default.
pub(crate) fn classify(message: &DwkpMessage) -> Kind {
    let v = message.header.v.get();
    if message.header.message_type != MessageType::Request {
        return Kind::NotARequest;
    }
    match &message.body {
        DwkpBody::Handshake(offer) => {
            VersionRange::new(offer.min_version.get(), offer.max_version.get())
                .map_or(Kind::NotARequest, |offered| Kind::Handshake { v, offered })
        }
        DwkpBody::Heartbeat(_)
        | DwkpBody::LeaseAcquire(_)
        | DwkpBody::LeaseRelease(_)
        | DwkpBody::AdmitRun(_)
        | DwkpBody::ReleaseRun(_)
        | DwkpBody::AuthorityQuery(_)
        | DwkpBody::ToolInvoke(_)
        | DwkpBody::CanonicalPreview(_)
        | DwkpBody::ToolInvokeV2(_)
        | DwkpBody::CanonicalPreviewV2(_)
        | DwkpBody::ToolInvokeV3(_)
        | DwkpBody::CanonicalPreviewV3(_) => Kind::AuthorityRequest { v },
        DwkpBody::HandshakeAccepted(_)
        | DwkpBody::LeaseGrant(_)
        | DwkpBody::RunGrant(_)
        | DwkpBody::EffectiveAuthority(_)
        | DwkpBody::AuthorityRefused(_)
        | DwkpBody::ToolResult(_)
        | DwkpBody::ToolDenied(_)
        | DwkpBody::ToolPreviewed(_)
        | DwkpBody::ToolRefused(_)
        | DwkpBody::ToolFailed(_)
        | DwkpBody::ToolResultV2(_)
        | DwkpBody::ToolDeniedV2(_)
        | DwkpBody::ToolPreviewedV2(_)
        | DwkpBody::ToolRefusedV2(_)
        | DwkpBody::ToolFailedV2(_)
        | DwkpBody::ToolResultV3(_)
        | DwkpBody::ToolDeniedV3(_)
        | DwkpBody::ToolPreviewedV3(_)
        | DwkpBody::ToolRefusedV3(_)
        | DwkpBody::ToolFailedV3(_)
        | DwkpBody::Ack(_)
        | DwkpBody::ProtocolError(_) => Kind::NotARequest,
    }
}

/// What the connection does next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Step {
    /// Answer the handshake with this version and become `Established`.
    Accept(u16),
    /// Hand the request to the authority, answer, and stay.
    Dispatch,
    /// Answer with this protocol error, record the violation, and close.
    Reject(ProtocolError, Violation),
    /// Record the violation and close without answering.
    Close(Violation),
}

/// The transition for one decoded message.
pub(crate) fn step(phase: Phase, kind: Kind) -> Step {
    match (phase, kind) {
        (_, Kind::NotARequest) => Step::Close(Violation::NotARequest),
        (Phase::AwaitingHandshake, Kind::Handshake { v, offered }) => {
            if v != HANDSHAKE_ENVELOPE_VERSION {
                return Step::Reject(
                    version_error(format!(
                        "a handshake is sent in envelope version {HANDSHAKE_ENVELOPE_VERSION}, \
                         not {v}"
                    )),
                    Violation::VersionUnsupported,
                );
            }
            match negotiate(offered, SUPPORTED_ENVELOPE, ENVELOPE_FLOOR) {
                Ok(version) => Step::Accept(version),
                Err(error) => Step::Reject(error, Violation::VersionUnsupported),
            }
        }
        (Phase::AwaitingHandshake, Kind::AuthorityRequest { .. }) => {
            Step::Close(Violation::HandshakeRequired)
        }
        (Phase::Established(_), Kind::Handshake { .. }) => {
            Step::Close(Violation::DuplicateHandshake)
        }
        (Phase::Established(version), Kind::AuthorityRequest { v }) => {
            if v == version {
                Step::Dispatch
            } else {
                Step::Reject(
                    version_error(format!(
                        "this connection negotiated envelope version {version}; a request in \
                         version {v} is not read as it"
                    )),
                    Violation::VersionMismatch,
                )
            }
        }
    }
}

fn version_error(detail: String) -> ProtocolError {
    ProtocolError::new(ErrorCode::VersionUnsupported, detail)
        .with_violation(FieldViolation::OutOfRange)
        .with_path("/v")
        .with_supported(SUPPORTED_ENVELOPE)
}

#[cfg(test)]
mod tests {
    use dwk_proto::error::ErrorCode;
    use dwk_proto::version::VersionRange;
    use proptest::prelude::*;

    use super::{Kind, Phase, Step, step};
    use crate::state::Violation;

    fn range(min: u16, max: u16) -> VersionRange {
        VersionRange::new(min, max).unwrap_or(VersionRange { min: 1, max: 1 })
    }

    #[test]
    fn a_handshake_opens_the_connection_at_the_highest_common_version() {
        let offer = Kind::Handshake {
            v: 1,
            offered: range(1, 9),
        };
        assert_eq!(step(Phase::AwaitingHandshake, offer), Step::Accept(1));
    }

    #[test]
    fn a_handshake_with_no_common_version_is_answered_and_closed() {
        let offer = Kind::Handshake {
            v: 1,
            offered: range(2, 9),
        };
        let Step::Reject(error, violation) = step(Phase::AwaitingHandshake, offer) else {
            unreachable!("a version it does not speak is refused")
        };
        assert_eq!(error.code, ErrorCode::VersionUnsupported);
        assert_eq!(error.supported, Some(range(1, 1)));
        assert_eq!(violation, Violation::VersionUnsupported);
    }

    #[test]
    fn nothing_before_the_handshake_is_dispatched() {
        assert_eq!(
            step(Phase::AwaitingHandshake, Kind::AuthorityRequest { v: 1 }),
            Step::Close(Violation::HandshakeRequired)
        );
        assert_eq!(
            step(Phase::AwaitingHandshake, Kind::NotARequest),
            Step::Close(Violation::NotARequest)
        );
    }

    #[test]
    fn a_second_handshake_closes_the_connection() {
        let offer = Kind::Handshake {
            v: 1,
            offered: range(1, 1),
        };
        assert_eq!(
            step(Phase::Established(1), offer),
            Step::Close(Violation::DuplicateHandshake)
        );
    }

    #[test]
    fn a_request_in_another_envelope_version_is_not_read_as_the_negotiated_one() {
        let Step::Reject(error, violation) =
            step(Phase::Established(1), Kind::AuthorityRequest { v: 2 })
        else {
            unreachable!("refused")
        };
        assert_eq!(error.code, ErrorCode::VersionUnsupported);
        assert_eq!(violation, Violation::VersionMismatch);
    }

    fn kind() -> impl Strategy<Value = Kind> {
        prop_oneof![
            (1u16..4, 1u16..4, 1u16..4).prop_map(|(v, a, b)| Kind::Handshake {
                v,
                offered: range(a.min(b), a.max(b)),
            }),
            (1u16..4).prop_map(|v| Kind::AuthorityRequest { v }),
            Just(Kind::NotARequest),
        ]
    }

    proptest! {
        /// Over any message sequence: nothing is dispatched until a handshake
        /// has been accepted, a closing step ends the connection, and a second
        /// handshake after acceptance always closes it.
        #[test]
        fn dispatch_never_precedes_an_accepted_handshake(
            kinds in proptest::collection::vec(kind(), 1..24)
        ) {
            let mut phase = Phase::AwaitingHandshake;
            let mut dispatched_before_accept = 0u32;
            for kind in kinds {
                let result = step(phase, kind);
                if let (Phase::Established(_), Kind::Handshake { .. }) = (phase, kind) {
                    prop_assert_eq!(&result, &Step::Close(Violation::DuplicateHandshake));
                }
                if kind == Kind::NotARequest {
                    prop_assert_eq!(&result, &Step::Close(Violation::NotARequest));
                }
                match result {
                    Step::Accept(version) => {
                        prop_assert_eq!(phase, Phase::AwaitingHandshake);
                        phase = Phase::Established(version);
                    }
                    Step::Dispatch => {
                        if phase == Phase::AwaitingHandshake {
                            dispatched_before_accept += 1;
                        }
                        let is_request = matches!(kind, Kind::AuthorityRequest { .. });
                        prop_assert!(is_request);
                    }
                    Step::Reject(..) | Step::Close(_) => break,
                }
            }
            prop_assert_eq!(dispatched_before_accept, 0);
        }
    }
}
