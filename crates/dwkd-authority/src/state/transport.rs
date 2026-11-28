//! Transport security events: the one audit entry point the DWKP server has.
//!
//! The server (`crate::server`, M3e) sees things no state operation does: a
//! peer the operator's policy does not name, a connection over the limit, a
//! frame that is not DWKP. Those are security-significant, so they belong in
//! `audit.log` — the authoritative record — and not in an operational log a
//! reviewer would have to trust separately ([ADR-0041]).
//!
//! # Narrow on purpose
//!
//! The transport hands this module a [`TransportEvent`]: a closed enum whose
//! every field is a kernel-reported number or a variant the authority chose.
//! There is no free-form text, no bytes from the peer and no key a caller can
//! name, so a hostile client cannot write into the chain through this door,
//! and an attacker who connects a thousand times appends a thousand records of
//! a fixed, small size — which the server additionally rate-limits.
//!
//! Nothing on the wire reaches this module. A record is written through the
//! same transactional outbox as every other event, and `fsync`ed before the
//! call returns.
//!
//! The approver endpoint (F-18 Phase 3.4, [ADR-0067], accepted) records here
//! too: who it refused, and which operator-declared approver it
//! authenticated -- and, since M6.3 ([ADR-0081], Proposed), whether that
//! connection was admitted to its one request or closed at the connection
//! limit, and each approver request it refused, with the authority's own code
//! for why. A decision the registry recorded is the registry's record
//! (`approval.granted`, `approval.denied`), not this module's.
//!
//! [ADR-0041]: ../../../../../docs/adr/0041-m3e-authenticated-dwkp-transport.md
//! [ADR-0067]: ../../../../../docs/adr/0067-f18-approver-endpoint-identity-boundary.md
//! [ADR-0081]: ../../../../../docs/adr/0081-the-approver-endpoints-operations-and-the-trusted-approver-client.md

use dwk_proto::approverp::{ApproverKind, RefusalCode};
use dwk_proto::error::ErrorCode;

use super::audit::{AuditEvent, Fields};
use super::identity::LeaseHolder;

/// How a connection broke the DWKP connection protocol. Closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Violation {
    /// A frame could not be read (`PROTOCOL_FRAME_*`,
    /// `PROTOCOL_CONTENT_TYPE_UNSUPPORTED`). The stream has no trustworthy
    /// next boundary.
    Framing(ErrorCode),
    /// A complete frame did not decode as a DWKP message: its JSON, its
    /// envelope, its schema version or its payload is not the contract.
    Malformed(ErrorCode),
    /// The handshake offered no envelope version this authority speaks.
    VersionUnsupported,
    /// The first message on the connection was not a handshake.
    HandshakeRequired,
    /// A handshake on a connection that had already completed one.
    DuplicateHandshake,
    /// A message the authority never receives: a response or an event.
    NotARequest,
    /// A request whose envelope version is not the one the handshake chose.
    VersionMismatch,
    /// The peer ended the stream part-way through a frame.
    Truncated,
}

impl Violation {
    /// The spelling in a record's `violation` field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Framing(_) => "framing",
            Self::Malformed(_) => "malformed",
            Self::VersionUnsupported => "version_unsupported",
            Self::HandshakeRequired => "handshake_required",
            Self::DuplicateHandshake => "duplicate_handshake",
            Self::NotARequest => "not_a_request",
            Self::VersionMismatch => "version_mismatch",
            Self::Truncated => "truncated",
        }
    }

    /// The protocol error code, where one applies.
    #[must_use]
    pub const fn code(self) -> Option<ErrorCode> {
        match self {
            Self::Framing(code) | Self::Malformed(code) => Some(code),
            Self::VersionUnsupported | Self::VersionMismatch => Some(ErrorCode::VersionUnsupported),
            Self::Truncated => Some(ErrorCode::FrameTruncated),
            Self::HandshakeRequired | Self::DuplicateHandshake | Self::NotARequest => None,
        }
    }
}

/// Which rate-limited stream a transport record belongs to. Closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransportClass {
    /// [`TransportEvent::PeerRefused`].
    PeerRefused,
    /// [`TransportEvent::ConnectionRefused`].
    ConnectionRefused,
    /// [`TransportEvent::ProtocolViolation`].
    ProtocolViolation,
    /// [`TransportEvent::ApproverRefused`].
    ApproverRefused,
    /// [`TransportEvent::ApproverAuthenticated`].
    ApproverAuthenticated,
    /// [`TransportEvent::ApproverRequestRefused`].
    ApproverRequestRefused,
}

impl TransportClass {
    /// Every class, in declaration order.
    pub const ALL: [Self; 6] = [
        Self::PeerRefused,
        Self::ConnectionRefused,
        Self::ProtocolViolation,
        Self::ApproverRefused,
        Self::ApproverAuthenticated,
        Self::ApproverRequestRefused,
    ];

    /// The spelling in a suppression record's `class` field.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PeerRefused => "peer_refused",
            Self::ConnectionRefused => "connection_refused",
            Self::ProtocolViolation => "protocol_violation",
            Self::ApproverRefused => "approver_refused",
            Self::ApproverAuthenticated => "approver_authenticated",
            Self::ApproverRequestRefused => "approver_request_refused",
        }
    }
}

/// A security-significant transport event. Every field is either reported by
/// the kernel (a uid, a pid) or chosen by the authority (a holder it minted, a
/// variant it classified); none is a byte the peer sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportEvent {
    /// The kernel reported a uid the operator's peer policy does not name.
    /// Refused before the first byte was read, so no holder was minted.
    PeerRefused {
        /// The peer's uid, as the kernel reported it.
        uid: u32,
        /// The peer's pid at connect time, as the kernel reported it.
        /// Diagnostic only: pids are recycled, and nothing is decided on one.
        pid: Option<u32>,
    },
    /// An allowed peer was refused because the server was at its connection
    /// limit. No holder was minted.
    ConnectionRefused {
        /// The peer's uid, as the kernel reported it.
        uid: u32,
        /// The peer's pid at connect time. Diagnostic only.
        pid: Option<u32>,
    },
    /// A connection was closed for breaking the connection protocol.
    ProtocolViolation {
        /// The peer's uid, as the kernel reported it.
        uid: u32,
        /// The holder the connection was given. It can no longer present it.
        holder: LeaseHolder,
        /// What the connection did.
        violation: Violation,
    },
    /// The approver endpoint (F-18 Phase 3.4, ADR-0067) refused a connection
    /// whose kernel-reported uid is not one of the operator's approvers -- a
    /// runtime's, the authority's, anyone else's -- before reading a byte.
    ApproverRefused {
        /// The peer's uid, as the kernel reported it.
        uid: u32,
        /// The peer's pid at connect time. Diagnostic only.
        pid: Option<u32>,
    },
    /// The approver endpoint authenticated an operator-declared approver by
    /// its kernel-reported uid, before reading a byte: admitted to one
    /// approver-protocol request (M6.3), or -- the endpoint at its connection
    /// limit -- closed unread. Not an approval, and nothing else either.
    ApproverAuthenticated {
        /// The approver's uid, as the kernel reported it.
        uid: u32,
        /// The approver's pid at connect time. Diagnostic only.
        pid: Option<u32>,
        /// Whether the connection was admitted to its request; `false` at the
        /// endpoint's connection limit, where nothing was read.
        admitted: bool,
    },
    /// The approver endpoint refused an authenticated approver's request
    /// (M6.3, ADR-0081): one that did not decode, or one the registry did not
    /// answer as asked -- an unknown request, one decided already, expired or
    /// of a run that ended, a binding hash that is not the request's, a
    /// self-approval, an approver no longer in the set, a level no approver
    /// can give. Nothing was decided.
    ApproverRequestRefused {
        /// The approver's uid, as the kernel reported it.
        uid: u32,
        /// The operation, if the request decoded.
        operation: Option<ApproverKind>,
        /// The authority's code for why.
        code: RefusalCode,
        /// The request it named, if it decoded and named one.
        request: Option<[u8; 32]>,
    },
    /// Records of one class that the rate limit withheld since the last one it
    /// wrote. A count, so that suppression is itself on the record.
    Suppressed {
        /// Which class.
        class: TransportClass,
        /// How many records were withheld.
        count: u64,
    },
}

impl TransportEvent {
    /// The class the server's rate limit counts this event against, or `None`
    /// for a suppression record, which is never itself suppressed.
    #[must_use]
    pub const fn class(&self) -> Option<TransportClass> {
        match self {
            Self::PeerRefused { .. } => Some(TransportClass::PeerRefused),
            Self::ConnectionRefused { .. } => Some(TransportClass::ConnectionRefused),
            Self::ProtocolViolation { .. } => Some(TransportClass::ProtocolViolation),
            Self::ApproverRefused { .. } => Some(TransportClass::ApproverRefused),
            Self::ApproverAuthenticated { .. } => Some(TransportClass::ApproverAuthenticated),
            Self::ApproverRequestRefused { .. } => Some(TransportClass::ApproverRequestRefused),
            Self::Suppressed { .. } => None,
        }
    }

    /// The record this event becomes: its kind and its fixed field set.
    pub(super) fn record(&self) -> (AuditEvent, Fields) {
        fn pid(fields: Fields, pid: Option<u32>) -> Fields {
            match pid {
                Some(pid) => fields.int("pid", u64::from(pid)),
                None => fields,
            }
        }
        match *self {
            Self::PeerRefused { uid, pid: peer } => (
                AuditEvent::TransportPeerRefused,
                pid(
                    Fields::new()
                        .int("uid", u64::from(uid))
                        .text("reason", "uid_not_allowed"),
                    peer,
                ),
            ),
            Self::ConnectionRefused { uid, pid: peer } => (
                AuditEvent::TransportConnectionRefused,
                pid(
                    Fields::new()
                        .int("uid", u64::from(uid))
                        .text("reason", "connection_limit"),
                    peer,
                ),
            ),
            Self::ProtocolViolation {
                uid,
                holder,
                violation,
            } => {
                let fields = Fields::new()
                    .int("uid", u64::from(uid))
                    .text("holder", holder.to_string())
                    .text("violation", violation.as_str());
                let fields = match violation.code() {
                    Some(code) => fields.text("code", code.as_str()),
                    None => fields,
                };
                (AuditEvent::TransportProtocolViolation, fields)
            }
            Self::ApproverRefused { uid, pid: peer } => (
                AuditEvent::ApproverPeerRefused,
                pid(
                    Fields::new()
                        .int("uid", u64::from(uid))
                        .text("reason", "uid_not_an_approver"),
                    peer,
                ),
            ),
            Self::ApproverAuthenticated {
                uid,
                pid: peer,
                admitted,
            } => (
                AuditEvent::ApproverPeerAuthenticated,
                pid(
                    if admitted {
                        Fields::new()
                            .int("uid", u64::from(uid))
                            .text("outcome", "admitted")
                    } else {
                        Fields::new()
                            .int("uid", u64::from(uid))
                            .text("outcome", "closed")
                            .text("reason", "connection_limit")
                    },
                    peer,
                ),
            ),
            Self::ApproverRequestRefused {
                uid,
                operation,
                code,
                request,
            } => (
                AuditEvent::ApproverRequestRefused,
                refused_fields(uid, operation, code, request),
            ),
            Self::Suppressed { class, count } => (
                AuditEvent::TransportAuditSuppressed,
                Fields::new()
                    .text("class", class.as_str())
                    .int("count", count),
            ),
        }
    }
}

/// An `approver.request_refused` record's fields: the approver as the kernel
/// reported them, the operation, the authority's code, the channel, and the
/// request the decoded message named.
fn refused_fields(
    uid: u32,
    operation: Option<ApproverKind>,
    code: RefusalCode,
    request: Option<[u8; 32]>,
) -> Fields {
    use core::fmt::Write as _;
    let fields = Fields::new()
        .text(
            "approver",
            super::identity::AuthenticatedSubject::unix_uid(uid).storage_key(),
        )
        .text(
            "operation",
            operation.map_or("unreadable", ApproverKind::as_str),
        )
        .text("code", code.as_str())
        .text("channel", "APPROVER_ENDPOINT");
    match request {
        Some(bytes) => fields.text(
            "request_id",
            bytes.iter().fold(String::with_capacity(64), |mut out, b| {
                let _ = write!(out, "{b:02x}");
                out
            }),
        ),
        None => fields,
    }
}

#[cfg(test)]
mod tests {
    use super::{ApproverKind, RefusalCode, TransportClass, TransportEvent, Violation};
    use crate::state::audit::AuditEvent;
    use crate::state::identity::LeaseHolder;
    use dwk_proto::error::ErrorCode;

    #[test]
    fn every_event_has_a_fixed_kind() {
        let holder = LeaseHolder::new(1, 2);
        let cases = [
            (
                TransportEvent::PeerRefused {
                    uid: 7,
                    pid: Some(9),
                },
                AuditEvent::TransportPeerRefused,
            ),
            (
                TransportEvent::ConnectionRefused { uid: 7, pid: None },
                AuditEvent::TransportConnectionRefused,
            ),
            (
                TransportEvent::ProtocolViolation {
                    uid: 7,
                    holder,
                    violation: Violation::Framing(ErrorCode::FrameTooLarge),
                },
                AuditEvent::TransportProtocolViolation,
            ),
            (
                TransportEvent::Suppressed {
                    class: TransportClass::PeerRefused,
                    count: 3,
                },
                AuditEvent::TransportAuditSuppressed,
            ),
            (
                TransportEvent::ApproverRefused { uid: 7, pid: None },
                AuditEvent::ApproverPeerRefused,
            ),
            (
                TransportEvent::ApproverAuthenticated {
                    uid: 8,
                    pid: Some(9),
                    admitted: true,
                },
                AuditEvent::ApproverPeerAuthenticated,
            ),
            (
                TransportEvent::ApproverRequestRefused {
                    uid: 8,
                    operation: Some(ApproverKind::Decide),
                    code: RefusalCode::SelfApproval,
                    request: Some([7; 32]),
                },
                AuditEvent::ApproverRequestRefused,
            ),
        ];
        for (event, kind) in cases {
            assert_eq!(event.record().0, kind);
        }
    }

    #[test]
    fn an_approver_record_says_who_the_kernel_reported_and_that_nothing_was_approved() {
        // F-18 Phase 3.4 (ADR-0067), M6.3 (ADR-0081): the approver endpoint's
        // records carry the kernel's uid and the authority's own words, never
        // a peer's bytes; the authenticated one says whether the connection
        // was admitted to its request or closed at the limit, and neither is
        // an approval.
        let (kind, fields) = TransportEvent::ApproverRefused {
            uid: 1001,
            pid: Some(4),
        }
        .record();
        assert_eq!(kind.as_str(), "approver.peer_refused");
        let text = format!("{fields:?}");
        assert!(
            text.contains("1001") && text.contains("uid_not_an_approver"),
            "{text}"
        );
        let (kind, fields) = TransportEvent::ApproverAuthenticated {
            uid: 2001,
            pid: None,
            admitted: true,
        }
        .record();
        assert_eq!(kind.as_str(), "approver.peer_authenticated");
        let text = format!("{fields:?}");
        assert!(text.contains("2001") && text.contains("admitted"), "{text}");
        assert!(!text.contains("approved"), "{text}");
        let (_, fields) = TransportEvent::ApproverAuthenticated {
            uid: 2001,
            pid: None,
            admitted: false,
        }
        .record();
        let text = format!("{fields:?}");
        assert!(
            text.contains("closed") && text.contains("connection_limit"),
            "{text}"
        );
        // Every class is rate-limited, each in a class of its own.
        assert_eq!(
            TransportEvent::ApproverRefused { uid: 1, pid: None }.class(),
            Some(TransportClass::ApproverRefused)
        );
        assert_eq!(
            TransportEvent::ApproverAuthenticated {
                uid: 1,
                pid: None,
                admitted: true
            }
            .class(),
            Some(TransportClass::ApproverAuthenticated)
        );
    }

    #[test]
    fn a_refused_approver_request_is_the_authoritys_words_never_the_peers() {
        // M6.3 (ADR-0081): the record names the approver as the kernel
        // reported them, the operation, the authority's code and the request
        // the decoded message named -- never a byte the peer chose otherwise.
        let event = TransportEvent::ApproverRequestRefused {
            uid: 2001,
            operation: Some(ApproverKind::Decide),
            code: RefusalCode::BindingMismatch,
            request: Some([0xab; 32]),
        };
        assert_eq!(event.class(), Some(TransportClass::ApproverRequestRefused));
        let (kind, fields) = event.record();
        assert_eq!(kind.as_str(), "approver.request_refused");
        let text = format!("{fields:?}");
        for word in [
            "uid:2001",
            "approver.decide",
            "BINDING_MISMATCH",
            "APPROVER_ENDPOINT",
            &"ab".repeat(32),
        ] {
            assert!(text.contains(word), "{word}: {text}");
        }
        let (_, fields) = TransportEvent::ApproverRequestRefused {
            uid: 2001,
            operation: None,
            code: RefusalCode::MalformedRequest,
            request: None,
        }
        .record();
        let text = format!("{fields:?}");
        assert!(
            text.contains("unreadable") && !text.contains("request_id"),
            "{text}"
        );
    }

    #[test]
    fn a_suppression_record_is_never_itself_rate_limited() {
        let suppressed = TransportEvent::Suppressed {
            class: TransportClass::ProtocolViolation,
            count: 1,
        };
        assert_eq!(suppressed.class(), None);
        for class in TransportClass::ALL {
            assert!(!class.as_str().is_empty());
        }
    }

    #[test]
    fn ordering_violations_carry_no_protocol_code() {
        // No wire code says "out of order"; the record says what happened in
        // the authority's own words instead of borrowing one that does not.
        for violation in [
            Violation::HandshakeRequired,
            Violation::DuplicateHandshake,
            Violation::NotARequest,
        ] {
            assert_eq!(violation.code(), None);
        }
        assert_eq!(Violation::Truncated.code(), Some(ErrorCode::FrameTruncated));
    }
}
