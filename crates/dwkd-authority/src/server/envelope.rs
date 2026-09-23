//! Response envelopes: what the authority writes around an answer.
//!
//! # What a response binds, and what it does not echo
//!
//! Every response is built here, from the request's decoded header, and the
//! rules come from the registry rather than from this module
//! (`dwk_proto::dwkp::registry`, `RESPONSE`):
//!
//! | field | value | why |
//! |---|---|---|
//! | `v` | the negotiated envelope version | the handshake chose it |
//! | `id` | a fresh `msg_` UUIDv7 the authority mints | never the request's, never chosen by the peer |
//! | `schema_version` | the registry's version for the response schema | `direwolf.run.grant`, `.authority.effective` and `.authority.refused` are version 2 only (ADR-0040) |
//! | `ts` | the authority's clock, advisory | never an input to anything |
//! | `causation_id` | the request's `id` | the one binding between a request and its answer |
//! | `correlation_id` | the request's, if it carried one | groups one logical operation; it is the caller's label |
//! | `session_id`, `run_id`, `epoch`, `idempotency_key` | absent | forbidden on responses: the payload says what the authority decided |
//!
//! A protocol error answering bytes that never decoded names no cause: there
//! is no trustworthy request id to point at, and the registry makes its
//! `causation_id` optional for exactly that reason.
//!
//! Identifiers are not authentication. A peer may reuse another connection's
//! `id` or `correlation_id`, or guess a session id; none of them names a
//! subject, a holder or an epoch, and none is compared with anything here.

use std::sync::atomic::{AtomicU64, Ordering};

use dwk_proto::dwkp::messages::ProtocolErrorPayload;
use dwk_proto::dwkp::{DwkpBody, DwkpMessage, registry};
use dwk_proto::envelope::Header;
use dwk_proto::error::ProtocolError;
use dwk_proto::wire::id::{AnyId, MessageId};
use dwk_proto::wire::scalar::{SchemaName, Timestamp, Version};

/// The largest timestamp a UUIDv7 carries.
const MAX_UUID_TS_MS: u64 = (1 << 48) - 1;

/// Mints `msg_` identifiers: UUIDv7 with the authority's clock in the time
/// field and a per-process counter and instance in the random fields
/// ([RFC 9562] §6.2, as `crate::state`'s ids do). Unique within a process by
/// the counter; uniqueness is not something the wire relies on.
///
/// [RFC 9562]: https://www.rfc-editor.org/rfc/rfc9562
#[derive(Debug)]
pub(crate) struct MessageIds {
    instance: u32,
    counter: AtomicU64,
}

impl MessageIds {
    /// A minter for this process.
    pub(crate) fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        Self {
            instance: std::process::id().rotate_left(16) ^ nanos,
            counter: AtomicU64::new(0),
        }
    }

    /// The next identifier, stamped with `now_ms`.
    pub(crate) fn next(&self, now_ms: u64) -> Option<AnyId> {
        let counter = u128::from(self.counter.fetch_add(1, Ordering::Relaxed) & ((1 << 42) - 1));
        let ts = u128::from(now_ms.min(MAX_UUID_TS_MS));
        let rand_a = (counter >> 30) & 0x0fff;
        let rand_b = ((counter & 0x3fff_ffff) << 32) | u128::from(self.instance);
        let value = (ts << 80) | (0x7 << 76) | (rand_a << 64) | (0b10 << 62) | rand_b;
        MessageId::from_uuid(value).and_then(|id| AnyId::parse(id.as_str()))
    }
}

/// The authority's wall clock, in milliseconds since the Unix epoch.
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` for a Unix time in milliseconds, or `None`
/// outside years 1970–9999.
pub(crate) fn timestamp(unix_ms: u64) -> Option<Timestamp> {
    let millis = unix_ms.rem_euclid(1000);
    let seconds = unix_ms.div_euclid(1000);
    let days = i64::try_from(seconds.div_euclid(86_400)).ok()?;
    let of_day = seconds.rem_euclid(86_400);
    let (hour, minute, second) = (
        of_day.div_euclid(3600),
        of_day.rem_euclid(3600).div_euclid(60),
        of_day.rem_euclid(60),
    );
    let (year, month, day) = civil_from_days(days);
    if !(1970..=9999).contains(&year) {
        return None;
    }
    Timestamp::new(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z"
    ))
}

/// Days since 1970-01-01 to a proleptic Gregorian `(year, month, day)`
/// (Howard Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe.div_euclid(1460) + doe.div_euclid(36_524) - doe.div_euclid(146_096))
        .div_euclid(365);
    let doy = doe - (365 * yoe + yoe.div_euclid(4) - yoe.div_euclid(100));
    let mp = (5 * doy + 2).div_euclid(153);
    let day = doy - (153 * mp + 2).div_euclid(5) + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Builds and encodes response frames.
#[derive(Debug)]
pub(crate) struct Responder {
    ids: MessageIds,
}

/// Why a response could not be built. Never expected: every body the
/// authority produces round-trips through the real decoder before it is sent,
/// and this is what that check reports if it ever does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Unencodable(pub(crate) String);

impl Responder {
    pub(crate) fn new() -> Self {
        Self {
            ids: MessageIds::new(),
        }
    }

    /// A complete frame answering `request` (or, for a protocol error that
    /// answers undecodable bytes, answering nothing) with `body`, in envelope
    /// version `v`.
    pub(crate) fn frame(
        &self,
        v: u16,
        request: Option<&Header>,
        body: DwkpBody,
    ) -> Result<Vec<u8>, Unencodable> {
        let (message_type, schema) = body.identity();
        let spec = registry::message(message_type, schema)
            .ok_or_else(|| Unencodable(format!("{schema} is not a registered message")))?;
        let now = now_ms();
        let header = Header {
            v: Version::new(v).ok_or_else(|| Unencodable("envelope version 0".to_owned()))?,
            id: self
                .ids
                .next(now)
                .ok_or_else(|| Unencodable("could not mint a message id".to_owned()))?,
            message_type,
            schema: SchemaName::new(schema)
                .ok_or_else(|| Unencodable(format!("{schema} is not a schema name")))?,
            // The registry's version for this response: the highest it
            // supports, which for the ADR-0040 messages is 2 and only 2.
            schema_version: Version::new(spec.versions.max)
                .ok_or_else(|| Unencodable("schema version 0".to_owned()))?,
            ts: timestamp(now)
                .ok_or_else(|| Unencodable("the clock is out of range".to_owned()))?,
            correlation_id: request.and_then(|h| h.correlation_id.clone()),
            causation_id: request.map(|h| h.id.clone()),
            session_id: None,
            run_id: None,
            epoch: None,
            idempotency_key: None,
        };
        DwkpMessage { header, body }
            .to_frame()
            .map_err(|error| Unencodable(error.to_string()))
    }

    /// A `direwolf.protocol.error` frame for `error`.
    pub(crate) fn protocol_error(
        &self,
        v: u16,
        request: Option<&Header>,
        error: &ProtocolError,
    ) -> Result<Vec<u8>, Unencodable> {
        self.frame(
            v,
            request,
            DwkpBody::ProtocolError(ProtocolErrorPayload::from(error)),
        )
    }
}

#[cfg(test)]
mod tests {
    use dwk_proto::dwkp::messages::{Ack, HandshakeAccepted};
    use dwk_proto::dwkp::{self, DwkpBody};
    use dwk_proto::envelope::MessageType;
    use dwk_proto::error::{ErrorCode, ProtocolError};
    use dwk_proto::frame::decode_all;
    use dwk_proto::wire::scalar::Version;

    use super::{MessageIds, Responder, timestamp};

    #[test]
    fn timestamps_are_calendar_exact() {
        let cases = [
            (0, "1970-01-01T00:00:00.000Z"),
            (951_782_400_000, "2000-02-29T00:00:00.000Z"),
            (951_868_799_999, "2000-02-29T23:59:59.999Z"),
            (1_758_000_000_000, "2025-09-16T05:20:00.000Z"),
            (4_107_542_399_999, "2100-02-28T23:59:59.999Z"),
            (4_107_542_400_000, "2100-03-01T00:00:00.000Z"),
            (253_402_300_799_999, "9999-12-31T23:59:59.999Z"),
        ];
        for (ms, text) in cases {
            assert_eq!(
                timestamp(ms)
                    .as_ref()
                    .map(dwk_proto::wire::scalar::Timestamp::as_str),
                Some(text),
                "{ms}"
            );
        }
        assert_eq!(timestamp(253_402_300_800_000), None, "year 10000");
    }

    #[test]
    fn minted_ids_are_distinct_message_ids() {
        let ids = MessageIds::new();
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..1000 {
            let Some(id) = ids.next(1_758_000_000_000) else {
                unreachable!("an id")
            };
            assert_eq!(id.prefix(), "msg");
            assert!(seen.insert(id.as_str().to_owned()));
        }
    }

    fn decoded(frame: &[u8]) -> dwkp::DwkpMessage {
        let Ok(frames) = decode_all(frame) else {
            unreachable!("one frame")
        };
        let Some(first) = frames.first() else {
            unreachable!("one frame")
        };
        let Ok(message) = dwkp::decode_frame(first) else {
            unreachable!("the real decoder accepts it")
        };
        message
    }

    fn uuid(n: u128) -> String {
        let ts: u128 = 1_758_000_000_000;
        dwk_proto::wire::id::encode_uuid((ts << 80) | (0x7 << 76) | (0b10 << 62) | n)
    }

    fn request() -> dwkp::DwkpMessage {
        let text = format!(
            r#"{{"v":1,"id":"msg_{}","type":"request","schema":"direwolf.handshake","schema_version":1,"ts":"2026-09-12T09:14:22.481Z","correlation_id":"cor_{}","payload":{{"min_version":1,"max_version":1}}}}"#,
            uuid(1),
            uuid(2)
        );
        let Ok(message) = dwkp::decode_body(text.as_bytes()) else {
            unreachable!("a valid handshake")
        };
        message
    }

    #[test]
    fn a_response_binds_the_request_and_echoes_only_its_correlation() {
        let responder = Responder::new();
        let request = request();
        let Some(version) = Version::new(1) else {
            unreachable!("1")
        };
        let Ok(frame) = responder.frame(
            1,
            Some(&request.header),
            DwkpBody::HandshakeAccepted(HandshakeAccepted { version }),
        ) else {
            unreachable!("encodes")
        };
        let response = decoded(&frame);
        assert_eq!(response.header.message_type, MessageType::Response);
        assert_eq!(
            response.header.causation_id,
            Some(request.header.id.clone())
        );
        assert_eq!(
            response.header.correlation_id,
            request.header.correlation_id
        );
        assert_ne!(
            response.header.id, request.header.id,
            "the authority mints its own id"
        );
        // The claims a request makes about authority state are never echoed.
        assert!(matches!(
            response.header,
            dwk_proto::envelope::Header {
                session_id: None,
                run_id: None,
                epoch: None,
                idempotency_key: None,
                ..
            }
        ));
    }

    #[test]
    fn a_protocol_error_for_undecodable_bytes_names_no_cause() {
        let responder = Responder::new();
        let error = ProtocolError::new(ErrorCode::InvalidJson, "not JSON");
        let Ok(frame) = responder.protocol_error(1, None, &error) else {
            unreachable!("encodes")
        };
        let response = decoded(&frame);
        assert_eq!(response.header.causation_id, None);
        let DwkpBody::ProtocolError(payload) = response.body else {
            unreachable!("a protocol error")
        };
        assert_eq!(payload.code, ErrorCode::InvalidJson);
    }

    #[test]
    fn a_response_uses_the_registry_schema_version() {
        let responder = Responder::new();
        let Ok(frame) = responder.frame(1, Some(&request().header), DwkpBody::Ack(Ack {})) else {
            unreachable!("encodes")
        };
        assert_eq!(decoded(&frame).header.schema_version.get(), 1);
    }
}
