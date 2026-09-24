//! The private authority → broker protocol (M4b, ADR-0043). **Not DWKP.**
//!
//! One exchange on one connection, and nothing else:
//!
//! ```text
//! dwkd-authority                         dwkd-broker
//!    connect ────────────────────────────▶ accept
//!    SO_PEERCRED == broker uid?           SO_PEERCRED == authority uid?
//!                                          (else: close, nothing read)
//!    ◀──────────────────────────── BrokerHello{channel}
//!    FsReadAuthorisation{channel, …} ────▶ + exactly one descriptor (SCM_RIGHTS)
//!                                          verify channel, count, kind, identity
//!                                          read at most max_bytes
//!    ◀────────────────── FsReadOutcome{channel, invocation, done | refused}
//!    close                                 close
//! ```
//!
//! Framing is DWKP's (a 5-byte header and canonical JSON), and every message
//! is a strict `reject` type, but the protocol is otherwise separate: it has
//! no envelope, no registry entry, no emitted schema and no Python binding —
//! nothing on the cognition side can name it. The runtime cannot reach the
//! broker's socket as a peer the broker will read from, because the broker
//! asks the kernel who connected before reading a byte.
//!
//! # Why a channel nonce and no MAC
//!
//! The broker issues a fresh `channel` value on every connection and executes
//! at most one authorisation carrying it. An authorisation is therefore bound
//! to the connection it was issued for: sent again on another connection, or
//! to a restarted broker, it names a channel that does not exist there, and it
//! is refused before any descriptor is touched. Only a process the kernel
//! reports as the authority's uid can deliver one at all. No key exists, so
//! the broker holds none, and no spent-authorisation table exists, so none
//! grows (ADR-0043).
//!
//! This module is wire types and nothing else: no socket, no descriptor, no
//! file. The two daemons do the I/O.

use crate::error::{ErrorCode, ProtocolError, Violation};
use crate::frame::{self, ContentType};
use crate::json::{self, Number, ParseOptions, Value};
use crate::limits::MAX_SAFE_INTEGER;
use crate::schema::{Defs, int, obj, string};
use crate::wire::id::InvocationId;
use crate::wire::macros::wire_struct;
use crate::wire::scalar::{HexContent, ReadLimit, wire_enum, wire_int, wire_text};
use crate::wire::{Cx, WireType, expect_integer, expect_string};

/// The protocol version this build speaks. There is one.
pub const PROTOCOL: u16 = 1;

/// The largest authorisation body the broker reads. An authorisation is a few
/// hundred bytes; the bound is a factor of forty above that and far below a
/// DWKP frame, so a peer cannot make the broker buffer much before it decides.
pub const MAX_AUTHORISATION_BODY: usize = 16 * 1024;

/// The largest hello body the authority reads.
pub const MAX_HELLO_BODY: usize = 1024;

/// The largest outcome body the authority reads: one DWKP frame, which the
/// largest permitted `fs.read` result is derived to fit.
pub const MAX_OUTCOME_BODY: usize = crate::limits::MAX_FRAME_BODY;

/// Descriptors an `fs.read` authorisation carries: exactly one, the file
/// opened for reading. Not the directory it is in, not the workspace root.
pub const FS_READ_DESCRIPTORS: u8 = 1;

wire_int! {
    /// The private protocol's version.
    ProtocolVersion(u16), min = 1, max = 1
}

wire_int! {
    /// How many descriptors accompany a message. For `fs.read`, exactly one.
    DescriptorCount(u8), min = 1, max = 1
}

wire_text! {
    /// A channel: 128 bits the broker chose for one connection, as 32
    /// lowercase hexadecimal characters. Unique per connection within a broker
    /// process and random across processes; it is what makes an authorisation
    /// single-use without a table of spent ones.
    ChannelNonce,
    max_chars = 32,
    pattern = Some("^[0-9a-f]{32}$"),
    format = None,
    validate = |s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

wire_text! {
    /// An unsigned 64-bit kernel number (a device or an inode) as decimal text,
    /// because JSON integers are exact only to 2^53 and an inode need not be
    /// smaller. One spelling per value: no sign, no leading zero.
    KernelNumber,
    max_chars = 20,
    pattern = Some("^(0|[1-9][0-9]{0,19})$"),
    format = None,
    validate = |s| {
        let digits_ok = !s.is_empty()
            && s.bytes().all(|b| b.is_ascii_digit())
            && (s == "0" || !s.starts_with('0'));
        digits_ok && s.parse::<u64>().is_ok()
    }
}

impl KernelNumber {
    /// Spell a number.
    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        Self(value.to_string())
    }

    /// The number. Validation guarantees it parses.
    #[must_use]
    pub fn value(&self) -> u64 {
        self.as_str().parse().unwrap_or(u64::MAX)
    }
}

wire_enum! {
    /// Which private message this is. Checked on decode, so no message can be
    /// read as another even where their fields would allow it.
    PrivateKind {
        /// The broker's greeting: the channel for this connection.
        Hello = "broker.hello",
        /// An `fs.read` authorisation.
        FsRead = "broker.fs_read",
        /// The broker's outcome for an authorisation.
        Outcome = "broker.outcome",
    }
}

wire_enum! {
    /// Why the broker refused an authorisation. Every refusal happens before a
    /// byte of the file is read.
    BrokerRefusal {
        /// The channel named is not this connection's.
        ChannelMismatch = "CHANNEL_MISMATCH",
        /// Not exactly the declared number of descriptors arrived, or the
        /// control data was truncated.
        DescriptorCount = "DESCRIPTOR_COUNT",
        /// The descriptor is not a regular file.
        DescriptorNotRegular = "DESCRIPTOR_NOT_REGULAR",
        /// The descriptor is not open for reading, and only for reading.
        DescriptorNotReadable = "DESCRIPTOR_NOT_READABLE",
        /// The descriptor's `(device, inode)` is not the authorised object's.
        IdentityMismatch = "IDENTITY_MISMATCH",
        /// Reading the descriptor failed.
        ReadFailed = "READ_FAILED",
    }
}

wire_struct! {
    /// The broker's first message on a connection it accepted from the
    /// authority's uid: the channel this connection's one authorisation must
    /// name.
    BrokerHello: reject {
        /// Always `broker.hello`.
        required kind: PrivateKind,
        /// The protocol version.
        required protocol: ProtocolVersion,
        /// This connection's channel.
        required channel: ChannelNonce,
    }
}

wire_struct! {
    /// One `fs.read` the authority authorised, for exactly one descriptor sent
    /// with it. Carries only what the broker must enforce: which object the
    /// descriptor must be, how many bytes it may read, and the ids that bind
    /// the outcome to this authorisation. No path, no policy, no capability.
    FsReadAuthorisation: reject {
        /// Always `broker.fs_read`.
        required kind: PrivateKind,
        /// The protocol version.
        required protocol: ProtocolVersion,
        /// The channel from this connection's hello.
        required channel: ChannelNonce,
        /// The authority's id for the invocation.
        required invocation_id: InvocationId,
        /// The authorised object's device (`st_dev`).
        required device: KernelNumber,
        /// The authorised object's inode (`st_ino`).
        required inode: KernelNumber,
        /// The most bytes to read, from offset zero.
        required max_bytes: ReadLimit,
        /// How many descriptors accompany this message: one.
        required descriptors: DescriptorCount,
    }
}

wire_struct! {
    /// The bytes the broker read.
    FsReadDone: reject {
        /// At most the authorised `max_bytes`, from offset zero.
        required content: HexContent,
        /// Whether a read returned no bytes before `max_bytes` were read: the
        /// end of the file was observed. Never discovered by reading past the
        /// bound (ADR-0043).
        required eof_observed: bool,
    }
}

wire_struct! {
    /// The broker's answer to one authorisation. Exactly one of `done` and
    /// `refused` is present; [`FsReadOutcome::decode_frame_body`] enforces it.
    FsReadOutcome: reject {
        /// Always `broker.outcome`.
        required kind: PrivateKind,
        /// The protocol version.
        required protocol: ProtocolVersion,
        /// The broker's channel for this connection.
        required channel: ChannelNonce,
        /// The invocation this answers.
        required invocation_id: InvocationId,
        /// What was read, if the read happened.
        optional done: FsReadDone,
        /// Why not, if it did not.
        optional refused: BrokerRefusal,
    }
}

/// Encode one private message as a complete frame, re-decoding it first: a
/// message this module would refuse is one it must never send.
///
/// # Errors
///
/// The value does not survive its own round trip, or the frame is too large.
pub fn encode_frame<T: WireType + PartialEq>(message: &T) -> Result<Vec<u8>, ProtocolError> {
    let value = message.encode()?;
    let bytes = json::to_canonical_bytes(&value);
    let reparsed: T = decode_bytes(&bytes, crate::limits::MAX_FRAME_BODY)?;
    if &reparsed != message {
        return Err(ProtocolError::schema(
            Violation::Inconsistent,
            "",
            "a private message does not survive its own round trip",
        ));
    }
    frame::encode(ContentType::Json, &bytes)
}

/// Decode one private message body, strictly, refusing anything over `max`.
///
/// # Errors
///
/// Too large, not the DWKP JSON profile, or not this type.
pub fn decode_bytes<T: WireType>(bytes: &[u8], max: usize) -> Result<T, ProtocolError> {
    if bytes.len() > max {
        return Err(ProtocolError::new(
            ErrorCode::FrameTooLarge,
            format!("a private message of {} bytes exceeds {max}", bytes.len()),
        ));
    }
    let value = json::parse(bytes, ParseOptions::dwkp())?;
    T::decode(value, &mut Cx::new())
}

fn expect_kind(found: PrivateKind, wanted: PrivateKind) -> Result<(), ProtocolError> {
    if found == wanted {
        Ok(())
    } else {
        Err(ProtocolError::schema(
            Violation::Inconsistent,
            "/kind",
            format!("expected {}, found {}", wanted.as_str(), found.as_str()),
        ))
    }
}

impl BrokerHello {
    /// A hello for `channel`.
    #[must_use]
    pub const fn new(channel: ChannelNonce) -> Self {
        Self {
            kind: PrivateKind::Hello,
            protocol: ProtocolVersion(PROTOCOL),
            channel,
        }
    }

    /// Decode a hello body.
    ///
    /// # Errors
    ///
    /// Malformed, or another message.
    pub fn decode_frame_body(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let hello: Self = decode_bytes(bytes, MAX_HELLO_BODY)?;
        expect_kind(hello.kind, PrivateKind::Hello)?;
        Ok(hello)
    }
}

impl FsReadAuthorisation {
    /// An authorisation for one read of the object `(device, inode)`.
    #[must_use]
    pub fn new(
        channel: ChannelNonce,
        invocation_id: InvocationId,
        device: u64,
        inode: u64,
        max_bytes: ReadLimit,
    ) -> Self {
        Self {
            kind: PrivateKind::FsRead,
            protocol: ProtocolVersion(PROTOCOL),
            channel,
            invocation_id,
            device: KernelNumber::from_u64(device),
            inode: KernelNumber::from_u64(inode),
            max_bytes,
            descriptors: DescriptorCount(FS_READ_DESCRIPTORS),
        }
    }

    /// Decode an authorisation body.
    ///
    /// # Errors
    ///
    /// Malformed, too large, or another message.
    pub fn decode_frame_body(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let authorisation: Self = decode_bytes(bytes, MAX_AUTHORISATION_BODY)?;
        expect_kind(authorisation.kind, PrivateKind::FsRead)?;
        Ok(authorisation)
    }
}

/// What an outcome says, once its shape is checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutcomeResult {
    /// The read happened.
    Done(FsReadDone),
    /// The broker refused before reading.
    Refused(BrokerRefusal),
}

impl FsReadOutcome {
    /// An outcome for `invocation_id` on `channel`.
    #[must_use]
    pub fn new(channel: ChannelNonce, invocation_id: InvocationId, result: OutcomeResult) -> Self {
        let (done, refused) = match result {
            OutcomeResult::Done(done) => (Some(done), None),
            OutcomeResult::Refused(why) => (None, Some(why)),
        };
        Self {
            kind: PrivateKind::Outcome,
            protocol: ProtocolVersion(PROTOCOL),
            channel,
            invocation_id,
            done,
            refused,
        }
    }

    /// Decode an outcome body, requiring exactly one of `done` and `refused`.
    ///
    /// # Errors
    ///
    /// Malformed, too large, another message, or neither or both results.
    pub fn decode_frame_body(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let outcome: Self = decode_bytes(bytes, MAX_OUTCOME_BODY)?;
        expect_kind(outcome.kind, PrivateKind::Outcome)?;
        outcome.result()?;
        Ok(outcome)
    }

    /// The result.
    ///
    /// # Errors
    ///
    /// Neither or both of `done` and `refused` present.
    pub fn result(&self) -> Result<OutcomeResult, ProtocolError> {
        match (&self.done, self.refused) {
            (Some(done), None) => Ok(OutcomeResult::Done(done.clone())),
            (None, Some(why)) => Ok(OutcomeResult::Refused(why)),
            _ => Err(ProtocolError::schema(
                Violation::Inconsistent,
                "",
                "an outcome carries exactly one of done and refused",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BrokerHello, BrokerRefusal, ChannelNonce, FsReadAuthorisation, FsReadDone, FsReadOutcome,
        KernelNumber, MAX_AUTHORISATION_BODY, OutcomeResult, encode_frame,
    };
    use crate::frame::{FrameDecoder, HEADER_LEN};
    use crate::limits::{MAX_FRAME_BODY, MAX_FS_READ_BYTES};
    use crate::wire::id::InvocationId;
    use crate::wire::scalar::{HexContent, ReadLimit};

    fn channel() -> ChannelNonce {
        ChannelNonce::new("0123456789abcdef0123456789abcdef").unwrap_or_else(|| unreachable!())
    }

    fn invocation() -> InvocationId {
        InvocationId::parse("inv_01M24BB8G3E0A851TRWE3M8FZF").unwrap_or_else(|| unreachable!())
    }

    fn body(frame: &[u8]) -> Vec<u8> {
        let mut decoder = FrameDecoder::new();
        match decoder.feed(frame) {
            Ok((_, Some(frame))) => frame.body,
            other => unreachable!("{other:?}"),
        }
    }

    #[test]
    fn each_message_round_trips_and_is_not_another() {
        let hello = BrokerHello::new(channel());
        let bytes = body(&encode_frame(&hello).unwrap_or_default());
        assert_eq!(BrokerHello::decode_frame_body(&bytes), Ok(hello));
        assert!(FsReadAuthorisation::decode_frame_body(&bytes).is_err());
        assert!(FsReadOutcome::decode_frame_body(&bytes).is_err());

        let limit = ReadLimit::new(4096).unwrap_or_else(|| unreachable!());
        let authorisation =
            FsReadAuthorisation::new(channel(), invocation(), 2049, u64::MAX, limit);
        let bytes = body(&encode_frame(&authorisation).unwrap_or_default());
        assert!(bytes.len() < MAX_AUTHORISATION_BODY);
        let decoded = FsReadAuthorisation::decode_frame_body(&bytes);
        assert_eq!(decoded.as_ref().map(|a| a.inode.value()), Ok(u64::MAX));
        assert_eq!(decoded, Ok(authorisation));
        assert!(BrokerHello::decode_frame_body(&bytes).is_err());
    }

    #[test]
    fn an_outcome_carries_exactly_one_result() {
        let done = FsReadDone {
            content: HexContent::from_bytes(b"hi").unwrap_or_else(|| unreachable!()),
            eof_observed: true,
        };
        for result in [
            OutcomeResult::Done(done.clone()),
            OutcomeResult::Refused(BrokerRefusal::IdentityMismatch),
        ] {
            let outcome = FsReadOutcome::new(channel(), invocation(), result.clone());
            let bytes = body(&encode_frame(&outcome).unwrap_or_default());
            let decoded = FsReadOutcome::decode_frame_body(&bytes);
            assert_eq!(decoded.and_then(|o| o.result()), Ok(result));
        }
        let mut both = FsReadOutcome::new(channel(), invocation(), OutcomeResult::Done(done));
        both.refused = Some(BrokerRefusal::ReadFailed);
        assert!(encode_frame(&both).is_err() || both.result().is_err());
        let text = r#"{"channel":"0123456789abcdef0123456789abcdef","invocation_id":"inv_01M24BB8G3E0A851TRWE3M8FZF","kind":"broker.outcome","protocol":1}"#;
        assert!(FsReadOutcome::decode_frame_body(text.as_bytes()).is_err());
    }

    #[test]
    fn unknown_members_and_second_spellings_are_refused() {
        for text in [
            r#"{"channel":"0123456789abcdef0123456789abcdef","kind":"broker.hello","protocol":1,"extra":1}"#,
            r#"{"channel":"0123456789ABCDEF0123456789ABCDEF","kind":"broker.hello","protocol":1}"#,
            r#"{"channel":"0123456789abcdef0123456789abcdef","kind":"broker.hello","protocol":2}"#,
            r#"{"channel":"0123456789abcdef0123456789abcdef","kind":"broker.hello","kind":"broker.hello","protocol":1}"#,
        ] {
            assert!(
                BrokerHello::decode_frame_body(text.as_bytes()).is_err(),
                "{text}"
            );
        }
        for (text, ok) in [
            ("0", true),
            ("18446744073709551615", true),
            ("007", false),
            ("18446744073709551616", false),
            ("-1", false),
            ("", false),
        ] {
            assert_eq!(KernelNumber::new(text).is_some(), ok, "{text:?}");
        }
    }

    #[test]
    fn the_largest_outcome_fits_one_frame() {
        let content = vec![0xffu8; MAX_FS_READ_BYTES];
        let done = FsReadDone {
            content: HexContent::from_bytes(&content).unwrap_or_else(|| unreachable!()),
            eof_observed: false,
        };
        let outcome = FsReadOutcome::new(channel(), invocation(), OutcomeResult::Done(done));
        let frame = encode_frame(&outcome).unwrap_or_default();
        assert!(frame.len() > HEADER_LEN + 2 * MAX_FS_READ_BYTES);
        assert!(frame.len() <= HEADER_LEN + MAX_FRAME_BODY);
        assert!(HexContent::from_bytes(&vec![0u8; MAX_FS_READ_BYTES + 1]).is_none());
    }
}
