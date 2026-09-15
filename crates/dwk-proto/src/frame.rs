//! DWKP framing.
//!
//! ```text
//! +-------------------------+------------------+---------------------------+
//! | length: u32, big-endian | content type: u8 | body: `length` bytes      |
//! +-------------------------+------------------+---------------------------+
//!   4 bytes                   1 byte             1 ..= 1 048 576 bytes
//! ```
//!
//! * `length` counts the **body only**; the 5-byte header is not included.
//! * `length == 0` is rejected: an empty body is not a message.
//! * `length > MAX_FRAME_BODY` is rejected **from the header alone**, before any
//!   body byte is buffered.
//! * The content-type byte is `0x01` for JSON. Every other value is reserved and
//!   rejected. It exists so a binary encoding can be negotiated later without a
//!   protocol revision (`PROTOCOL.md` §7, ADR-0016).
//!
//! The framing layer knows nothing about JSON, envelopes or operations. It does
//! not trust transport message boundaries: a read may deliver half a header or
//! three frames, and the decoder handles both.
//!
//! **A framing error is fatal to the stream.** After one, the decoder is
//! poisoned and returns the same error forever: once a length prefix has been
//! misread there is no reliable way to find the next frame boundary, and
//! guessing is how a desynchronised stream turns into a smuggled message.

use crate::error::{ErrorCode, ProtocolError};
use crate::limits::MAX_FRAME_BODY;

/// Header length in bytes: 4 (length) + 1 (content type).
pub const HEADER_LEN: usize = 5;

/// The encoding of a frame body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentType {
    /// UTF-8 JSON, canonical (RFC 8785) when produced by this crate.
    Json,
}

impl ContentType {
    /// The header byte.
    #[must_use]
    pub const fn byte(self) -> u8 {
        match self {
            Self::Json => 0x01,
        }
    }

    /// Parse a header byte. Unassigned values return `None`.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Json),
            _ => None,
        }
    }
}

/// One complete frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The body encoding.
    pub content_type: ContentType,
    /// The body bytes, exactly as received.
    pub body: Vec<u8>,
}

/// Encode one frame.
pub fn encode(content_type: ContentType, body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if body.is_empty() {
        return Err(ProtocolError::new(
            ErrorCode::FrameEmpty,
            "refusing to encode an empty body",
        ));
    }
    if body.len() > MAX_FRAME_BODY {
        return Err(ProtocolError::new(
            ErrorCode::FrameTooLarge,
            format!(
                "body of {} bytes exceeds the {MAX_FRAME_BODY}-byte limit",
                body.len()
            ),
        ));
    }
    let length = u32::try_from(body.len())
        .map_err(|_| ProtocolError::new(ErrorCode::FrameTooLarge, "body length overflows u32"))?;
    let mut out = Vec::with_capacity(HEADER_LEN.saturating_add(body.len()));
    out.extend_from_slice(&length.to_be_bytes());
    out.push(content_type.byte());
    out.extend_from_slice(body);
    Ok(out)
}

/// Incremental, bounded frame decoder.
///
/// Memory held at any moment is at most one header plus one declared body, and
/// the declared body is validated against [`MAX_FRAME_BODY`] before the first
/// body byte is stored. The body buffer grows only as bytes actually arrive, so
/// a peer that declares a megabyte and sends nothing costs nothing.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    header: [u8; HEADER_LEN],
    header_filled: usize,
    pending: Option<(ContentType, usize)>,
    body: Vec<u8>,
    poisoned: Option<ProtocolError>,
}

impl FrameDecoder {
    /// A decoder at a frame boundary.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed bytes from the transport.
    ///
    /// Consumes bytes up to the end of the current frame at most, and returns
    /// how many were consumed together with the frame if one completed. The
    /// caller re-feeds the unconsumed remainder, so frames are never merged and
    /// trailing bytes are never skipped.
    pub fn feed(&mut self, input: &[u8]) -> Result<(usize, Option<Frame>), ProtocolError> {
        if let Some(err) = &self.poisoned {
            return Err(err.clone());
        }
        let mut consumed = 0;

        if self.pending.is_none() {
            let need = HEADER_LEN.saturating_sub(self.header_filled);
            let take = need.min(input.len());
            let chunk = input.get(..take).unwrap_or_default();
            for (slot, byte) in self.header.iter_mut().skip(self.header_filled).zip(chunk) {
                *slot = *byte;
            }
            self.header_filled = self.header_filled.saturating_add(take);
            consumed = take;
            if self.header_filled < HEADER_LEN {
                return Ok((consumed, None));
            }
            match Self::parse_header(self.header) {
                Ok(pending) => self.pending = Some(pending),
                Err(err) => {
                    self.poisoned = Some(err.clone());
                    return Err(err);
                }
            }
        }

        let Some((content_type, length)) = self.pending else {
            return Ok((consumed, None));
        };
        let remaining_input = input.get(consumed..).unwrap_or_default();
        let still_needed = length.saturating_sub(self.body.len());
        let take = still_needed.min(remaining_input.len());
        self.body
            .extend_from_slice(remaining_input.get(..take).unwrap_or_default());
        consumed = consumed.saturating_add(take);

        if self.body.len() < length {
            return Ok((consumed, None));
        }
        let frame = Frame {
            content_type,
            body: std::mem::take(&mut self.body),
        };
        self.header_filled = 0;
        self.pending = None;
        Ok((consumed, Some(frame)))
    }

    /// Whether the decoder is at a frame boundary with nothing buffered.
    #[must_use]
    pub const fn is_idle(&self) -> bool {
        self.header_filled == 0 && self.pending.is_none() && self.poisoned.is_none()
    }

    /// Signal end of stream. Buffered partial data is an error.
    pub fn finish(&self) -> Result<(), ProtocolError> {
        if let Some(err) = &self.poisoned {
            return Err(err.clone());
        }
        if self.header_filled == 0 && self.pending.is_none() {
            return Ok(());
        }
        let detail = match self.pending {
            None => format!(
                "stream ended after {} of {HEADER_LEN} header bytes",
                self.header_filled
            ),
            Some((_, length)) => {
                format!(
                    "stream ended after {} of {length} body bytes",
                    self.body.len()
                )
            }
        };
        Err(ProtocolError::new(ErrorCode::FrameTruncated, detail))
    }

    fn parse_header(header: [u8; HEADER_LEN]) -> Result<(ContentType, usize), ProtocolError> {
        let [a, b, c, d, content] = header;
        let declared = u32::from_be_bytes([a, b, c, d]);
        let length = usize::try_from(declared).unwrap_or(usize::MAX);
        if length == 0 {
            return Err(ProtocolError::new(
                ErrorCode::FrameEmpty,
                "frame declares an empty body",
            ));
        }
        if length > MAX_FRAME_BODY {
            return Err(ProtocolError::new(
                ErrorCode::FrameTooLarge,
                format!("frame declares {declared} body bytes; the limit is {MAX_FRAME_BODY}"),
            ));
        }
        let content_type = ContentType::from_byte(content).ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::ContentTypeUnsupported,
                format!("content-type byte 0x{content:02x} is reserved"),
            )
        })?;
        Ok((content_type, length))
    }
}

/// Decode every frame in a complete byte string. Trailing partial data is
/// [`ErrorCode::FrameTruncated`].
pub fn decode_all(mut input: &[u8]) -> Result<Vec<Frame>, ProtocolError> {
    let mut decoder = FrameDecoder::new();
    let mut frames = Vec::new();
    while !input.is_empty() {
        let (consumed, frame) = decoder.feed(input)?;
        if let Some(frame) = frame {
            frames.push(frame);
        }
        input = input.get(consumed..).unwrap_or_default();
        if consumed == 0 {
            break;
        }
    }
    decoder.finish()?;
    Ok(frames)
}
