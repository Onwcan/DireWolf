//! Hard protocol limits.
//!
//! Every limit here is enforced by the parser **before** the allocation it
//! bounds, not validated afterwards. They are constants rather than
//! configuration: a limit an attacker-influenced config file can raise is not a
//! limit. Values and rationale are recorded in ADR-0032.

/// Maximum frame body, in bytes: exactly 1 MiB (`PROTOCOL.md` §2).
///
/// The 5-byte frame header is not counted. The decoder rejects a declared
/// length above this from the header alone, before reserving any buffer.
pub const MAX_FRAME_BODY: usize = 1 << 20;

/// Maximum size of a DWCP message or an event-log record, in bytes.
///
/// These families have no DireWolf framing of their own (DWCP rides WebSocket,
/// records live in the event log), so the same bound is applied at the decode
/// entry point.
pub const MAX_MESSAGE_BYTES: usize = MAX_FRAME_BODY;

/// Maximum JSON nesting depth: the number of arrays and objects that may
/// enclose a value. The top-level container is depth 1.
///
/// The deepest DWKP message defined by M2 nests 3 levels (envelope → payload →
/// version range). 32 leaves a factor of ten for growth while keeping the
/// recursion in the lexer trivially bounded; see ADR-0032.
pub const MAX_DEPTH: usize = 32;

/// Largest integer magnitude admitted on the wire: 2^53 − 1.
///
/// Every integer in this range survives a round trip through an IEEE-754
/// double, so Rust, Python and a browser client all read the same value, and
/// RFC 8785 serialises it as plain digits (I-JSON, RFC 7493 §2.2).
pub const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

/// Maximum length, in Unicode scalar values, of a JSON Pointer reported in a
/// protocol error. Paths can contain attacker-chosen keys and errors are
/// audited, so they are truncated rather than echoed in full.
pub const MAX_ERROR_PATH_CHARS: usize = 256;

/// Maximum length, in Unicode scalar values, of a protocol error's `detail`.
pub const MAX_ERROR_DETAIL_CHARS: usize = 512;
