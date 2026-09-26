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

/// The most bytes one `fs.read` may return, inline, in one response (M4b,
/// ADR-0043).
///
/// **Derived from the frame, not chosen for the tool.** The content travels as
/// lowercase hexadecimal — two characters a byte, one spelling per value — so
/// 262 144 bytes are 524 288 characters. That leaves 524 288 bytes of a
/// 1 MiB frame ([`MAX_FRAME_BODY`]) for the envelope, the canonical action and
/// the decision, which together are bounded at under 8 KiB (a 384-character
/// path is at most 2 304 bytes even when every character is a control
/// character that canonical JSON escapes to six, and every other field is a
/// bounded identifier, enum or integer). The factor of more than sixty between
/// the two is the safety margin. A test (`tests/dwkp.rs`) encodes the largest
/// result every field allows and asserts the frame fits.
///
/// A request may ask for less. It may not ask for more: there is no artifact
/// spill in M4b, and a read the transport cannot return is refused at the
/// boundary rather than truncated silently.
pub const MAX_FS_READ_BYTES: usize = 256 * 1024;

// ---------------------------------------------------------------------------
// M4c filesystem operations (ADR-0044 §12). Each bound is derived from the
// 1 MiB frame, which carries everything inline: there is still no artifact
// spill, so a result the transport cannot return is refused, never truncated.
// ---------------------------------------------------------------------------

/// The most bytes one `fs.write` may carry, inline. The same derivation as
/// [`MAX_FS_READ_BYTES`]: 524 288 hex characters, leaving half the frame for
/// the envelope and the path.
pub const MAX_FS_WRITE_BYTES: usize = 256 * 1024;

/// The largest file `fs.patch` operates on, before and after: the broker holds
/// the base and the result in memory, and hashes both. The file's bytes never
/// cross DWKP — only its revisions and the edits do.
pub const MAX_PATCH_FILE_BYTES: usize = 1024 * 1024;

/// The most edits one `fs.patch` may carry.
pub const MAX_PATCH_EDITS: usize = 64;

/// The most bytes all of one `fs.patch`'s edits may insert, **together**.
///
/// **Derived from the frame, like [`MAX_FS_WRITE_BYTES`], and for the same
/// reason**: the inserted bytes are the only part of a patch that grows with
/// the change, and they travel inline as hexadecimal — two characters a byte.
/// 262 144 bytes are 524 288 characters; everything else a worst-case
/// `ToolInvoke` carries (the envelope, a 384-character path at six bytes a
/// character, two revisions, and 64 edits' offsets, lengths and punctuation) is
/// bounded at [`MAX_PATCH_REQUEST_OVERHEAD_BYTES`], so the largest valid patch
/// request is at most [`MAX_PATCH_REQUEST_ENCODED_BYTES`] — leaving
/// [`PATCH_FRAME_MARGIN_BYTES`] of the 1 MiB frame unused. A test
/// (`tests/dwkp_v2.rs`) builds that request and encodes the whole envelope.
///
/// The bytes an edit **deletes** are not bounded separately: they are a range
/// of the base, which is at most [`MAX_PATCH_FILE_BYTES`], and they cross DWKP
/// as two integers, not as bytes. A patch whose inserts exceed this is refused
/// `PATCH_TOO_LARGE` before anything is resolved or recorded (ADR-0044 §12);
/// the 1 MiB file bound is unchanged, because the file itself never crosses.
pub const MAX_PATCH_INSERT_BYTES_TOTAL: usize = 256 * 1024;

/// Everything in the largest `fs.patch` request that is not inserted content,
/// bounded above: the envelope (under 1 KiB), the path (384 characters, at most
/// six bytes each when canonical JSON escapes it: 2 306 bytes with its quotes),
/// two revisions (under 256 bytes), and 64 edits of at most 64 bytes of
/// offsets, lengths, names and punctuation each (4 096 bytes). 16 KiB is more
/// than twice their sum.
pub const MAX_PATCH_REQUEST_OVERHEAD_BYTES: usize = 16 * 1024;

/// The largest a valid `fs.patch` `ToolInvoke` can encode to, frame header
/// included: every inserted byte as two hexadecimal characters, and the
/// overhead above.
pub const MAX_PATCH_REQUEST_ENCODED_BYTES: usize =
    2 * MAX_PATCH_INSERT_BYTES_TOTAL + MAX_PATCH_REQUEST_OVERHEAD_BYTES;

/// How much of the frame the largest valid `fs.patch` request leaves unused.
pub const PATCH_FRAME_MARGIN_BYTES: usize = MAX_FRAME_BODY - MAX_PATCH_REQUEST_ENCODED_BYTES;

const _: () = assert!(MAX_PATCH_REQUEST_ENCODED_BYTES < MAX_FRAME_BODY);
const _: () = assert!(PATCH_FRAME_MARGIN_BYTES >= MAX_FRAME_BODY >> 2);

/// The most directory entries one `fs.list` examines and returns. A listing
/// of 512 names of 255 bytes each, every byte a `"` that canonical JSON escapes
/// to two, is 261 120 characters of names: under a third of the frame.
pub const MAX_LIST_ENTRIES: usize = 512;

/// The most names one `fs.list` reads from a directory before it sorts them:
/// the same bound the resolver keeps when it verifies a name in a directory
/// (ADR-0042). A larger directory is refused, never listed in part by an order
/// the directory chose. At most 255 bytes a name, the broker holds at most
/// 16 MiB of names.
pub const MAX_LIST_SCAN_ENTRIES: usize = 65_536;

/// The most bytes one `fs.search` may scan. Scanning moves no content across
/// DWKP, so this bounds the broker's work, not the frame.
pub const MAX_SEARCH_SCAN_BYTES: usize = 16 * 1024 * 1024;

/// The most match offsets one `fs.search` returns: at most 16 digits each.
pub const MAX_SEARCH_MATCHES: usize = 1024;

/// The longest literal `fs.search` needle, in bytes.
pub const MAX_SEARCH_NEEDLE_BYTES: usize = 1024;

/// The most canonical actions one tool plan holds (`fs.patch` and a creating
/// `fs.write` need two, `fs.move` two; four leaves room and no more).
pub const MAX_PLAN_ACTIONS: usize = 4;

// ---------------------------------------------------------------------------
// M4d process execution (ADR-0045). Arguments travel inline as JSON strings;
// output travels inline as hexadecimal. Both are derived from the unchanged
// 1 MiB frame, like M4c's bounds: a request or a result the transport cannot
// carry is refused, never truncated.
// ---------------------------------------------------------------------------

/// The longest executable path a request or a declaration may state, in bytes:
/// `PATH_MAX`. The resolver bounds the canonical path it derives the same way.
pub const MAX_EXECUTABLE_PATH_BYTES: usize = 4096;

/// The most arguments one `process.exec` may carry after `argv[0]`, which the
/// authority constructs (ADR-0045 §7).
pub const MAX_PROCESS_ARGS: usize = 128;

/// The longest one argument may be, in UTF-8 bytes.
pub const MAX_PROCESS_ARG_BYTES: usize = 8192;

/// The most bytes all of one `process.exec`'s arguments may hold together.
///
/// **Derived from the frame.** Canonical JSON escapes a control character to
/// six bytes, so 65 536 bytes of arguments encode to at most 393 216 bytes;
/// the rest of the largest request (the envelope, a 4 096-byte executable path
/// at six bytes a byte, a working directory, 128 arguments' quotes and commas)
/// is bounded at [`MAX_PROCESS_REQUEST_OVERHEAD_BYTES`]. A test
/// (`tests/dwkp_v3.rs`) builds that request and encodes the whole envelope.
pub const MAX_PROCESS_ARGV_BYTES: usize = 65_536;

/// Everything in the largest `process.exec` request that is not argument
/// content, bounded above: the envelope (under 1 KiB), the executable path
/// (4 096 bytes at six each: 24 578 with its quotes), a working directory (384
/// characters at six bytes: 2 306), and 128 arguments' quotes and separators
/// (384). 64 KiB is more than twice their sum.
pub const MAX_PROCESS_REQUEST_OVERHEAD_BYTES: usize = 64 * 1024;

/// The largest a valid `process.exec` request can encode to, frame header
/// included.
pub const MAX_PROCESS_REQUEST_ENCODED_BYTES: usize =
    6 * MAX_PROCESS_ARGV_BYTES + MAX_PROCESS_REQUEST_OVERHEAD_BYTES;

/// How much of the frame the largest `process.exec` request leaves unused.
pub const PROCESS_REQUEST_FRAME_MARGIN_BYTES: usize =
    MAX_FRAME_BODY - MAX_PROCESS_REQUEST_ENCODED_BYTES;

/// The most bytes of one stream (`stdout` or `stderr`) a process status may
/// return, inline: its **first** bytes, in order. Two streams at two hex
/// characters a byte are 524 288 characters — the same budget as
/// [`MAX_FS_READ_BYTES`].
pub const MAX_PROCESS_STREAM_BYTES: usize = 128 * 1024;

/// The most output bytes a process retains for its caller: both streams
/// together. A `max_output_bytes=N` obligation narrows it to `N` — each stream
/// then retains its first `N / 2` bytes — and never widens it.
pub const MAX_PROCESS_OUTPUT_BYTES: usize = 2 * MAX_PROCESS_STREAM_BYTES;

/// The most one process action in a plan can encode to: a 4 096-byte canonical
/// executable path at six bytes a byte (24 578 with its quotes), a working
/// directory (384 characters at six: 2 306), two digests, a process id, and a
/// decision whose rule id and source are at their longest (under 1 KiB). The
/// authority plans one process action; the wire admits [`MAX_PLAN_ACTIONS`],
/// and the bound below covers what the wire admits.
pub const MAX_PROCESS_PLAN_ACTION_ENCODED_BYTES: usize = 32 * 1024;

const _: () = assert!(
    6 * MAX_EXECUTABLE_PATH_BYTES + 2 + 6 * 384 + 2 + 4 * 1024
        <= MAX_PROCESS_PLAN_ACTION_ENCODED_BYTES
);

/// Everything in the largest process-status response that is not output
/// content: a plan of [`MAX_PLAN_ACTIONS`] process actions at their largest,
/// and 64 KiB for the envelope, the state and both streams' counts and flags
/// (under 2 KiB together).
pub const MAX_PROCESS_RESULT_OVERHEAD_BYTES: usize =
    MAX_PLAN_ACTIONS * MAX_PROCESS_PLAN_ACTION_ENCODED_BYTES + 64 * 1024;

/// The largest a process-status response can encode to, frame header included:
/// both streams' retained bytes as hexadecimal, and the overhead above.
pub const MAX_PROCESS_RESULT_ENCODED_BYTES: usize =
    2 * MAX_PROCESS_OUTPUT_BYTES + MAX_PROCESS_RESULT_OVERHEAD_BYTES;

/// How much of the frame the largest process-status response leaves unused.
pub const PROCESS_RESULT_FRAME_MARGIN_BYTES: usize =
    MAX_FRAME_BODY - MAX_PROCESS_RESULT_ENCODED_BYTES;

const _: () = assert!(MAX_PROCESS_REQUEST_ENCODED_BYTES < MAX_FRAME_BODY);
const _: () = assert!(PROCESS_REQUEST_FRAME_MARGIN_BYTES >= MAX_FRAME_BODY >> 3);
const _: () = assert!(MAX_PROCESS_RESULT_ENCODED_BYTES < MAX_FRAME_BODY);
const _: () = assert!(PROCESS_RESULT_FRAME_MARGIN_BYTES >= MAX_FRAME_BODY >> 3);
const _: () = assert!(MAX_PROCESS_ARGS * MAX_PROCESS_ARG_BYTES >= MAX_PROCESS_ARGV_BYTES);

/// The largest executable the authority hashes and the broker re-hashes, in
/// bytes. A bound on work: a larger file is refused, never hashed in part.
pub const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
