//! The private authority → broker protocol (M4b, ADR-0043; version 2 for the
//! M4c filesystem operations, ADR-0044). **Not DWKP.**
//!
//! One exchange on one connection, and nothing else:
//!
//! ```text
//! dwkd-authority                         dwkd-broker
//!    connect ────────────────────────────▶ accept
//!    SO_PEERCRED == broker uid?           SO_PEERCRED == authority uid?
//!                                          (else: close, nothing read)
//!    ◀──────────────────────────── BrokerHello{channel}
//!    <operation>Authorisation{channel, …} ▶ + exactly the operation's
//!                                            descriptors (SCM_RIGHTS)
//!                                          verify channel, count, kinds,
//!                                          identities; perform
//!    ◀──── BrokerOutcome{channel, invocation, done | refused | indeterminate}
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
//! # One message per operation, and every descriptor's role fixed
//!
//! Each operation has its own authorisation type, with exactly the fields the
//! broker must enforce and nothing it could decide on: identities to re-prove,
//! bounds, and — for a namespace operation — the **single validated name
//! component** it acts on relative to a transferred directory. Never a path,
//! never a host root, never a policy or a capability. The descriptors each
//! carries are fixed per operation ([`PrivateKind::descriptors`]), in a fixed
//! order; any other count is refused with every received descriptor closed.
//!
//! # Three kinds of answer
//!
//! * `done` — the operation completed; its per-operation result.
//! * `refused` — **no persistent change**: the broker refused before acting,
//!   or its change reached an object it did not prove and it undid the change
//!   and proved the undo (for that moment the change may have been visible;
//!   ADR-0044 §5). The authority records a failure that is provably without
//!   lasting effect.
//! * `indeterminate` — the broker may have changed something and cannot prove
//!   the final state (a displaced object could not be put back; a directory
//!   could not be made durable after a rename). The authority records the
//!   outcome as unknown and never performs the invocation again.
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

pub use crate::dwkp::fsops::{ContentRevision, PatchEdit, PatchEdits};
use crate::error::{ErrorCode, ProtocolError, Violation};
use crate::frame::{self, ContentType};
use crate::json::{self, Number, ParseOptions, Value};
use crate::limits::{
    MAX_LIST_ENTRIES, MAX_PATCH_INSERT_BYTES_TOTAL, MAX_SAFE_INTEGER, MAX_SEARCH_MATCHES,
};
use crate::schema::{Defs, int, obj, string};
use crate::wire::id::InvocationId;
use crate::wire::list::BoundedList;
use crate::wire::macros::wire_struct;
use crate::wire::scalar::{
    ByteCount, EntryKind, HexContent, LinkCount, ListLimit, MatchLimit, Needle, ObjectState,
    PatchOutcome, ReadLimit, ScanLimit, StatKind, wire_enum, wire_int, wire_text,
};
use crate::wire::{Cx, WireType, expect_integer, expect_string};

/// The protocol version this build speaks. Version 2 (ADR-0044) adds the M4c
/// operations and the `indeterminate` answer; a version-1 peer is refused by
/// its hello, never half-understood.
pub const PROTOCOL: u16 = 2;

/// The largest authorisation body the broker reads: one DWKP frame, because an
/// `fs.write` carries its content and an `fs.patch` its edits. Read from the
/// frame header before a body byte is buffered, and only from a peer the
/// kernel reported as the authority's uid.
pub const MAX_AUTHORISATION_BODY: usize = crate::limits::MAX_FRAME_BODY;

/// The largest hello body the authority reads.
pub const MAX_HELLO_BODY: usize = 1024;

/// The largest outcome body the authority reads: one DWKP frame, which the
/// largest permitted result is derived to fit.
pub const MAX_OUTCOME_BODY: usize = crate::limits::MAX_FRAME_BODY;

/// Descriptors an `fs.read` authorisation carries: exactly one, the file
/// opened for reading. Not the directory it is in, not the workspace root.
pub const FS_READ_DESCRIPTORS: u8 = 1;

/// The mode every file `fs.write` creates has, exactly, whatever the broker's
/// umask: read and write for its owner and its group, nothing for others, and
/// never an execute bit (ADR-0044 §5). A replacement keeps the replaced file's
/// permission bits instead.
pub const CREATED_FILE_MODE: u32 = 0o660;

wire_int! {
    /// The private protocol's version.
    ProtocolVersion(u16), min = 2, max = 2
}

wire_int! {
    /// How many descriptors accompany an authorisation: one or two, fixed by
    /// its kind.
    DescriptorCount(u8), min = 1, max = 2
}

wire_int! {
    /// A file's permission bits, as `st_mode & 0o7777`.
    ModeBits(u16), min = 0, max = 0o7777
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

wire_text! {
    /// **One** name component a namespace operation acts on, relative to a
    /// directory descriptor it was handed: the name the authority validated
    /// against the canonical grammar (ADR-0042) and checked in that directory.
    /// Lexically bounded here as defence in depth — 1 to 255 bytes, no `/`,
    /// no NUL, not `.` or `..` — so that no decoded message can carry a path,
    /// a traversal or a second component, whatever the sender validated.
    LeafName,
    max_chars = 255,
    pattern = Some("^(?!\\.\\.?$)[^/\\u0000]{1,255}$"),
    format = None,
    validate = valid_leaf
}

fn valid_leaf(s: &str) -> bool {
    !s.is_empty() && s.len() <= 255 && s != "." && s != ".." && !s.contains(['/', '\0'])
}

wire_text! {
    /// A directory entry's name exactly as the directory holds it — any bytes
    /// but `/` and NUL, which need not be UTF-8 — as lowercase hexadecimal.
    /// The broker does not judge names; the authority applies the canonical
    /// grammar to them and emits only those a canonical path can name
    /// (ADR-0044 §6).
    RawName,
    max_chars = 510,
    pattern = Some("^(?:[0-9a-f]{2}){1,255}$"),
    format = None,
    validate = |s| !s.is_empty() && s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl RawName {
    /// Spell a name's bytes, or `None` if empty or over 255 bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Self::new(HexContent::from_bytes(bytes)?.as_str())
    }

    /// The name's bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        HexContent::new(self.as_str()).map_or_else(Vec::new, |hex| hex.to_bytes())
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
        /// An `fs.stat` authorisation.
        FsStat = "broker.fs_stat",
        /// An `fs.list` authorisation.
        FsList = "broker.fs_list",
        /// An `fs.search` authorisation.
        FsSearch = "broker.fs_search",
        /// An `fs.write` authorisation.
        FsWrite = "broker.fs_write",
        /// An `fs.patch` authorisation.
        FsPatch = "broker.fs_patch",
        /// An `fs.move` authorisation.
        FsMove = "broker.fs_move",
        /// An `fs.delete` authorisation.
        FsDelete = "broker.fs_delete",
        /// An authorisation to reclaim one invocation's staging directory.
        FsReclaim = "broker.fs_reclaim",
        /// The broker's outcome for an authorisation.
        Outcome = "broker.outcome",
    }
}

impl PrivateKind {
    /// How many descriptors an authorisation of this kind carries, in order
    /// (ADR-0044 §8):
    ///
    /// | kind | descriptors |
    /// |---|---|
    /// | `fs_read`, `fs_search` | the file, open for reading |
    /// | `fs_stat` | the object, `O_PATH` |
    /// | `fs_list` | the directory, open for reading |
    /// | `fs_write`, `fs_delete` | the parent directory, open for reading |
    /// | `fs_patch` | the parent directory; the file, open for reading |
    /// | `fs_move` | the source's parent directory; the destination's |
    /// | `fs_reclaim` | the directory the staging directory is in, open for reading |
    ///
    /// `None` for the hello and the outcome, which carry none.
    #[must_use]
    pub const fn descriptors(self) -> Option<u8> {
        match self {
            Self::FsRead
            | Self::FsStat
            | Self::FsList
            | Self::FsSearch
            | Self::FsWrite
            | Self::FsDelete
            | Self::FsReclaim => Some(1),
            Self::FsPatch | Self::FsMove => Some(2),
            Self::Hello | Self::Outcome => None,
        }
    }
}

wire_enum! {
    /// Why the broker refused an authorisation. **A refusal means no
    /// persistent change**: the broker refused before acting, or it undid its
    /// change and proved the undo (ADR-0044 §5).
    BrokerRefusal {
        /// The channel named is not this connection's.
        ChannelMismatch = "CHANNEL_MISMATCH",
        /// Not exactly the operation's number of descriptors arrived, or the
        /// control data was truncated.
        DescriptorCount = "DESCRIPTOR_COUNT",
        /// A descriptor that must be a regular file is not.
        DescriptorNotRegular = "DESCRIPTOR_NOT_REGULAR",
        /// A descriptor that must be a directory is not.
        DescriptorNotDirectory = "DESCRIPTOR_NOT_DIRECTORY",
        /// A descriptor is not open for reading, and only for reading.
        DescriptorNotReadable = "DESCRIPTOR_NOT_READABLE",
        /// A descriptor that must be `O_PATH` — able to name the object and
        /// nothing more — is not.
        DescriptorNotPath = "DESCRIPTOR_NOT_PATH",
        /// A descriptor's `(device, inode)` is not the authorised object's.
        IdentityMismatch = "IDENTITY_MISMATCH",
        /// Reading a descriptor failed.
        ReadFailed = "READ_FAILED",
        /// The name no longer binds the authorised object (it was replaced,
        /// renamed or removed). Nothing was changed.
        ObjectChanged = "OBJECT_CHANGED",
        /// A name that was to be created is occupied. Nothing was created and
        /// nothing replaced.
        TargetOccupied = "TARGET_OCCUPIED",
        /// A patch's file holds neither its base nor its post revision, or
        /// changed while it was being replaced. Nothing was changed.
        Conflict = "CONFLICT",
        /// The directory to remove is not empty. Nothing was removed.
        DirectoryNotEmpty = "DIRECTORY_NOT_EMPTY",
        /// The broker's identity may not change names in the directory.
        WriteDenied = "WRITE_DENIED",
        /// A replacement could not keep the replaced file's group.
        AttributesNotPreserved = "ATTRIBUTES_NOT_PRESERVED",
        /// The directory whose names would change is writable by every user:
        /// a writer outside the trusted set could race the change, which the
        /// permission model must exclude (ADR-0044 §8).
        SharedDirectory = "SHARED_DIRECTORY",
        /// The object or the filesystem cannot be operated on as the contract
        /// requires: a setuid, setgid or sticky file; no atomic exchange.
        Unsupported = "UNSUPPORTED",
        /// The directory holds more entries than a listing may examine.
        DirectoryTooLarge = "DIRECTORY_TOO_LARGE",
        /// Another operating-system error, before anything was changed.
        IoError = "IO_ERROR",
    }
}

wire_enum! {
    /// Why the broker cannot say what it changed. The authority records the
    /// outcome as unknown and never performs the invocation again.
    Indeterminate {
        /// An object the broker had moved aside could not be put back.
        RestoreFailed = "RESTORE_FAILED",
        /// A name was changed, and the directory holding it could not then be
        /// made durable.
        DurabilityUnconfirmed = "DURABILITY_UNCONFIRMED",
        /// A namespace system call failed in a way that does not prove it did
        /// nothing.
        EffectUnconfirmed = "EFFECT_UNCONFIRMED",
    }
}

wire_enum! {
    /// Which operation a staging directory was made for: what the broker may
    /// have put in it, and so how it is judged when it is reclaimed.
    StagingOperation {
        /// An `fs.write` replacing a file, or an `fs.patch`.
        Replace = "REPLACE",
        /// An `fs.write` creating a file.
        Create = "CREATE",
        /// An `fs.delete`.
        Delete = "DELETE",
    }
}

wire_enum! {
    /// What reclaiming a staging directory found and did (ADR-0044 §10).
    ReclaimState {
        /// There is no staging directory: nothing to do.
        Absent = "ABSENT",
        /// It provably held only what the broker wrote before any effect, and
        /// it is gone.
        Removed = "REMOVED",
        /// It may hold an object that was in the workspace, or it is the
        /// evidence of an effect: it is kept, untouched.
        Retained = "RETAINED",
        /// The name is not a staging directory this broker made for this
        /// invocation: it is untouched.
        Foreign = "FOREIGN",
    }
}

wire_enum! {
    /// Why a staging directory is retained.
    StagingHolds {
        /// The object an exchange displaced from the workspace — the replaced
        /// file, or whatever a concurrent writer had put under its name.
        Displaced = "DISPLACED",
        /// The object a delete took out of the workspace, not yet removed.
        Taken = "TAKEN",
        /// No object: the effect completed, and the directory's record is the
        /// evidence that it did.
        Evidence = "EVIDENCE",
        /// Entries the broker cannot account for.
        Unexpected = "UNEXPECTED",
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
    /// One `fs.stat`: report the metadata of the object whose `O_PATH`
    /// descriptor accompanies it.
    FsStatAuthorisation: reject {
        /// Always `broker.fs_stat`.
        required kind: PrivateKind,
        /// The protocol version.
        required protocol: ProtocolVersion,
        /// The channel from this connection's hello.
        required channel: ChannelNonce,
        /// The authority's id for the invocation.
        required invocation_id: InvocationId,
        /// The authorised object's device.
        required device: KernelNumber,
        /// The authorised object's inode.
        required inode: KernelNumber,
        /// One: the object, `O_PATH`.
        required descriptors: DescriptorCount,
    }
}

wire_struct! {
    /// One `fs.list`: enumerate the directory whose descriptor accompanies it,
    /// through that descriptor, examining at most `max_entries` names in byte
    /// order.
    FsListAuthorisation: reject {
        /// Always `broker.fs_list`.
        required kind: PrivateKind,
        /// The protocol version.
        required protocol: ProtocolVersion,
        /// The channel from this connection's hello.
        required channel: ChannelNonce,
        /// The authority's id for the invocation.
        required invocation_id: InvocationId,
        /// The directory's device.
        required device: KernelNumber,
        /// The directory's inode.
        required inode: KernelNumber,
        /// The most entries to examine.
        required max_entries: ListLimit,
        /// One: the directory, open for reading.
        required descriptors: DescriptorCount,
    }
}

wire_struct! {
    /// One `fs.search`: find `needle` in the first `max_scan_bytes` of the file
    /// whose readable descriptor accompanies it. Never a byte past the bound.
    FsSearchAuthorisation: reject {
        /// Always `broker.fs_search`.
        required kind: PrivateKind,
        /// The protocol version.
        required protocol: ProtocolVersion,
        /// The channel from this connection's hello.
        required channel: ChannelNonce,
        /// The authority's id for the invocation.
        required invocation_id: InvocationId,
        /// The file's device.
        required device: KernelNumber,
        /// The file's inode.
        required inode: KernelNumber,
        /// The bytes to find.
        required needle: Needle,
        /// The most bytes to scan.
        required max_scan_bytes: ScanLimit,
        /// The most offsets to report.
        required max_matches: MatchLimit,
        /// One: the file, open for reading.
        required descriptors: DescriptorCount,
    }
}

wire_struct! {
    /// One `fs.write`: replace the file `leaf` names in the accompanying
    /// directory with `content`, or create it — atomically: a new file written
    /// and synced in a private staging directory, then exchanged or renamed
    /// into place, then the directory synced.
    ///
    /// `object` says which: `EXISTING` names the file that must still be at
    /// `leaf` (`target_device`, `target_inode`, both required); `VACANT` says
    /// nothing may be (both absent). The broker exchanges only after checking
    /// the name binds the object it was told of, undoes an exchange that
    /// displaced anything else (ADR-0044 §5), and never creates over anything.
    FsWriteAuthorisation: reject {
        /// Always `broker.fs_write`.
        required kind: PrivateKind,
        /// The protocol version.
        required protocol: ProtocolVersion,
        /// The channel from this connection's hello.
        required channel: ChannelNonce,
        /// The authority's id for the invocation.
        required invocation_id: InvocationId,
        /// The parent directory's device.
        required parent_device: KernelNumber,
        /// The parent directory's inode.
        required parent_inode: KernelNumber,
        /// The one name, in that directory.
        required leaf: LeafName,
        /// Whether a file is to be replaced or created.
        required object: ObjectState,
        /// For a replacement: the file's device.
        optional target_device: KernelNumber,
        /// For a replacement: the file's inode.
        optional target_inode: KernelNumber,
        /// The complete new content.
        required content: HexContent,
        /// One: the parent directory, open for reading.
        required descriptors: DescriptorCount,
    }
}

wire_struct! {
    /// One `fs.patch`: if the file holds `base`, replace it with `base` edited
    /// by `edits`, which must be `post`; if it already holds `post`, change
    /// nothing; otherwise refuse. Atomically, as `fs.write` replaces.
    FsPatchAuthorisation: reject {
        /// Always `broker.fs_patch`.
        required kind: PrivateKind,
        /// The protocol version.
        required protocol: ProtocolVersion,
        /// The channel from this connection's hello.
        required channel: ChannelNonce,
        /// The authority's id for the invocation.
        required invocation_id: InvocationId,
        /// The parent directory's device.
        required parent_device: KernelNumber,
        /// The parent directory's inode.
        required parent_inode: KernelNumber,
        /// The file's name, in that directory.
        required leaf: LeafName,
        /// The file's device.
        required target_device: KernelNumber,
        /// The file's inode.
        required target_inode: KernelNumber,
        /// What the file must hold for the edits to apply.
        required base: ContentRevision,
        /// What it holds afterwards.
        required post: ContentRevision,
        /// The edits, against the base.
        required edits: PatchEdits,
        /// Two: the parent directory, then the file, both open for reading.
        required descriptors: DescriptorCount,
    }
}

wire_struct! {
    /// One `fs.move`: rename the regular file `source_leaf` names in the first
    /// directory to the vacant name `destination_leaf` in the second, with one
    /// `renameat2(RENAME_NOREPLACE)`. Never replaces; never copies.
    FsMoveAuthorisation: reject {
        /// Always `broker.fs_move`.
        required kind: PrivateKind,
        /// The protocol version.
        required protocol: ProtocolVersion,
        /// The channel from this connection's hello.
        required channel: ChannelNonce,
        /// The authority's id for the invocation.
        required invocation_id: InvocationId,
        /// The source's parent directory's device.
        required source_parent_device: KernelNumber,
        /// The source's parent directory's inode.
        required source_parent_inode: KernelNumber,
        /// The source's name.
        required source_leaf: LeafName,
        /// The file's device.
        required source_device: KernelNumber,
        /// The file's inode.
        required source_inode: KernelNumber,
        /// The destination's parent directory's device.
        required destination_parent_device: KernelNumber,
        /// The destination's parent directory's inode.
        required destination_parent_inode: KernelNumber,
        /// The destination's name, which must be vacant.
        required destination_leaf: LeafName,
        /// Two: the source's parent directory, then the destination's, both
        /// open for reading — the same directory twice when they are one.
        required descriptors: DescriptorCount,
    }
}

wire_struct! {
    /// One `fs.delete`: remove the name `leaf` in the accompanying directory,
    /// if it still binds the authorised object — moved first into a private
    /// staging directory, proved there, and only then removed.
    FsDeleteAuthorisation: reject {
        /// Always `broker.fs_delete`.
        required kind: PrivateKind,
        /// The protocol version.
        required protocol: ProtocolVersion,
        /// The channel from this connection's hello.
        required channel: ChannelNonce,
        /// The authority's id for the invocation.
        required invocation_id: InvocationId,
        /// The parent directory's device.
        required parent_device: KernelNumber,
        /// The parent directory's inode.
        required parent_inode: KernelNumber,
        /// The one name, in that directory.
        required leaf: LeafName,
        /// The object's device.
        required target_device: KernelNumber,
        /// The object's inode.
        required target_inode: KernelNumber,
        /// A regular file, or an empty directory.
        required target_kind: StatKind,
        /// One: the parent directory, open for reading.
        required descriptors: DescriptorCount,
    }
}

wire_struct! {
    /// Reclaim the staging directory of `invocation_id` in the accompanying
    /// directory (ADR-0044 §10): remove it only if it provably holds nothing
    /// but what the broker wrote before any effect; otherwise keep it and say
    /// what it holds. Never a directory by its spelling alone: it must be the
    /// broker's own (owner, mode) and its record must name this invocation,
    /// operation, name and target.
    FsReclaimAuthorisation: reject {
        /// Always `broker.fs_reclaim`.
        required kind: PrivateKind,
        /// The protocol version.
        required protocol: ProtocolVersion,
        /// The channel from this connection's hello.
        required channel: ChannelNonce,
        /// The invocation whose staging directory this is. Its outcome is
        /// already recorded; this is never that invocation again.
        required invocation_id: InvocationId,
        /// The directory's device.
        required parent_device: KernelNumber,
        /// The directory's inode.
        required parent_inode: KernelNumber,
        /// The name the invocation changed.
        required leaf: LeafName,
        /// What the invocation was.
        required operation: StagingOperation,
        /// For a replacement or a delete: the object authorised.
        optional target_device: KernelNumber,
        /// For a replacement or a delete: the object authorised.
        optional target_inode: KernelNumber,
        /// One: the directory, open for reading.
        required descriptors: DescriptorCount,
    }
}

// ---------------------------------------------------------------------------
// Outcomes.
// ---------------------------------------------------------------------------

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
    /// What `fstat` said about the object.
    FsStatDone: reject {
        /// What it is.
        required kind: StatKind,
        /// `st_size`.
        required size: ByteCount,
        /// `st_nlink`.
        required link_count: LinkCount,
        /// `st_mode & 0o7777`.
        required mode: ModeBits,
    }
}

wire_struct! {
    /// One directory entry, as the directory holds it.
    RawEntry: reject {
        /// Its name's bytes.
        required name: RawName,
        /// Its `d_type`.
        required kind: EntryKind,
    }
}

/// A listing's entries, in ascending byte order of their names.
pub type RawEntries = BoundedList<RawEntry, MAX_LIST_ENTRIES>;

wire_struct! {
    /// The first `max_entries` names of the directory in byte order, and
    /// whether that was all of them.
    FsListDone: reject {
        /// The entries, in ascending byte order; `.` and `..` omitted.
        required entries: RawEntries,
        /// Whether every entry was examined.
        required complete: bool,
    }
}

/// Match offsets, ascending.
pub type RawOffsets = BoundedList<ByteCount, MAX_SEARCH_MATCHES>;

wire_struct! {
    /// Where the needle occurs in the scanned bytes.
    FsSearchDone: reject {
        /// Every offset at which the needle starts and ends within the scanned
        /// bytes, overlapping occurrences included, up to `max_matches`.
        required offsets: RawOffsets,
        /// How many bytes were scanned.
        required scanned: ByteCount,
        /// Whether the end of the file was observed within the scan.
        required eof_observed: bool,
        /// Whether more matches were found than reported.
        required matches_truncated: bool,
    }
}

wire_struct! {
    /// An `fs.write` completed and is durable.
    FsWriteDone: reject {
        /// Whether the file was created rather than replaced.
        required created: bool,
        /// Whether the private staging directory could not be removed
        /// afterwards (its name derives from the invocation id).
        required debris: bool,
    }
}

wire_struct! {
    /// An `fs.patch` completed and is durable, or had already been applied.
    FsPatchDone: reject {
        /// Whether the file was changed.
        required outcome: PatchOutcome,
        /// Whether the private staging directory could not be removed.
        required debris: bool,
    }
}

wire_struct! {
    /// An `fs.move` completed and is durable.
    FsMoveDone: reject {}
}

wire_struct! {
    /// An `fs.delete` completed and is durable.
    FsDeleteDone: reject {
        /// Whether the private staging directory could not be removed.
        required debris: bool,
    }
}

wire_struct! {
    /// What reclaiming a staging directory found and did.
    FsReclaimDone: reject {
        /// Absent, removed, retained or foreign.
        required state: ReclaimState,
        /// For a retained directory: why.
        optional holds: StagingHolds,
        /// For a retained object: its device.
        optional held_device: KernelNumber,
        /// For a retained object: its inode.
        optional held_inode: KernelNumber,
    }
}

wire_struct! {
    /// A completed operation's result: exactly one member, the operation's own.
    BrokerDone: reject {
        /// An `fs.read`'s bytes.
        optional fs_read: FsReadDone,
        /// An `fs.stat`'s metadata.
        optional fs_stat: FsStatDone,
        /// An `fs.list`'s entries.
        optional fs_list: FsListDone,
        /// An `fs.search`'s offsets.
        optional fs_search: FsSearchDone,
        /// An `fs.write`'s acknowledgement.
        optional fs_write: FsWriteDone,
        /// An `fs.patch`'s acknowledgement.
        optional fs_patch: FsPatchDone,
        /// An `fs.move`'s acknowledgement.
        optional fs_move: FsMoveDone,
        /// An `fs.delete`'s acknowledgement.
        optional fs_delete: FsDeleteDone,
        /// A staging directory's reclamation.
        optional fs_reclaim: FsReclaimDone,
    }
    exactly_one(
        fs_read, fs_stat, fs_list, fs_search, fs_write, fs_patch, fs_move, fs_delete, fs_reclaim
    )
}

wire_struct! {
    /// The broker's answer to one authorisation: exactly one of `done`,
    /// `refused` and `indeterminate`.
    BrokerOutcome: reject {
        /// Always `broker.outcome`.
        required kind: PrivateKind,
        /// The protocol version.
        required protocol: ProtocolVersion,
        /// The broker's channel for this connection.
        required channel: ChannelNonce,
        /// The invocation this answers.
        required invocation_id: InvocationId,
        /// The operation completed.
        optional done: BrokerDone,
        /// Nothing was changed, and why.
        optional refused: BrokerRefusal,
        /// Something may have changed, and the broker cannot prove what.
        optional indeterminate: Indeterminate,
    }
    exactly_one(done, refused, indeterminate)
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

fn expect_descriptors(found: DescriptorCount, kind: PrivateKind) -> Result<(), ProtocolError> {
    if kind.descriptors() == Some(found.get()) {
        Ok(())
    } else {
        Err(ProtocolError::schema(
            Violation::Inconsistent,
            "/descriptors",
            format!("{} carries a fixed number of descriptors", kind.as_str()),
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
        match Authorisation::decode_frame_body(bytes)? {
            Authorisation::FsRead(read) => Ok(read),
            other => Err(ProtocolError::schema(
                Violation::Inconsistent,
                "/kind",
                format!("expected broker.fs_read, found {}", other.kind().as_str()),
            )),
        }
    }
}

/// The fields every authorisation starts with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Common {
    /// The channel from this connection's hello.
    pub channel: ChannelNonce,
    /// The authority's id for the invocation.
    pub invocation_id: InvocationId,
}

impl Common {
    /// The common fields.
    #[must_use]
    pub const fn new(channel: ChannelNonce, invocation_id: InvocationId) -> Self {
        Self {
            channel,
            invocation_id,
        }
    }
}

/// Any authorisation, decoded by its `kind` into its own strict type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authorisation {
    /// `broker.fs_read`.
    FsRead(FsReadAuthorisation),
    /// `broker.fs_stat`.
    FsStat(FsStatAuthorisation),
    /// `broker.fs_list`.
    FsList(FsListAuthorisation),
    /// `broker.fs_search`.
    FsSearch(FsSearchAuthorisation),
    /// `broker.fs_write`.
    FsWrite(FsWriteAuthorisation),
    /// `broker.fs_patch`.
    FsPatch(FsPatchAuthorisation),
    /// `broker.fs_move`.
    FsMove(FsMoveAuthorisation),
    /// `broker.fs_delete`.
    FsDelete(FsDeleteAuthorisation),
    /// `broker.fs_reclaim`.
    FsReclaim(FsReclaimAuthorisation),
}

impl Authorisation {
    /// Decode an authorisation body: its `kind` selects its type, and the
    /// type decodes strictly; the declared descriptor count must be the
    /// kind's. An `fs.write`'s existing-or-vacant fields must agree.
    ///
    /// # Errors
    ///
    /// Malformed, too large, a hello or an outcome, or inconsistent.
    pub fn decode_frame_body(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() > MAX_AUTHORISATION_BODY {
            return Err(ProtocolError::new(
                ErrorCode::FrameTooLarge,
                format!(
                    "an authorisation of {} bytes exceeds {MAX_AUTHORISATION_BODY}",
                    bytes.len()
                ),
            ));
        }
        let value = json::parse(bytes, ParseOptions::dwkp())?;
        let kind = match &value {
            Value::Object(object) => match object.get("kind") {
                Some(kind) => PrivateKind::decode(kind.clone(), &mut Cx::new())?,
                None => {
                    return Err(ProtocolError::schema(
                        Violation::MissingField,
                        "/kind",
                        "an authorisation names its kind",
                    ));
                }
            },
            _ => {
                return Err(ProtocolError::schema(
                    Violation::WrongType,
                    "",
                    "an authorisation is an object",
                ));
            }
        };
        let cx = &mut Cx::new();
        let decoded = match kind {
            PrivateKind::FsRead => Self::FsRead(FsReadAuthorisation::decode(value, cx)?),
            PrivateKind::FsStat => Self::FsStat(FsStatAuthorisation::decode(value, cx)?),
            PrivateKind::FsList => Self::FsList(FsListAuthorisation::decode(value, cx)?),
            PrivateKind::FsSearch => Self::FsSearch(FsSearchAuthorisation::decode(value, cx)?),
            PrivateKind::FsWrite => Self::FsWrite(FsWriteAuthorisation::decode(value, cx)?),
            PrivateKind::FsPatch => Self::FsPatch(FsPatchAuthorisation::decode(value, cx)?),
            PrivateKind::FsMove => Self::FsMove(FsMoveAuthorisation::decode(value, cx)?),
            PrivateKind::FsDelete => Self::FsDelete(FsDeleteAuthorisation::decode(value, cx)?),
            PrivateKind::FsReclaim => Self::FsReclaim(FsReclaimAuthorisation::decode(value, cx)?),
            PrivateKind::Hello | PrivateKind::Outcome => {
                return Err(ProtocolError::schema(
                    Violation::Inconsistent,
                    "/kind",
                    format!("{} is not an authorisation", kind.as_str()),
                ));
            }
        };
        decoded.check()?;
        Ok(decoded)
    }

    /// The kind.
    #[must_use]
    pub const fn kind(&self) -> PrivateKind {
        match self {
            Self::FsRead(_) => PrivateKind::FsRead,
            Self::FsStat(_) => PrivateKind::FsStat,
            Self::FsList(_) => PrivateKind::FsList,
            Self::FsSearch(_) => PrivateKind::FsSearch,
            Self::FsWrite(_) => PrivateKind::FsWrite,
            Self::FsPatch(_) => PrivateKind::FsPatch,
            Self::FsMove(_) => PrivateKind::FsMove,
            Self::FsDelete(_) => PrivateKind::FsDelete,
            Self::FsReclaim(_) => PrivateKind::FsReclaim,
        }
    }

    /// The channel it names.
    #[must_use]
    pub const fn channel(&self) -> &ChannelNonce {
        match self {
            Self::FsRead(a) => &a.channel,
            Self::FsStat(a) => &a.channel,
            Self::FsList(a) => &a.channel,
            Self::FsSearch(a) => &a.channel,
            Self::FsWrite(a) => &a.channel,
            Self::FsPatch(a) => &a.channel,
            Self::FsMove(a) => &a.channel,
            Self::FsDelete(a) => &a.channel,
            Self::FsReclaim(a) => &a.channel,
        }
    }

    /// The invocation it authorises.
    #[must_use]
    pub const fn invocation_id(&self) -> &InvocationId {
        match self {
            Self::FsRead(a) => &a.invocation_id,
            Self::FsStat(a) => &a.invocation_id,
            Self::FsList(a) => &a.invocation_id,
            Self::FsSearch(a) => &a.invocation_id,
            Self::FsWrite(a) => &a.invocation_id,
            Self::FsPatch(a) => &a.invocation_id,
            Self::FsMove(a) => &a.invocation_id,
            Self::FsDelete(a) => &a.invocation_id,
            Self::FsReclaim(a) => &a.invocation_id,
        }
    }

    /// The descriptor count it declares.
    #[must_use]
    pub const fn declared_descriptors(&self) -> u8 {
        match self {
            Self::FsRead(a) => a.descriptors.get(),
            Self::FsStat(a) => a.descriptors.get(),
            Self::FsList(a) => a.descriptors.get(),
            Self::FsSearch(a) => a.descriptors.get(),
            Self::FsWrite(a) => a.descriptors.get(),
            Self::FsPatch(a) => a.descriptors.get(),
            Self::FsMove(a) => a.descriptors.get(),
            Self::FsDelete(a) => a.descriptors.get(),
            Self::FsReclaim(a) => a.descriptors.get(),
        }
    }

    fn check(&self) -> Result<(), ProtocolError> {
        // The protocol version is checked by its type on decode (2 and only 2).
        let descriptors = DescriptorCount::new(self.declared_descriptors()).ok_or_else(|| {
            ProtocolError::schema(Violation::OutOfRange, "/descriptors", "no such count")
        })?;
        expect_descriptors(descriptors, self.kind())?;
        match self {
            Self::FsWrite(write) => {
                let targets = (write.target_device.is_some(), write.target_inode.is_some());
                let consistent = match write.object {
                    ObjectState::Existing => targets == (true, true),
                    ObjectState::Vacant => targets == (false, false),
                };
                if !consistent {
                    return Err(ProtocolError::schema(
                        Violation::Inconsistent,
                        "/object",
                        "a replacement names its target and a creation names none",
                    ));
                }
            }
            Self::FsPatch(patch) => {
                // Defence in depth: the authority refused a larger patch
                // already (`PATCH_TOO_LARGE`).
                if patch_insert_bytes(&patch.edits) > MAX_PATCH_INSERT_BYTES_TOTAL {
                    return Err(ProtocolError::schema(
                        Violation::TooLong,
                        "/edits",
                        "a patch inserts more than an inline patch may carry",
                    ));
                }
            }
            Self::FsReclaim(reclaim) => {
                let targets = (
                    reclaim.target_device.is_some(),
                    reclaim.target_inode.is_some(),
                );
                let expected = match reclaim.operation {
                    StagingOperation::Replace | StagingOperation::Delete => (true, true),
                    StagingOperation::Create => (false, false),
                };
                if targets != expected {
                    return Err(ProtocolError::schema(
                        Violation::Inconsistent,
                        "/operation",
                        "a replacement or a delete names its target and a creation names none",
                    ));
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Encode as a frame.
    ///
    /// # Errors
    ///
    /// As [`encode_frame`].
    pub fn encode_frame(&self) -> Result<Vec<u8>, ProtocolError> {
        self.check()?;
        match self {
            Self::FsRead(a) => encode_frame(a),
            Self::FsStat(a) => encode_frame(a),
            Self::FsList(a) => encode_frame(a),
            Self::FsSearch(a) => encode_frame(a),
            Self::FsWrite(a) => encode_frame(a),
            Self::FsPatch(a) => encode_frame(a),
            Self::FsMove(a) => encode_frame(a),
            Self::FsDelete(a) => encode_frame(a),
            Self::FsReclaim(a) => encode_frame(a),
        }
    }
}

/// Build the fields every authorisation shares.
macro_rules! authorisation_head {
    ($kind:expr, $common:expr) => {
        (
            $kind,
            ProtocolVersion(PROTOCOL),
            $common.channel,
            $common.invocation_id,
            DescriptorCount(match $kind.descriptors() {
                Some(n) => n,
                None => 1,
            }),
        )
    };
}

impl FsStatAuthorisation {
    /// A stat of the object `(device, inode)`.
    #[must_use]
    pub fn new(common: Common, device: u64, inode: u64) -> Self {
        let (kind, protocol, channel, invocation_id, descriptors) =
            authorisation_head!(PrivateKind::FsStat, common);
        Self {
            kind,
            protocol,
            channel,
            invocation_id,
            device: KernelNumber::from_u64(device),
            inode: KernelNumber::from_u64(inode),
            descriptors,
        }
    }
}

impl FsListAuthorisation {
    /// A listing of the directory `(device, inode)`.
    #[must_use]
    pub fn new(common: Common, device: u64, inode: u64, max_entries: ListLimit) -> Self {
        let (kind, protocol, channel, invocation_id, descriptors) =
            authorisation_head!(PrivateKind::FsList, common);
        Self {
            kind,
            protocol,
            channel,
            invocation_id,
            device: KernelNumber::from_u64(device),
            inode: KernelNumber::from_u64(inode),
            max_entries,
            descriptors,
        }
    }
}

impl FsSearchAuthorisation {
    /// A search of the file `(device, inode)`.
    #[must_use]
    pub fn new(
        common: Common,
        (device, inode): (u64, u64),
        needle: Needle,
        max_scan_bytes: ScanLimit,
        max_matches: MatchLimit,
    ) -> Self {
        let (kind, protocol, channel, invocation_id, descriptors) =
            authorisation_head!(PrivateKind::FsSearch, common);
        Self {
            kind,
            protocol,
            channel,
            invocation_id,
            device: KernelNumber::from_u64(device),
            inode: KernelNumber::from_u64(inode),
            needle,
            max_scan_bytes,
            max_matches,
            descriptors,
        }
    }
}

impl FsWriteAuthorisation {
    /// A write of `leaf` in the directory `parent`: replacing `target` if it
    /// is `Some`, creating otherwise.
    #[must_use]
    pub fn new(
        common: Common,
        parent: (u64, u64),
        leaf: LeafName,
        target: Option<(u64, u64)>,
        content: HexContent,
    ) -> Self {
        let (kind, protocol, channel, invocation_id, descriptors) =
            authorisation_head!(PrivateKind::FsWrite, common);
        Self {
            kind,
            protocol,
            channel,
            invocation_id,
            parent_device: KernelNumber::from_u64(parent.0),
            parent_inode: KernelNumber::from_u64(parent.1),
            leaf,
            object: if target.is_some() {
                ObjectState::Existing
            } else {
                ObjectState::Vacant
            },
            target_device: target.map(|t| KernelNumber::from_u64(t.0)),
            target_inode: target.map(|t| KernelNumber::from_u64(t.1)),
            content,
            descriptors,
        }
    }

    /// The file to replace, or `None` for a creation.
    #[must_use]
    pub fn target(&self) -> Option<(u64, u64)> {
        match (&self.target_device, &self.target_inode) {
            (Some(device), Some(inode)) => Some((device.value(), inode.value())),
            _ => None,
        }
    }
}

impl FsPatchAuthorisation {
    /// A patch of the file `target`, named `leaf` in `parent`.
    #[must_use]
    pub fn new(
        common: Common,
        parent: (u64, u64),
        leaf: LeafName,
        target: (u64, u64),
        (base, post, edits): (ContentRevision, ContentRevision, PatchEdits),
    ) -> Self {
        let (kind, protocol, channel, invocation_id, descriptors) =
            authorisation_head!(PrivateKind::FsPatch, common);
        Self {
            kind,
            protocol,
            channel,
            invocation_id,
            parent_device: KernelNumber::from_u64(parent.0),
            parent_inode: KernelNumber::from_u64(parent.1),
            leaf,
            target_device: KernelNumber::from_u64(target.0),
            target_inode: KernelNumber::from_u64(target.1),
            base,
            post,
            edits,
            descriptors,
        }
    }
}

/// One side of a move: a parent directory, a name in it, and — for the
/// source — the object it must bind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoveSide {
    /// The directory's `(device, inode)`.
    pub parent: (u64, u64),
    /// The name.
    pub leaf: LeafName,
}

impl FsMoveAuthorisation {
    /// A move of the file `source_identity`, named by `source`, to the vacant
    /// `destination`.
    #[must_use]
    pub fn new(
        common: Common,
        source: MoveSide,
        source_identity: (u64, u64),
        destination: MoveSide,
    ) -> Self {
        let (kind, protocol, channel, invocation_id, descriptors) =
            authorisation_head!(PrivateKind::FsMove, common);
        Self {
            kind,
            protocol,
            channel,
            invocation_id,
            source_parent_device: KernelNumber::from_u64(source.parent.0),
            source_parent_inode: KernelNumber::from_u64(source.parent.1),
            source_leaf: source.leaf,
            source_device: KernelNumber::from_u64(source_identity.0),
            source_inode: KernelNumber::from_u64(source_identity.1),
            destination_parent_device: KernelNumber::from_u64(destination.parent.0),
            destination_parent_inode: KernelNumber::from_u64(destination.parent.1),
            destination_leaf: destination.leaf,
            descriptors,
        }
    }
}

impl FsDeleteAuthorisation {
    /// A removal of the object `target`, of `target_kind`, named `leaf` in
    /// `parent`.
    #[must_use]
    pub fn new(
        common: Common,
        parent: (u64, u64),
        leaf: LeafName,
        target: (u64, u64),
        target_kind: StatKind,
    ) -> Self {
        let (kind, protocol, channel, invocation_id, descriptors) =
            authorisation_head!(PrivateKind::FsDelete, common);
        Self {
            kind,
            protocol,
            channel,
            invocation_id,
            parent_device: KernelNumber::from_u64(parent.0),
            parent_inode: KernelNumber::from_u64(parent.1),
            leaf,
            target_device: KernelNumber::from_u64(target.0),
            target_inode: KernelNumber::from_u64(target.1),
            target_kind,
            descriptors,
        }
    }
}

/// How many bytes a patch's edits insert, together.
#[must_use]
pub fn patch_insert_bytes(edits: &PatchEdits) -> usize {
    edits
        .iter()
        .map(|edit| edit.insert.byte_len())
        .fold(0usize, usize::saturating_add)
}

impl FsReclaimAuthorisation {
    /// A reclamation of the staging directory of `common.invocation_id`, made
    /// for `operation` on `leaf` in the directory `parent` — naming, for a
    /// replacement or a delete, the object that was authorised.
    #[must_use]
    pub fn new(
        common: Common,
        parent: (u64, u64),
        leaf: LeafName,
        operation: StagingOperation,
        target: Option<(u64, u64)>,
    ) -> Self {
        let (kind, protocol, channel, invocation_id, descriptors) =
            authorisation_head!(PrivateKind::FsReclaim, common);
        Self {
            kind,
            protocol,
            channel,
            invocation_id,
            parent_device: KernelNumber::from_u64(parent.0),
            parent_inode: KernelNumber::from_u64(parent.1),
            leaf,
            operation,
            target_device: target.map(|t| KernelNumber::from_u64(t.0)),
            target_inode: target.map(|t| KernelNumber::from_u64(t.1)),
            descriptors,
        }
    }

    /// The authorised object, for a replacement or a delete.
    #[must_use]
    pub fn target(&self) -> Option<(u64, u64)> {
        match (&self.target_device, &self.target_inode) {
            (Some(device), Some(inode)) => Some((device.value(), inode.value())),
            _ => None,
        }
    }
}

/// What an outcome says, once its shape is checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutcomeResult {
    /// The operation completed.
    Done(BrokerDone),
    /// Nothing was changed.
    Refused(BrokerRefusal),
    /// Something may have changed; the broker cannot prove what.
    Indeterminate(Indeterminate),
}

impl BrokerOutcome {
    /// An outcome for `invocation_id` on `channel`.
    #[must_use]
    pub fn new(channel: ChannelNonce, invocation_id: InvocationId, result: OutcomeResult) -> Self {
        let (done, refused, indeterminate) = match result {
            OutcomeResult::Done(done) => (Some(done), None, None),
            OutcomeResult::Refused(why) => (None, Some(why), None),
            OutcomeResult::Indeterminate(why) => (None, None, Some(why)),
        };
        Self {
            kind: PrivateKind::Outcome,
            protocol: ProtocolVersion(PROTOCOL),
            channel,
            invocation_id,
            done,
            refused,
            indeterminate,
        }
    }

    /// Decode an outcome body.
    ///
    /// # Errors
    ///
    /// Malformed, too large, another message, or not exactly one result.
    pub fn decode_frame_body(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let outcome: Self = decode_bytes(bytes, MAX_OUTCOME_BODY)?;
        expect_kind(outcome.kind, PrivateKind::Outcome)?;
        Ok(outcome)
    }

    /// The result. The decoder has already required exactly one.
    #[must_use]
    pub fn result(&self) -> OutcomeResult {
        match (&self.done, self.refused, self.indeterminate) {
            (Some(done), _, _) => OutcomeResult::Done(done.clone()),
            (None, Some(why), _) => OutcomeResult::Refused(why),
            (None, None, Some(why)) => OutcomeResult::Indeterminate(why),
            // Unreachable for a decoded outcome; fail closed if constructed.
            (None, None, None) => OutcomeResult::Indeterminate(Indeterminate::EffectUnconfirmed),
        }
    }
}

impl BrokerDone {
    /// A completed operation's result.
    #[must_use]
    pub fn read(done: FsReadDone) -> Self {
        Self {
            fs_read: Some(done),
            ..Self::empty()
        }
    }

    /// No member: the starting point for the one-member constructors.
    const fn empty() -> Self {
        Self {
            fs_read: None,
            fs_stat: None,
            fs_list: None,
            fs_search: None,
            fs_write: None,
            fs_patch: None,
            fs_move: None,
            fs_delete: None,
            fs_reclaim: None,
        }
    }

    /// An `fs.stat` result.
    #[must_use]
    pub fn stat(done: FsStatDone) -> Self {
        Self {
            fs_stat: Some(done),
            ..Self::empty()
        }
    }

    /// An `fs.list` result.
    #[must_use]
    pub fn list(done: FsListDone) -> Self {
        Self {
            fs_list: Some(done),
            ..Self::empty()
        }
    }

    /// An `fs.search` result.
    #[must_use]
    pub fn search(done: FsSearchDone) -> Self {
        Self {
            fs_search: Some(done),
            ..Self::empty()
        }
    }

    /// An `fs.write` result.
    #[must_use]
    pub fn write(done: FsWriteDone) -> Self {
        Self {
            fs_write: Some(done),
            ..Self::empty()
        }
    }

    /// An `fs.patch` result.
    #[must_use]
    pub fn patch(done: FsPatchDone) -> Self {
        Self {
            fs_patch: Some(done),
            ..Self::empty()
        }
    }

    /// An `fs.move` result.
    #[must_use]
    pub fn moved() -> Self {
        Self {
            fs_move: Some(FsMoveDone {}),
            ..Self::empty()
        }
    }

    /// An `fs.delete` result.
    #[must_use]
    pub fn delete(done: FsDeleteDone) -> Self {
        Self {
            fs_delete: Some(done),
            ..Self::empty()
        }
    }

    /// A staging directory's reclamation.
    #[must_use]
    pub fn reclaim(done: FsReclaimDone) -> Self {
        Self {
            fs_reclaim: Some(done),
            ..Self::empty()
        }
    }

    /// Which operation this result is for.
    #[must_use]
    pub const fn kind(&self) -> Option<PrivateKind> {
        Some(if self.fs_read.is_some() {
            PrivateKind::FsRead
        } else if self.fs_stat.is_some() {
            PrivateKind::FsStat
        } else if self.fs_list.is_some() {
            PrivateKind::FsList
        } else if self.fs_search.is_some() {
            PrivateKind::FsSearch
        } else if self.fs_write.is_some() {
            PrivateKind::FsWrite
        } else if self.fs_patch.is_some() {
            PrivateKind::FsPatch
        } else if self.fs_move.is_some() {
            PrivateKind::FsMove
        } else if self.fs_delete.is_some() {
            PrivateKind::FsDelete
        } else if self.fs_reclaim.is_some() {
            PrivateKind::FsReclaim
        } else {
            return None;
        })
    }
}

#[cfg(test)]
mod tests;
