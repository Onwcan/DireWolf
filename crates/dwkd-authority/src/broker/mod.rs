//! The authority's side of the private broker channel (M4b, [ADR-0043]; the
//! M4c operations, [ADR-0044]; the M4d process operations, [ADR-0045]).
//!
//! The authority decides; `dwkd-broker` does ([ADR-0018]). This module is the
//! one place an authorised effect crosses from the first to the second: the
//! state layer hands it a [`BrokerOrder`] — an invocation whose whole plan was
//! allowed, whose intent is already durable, holding exactly the checked
//! descriptors the operation needs — and gets back the result, or why there is
//! none, and whether the authorisation had left.
//!
//! # What it trusts, and what it does not
//!
//! * **The socket path is not trusted; the peer is.** [`UnixBroker`] connects,
//!   then asks the kernel who is on the other end (`SO_PEERCRED`), and sends
//!   nothing — not a byte, not a descriptor — unless it is the configured
//!   broker uid. A socket the runtime planted, or a broker started under the
//!   wrong identity, gets a connection and nothing else.
//! * **One connection, one authorisation.** The broker's hello names a fresh
//!   channel; the authorisation names it back; the broker executes at most
//!   one per connection. No key, no MAC, no token outlives the connection.
//! * **Exactly the operation's descriptors, and they leave by `SCM_RIGHTS`.**
//!   Never a path, a host root or a number that grants anything.
//! * **The reply is checked, not believed.** It must answer this invocation on
//!   this channel, carry exactly one answer, be the answer to *this*
//!   operation, and stay within every bound the plan was decided on.
//!
//! The broker decides nothing and this module decides nothing: it has no
//! policy, no capability and no store. What to do with an outcome — audit it,
//! raise taint, record it as unknown, answer the runtime — is the state
//! layer's.
//!
//! [ADR-0018]: ../../../../docs/adr/0018-authority-broker-split.md
//! [ADR-0043]: ../../../../docs/adr/0043-m4b-private-broker-channel-and-brokered-fs-read.md
//! [ADR-0044]: ../../../../docs/adr/0044-m4c-filesystem-operations-plans-and-atomic-mutation.md
//! [ADR-0045]: ../../../../docs/adr/0045-m4d-process-execution-broker.md

#[cfg(target_os = "linux")]
mod link;

use core::fmt;
use std::path::PathBuf;
use std::time::Duration;

use dwk_proto::brokerp::{
    BrokerGeneration, BrokerRefusal, ExecEnvironment, Indeterminate, ReclaimState, StagingHolds,
    StagingOperation,
};
use dwk_proto::dwkp::fsops::{ContentRevision, PatchEdits};
use dwk_proto::wire::id::{InvocationId, ProcessId};
use dwk_proto::wire::scalar::{
    EntryKind, KillOutcome, ListLimit, MatchLimit, Needle, PatchOutcome, ProcessState, ReadLimit,
    ScanLimit, StatKind,
};

use crate::resource::{ExecHandoff, FileIdentity, ObjectHandoff, ParentHandoff, ReadHandoff};

/// How long one broker exchange may take, end to end: connect, hello,
/// authorisation, the operation, outcome. A bound, not a target — every
/// operation is local and bounded, and takes milliseconds.
pub const EXCHANGE_DEADLINE: Duration = Duration::from_secs(10);

/// What an order asks for, and the checked descriptors it holds.
#[derive(Debug)]
pub enum Operation {
    /// Read at most `max_bytes` of the file.
    Read {
        /// The bound.
        max_bytes: ReadLimit,
        /// The file, open for reading.
        file: ReadHandoff,
    },
    /// Report the object's metadata.
    Stat {
        /// The object, `O_PATH`.
        object: ObjectHandoff,
    },
    /// List the directory.
    List {
        /// How many entries to examine.
        max_entries: ListLimit,
        /// The directory, open for reading.
        directory: ObjectHandoff,
    },
    /// Search the file.
    Search {
        /// The bytes to find.
        needle: Needle,
        /// The most bytes to scan.
        max_scan_bytes: ScanLimit,
        /// The most offsets to report.
        max_matches: MatchLimit,
        /// The file, open for reading.
        file: ReadHandoff,
    },
    /// Replace or create the file the name in `parent` names.
    Write {
        /// The parent, the name and — for a replacement — the target.
        parent: ParentHandoff,
        /// The complete new content.
        content: Vec<u8>,
    },
    /// Patch the file.
    Patch {
        /// The parent, the name and the target.
        parent: ParentHandoff,
        /// The file, open for reading.
        file: ReadHandoff,
        /// What it must hold.
        base: ContentRevision,
        /// What it will hold.
        post: ContentRevision,
        /// The edits.
        edits: PatchEdits,
    },
    /// Rename a file to a vacant name.
    Move {
        /// The source's parent, name and target.
        source: ParentHandoff,
        /// The destination's parent and name.
        destination: ParentHandoff,
    },
    /// Remove a name.
    Delete {
        /// The parent, the name and the target.
        parent: ParentHandoff,
    },
    /// Reclaim the staging directory of an invocation whose outcome is
    /// recorded (ADR-0044 §10): the order's invocation is that one.
    Reclaim {
        /// The directory the staging directory is in, open for reading.
        directory: ObjectHandoff,
        /// What the staging directory was made for.
        staging: StagingSpec,
    },
    /// Start a process (M4d, ADR-0045): the checked executable, open for
    /// reading and proved to be the object hashed; the checked working
    /// directory, open for reading; and the launch's arguments, environment
    /// profile and output bound. `argv[0]` is the executable's canonical path.
    ProcessStart {
        /// The authority's handle for the process.
        process_id: ProcessId,
        /// The executable.
        executable: ExecHandoff,
        /// The working directory.
        cwd: ObjectHandoff,
        /// The arguments after `argv[0]`: data, never a command line.
        args: Vec<String>,
        /// The environment profile.
        environment: ExecEnvironment,
        /// Each stream's retained bytes.
        stream_limit: u32,
    },
    /// Observe a process this broker instance launched. No descriptor.
    ProcessStatus {
        /// The handle.
        process_id: ProcessId,
        /// The broker instance that launched it.
        generation: BrokerGeneration,
    },
    /// Kill a process this broker instance launched, and its process group.
    /// No descriptor.
    ProcessKill {
        /// The handle.
        process_id: ProcessId,
        /// The broker instance that launched it.
        generation: BrokerGeneration,
    },
}

/// What a staging directory was made for: the operation, the one name it
/// concerned, and — for a replacement or a delete — the object authorised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagingSpec {
    /// Replace, create or delete.
    pub operation: StagingOperation,
    /// The name the invocation changed.
    pub leaf: String,
    /// The object authorised: `(device, inode)`.
    pub target: Option<(u64, u64)>,
}

impl Operation {
    /// A stable name for the audit record.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Read { .. } => "fs.read",
            Self::Stat { .. } => "fs.stat",
            Self::List { .. } => "fs.list",
            Self::Search { .. } => "fs.search",
            Self::Write { .. } => "fs.write",
            Self::Patch { .. } => "fs.patch",
            Self::Move { .. } => "fs.move",
            Self::Delete { .. } => "fs.delete",
            Self::Reclaim { .. } => "staging.reclaim",
            Self::ProcessStart { .. } => "process.start",
            Self::ProcessStatus { .. } => "process.status",
            Self::ProcessKill { .. } => "process.kill",
        }
    }
}

/// One operation the authority authorised, ready to hand over.
///
/// Built only by the state layer, after every action of the plan was allowed
/// and the intent was recorded. Holds the checked descriptors; dropping an
/// order closes them.
#[derive(Debug)]
pub struct BrokerOrder {
    invocation: InvocationId,
    operation: Operation,
}

impl BrokerOrder {
    /// An order. Crate-internal: only the state layer makes one.
    pub(crate) const fn new(invocation: InvocationId, operation: Operation) -> Self {
        Self {
            invocation,
            operation,
        }
    }

    /// The invocation it authorises.
    #[must_use]
    pub const fn invocation(&self) -> &InvocationId {
        &self.invocation
    }

    /// What it asks for.
    #[must_use]
    pub const fn operation(&self) -> &Operation {
        &self.operation
    }

    /// The identity of the object it names first: the file, directory or
    /// object for the read family, the target (or, for a creation, the parent
    /// directory), the executable of a launch. `None` for a status or a kill,
    /// which name a process, not an object.
    #[must_use]
    pub fn identity(&self) -> Option<FileIdentity> {
        Some(match &self.operation {
            Operation::Read { file, .. } | Operation::Search { file, .. } => file.identity(),
            Operation::Stat { object } => object.identity(),
            Operation::List { directory, .. } | Operation::Reclaim { directory, .. } => {
                directory.identity()
            }
            Operation::Write { parent, .. }
            | Operation::Patch { parent, .. }
            | Operation::Delete { parent } => parent
                .target()
                .map_or_else(|| parent.directory_identity(), |(identity, _)| identity),
            Operation::Move { source, .. } => source
                .target()
                .map_or_else(|| source.directory_identity(), |(identity, _)| identity),
            Operation::ProcessStart { executable, .. } => executable.object(),
            Operation::ProcessStatus { .. } | Operation::ProcessKill { .. } => return None,
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn into_parts(self) -> (InvocationId, Operation) {
        (self.invocation, self.operation)
    }
}

/// What the broker read: at most the authorised bound, from offset zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsReadDelivery {
    /// The bytes, exactly.
    pub content: Vec<u8>,
    /// Whether the end of the file was observed: a read returned fewer bytes
    /// than the bound. `false` when exactly the bound was read — the end is
    /// then not proven, because nothing past the bound is ever read.
    pub eof_observed: bool,
}

/// What `fstat` said about the object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatDelivery {
    /// What it is.
    pub kind: StatKind,
    /// `st_size`.
    pub size: u64,
    /// `st_nlink`.
    pub link_count: u64,
    /// `st_mode & 0o7777`.
    pub mode: u16,
}

/// One entry of a listing, as the directory holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawListEntry {
    /// The name's bytes, which need not be UTF-8.
    pub name: Vec<u8>,
    /// Its `d_type`.
    pub kind: EntryKind,
}

/// What the broker listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListDelivery {
    /// The first `max_entries` entries in byte order of their names.
    pub entries: Vec<RawListEntry>,
    /// Whether every entry was examined.
    pub complete: bool,
}

/// Where the needle was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchDelivery {
    /// Ascending start offsets.
    pub offsets: Vec<u64>,
    /// How many bytes were scanned.
    pub scanned: u64,
    /// Whether the end of the file was observed within the scan.
    pub eof_observed: bool,
    /// Whether more matches were found than reported.
    pub matches_truncated: bool,
}

/// A launch the broker confirmed: the helper replaced itself with the
/// executable, and the broker supervises it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessStartDelivery {
    /// The broker instance that launched it.
    pub generation: BrokerGeneration,
    /// Its state when the launch was confirmed.
    pub state: ProcessState,
    /// Its exit code, if it had already exited.
    pub exit_code: Option<u8>,
    /// The signal that ended it, if one already had.
    pub signal: Option<u8>,
}

/// One stream as the broker retained it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamDelivery {
    /// The retained bytes.
    pub content: Vec<u8>,
    /// Every byte written so far.
    pub observed: u64,
    /// Whether more was written than retained.
    pub truncated: bool,
}

/// What the broker observed of a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessStatusDelivery {
    /// Its state.
    pub state: ProcessState,
    /// Its exit code, once it exited.
    pub exit_code: Option<u8>,
    /// The signal that ended it, once one did.
    pub signal: Option<u8>,
    /// Whether the broker's wall clock ended it.
    pub timed_out: bool,
    /// `stdout`.
    pub stdout: StreamDelivery,
    /// `stderr`.
    pub stderr: StreamDelivery,
}

/// What the broker did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerDelivery {
    /// `fs.read`'s bytes.
    Read(FsReadDelivery),
    /// `fs.stat`'s metadata.
    Stat(StatDelivery),
    /// `fs.list`'s entries.
    List(ListDelivery),
    /// `fs.search`'s offsets.
    Search(SearchDelivery),
    /// `fs.write` completed, durably.
    Write {
        /// Whether the file was created.
        created: bool,
        /// Whether the staging directory was left behind.
        debris: bool,
    },
    /// `fs.patch` completed, durably, or had already been applied.
    Patch {
        /// Which.
        outcome: PatchOutcome,
        /// Whether the staging directory was left behind.
        debris: bool,
    },
    /// `fs.move` completed, durably.
    Move,
    /// `fs.delete` completed, durably.
    Delete {
        /// Whether the staging directory was left behind.
        debris: bool,
    },
    /// A staging directory was judged, and removed only if disposable.
    Reclaim {
        /// What was found and done.
        state: ReclaimState,
        /// For a retained directory: why.
        holds: Option<StagingHolds>,
        /// For a retained object: its `(device, inode)`.
        held: Option<(u64, u64)>,
    },
    /// A launch, confirmed.
    ProcessStarted(ProcessStartDelivery),
    /// A process's state and output.
    ProcessStatus(ProcessStatusDelivery),
    /// A kill's acknowledgement.
    ProcessKilled(KillOutcome),
}

/// Why no connection could be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreachable {
    /// Connecting to the configured socket failed.
    Connect,
    /// The kernel would not report the peer's credentials.
    PeerCredentials,
    /// The broker said nothing in time, or the exchange overran its deadline.
    Timeout,
    /// The connection failed mid-exchange.
    Io,
    /// This platform has no broker channel.
    Unsupported,
}

impl Unreachable {
    /// The audit spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::PeerCredentials => "peer_credentials",
            Self::Timeout => "timeout",
            Self::Io => "io",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Why an order produced no result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerFailure {
    /// No broker is configured: this authority performs no effects.
    NotConfigured,
    /// No usable connection: see [`Unreachable`].
    Unreachable(Unreachable),
    /// The kernel reported a peer that is not the configured broker. Nothing
    /// was sent to it.
    PeerRefused {
        /// The uid the kernel reported.
        observed_uid: u32,
    },
    /// The broker's messages did not decode, or did not answer this
    /// invocation on this channel, or claimed more than was authorised.
    Protocol(&'static str),
    /// The broker refused: it changed nothing.
    Refused(BrokerRefusal),
    /// The broker may have changed something and cannot prove what.
    Indeterminate(Indeterminate),
}

impl BrokerFailure {
    /// The audit spelling of the class.
    #[must_use]
    pub const fn class(self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::Unreachable(_) => "unreachable",
            Self::PeerRefused { .. } => "peer_refused",
            Self::Protocol(_) => "protocol",
            Self::Refused(_) => "refused",
            Self::Indeterminate(_) => "indeterminate",
        }
    }
}

impl fmt::Display for BrokerFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConfigured => f.write_str("no broker is configured"),
            Self::Unreachable(why) => write!(f, "the broker is unreachable: {}", why.as_str()),
            Self::PeerRefused { observed_uid } => {
                write!(
                    f,
                    "the peer at the broker socket is uid {observed_uid}, not the broker"
                )
            }
            Self::Protocol(why) => write!(f, "broker protocol error: {why}"),
            Self::Refused(why) => write!(f, "the broker refused: {}", why.as_str()),
            Self::Indeterminate(why) => {
                write!(f, "the broker cannot say what changed: {}", why.as_str())
            }
        }
    }
}

/// An order that produced no result, and — what decides whether the effect
/// is provably absent — whether the authorisation had left for the broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrokerError {
    /// What went wrong.
    pub failure: BrokerFailure,
    /// Whether the authorisation was sent. `false` means the broker was told
    /// nothing, so nothing was done. `true` means the broker may have acted,
    /// unless it said it refused.
    pub sent: bool,
}

impl BrokerError {
    /// A failure before anything was sent.
    #[must_use]
    pub const fn before_sending(failure: BrokerFailure) -> Self {
        Self {
            failure,
            sent: false,
        }
    }

    /// A failure after the authorisation left.
    #[must_use]
    pub const fn after_sending(failure: BrokerFailure) -> Self {
        Self {
            failure,
            sent: true,
        }
    }

    /// Whether the broker provably changed nothing: it was told nothing, or it
    /// said it refused.
    #[must_use]
    pub const fn provably_without_effect(&self) -> bool {
        !self.sent || matches!(self.failure, BrokerFailure::Refused(_))
    }
}

/// Something that performs an authorised operation.
///
/// One production implementation, [`UnixBroker`]. The trait exists so the
/// state layer's phase boundaries can be tested in process; a fake cannot take
/// a descriptor out of an order (nothing outside this crate can), so it can
/// only ever return results it made up — which is why no fake counts as
/// end-to-end evidence (ADR-0043).
pub trait EffectBroker: Send + Sync + fmt::Debug {
    /// Perform one operation.
    ///
    /// # Errors
    ///
    /// [`BrokerError`]: no result, and whether the authorisation had left.
    fn perform(&self, order: BrokerOrder) -> Result<BrokerDelivery, BrokerError>;
}

/// The broker channel: a Unix-domain socket the broker listens on, and the uid
/// the kernel must report for whoever is listening there.
///
/// Operator configuration, from the command line (`--broker-socket`,
/// `--broker-uid`); nothing on the wire names or changes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnixBroker {
    socket: PathBuf,
    broker_uid: u32,
    deadline: Duration,
}

impl UnixBroker {
    /// A channel to the broker at `socket`, which must be served by
    /// `broker_uid`.
    #[must_use]
    pub const fn new(socket: PathBuf, broker_uid: u32) -> Self {
        Self {
            socket,
            broker_uid,
            deadline: EXCHANGE_DEADLINE,
        }
    }

    /// The same, with a shorter deadline: for tests of a broker that stalls.
    #[must_use]
    pub const fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// The configured socket.
    #[must_use]
    pub const fn socket(&self) -> &PathBuf {
        &self.socket
    }

    /// The configured broker uid.
    #[must_use]
    pub const fn broker_uid(&self) -> u32 {
        self.broker_uid
    }
}

impl EffectBroker for UnixBroker {
    #[cfg(target_os = "linux")]
    fn perform(&self, order: BrokerOrder) -> Result<BrokerDelivery, BrokerError> {
        link::perform(&self.socket, self.broker_uid, self.deadline, order)
    }

    #[cfg(not(target_os = "linux"))]
    fn perform(&self, order: BrokerOrder) -> Result<BrokerDelivery, BrokerError> {
        drop(order);
        Err(BrokerError::before_sending(BrokerFailure::Unreachable(
            Unreachable::Unsupported,
        )))
    }
}
