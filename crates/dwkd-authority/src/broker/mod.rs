//! The authority's side of the private broker channel (M4b, [ADR-0043]).
//!
//! The authority decides; `dwkd-broker` does ([ADR-0018]). This module is the
//! one place an authorised effect crosses from the first to the second: the
//! state layer hands it an [`FsReadOrder`] — an invocation both gates allowed,
//! whose intent is already durable, holding the one checked file opened for
//! reading — and gets back the bytes, or why there are none.
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
//! * **One descriptor, and it leaves by `SCM_RIGHTS`.** The readable file is
//!   the only thing sent that grants anything, and it is sent as a descriptor,
//!   never as a path or a number.
//! * **The reply is checked, not believed.** It must answer this invocation on
//!   this channel, carry exactly one result, and hold no more bytes than were
//!   authorised.
//!
//! The broker decides nothing and this module decides nothing: it has no
//! policy, no capability and no store. What to do with an outcome — audit it,
//! raise taint, answer the runtime — is the state layer's.
//!
//! [ADR-0018]: ../../../../docs/adr/0018-authority-broker-split.md
//! [ADR-0043]: ../../../../docs/adr/0043-m4b-private-broker-channel-and-brokered-fs-read.md

#[cfg(target_os = "linux")]
mod link;

use core::fmt;
use std::path::PathBuf;
use std::time::Duration;

use dwk_proto::brokerp::BrokerRefusal;
use dwk_proto::wire::id::InvocationId;
use dwk_proto::wire::scalar::ReadLimit;

use crate::resource::{FileIdentity, ReadHandoff};

/// How long one broker exchange may take, end to end: connect, hello,
/// authorisation, read, outcome. A bound, not a target — a read of the largest
/// permitted size from a local file takes milliseconds.
pub const EXCHANGE_DEADLINE: Duration = Duration::from_secs(10);

/// One `fs.read` the authority authorised, ready to hand over.
///
/// Built only by the state layer, after both gates allowed the action and its
/// intent was recorded. Holds the checked file; dropping an order closes it.
#[derive(Debug)]
pub struct FsReadOrder {
    invocation: InvocationId,
    max_bytes: ReadLimit,
    file: ReadHandoff,
}

impl FsReadOrder {
    /// An order. Crate-internal: only the state layer makes one.
    pub(crate) const fn new(
        invocation: InvocationId,
        max_bytes: ReadLimit,
        file: ReadHandoff,
    ) -> Self {
        Self {
            invocation,
            max_bytes,
            file,
        }
    }

    /// The invocation it authorises.
    #[must_use]
    pub const fn invocation(&self) -> &InvocationId {
        &self.invocation
    }

    /// The most bytes it authorises.
    #[must_use]
    pub const fn max_bytes(&self) -> ReadLimit {
        self.max_bytes
    }

    /// The identity of the file it authorises.
    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.file.identity()
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

/// Why no connection could be used. Nothing was sent in any of these cases.
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

/// Why an `fs.read` produced no bytes.
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
    /// invocation on this channel, or claimed more bytes than authorised.
    Protocol(&'static str),
    /// The broker refused the authorisation before reading.
    Refused(BrokerRefusal),
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
        }
    }
}

/// Something that performs an authorised `fs.read`.
///
/// One production implementation, [`UnixBroker`]. The trait exists so the
/// state layer's phase boundaries can be tested in process; a fake cannot take
/// the descriptor out of an order (nothing outside this crate can), so it can
/// only ever return bytes it made up — which is why no fake counts as
/// end-to-end evidence (ADR-0043).
pub trait EffectBroker: Send + Sync + fmt::Debug {
    /// Perform one `fs.read`.
    ///
    /// # Errors
    ///
    /// [`BrokerFailure`]: nothing was read, or nothing trustworthy came back.
    fn fs_read(&self, order: FsReadOrder) -> Result<FsReadDelivery, BrokerFailure>;
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
    fn fs_read(&self, order: FsReadOrder) -> Result<FsReadDelivery, BrokerFailure> {
        link::fs_read(&self.socket, self.broker_uid, self.deadline, order)
    }

    #[cfg(not(target_os = "linux"))]
    fn fs_read(&self, order: FsReadOrder) -> Result<FsReadDelivery, BrokerFailure> {
        drop(order);
        Err(BrokerFailure::Unreachable(Unreachable::Unsupported))
    }
}
