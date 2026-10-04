//! The egress proxy's wire vocabulary (M5b, ADR-0048): what the authority
//! grants a `PROXY_ONLY` environment's CONNECT proxy, and what the broker
//! reports it did.
//!
//! **A grant is typed facts, never a policy.** The authority decides which
//! hosts and ports an environment's processes may tunnel to — from the run's
//! granted `network.https` capabilities, exact hosts with explicit ports —
//! and the budgets each tunnel gets; the broker enforces exactly that list,
//! by exact canonical comparison, and decides nothing else. There is no
//! pattern, no wildcard, no address range and no flag here: a grant cannot
//! make an address the IP guard blocks reachable.
//!
//! What comes back is counts — how many tunnels ended how, and how many
//! bytes moved — never a host, a payload or anything read inside a tunnel.

use crate::error::{ProtocolError, Violation};
use crate::json::{Number, Value};
use crate::limits::MAX_SAFE_INTEGER;
use crate::schema::{Defs, int, obj, string};
use crate::wire::host;
use crate::wire::list::BoundedList;
use crate::wire::macros::wire_struct;
use crate::wire::scalar::{ByteCount, wire_enum, wire_int, wire_text};
use crate::wire::{Cx, WireType, expect_integer, expect_string};

wire_text! {
    /// A host an environment may tunnel to, in the one canonical spelling
    /// (`crate::wire::host`): lowercase LDH labels, no trailing dot, no
    /// Unicode — and never an address literal, which no TLS server name
    /// carries.
    EgressHost,
    max_chars = 253,
    pattern = None,
    format = None,
    validate = |s| host::is_host(s) && !host::is_address_literal(s)
}

wire_int! {
    /// A TCP port, never 0.
    EgressPort(u16), min = 1, max = 65535
}

wire_struct! {
    /// One destination a tunnel may be opened to: exactly this host, exactly
    /// this port.
    EgressTarget: reject {
        /// The host.
        required host: EgressHost,
        /// The port.
        required port: EgressPort,
    }
}

/// The most destinations one grant names.
pub const MAX_EGRESS_TARGETS: usize = 64;

/// A grant's destinations.
pub type EgressTargets = BoundedList<EgressTarget, MAX_EGRESS_TARGETS>;

wire_int! {
    /// The most tunnels one environment may have open at once.
    EgressTunnelLimit(u16), min = 1, max = 64
}

wire_int! {
    /// An environment's byte budget in one direction, across all its
    /// tunnels together: at least one byte, at most 16 GiB. Spent, never
    /// refilled: the tunnel that would exceed it is closed, and so is every
    /// later one that carries a byte.
    EgressByteBudget(u64), min = 1, max = 17_179_869_184
}

wire_struct! {
    /// What a `PROXY_ONLY` environment's processes may reach through the
    /// broker's CONNECT proxy, and how much: the authority's decision, which
    /// the broker enforces at the socket and never widens.
    EgressGrant: reject {
        /// The destinations, each exactly: no other host or port is tunnelled
        /// to. An empty list is a proxy that refuses every request.
        required targets: EgressTargets,
        /// The most tunnels open at once.
        required max_tunnels: EgressTunnelLimit,
        /// The most bytes the environment's tunnels carry, together and over
        /// its whole life, to their destinations, counted where the broker
        /// writes them.
        required max_upload_bytes: EgressByteBudget,
        /// The most bytes they carry back, together and over its whole life,
        /// counted where the broker reads them.
        required max_download_bytes: EgressByteBudget,
    }
}

impl EgressGrant {
    /// Whether `host:port` is exactly one of the granted destinations.
    #[must_use]
    pub fn permits(&self, host: &str, port: u16) -> bool {
        self.targets
            .iter()
            .any(|t| t.host.as_str() == host && t.port.get() == port)
    }
}

wire_enum! {
    /// How one CONNECT ended (M5b, ADR-0048): refused before anything was
    /// tunnelled, or accepted and later closed — and why. Counted, never
    /// carrying the request.
    EgressDisposition {
        /// The request was not a well-formed `CONNECT host:port HTTP/1.1`
        /// within its bounds.
        Malformed = "MALFORMED",
        /// The request arrived too slowly, or not at all.
        RequestTimeout = "REQUEST_TIMEOUT",
        /// The method was not `CONNECT`.
        NotConnect = "NOT_CONNECT",
        /// The target is not a canonical host name: an address literal, an
        /// uppercase or Unicode name, a trailing dot, userinfo, a bracketed
        /// address.
        TargetNotCanonical = "TARGET_NOT_CANONICAL",
        /// The host and port are not exactly a granted destination.
        TargetNotGranted = "TARGET_NOT_GRANTED",
        /// The environment already has its most tunnels open.
        TunnelLimit = "TUNNEL_LIMIT",
        /// The trusted resolver found no address.
        ResolutionFailed = "RESOLUTION_FAILED",
        /// The trusted resolver did not answer in time.
        ResolutionTimeout = "RESOLUTION_TIMEOUT",
        /// Every address the name resolved to is one the IP guard blocks.
        AddressBlocked = "ADDRESS_BLOCKED",
        /// The name resolved to blocked and unblocked addresses together:
        /// refused outright, never filtered (`NETWORK_SECURITY.md` §2).
        AddressMixed = "ADDRESS_MIXED",
        /// The pinned address could not be connected to.
        ConnectFailed = "CONNECT_FAILED",
        /// No TLS `ClientHello` arrived in time after the tunnel was granted.
        ClientHelloTimeout = "CLIENT_HELLO_TIMEOUT",
        /// What arrived was not a well-formed, bounded TLS `ClientHello`.
        ClientHelloMalformed = "CLIENT_HELLO_MALFORMED",
        /// The `ClientHello` named no server.
        SniMissing = "SNI_MISSING",
        /// The `ClientHello` named more than one server, or named it twice.
        SniAmbiguous = "SNI_AMBIGUOUS",
        /// The `ClientHello` named a server other than the CONNECT target.
        SniMismatch = "SNI_MISMATCH",
        /// The `ClientHello` carried Encrypted Client Hello: the server it
        /// really names is hidden from the proxy, so it cannot agree.
        EchRefused = "ECH_REFUSED",
        /// Accepted, and closed by either side within its budgets.
        Closed = "CLOSED",
        /// Accepted, and closed when the environment's upload budget was spent.
        UploadBudget = "UPLOAD_BUDGET",
        /// Accepted, and closed when the environment's download budget was
        /// spent.
        DownloadBudget = "DOWNLOAD_BUDGET",
        /// Accepted, and closed when nothing moved for too long.
        IdleTimeout = "IDLE_TIMEOUT",
        /// Accepted, and closed at its longest lifetime.
        LifetimeExceeded = "LIFETIME_EXCEEDED",
        /// Accepted, and closed because the environment was destroyed.
        EnvironmentClosed = "ENVIRONMENT_CLOSED",
    }
}

wire_int! {
    /// How many tunnels ended one way.
    EgressCountValue(u64), min = 0, max = 9_007_199_254_740_991
}

wire_struct! {
    /// How many requests ended one way.
    EgressCount: reject {
        /// The way.
        required disposition: EgressDisposition,
        /// How many.
        required count: EgressCountValue,
    }
}

/// One count per disposition, at most.
pub type EgressCountList = BoundedList<EgressCount, 32>;

wire_struct! {
    /// What an environment's proxy has done since it was opened: counts by
    /// disposition, and the bytes it moved. No host, no payload.
    EgressCounters: reject {
        /// Every disposition seen, once each.
        required dispositions: EgressCountList,
        /// Bytes carried from the environment to its destinations.
        required bytes_upstream: ByteCount,
        /// Bytes carried back.
        required bytes_downstream: ByteCount,
    }
}

impl EgressCounters {
    /// The count for `disposition`; zero when it was never seen.
    #[must_use]
    pub fn count(&self, disposition: EgressDisposition) -> u64 {
        self.dispositions
            .iter()
            .find(|c| c.disposition == disposition)
            .map_or(0, |c| c.count.get())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test fixtures")]
mod tests {
    use super::*;

    #[test]
    fn a_host_is_canonical_and_never_an_address() {
        for good in ["api.github.com", "pypi.org", "xn--bcher-kva.example"] {
            assert!(EgressHost::new(good).is_some(), "{good}");
        }
        for bad in [
            "10.0.0.1",
            "2130706433",
            "API.github.com",
            "github.com.",
            "[::1]",
            "user@github.com",
            "*.github.com",
            "github.com:443",
            "",
        ] {
            assert!(EgressHost::new(bad).is_none(), "{bad:?}");
        }
        assert!(EgressPort::new(0).is_none() && EgressPort::new(443).is_some());
        assert!(EgressByteBudget::new(0).is_none());
    }

    #[test]
    fn a_grant_permits_exactly_its_targets() {
        let target = |h: &str, p: u16| EgressTarget {
            host: EgressHost::new(h).unwrap(),
            port: EgressPort::new(p).unwrap(),
        };
        let grant = EgressGrant {
            targets: EgressTargets::new(vec![target("pypi.org", 443)]).unwrap(),
            max_tunnels: EgressTunnelLimit::new(4).unwrap(),
            max_upload_bytes: EgressByteBudget::new(1024).unwrap(),
            max_download_bytes: EgressByteBudget::new(4096).unwrap(),
        };
        assert!(grant.permits("pypi.org", 443));
        for (host, port) in [
            ("pypi.org", 80),
            ("files.pypi.org", 443),
            ("evil-pypi.org", 443),
            ("PYPI.org", 443),
            ("pypi.org.", 443),
        ] {
            assert!(!grant.permits(host, port), "{host}:{port}");
        }
    }
}
