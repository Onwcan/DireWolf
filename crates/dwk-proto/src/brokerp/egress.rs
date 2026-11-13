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
//!
//! **A workload's egress authorisation** (F-17, ADR-0061, Proposed) narrows
//! the grant for the life of one workload: the authority's decision, by both
//! gates, for each granted destination ([`WorkloadEgress`]). It is still
//! typed facts. For each destination it holds four cells -- the destination
//! not yet reached or reached, and the workspace not yet exposed to anything
//! an origin sent or exposed -- and each cell is a bit per *piece* of the
//! address space: the pieces are the active policy's own address ranges,
//! each address in the most specific one that contains it
//! ([`WorkloadEgress::piece`]). The broker looks a pinned address up and
//! reads a bit; it evaluates no rule. Nothing here unblocks an address the
//! guard refuses: the guard judges first, and a cell only ever refuses more.

use crate::error::{ProtocolError, Violation};
use crate::json::{Number, Value};
use crate::limits::MAX_SAFE_INTEGER;
use crate::schema::{Defs, int, obj, string};
use crate::wire::guard::Address;
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
        /// Granted, but no workload's egress authorisation is in force for
        /// the environment (F-17): nothing is decided outside a workload.
        NotAuthorised = "NOT_AUTHORISED",
        /// Granted, but the workload's authorisation allows no address of
        /// it in the cell that applies: policy denied it. Refused before
        /// anything is resolved.
        PolicyDenied = "POLICY_DENIED",
        /// An address the name resolved to lies outside what the
        /// authorisation allows: refused whole, never filtered.
        PolicyAddressDenied = "POLICY_ADDRESS_DENIED",
        /// Accepted, and closed when it carried back as many bytes as the
        /// policy's `max_output_bytes` allows one tunnel.
        TunnelOutputLimit = "TUNNEL_OUTPUT_LIMIT",
        /// Accepted, and closed because its workload ended.
        WorkloadEnded = "WORKLOAD_ENDED",
        /// Accepted, and closed -- before the byte that exposed the
        /// workspace reached anything -- because the exposed decision no
        /// longer allows it.
        ExposureRevoked = "EXPOSURE_REVOKED",
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

// ===========================================================================
// A workload's egress authorisation (F-17, ADR-0061, Proposed).
// ===========================================================================

/// The canonical text of an address: IPv4 in dotted decimal, IPv6 as eight
/// groups of four lowercase hexadecimal digits -- no elision, one spelling.
#[must_use]
pub fn address_text(address: &Address) -> String {
    match address {
        Address::V4(o) => o.iter().map(u8::to_string).collect::<Vec<_>>().join("."),
        Address::V6(o) => o
            .chunks(2)
            .map(|pair| match pair {
                [high, low] => format!("{:04x}", u16::from(*high) << 8 | u16::from(*low)),
                _ => String::new(),
            })
            .collect::<Vec<_>>()
            .join(":"),
    }
}

/// Parse an address in its canonical text ([`address_text`]), exactly.
#[must_use]
pub fn parse_address_text(text: &str) -> Option<Address> {
    if text.contains(':') {
        let groups: Vec<&str> = text.split(':').collect();
        if groups.len() != 8 {
            return None;
        }
        let mut octets = [0u8; 16];
        for (index, group) in groups.iter().enumerate() {
            if group.len() != 4
                || !group
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return None;
            }
            let value = u16::from_str_radix(group, 16).ok()?;
            let [high, low] = value.to_be_bytes();
            *octets.get_mut(index.checked_mul(2)?)? = high;
            *octets.get_mut(index.checked_mul(2)?.checked_add(1)?)? = low;
        }
        return Some(Address::V6(octets));
    }
    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (index, part) in parts.iter().enumerate() {
        let canonical = !part.is_empty()
            && part.len() <= 3
            && part.bytes().all(|b| b.is_ascii_digit())
            && (part.len() == 1 || !part.starts_with('0'));
        if !canonical {
            return None;
        }
        *octets.get_mut(index)? = part.parse().ok()?;
    }
    Some(Address::V4(octets))
}

/// How many bits an address of `address`'s family has.
const fn family_bits(address: &Address) -> u8 {
    match address {
        Address::V4(_) => 32,
        Address::V6(_) => 128,
    }
}

fn octets(address: &Address) -> &[u8] {
    match address {
        Address::V4(o) => o,
        Address::V6(o) => o,
    }
}

/// Whether `candidate` lies in the range `network`/`length`: the same family
/// and the same leading `length` bits. An address of the other family never
/// does, exactly as the policy's own `Cidr::contains` (no mapping between
/// IPv4 and IPv6, in either direction).
#[must_use]
pub fn prefix_contains(network: &Address, length: u8, candidate: &Address) -> bool {
    let (net, cand) = (octets(network), octets(candidate));
    if net.len() != cand.len() || length > family_bits(network) {
        return false;
    }
    let whole = usize::from(length >> 3);
    let remainder = length & 7;
    if net.get(..whole) != cand.get(..whole) {
        return false;
    }
    if remainder == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - remainder);
    match (net.get(whole), cand.get(whole)) {
        (Some(a), Some(b)) => a & mask == b & mask,
        _ => false,
    }
}

/// Whether every bit of `address` past `length` is zero: a range has one
/// spelling, its first address.
fn host_bits_clear(address: &Address, length: u8) -> bool {
    let all = octets(address);
    let whole = usize::from(length >> 3);
    let remainder = length & 7;
    let mut rest = all.iter().skip(whole);
    if remainder != 0 {
        let mask = 0xFFu8 << (8 - remainder);
        if rest.next().is_some_and(|byte| byte & !mask != 0) {
            return false;
        }
    }
    rest.all(|byte| *byte == 0)
}

/// Parse a range in its canonical text: `<address>/<length>`, the address
/// canonical ([`address_text`]), the length a plain decimal within the
/// family, and every host bit zero.
#[must_use]
pub fn parse_prefix(text: &str) -> Option<(Address, u8)> {
    let (address, length) = text.split_once('/')?;
    let canonical_length = !length.is_empty()
        && length.len() <= 3
        && length.bytes().all(|b| b.is_ascii_digit())
        && (length.len() == 1 || !length.starts_with('0'));
    if !canonical_length {
        return None;
    }
    let length: u8 = length.parse().ok()?;
    let address = parse_address_text(address)?;
    if length > family_bits(&address) || !host_bits_clear(&address, length) {
        return None;
    }
    Some((address, length))
}

wire_text! {
    /// An address range of the active policy (`when.ip_in`), in one canonical
    /// spelling: the range's first address ([`address_text`]), `/`, and its
    /// length -- every host bit zero.
    EgressPrefix,
    max_chars = 43,
    pattern = None,
    format = None,
    validate = |s| parse_prefix(s).is_some()
}

impl EgressPrefix {
    /// The range: its first address and its length.
    #[must_use]
    pub fn range(&self) -> Option<(Address, u8)> {
        parse_prefix(self.as_str())
    }

    /// The range `address`/`length`, if it is one: host bits zero, length
    /// within the family.
    #[must_use]
    pub fn of(address: &Address, length: u8) -> Option<Self> {
        Self::new(format!("{}/{length}", address_text(address)))
    }
}

/// The most address ranges one authorisation carries: the active policy's,
/// each once. A policy with more is too fine to be decided per address
/// ahead of a tunnel, and its address-dependent decisions refuse.
pub const MAX_EGRESS_PREFIXES: usize = 256;

/// An authorisation's address ranges.
pub type EgressPrefixes = BoundedList<EgressPrefix, MAX_EGRESS_PREFIXES>;

/// The most pieces the address space is cut into: one per range, and one
/// per family for the addresses in no range.
pub const MAX_EGRESS_PIECES: usize = MAX_EGRESS_PREFIXES + 2;

/// The hexadecimal digits one cell's bits take at most.
pub const MAX_EGRESS_BITS_CHARS: usize = MAX_EGRESS_PIECES.div_ceil(4);

wire_text! {
    /// Which pieces a cell allows: one bit per piece, the first piece in the
    /// first digit's highest bit, as lowercase hexadecimal; every bit past
    /// the last piece zero.
    EgressBits,
    max_chars = MAX_EGRESS_BITS_CHARS,
    pattern = None,
    format = None,
    validate = |s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl EgressBits {
    /// The bits for `pieces` pieces, set where `allowed` says.
    #[must_use]
    pub fn from_pieces(allowed: &[bool]) -> Option<Self> {
        if allowed.is_empty() || allowed.len() > MAX_EGRESS_PIECES {
            return None;
        }
        let digits: String = allowed
            .chunks(4)
            .map(|nibble| {
                let mut value = 0u32;
                for (index, set) in nibble.iter().enumerate() {
                    if *set {
                        value |= 8 >> index;
                    }
                }
                char::from_digit(value, 16).unwrap_or('0')
            })
            .collect();
        Self::new(digits)
    }

    /// Whether piece `piece` is allowed. A piece past the bits is not.
    #[must_use]
    pub fn get(&self, piece: usize) -> bool {
        let Some(digit) = self.as_str().as_bytes().get(piece >> 2) else {
            return false;
        };
        let value = char::from(*digit).to_digit(16).unwrap_or(0);
        value & (8 >> (piece & 3)) != 0
    }

    /// Whether any piece is allowed.
    #[must_use]
    pub fn any(&self) -> bool {
        self.as_str().bytes().any(|b| b != b'0')
    }

    /// Whether these bits describe exactly `pieces` pieces: the right number
    /// of digits, and no bit set past the last piece.
    #[must_use]
    pub fn fits(&self, pieces: usize) -> bool {
        self.as_str().len() == pieces.div_ceil(4)
            && (pieces..pieces.div_ceil(4).saturating_mul(4)).all(|p| !self.get(p))
    }

    /// Whether every piece allowed here is allowed by `wider` too.
    #[must_use]
    pub fn within(&self, wider: &Self) -> bool {
        self.as_str().len() == wider.as_str().len()
            && (0..self.as_str().len().saturating_mul(4)).all(|p| !self.get(p) || wider.get(p))
    }
}

wire_struct! {
    /// One cell of a destination's decision: which pieces of the address
    /// space a tunnel may reach, and the most bytes one tunnel may carry
    /// back -- the policy's `max_output_bytes`, kept at the socket, which
    /// bounds every response the tunnel carries.
    EgressCell: reject {
        /// The pieces allowed.
        required allowed: EgressBits,
        /// The most bytes one tunnel carries back. Absent: the environment's
        /// download budget is the only bound.
        optional max_tunnel_download_bytes: EgressByteBudget,
    }
}

impl EgressCell {
    /// Whether `narrower` allows nothing this cell does not, and never more
    /// bytes per tunnel.
    #[must_use]
    pub fn admits(&self, narrower: &Self) -> bool {
        // A cell that allows nothing carries no tunnel, so its bound is moot.
        let bytes_within = !narrower.allowed.any()
            || match (
                self.max_tunnel_download_bytes,
                narrower.max_tunnel_download_bytes,
            ) {
                (None, _) => true,
                (Some(_), None) => false,
                (Some(wide), Some(narrow)) => narrow.get() <= wide.get(),
            };
        narrower.allowed.within(&self.allowed) && bytes_within
    }
}

wire_struct! {
    /// One destination of a workload's authorisation: its host and port --
    /// exactly one of the environment's granted destinations -- whether the
    /// run had reached it when the workload started, and its four cells.
    WorkloadEgressTarget: reject {
        /// The host.
        required host: EgressHost,
        /// The port.
        required port: EgressPort,
        /// Whether the run had reached it already: the `SEEN` cells apply
        /// from the start. Otherwise the `NOVEL` ones apply until a tunnel
        /// of this workload reaches it.
        required seen: bool,
        /// Not yet reached; the workspace not yet exposed.
        required novel_pristine: EgressCell,
        /// Not yet reached; the workspace exposed.
        required novel_exposed: EgressCell,
        /// Reached; the workspace not yet exposed.
        required seen_pristine: EgressCell,
        /// Reached; the workspace exposed.
        required seen_exposed: EgressCell,
    }
}

impl WorkloadEgressTarget {
    /// The cell for `seen` and `exposed`.
    #[must_use]
    pub const fn cell(&self, seen: bool, exposed: bool) -> &EgressCell {
        match (seen, exposed) {
            (false, false) => &self.novel_pristine,
            (false, true) => &self.novel_exposed,
            (true, false) => &self.seen_pristine,
            (true, true) => &self.seen_exposed,
        }
    }
}

/// A workload authorisation's destinations.
pub type WorkloadEgressTargets = BoundedList<WorkloadEgressTarget, MAX_EGRESS_TARGETS>;

wire_struct! {
    /// What one workload's processes may reach through the environment's
    /// proxy while it runs (F-17, ADR-0061, Proposed): the authority's
    /// decision, by both gates, for each of the environment's granted
    /// destinations. The broker holds it only while the workload is
    /// supervised; a CONNECT with none in force is refused.
    WorkloadEgress: reject {
        /// Whether the workspace was exposed when the workload started: the
        /// exposed cells apply from the start.
        required exposed: bool,
        /// The active policy's address ranges: piece `2 + i` is the
        /// addresses whose most specific range is range `i`.
        required prefixes: EgressPrefixes,
        /// Each destination, at most once.
        required targets: WorkloadEgressTargets,
    }
}

/// Piece 0: the IPv4 addresses in no range.
pub const PIECE_V4_OTHER: usize = 0;
/// Piece 1: the IPv6 addresses in no range.
pub const PIECE_V6_OTHER: usize = 1;

/// The most bytes one encoded authorisation may take. Derived, not chosen:
/// the largest one -- 256 IPv6 ranges, 64 destinations of 253 characters,
/// four cells each of 258 pieces with a byte bound -- encodes well within it
/// (a unit test builds it), and the largest workload start's arguments and
/// this together fit one authorisation body.
pub const MAX_EGRESS_AUTHORISATION_BYTES: usize = 128 * 1024;

const _: () = assert!(
    crate::limits::MAX_PROCESS_REQUEST_ENCODED_BYTES + MAX_EGRESS_AUTHORISATION_BYTES
        <= super::MAX_AUTHORISATION_BODY
);

impl WorkloadEgress {
    /// An authorisation for `destinations` whose every cell allows every
    /// address (`allowed`) or none: no ranges, so two pieces. What the
    /// broker's evidence plays the authority with; the authority builds its
    /// own from decisions.
    #[must_use]
    pub fn uniform(destinations: &[(&str, u16)], allowed: bool, exposed: bool) -> Option<Self> {
        let cell = EgressCell {
            allowed: EgressBits::from_pieces(&[allowed, allowed])?,
            max_tunnel_download_bytes: None,
        };
        let mut targets = Vec::with_capacity(destinations.len());
        for (host, port) in destinations {
            targets.push(WorkloadEgressTarget {
                host: EgressHost::new(*host)?,
                port: EgressPort::new(*port)?,
                seen: false,
                novel_pristine: cell.clone(),
                novel_exposed: cell.clone(),
                seen_pristine: cell.clone(),
                seen_exposed: cell.clone(),
            });
        }
        let egress = Self {
            exposed,
            prefixes: EgressPrefixes::new(Vec::new())?,
            targets: WorkloadEgressTargets::new(targets)?,
        };
        egress.check().ok()?;
        Some(egress)
    }

    /// How many pieces the address space is cut into.
    #[must_use]
    pub fn pieces(&self) -> usize {
        self.prefixes.len().saturating_add(2)
    }

    /// The piece `address` is in: the most specific range that contains it,
    /// or its family's "in no range" piece. Ranges are compared within a
    /// family only, as policy compares them.
    #[must_use]
    pub fn piece(&self, address: &Address) -> usize {
        let mut best: Option<(usize, u8)> = None;
        for (index, prefix) in self.prefixes.iter().enumerate() {
            let Some((network, length)) = prefix.range() else {
                continue;
            };
            if prefix_contains(&network, length, address)
                && best.is_none_or(|(_, longest)| length > longest)
            {
                best = Some((index, length));
            }
        }
        match (best, address) {
            (Some((index, _)), _) => index.saturating_add(2),
            (None, Address::V4(_)) => PIECE_V4_OTHER,
            (None, Address::V6(_)) => PIECE_V6_OTHER,
        }
    }

    /// The destination `host:port`, by position.
    #[must_use]
    pub fn index_of(&self, host: &str, port: u16) -> Option<usize> {
        self.targets
            .iter()
            .position(|t| t.host.as_str() == host && t.port.get() == port)
    }

    /// Whether destination `target`'s cell for `seen` and `exposed` allows
    /// any address at all: what is known before a name is resolved.
    #[must_use]
    pub fn allows_some(&self, target: usize, seen: bool, exposed: bool) -> bool {
        self.targets
            .as_slice()
            .get(target)
            .is_some_and(|t| t.cell(seen, exposed).allowed.any())
    }

    /// Whether destination `target`'s cell for `seen` and `exposed` allows
    /// **every** address in `addresses` -- none at all allows nothing.
    #[must_use]
    pub fn allows_all(
        &self,
        target: usize,
        (seen, exposed): (bool, bool),
        addresses: &[Address],
    ) -> bool {
        let Some(t) = self.targets.as_slice().get(target) else {
            return false;
        };
        let cell = t.cell(seen, exposed);
        !addresses.is_empty()
            && addresses
                .iter()
                .all(|address| cell.allowed.get(self.piece(address)))
    }

    /// The most bytes one tunnel to `target` carries back in that cell.
    #[must_use]
    pub fn tunnel_cap(&self, target: usize, seen: bool, exposed: bool) -> Option<u64> {
        self.targets
            .as_slice()
            .get(target)
            .and_then(|t| t.cell(seen, exposed).max_tunnel_download_bytes)
            .map(EgressByteBudget::get)
    }

    /// Whether any cell of any destination allows anything: a workload whose
    /// authorisation allows nothing can reach no origin.
    #[must_use]
    pub fn allows_anything(&self) -> bool {
        self.targets.iter().any(|t| {
            [
                &t.novel_pristine,
                &t.novel_exposed,
                &t.seen_pristine,
                &t.seen_exposed,
            ]
            .iter()
            .any(|c| c.allowed.any())
        })
    }

    /// The authorisation's own consistency: every range canonical and
    /// distinct, every destination distinct, every cell's bits exactly the
    /// pieces, and each exposed cell within its pristine one -- exposure
    /// only ever takes away.
    ///
    /// # Errors
    ///
    /// The first inconsistency.
    pub fn check(&self) -> Result<(), &'static str> {
        let mut ranges = Vec::with_capacity(self.prefixes.len());
        for prefix in &self.prefixes {
            let range = prefix.range().ok_or("a range is not canonical")?;
            if ranges.contains(&range) {
                return Err("a range is named twice");
            }
            ranges.push(range);
        }
        let pieces = self.pieces();
        for (index, target) in self.targets.iter().enumerate() {
            if self
                .targets
                .iter()
                .take(index)
                .any(|t| t.host == target.host && t.port == target.port)
            {
                return Err("a destination is named twice");
            }
            for cell in [
                &target.novel_pristine,
                &target.novel_exposed,
                &target.seen_pristine,
                &target.seen_exposed,
            ] {
                if !cell.allowed.fits(pieces) {
                    return Err("a cell's bits are not the pieces");
                }
            }
            if !target.novel_pristine.admits(&target.novel_exposed)
                || !target.seen_pristine.admits(&target.seen_exposed)
            {
                return Err("an exposed cell allows what its pristine one does not");
            }
        }
        Ok(())
    }
}

wire_text! {
    /// An address a tunnel's name resolved to, in its canonical text
    /// ([`address_text`]).
    EgressAddress,
    max_chars = 39,
    pattern = None,
    format = None,
    validate = |s| parse_address_text(s).is_some()
}

wire_struct! {
    /// One address a destination's name resolved to while the workload ran,
    /// and how many tunnels the authorisation let reach it or refused for it.
    EgressAddressUse: reject {
        /// The address.
        required address: EgressAddress,
        /// Tunnels dialled to it.
        required allowed: EgressCountValue,
        /// Tunnels refused because the answer held it
        /// (`POLICY_ADDRESS_DENIED`).
        required refused: EgressCountValue,
    }
}

/// The most addresses one destination's report names; more are counted.
pub const MAX_REPORTED_ADDRESSES: usize = 8;

/// A destination's reported addresses.
pub type EgressAddressUses = BoundedList<EgressAddressUse, MAX_REPORTED_ADDRESSES>;

wire_struct! {
    /// What a workload's tunnels to one destination did: whether one reached
    /// it (an origin byte came back), how each attempt ended, the bytes each
    /// way, and the addresses judged. No payload.
    WorkloadEgressTargetReport: reject {
        /// Whether a tunnel of this workload reached it.
        required reached: bool,
        /// How each CONNECT for it ended.
        required dispositions: EgressCountList,
        /// Bytes carried to it.
        required bytes_upstream: ByteCount,
        /// Bytes carried back from it.
        required bytes_downstream: ByteCount,
        /// The addresses judged, at most [`MAX_REPORTED_ADDRESSES`].
        required addresses: EgressAddressUses,
        /// How many more addresses were judged than are named.
        required addresses_omitted: EgressCountValue,
    }
}

/// A report's destinations, in the authorisation's order.
pub type WorkloadEgressTargetReports = BoundedList<WorkloadEgressTargetReport, MAX_EGRESS_TARGETS>;

wire_struct! {
    /// What one workload's tunnels did, as its supervisor saw them once it
    /// ended (F-17): whether any origin byte reached the workload, each
    /// destination's report in the authorisation's order, and the CONNECTs
    /// that named no destination of it.
    WorkloadEgressReport: reject {
        /// Whether any tunnel of this workload carried a byte back from an
        /// origin.
        required exposed: bool,
        /// One per destination of the authorisation, in its order.
        required targets: WorkloadEgressTargetReports,
        /// CONNECTs that named no destination of the authorisation.
        required unattributed: EgressCountList,
    }
}

impl WorkloadEgressReport {
    /// Whether this report can be a report of `egress`: one entry per
    /// destination, a destination reached only where some cell allowed it,
    /// bytes back only from a reached one, and exposure exactly when some
    /// destination was reached.
    #[must_use]
    pub fn consistent_with(&self, egress: &WorkloadEgress) -> bool {
        if self.targets.len() != egress.targets.len() {
            return false;
        }
        let mut any_reached = false;
        for (report, target) in self.targets.iter().zip(egress.targets.iter()) {
            let allowed_somewhere = [
                &target.novel_pristine,
                &target.novel_exposed,
                &target.seen_pristine,
                &target.seen_exposed,
            ]
            .iter()
            .any(|c| c.allowed.any());
            if report.reached && !allowed_somewhere {
                return false;
            }
            if report.bytes_downstream.get() > 0 && !report.reached {
                return false;
            }
            any_reached |= report.reached;
        }
        any_reached == self.exposed
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test fixtures"
)]
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

    fn v4(a: u8, b: u8, c: u8, d: u8) -> Address {
        Address::V4([a, b, c, d])
    }

    fn v6(groups: [u16; 8]) -> Address {
        let mut octets = [0u8; 16];
        for (index, group) in groups.iter().enumerate() {
            let [high, low] = group.to_be_bytes();
            octets[index * 2] = high;
            octets[index * 2 + 1] = low;
        }
        Address::V6(octets)
    }

    #[test]
    fn an_address_and_a_range_have_one_spelling() {
        for (address, text) in [
            (v4(10, 0, 0, 1), "10.0.0.1"),
            (v4(0, 0, 0, 0), "0.0.0.0"),
            (v4(255, 255, 255, 255), "255.255.255.255"),
            (
                v6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]),
                "2001:0db8:0000:0000:0000:0000:0000:0001",
            ),
        ] {
            assert_eq!(address_text(&address), text);
            assert_eq!(parse_address_text(text), Some(address));
        }
        for bad in [
            "010.0.0.1",
            "10.0.0",
            "10.0.0.256",
            "10.0.0.1 ",
            "2001:db8::1",
            "2001:0DB8:0000:0000:0000:0000:0000:0001",
            "::ffff:10.0.0.1",
            "",
        ] {
            assert_eq!(parse_address_text(bad), None, "{bad:?}");
        }
        for good in [
            "10.0.0.0/8",
            "0.0.0.0/0",
            "192.168.1.7/32",
            "fc00:0000:0000:0000:0000:0000:0000:0000/7",
            "0000:0000:0000:0000:0000:0000:0000:0000/0",
        ] {
            assert!(EgressPrefix::new(good).is_some(), "{good}");
        }
        for bad in [
            "10.0.0.1/8",
            "10.0.0.0/33",
            "10.0.0.0/08",
            "10.0.0.0/",
            "10.0.0.0",
            "fc00:0000:0000:0000:0000:0000:0000:0001/7",
            "fc00::/7",
            "0000:0000:0000:0000:0000:0000:0000:0000/129",
        ] {
            assert!(EgressPrefix::new(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn a_range_holds_its_own_family_only() {
        let ten = (v4(10, 0, 0, 0), 8);
        assert!(prefix_contains(&ten.0, ten.1, &v4(10, 255, 1, 2)));
        assert!(!prefix_contains(&ten.0, ten.1, &v4(11, 0, 0, 0)));
        // An IPv4-mapped IPv6 address is not in an IPv4 range, and the
        // whole IPv6 space does not hold an IPv4 address: as policy.
        let mapped = v6([0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001]);
        assert!(!prefix_contains(&ten.0, ten.1, &mapped));
        assert!(!prefix_contains(&v6([0; 8]), 0, &v4(10, 0, 0, 1)));
        assert!(prefix_contains(&v6([0; 8]), 0, &mapped));
        // A partial octet.
        assert!(prefix_contains(&v4(172, 16, 0, 0), 12, &v4(172, 31, 9, 9)));
        assert!(!prefix_contains(&v4(172, 16, 0, 0), 12, &v4(172, 32, 0, 0)));
    }

    fn prefixes(texts: &[&str]) -> EgressPrefixes {
        EgressPrefixes::new(
            texts
                .iter()
                .map(|t| EgressPrefix::new(*t).unwrap())
                .collect(),
        )
        .unwrap()
    }

    fn egress_with(texts: &[&str], cells: [&[bool]; 4]) -> WorkloadEgress {
        let cell = |bits: &[bool]| EgressCell {
            allowed: EgressBits::from_pieces(bits).unwrap(),
            max_tunnel_download_bytes: None,
        };
        WorkloadEgress {
            exposed: false,
            prefixes: prefixes(texts),
            targets: WorkloadEgressTargets::new(vec![WorkloadEgressTarget {
                host: EgressHost::new("api.example.com").unwrap(),
                port: EgressPort::new(443).unwrap(),
                seen: false,
                novel_pristine: cell(cells[0]),
                novel_exposed: cell(cells[1]),
                seen_pristine: cell(cells[2]),
                seen_exposed: cell(cells[3]),
            }])
            .unwrap(),
        }
    }

    #[test]
    fn an_address_is_in_its_most_specific_range_or_its_familys_other_piece() {
        // 10/8 holds 10.1/16; an address of 10.1/16 is in that piece, one
        // only of 10/8 in 10/8's; v4 and v6 outside every range are pieces
        // 0 and 1.
        let all = [true; 5];
        let e = egress_with(
            &[
                "10.0.0.0/8",
                "10.1.0.0/16",
                "2000:0000:0000:0000:0000:0000:0000:0000/3",
            ],
            [&all, &all, &all, &all],
        );
        assert_eq!(e.pieces(), 5);
        assert_eq!(e.piece(&v4(10, 1, 2, 3)), 3);
        assert_eq!(e.piece(&v4(10, 2, 2, 3)), 2);
        assert_eq!(e.piece(&v4(8, 8, 8, 8)), PIECE_V4_OTHER);
        assert_eq!(e.piece(&v6([0x2606, 0x4700, 0, 0, 0, 0, 0, 1])), 4);
        assert_eq!(e.piece(&v6([0xfc00, 0, 0, 0, 0, 0, 0, 1])), PIECE_V6_OTHER);
        // A mapped address is IPv6's, never the IPv4 range's.
        assert_eq!(
            e.piece(&v6([0, 0, 0, 0, 0, 0xffff, 0x0a01, 1])),
            PIECE_V6_OTHER
        );
    }

    #[test]
    fn a_cell_allows_a_whole_answer_or_nothing() {
        // Pieces: v4-other, v6-other, 10/8. Pristine allows v4-other and
        // 10/8; exposed only v4-other.
        let e = egress_with(
            &["10.0.0.0/8"],
            [
                &[true, false, true],
                &[true, false, false],
                &[true, false, true],
                &[true, false, false],
            ],
        );
        assert_eq!(e.check(), Ok(()));
        let public = v4(93, 184, 216, 34);
        let private = v4(10, 0, 0, 9);
        assert!(e.allows_all(0, (false, false), &[public, private]));
        assert!(!e.allows_all(0, (false, true), &[public, private]));
        assert!(e.allows_all(0, (false, true), &[public]));
        // Nothing resolved allows nothing; a destination past the list is
        // none.
        assert!(!e.allows_all(0, (false, false), &[]));
        assert!(!e.allows_all(1, (false, false), &[public]));
        assert!(e.allows_some(0, true, true));
        assert!(e.allows_anything());
        let none = egress_with(&[], [&[false, false]; 4]);
        assert!(!none.allows_some(0, false, false));
        assert!(!none.allows_anything());
    }

    #[test]
    fn bits_are_exactly_the_pieces() {
        let bits = EgressBits::from_pieces(&[true, false, false, true, true]).unwrap();
        assert_eq!(bits.as_str(), "98");
        assert!(bits.get(0) && bits.get(3) && bits.get(4));
        assert!(!bits.get(1) && !bits.get(5) && !bits.get(400));
        assert!(bits.fits(5));
        assert!(!bits.fits(4));
        assert!(!bits.fits(9));
        // A bit set past the last piece does not fit.
        assert!(!EgressBits::new("9c").unwrap().fits(5));
        assert!(EgressBits::new("9C").is_none());
        assert!(EgressBits::from_pieces(&[]).is_none());
        let narrow = EgressBits::from_pieces(&[true, false, false, false, true]).unwrap();
        assert!(narrow.within(&bits));
        assert!(!bits.within(&narrow));
        // The largest bits fit the largest piece count.
        let most = EgressBits::from_pieces(&[true; MAX_EGRESS_PIECES]).unwrap();
        assert!(most.fits(MAX_EGRESS_PIECES));
    }

    #[test]
    fn an_inconsistent_authorisation_is_refused() {
        let fine = egress_with(&["10.0.0.0/8"], [&[true, true, true]; 4]);
        assert_eq!(fine.check(), Ok(()));
        // A range named twice.
        let mut twice = fine.clone();
        twice.prefixes = prefixes(&["10.0.0.0/8", "10.0.0.0/8"]);
        assert!(twice.check().is_err());
        // Bits for another number of pieces: five pieces take two digits.
        let short = egress_with(
            &["10.0.0.0/8", "11.0.0.0/8", "12.0.0.0/8"],
            [&[true, true]; 4],
        );
        assert!(short.check().is_err());
        // A bit set for a piece that does not exist.
        let mut stray = fine.clone();
        stray.targets = WorkloadEgressTargets::new(
            fine.targets
                .iter()
                .map(|t| WorkloadEgressTarget {
                    seen_exposed: EgressCell {
                        allowed: EgressBits::new("f").unwrap(),
                        max_tunnel_download_bytes: None,
                    },
                    ..t.clone()
                })
                .collect(),
        )
        .unwrap();
        assert!(stray.check().is_err());
        // An exposed cell wider than its pristine one.
        let wider = egress_with(
            &["10.0.0.0/8"],
            [
                &[true, false, false],
                &[true, true, false],
                &[true, true, true],
                &[true, true, true],
            ],
        );
        assert!(wider.check().is_err());
        // An exposed cell that lifts the pristine one's byte bound.
        let mut lifted = fine.clone();
        let bound = |n| Some(EgressByteBudget::new(n).unwrap());
        lifted.targets = WorkloadEgressTargets::new(
            fine.targets
                .iter()
                .map(|t| WorkloadEgressTarget {
                    novel_pristine: EgressCell {
                        max_tunnel_download_bytes: bound(10),
                        ..t.novel_pristine.clone()
                    },
                    novel_exposed: EgressCell {
                        max_tunnel_download_bytes: bound(11),
                        ..t.novel_exposed.clone()
                    },
                    ..t.clone()
                })
                .collect(),
        )
        .unwrap();
        assert!(lifted.check().is_err());
        // An exposed cell that allows nothing carries no tunnel: it needs no
        // bound, whatever its pristine one's.
        let mut emptied = fine.clone();
        emptied.targets = WorkloadEgressTargets::new(
            fine.targets
                .iter()
                .map(|t| WorkloadEgressTarget {
                    novel_pristine: EgressCell {
                        max_tunnel_download_bytes: bound(10),
                        ..t.novel_pristine.clone()
                    },
                    novel_exposed: EgressCell {
                        allowed: EgressBits::from_pieces(&[false, false, false]).unwrap(),
                        max_tunnel_download_bytes: None,
                    },
                    ..t.clone()
                })
                .collect(),
        )
        .unwrap();
        assert_eq!(emptied.check(), Ok(()));
        // A destination named twice.
        let mut doubled = fine.clone();
        doubled.targets = WorkloadEgressTargets::new(
            fine.targets
                .iter()
                .chain(fine.targets.iter())
                .cloned()
                .collect(),
        )
        .unwrap();
        assert!(doubled.check().is_err());
    }

    #[test]
    fn the_largest_authorisation_fits_its_bound_and_round_trips() {
        let texts: Vec<String> = (0..MAX_EGRESS_PREFIXES)
            .map(|n| {
                let n = u16::try_from(n).unwrap();
                format!(
                    "{}/128",
                    address_text(&v6([0x2001, 0xdb8, n, n, n, n, n, n]))
                )
            })
            .collect();
        let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
        let cell = EgressCell {
            allowed: EgressBits::from_pieces(&[true; MAX_EGRESS_PIECES]).unwrap(),
            max_tunnel_download_bytes: Some(EgressByteBudget::new(17_179_869_184).unwrap()),
        };
        let label = "a".repeat(63);
        let targets = (0..MAX_EGRESS_TARGETS)
            .map(|n| WorkloadEgressTarget {
                host: EgressHost::new(format!("{label}.{label}.{label}.{}{n:02}", "b".repeat(59)))
                    .unwrap(),
                port: EgressPort::new(65535).unwrap(),
                seen: false,
                novel_pristine: cell.clone(),
                novel_exposed: cell.clone(),
                seen_pristine: cell.clone(),
                seen_exposed: cell.clone(),
            })
            .collect();
        let egress = WorkloadEgress {
            exposed: true,
            prefixes: prefixes(&refs),
            targets: WorkloadEgressTargets::new(targets).unwrap(),
        };
        assert_eq!(egress.check(), Ok(()));
        let frame = super::super::encode_frame(&egress).unwrap();
        assert!(
            frame.len() <= MAX_EGRESS_AUTHORISATION_BYTES,
            "{} bytes",
            frame.len()
        );
        let mut cx = Cx::default();
        let value = egress.encode().unwrap();
        assert_eq!(WorkloadEgress::decode(value, &mut cx), Ok(egress));
    }

    fn report(reached: bool, down: u64, exposed: bool) -> WorkloadEgressReport {
        WorkloadEgressReport {
            exposed,
            targets: WorkloadEgressTargetReports::new(vec![WorkloadEgressTargetReport {
                reached,
                dispositions: EgressCountList::new(Vec::new()).unwrap(),
                bytes_upstream: ByteCount::new(0).unwrap(),
                bytes_downstream: ByteCount::new(down).unwrap(),
                addresses: EgressAddressUses::new(Vec::new()).unwrap(),
                addresses_omitted: EgressCountValue::new(0).unwrap(),
            }])
            .unwrap(),
            unattributed: EgressCountList::new(Vec::new()).unwrap(),
        }
    }

    #[test]
    fn a_report_agrees_with_its_authorisation_or_is_not_believed() {
        let allowed = egress_with(&[], [&[true, true]; 4]);
        let denied = egress_with(&[], [&[false, false]; 4]);
        assert!(report(true, 10, true).consistent_with(&allowed));
        assert!(report(false, 0, false).consistent_with(&allowed));
        assert!(report(false, 0, false).consistent_with(&denied));
        // Reached where nothing allowed it; bytes back without a reach;
        // exposure that disagrees with the reaches; a count of destinations
        // that is not the authorisation's.
        assert!(!report(true, 10, true).consistent_with(&denied));
        assert!(!report(false, 10, false).consistent_with(&allowed));
        assert!(!report(true, 10, false).consistent_with(&allowed));
        assert!(!report(false, 0, true).consistent_with(&allowed));
        let mut empty = report(false, 0, false);
        empty.targets = WorkloadEgressTargetReports::new(Vec::new()).unwrap();
        assert!(!empty.consistent_with(&allowed));
        let mut cx = Cx::default();
        let value = report(true, 10, true).encode().unwrap();
        assert_eq!(
            WorkloadEgressReport::decode(value, &mut cx),
            Ok(report(true, 10, true))
        );
    }

    #[test]
    fn a_uniform_authorisation_is_consistent() {
        let open = WorkloadEgress::uniform(
            &[("a.example.com", 443), ("b.example.com", 8443)],
            true,
            false,
        )
        .unwrap();
        assert!(open.allows_all(1, (false, false), &[v4(93, 184, 216, 34)]));
        assert_eq!(open.index_of("b.example.com", 8443), Some(1));
        assert_eq!(open.index_of("b.example.com", 443), None);
        let shut = WorkloadEgress::uniform(&[("a.example.com", 443)], false, true).unwrap();
        assert!(!shut.allows_anything());
        assert!(WorkloadEgress::uniform(&[("10.0.0.1", 443)], true, false).is_none());
    }
}
