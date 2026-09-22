//! The values a rule writes on the right of a predicate.
//!
//! A rule-side path, executable or address range is a **declaration**, exactly
//! as a `DeclaredPath` in a capability string is. It is compared against a
//! canonical value the authority already holds; it is never resolved, and
//! nothing here touches a filesystem, a resolver or the process environment.

use core::fmt;

use crate::capability::{CanonicalPath, ExecutableIdentity};

use super::action::IpAddress;
use super::context::{PathAnchor, PathAnchors};
use super::error::ValueError;
use super::limits;

/// A rule-side path: a closed symbolic anchor and a sequence of segments.
///
/// # `${WORKSPACE}` is not an environment variable
///
/// [`POLICY.md`] §3 writes `${WORKSPACE}`, `${DIREWOLF_HOME}`,
/// `${DIREWOLF_CONFIG}`, `${DIREWOLF_INSTALL}` and `~/.ssh`. They look like
/// shell, and they are not: [`PathAnchor`] is a closed enum, an unrecognised
/// `${...}` is a load error, and what each anchor *means* comes from
/// [`PathAnchors`] — kernel-owned state that M4's canonicaliser fills (M3d
/// leaves every anchor unresolved) — rather than from
/// `std::env`. There is no interpolation, no word expansion, no home-directory
/// lookup and no fallback to a variable of the same name.
///
/// That matters beyond tidiness. `${WORKSPACE}` has to be the directory pinned
/// by `(dev, ino)` at admission, not whatever a `WORKSPACE` variable says at
/// the moment a rule is evaluated; the whole point of pinning it is that the
/// name can be made to lie.
///
/// # Segments are canonical-path segments
///
/// `.` and `..` are refused. A canonical path has had them resolved away, so a
/// rule containing one names a path no candidate can ever equal — and a rule
/// that can never match is a denial that silently does not fire.
///
/// [`POLICY.md`]: ../../../../../docs/POLICY.md
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RulePath {
    anchor: PathAnchor,
    segments: Vec<String>,
}

impl RulePath {
    /// Parse `${ANCHOR}/a/b`, `~/a/b` or `/a/b`.
    ///
    /// # Errors
    ///
    /// [`ValueError::UnknownPathAnchor`] for a `${...}` outside the closed set,
    /// and [`ValueError::MalformedPath`] for anything that is neither anchored
    /// nor absolute, for a segment a canonical path could not contain, and past
    /// the depth bound.
    pub fn parse(text: &str) -> Result<Self, ValueError> {
        if text.is_empty() || text.contains('\0') {
            return Err(ValueError::MalformedPath);
        }
        let (anchor, rest) = split_anchor(text)?;
        let mut segments = Vec::new();
        // An anchor on its own -- `${WORKSPACE}`, `~`, `/` -- is the anchor
        // with nothing below it, and `"".split('/')` would otherwise yield one
        // empty segment and be refused as malformed.
        if !rest.is_empty() {
            for segment in rest.split('/') {
                if !is_path_segment(segment) {
                    // Also catches a doubled or trailing separator, which
                    // splits to an empty segment. `/etc//shadow` and
                    // `/etc/shadow/` are the same path as `/etc/shadow` to an
                    // operating system and a different string to a comparison,
                    // so the fail-closed reading refuses rather than
                    // normalises.
                    return Err(ValueError::MalformedPath);
                }
                segments.push(segment.to_owned());
            }
        }
        if segments.len() > limits::MAX_PATH_SEGMENTS {
            return Err(ValueError::MalformedPath);
        }
        Ok(Self { anchor, segments })
    }

    /// The symbolic root.
    #[must_use]
    pub const fn anchor(&self) -> PathAnchor {
        self.anchor
    }

    /// The segments below it.
    #[must_use]
    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    /// Whether `candidate` lies under this path.
    ///
    /// **Component-wise containment, never `starts_with` on a string.** The
    /// prefix is the anchor's own components followed by this path's segments,
    /// and a candidate matches when its components begin with that whole
    /// sequence. So `${WORKSPACE}` covers `/workspace/src/main.rs` and does not
    /// cover `/workspaceX`, which is a directory an attacker can create.
    ///
    /// # Errors
    ///
    /// The anchor, if the context does not say what it resolves to. The caller
    /// turns that into a denial rather than into "did not match": a deny rule
    /// whose anchor is missing must not quietly stop denying.
    pub fn contains(
        &self,
        anchors: &PathAnchors,
        candidate: &CanonicalPath,
    ) -> Result<bool, PathAnchor> {
        let root: &[_] = match self.anchor {
            // Not "missing": the filesystem root is the empty prefix, and
            // every canonical path begins with it.
            PathAnchor::Absolute => &[],
            other => anchors.get(other).ok_or(other)?.components(),
        };
        let components = candidate.components();
        if components.len() < root.len() + self.segments.len() {
            return Ok(false);
        }
        let under_root = components
            .iter()
            .zip(root.iter())
            .all(|(actual, expected)| actual == expected);
        if !under_root {
            return Ok(false);
        }
        let below = components.iter().skip(root.len());
        Ok(below
            .zip(self.segments.iter())
            .all(|(actual, expected)| actual.as_str() == expected))
    }
}

impl fmt::Display for RulePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(anchor) = self.anchor.as_str() {
            f.write_str(anchor)?;
        }
        for segment in &self.segments {
            write!(f, "/{segment}")?;
        }
        if self.segments.is_empty() && self.anchor == PathAnchor::Absolute {
            f.write_str("/")?;
        }
        Ok(())
    }
}

/// Split the anchor off the front, returning it and the remaining path body
/// with no leading separator.
fn split_anchor(text: &str) -> Result<(PathAnchor, &str), ValueError> {
    if let Some(rest) = text.strip_prefix("${") {
        let Some((symbol, rest)) = rest.split_once('}') else {
            return Err(ValueError::UnknownPathAnchor);
        };
        let full = format!("${{{symbol}}}");
        let anchor = PathAnchor::SYMBOLIC
            .into_iter()
            .find(|a| a.as_str() == Some(full.as_str()))
            .ok_or(ValueError::UnknownPathAnchor)?;
        return Ok((anchor, strip_separator(rest)?));
    }
    if let Some(rest) = text.strip_prefix('~') {
        return Ok((PathAnchor::Home, strip_separator(rest)?));
    }
    match text.strip_prefix('/') {
        Some(rest) => Ok((PathAnchor::Absolute, rest)),
        // Neither anchored nor absolute. A relative rule-side path has no
        // meaning: there is nothing for it to be relative *to* that is not one
        // of the anchors.
        None => Err(ValueError::MalformedPath),
    }
}

/// After an anchor, either nothing or a `/`-separated body.
fn strip_separator(rest: &str) -> Result<&str, ValueError> {
    if rest.is_empty() {
        return Ok("");
    }
    rest.strip_prefix('/').ok_or(ValueError::MalformedPath)
}

/// Whether a segment is one a canonical path could contain.
///
/// The same rule `PathComponent::new` applies, restated here because this side
/// is a *declaration* and cannot borrow the other side's constructor — nothing
/// outside `crate::resource` may call it ([ADR-0037]). The duplication is
/// deliberate and the two are tested against each other.
///
/// [ADR-0037]: ../../../../../docs/adr/0037-capability-specifications-and-canonical-authority-identities.md
fn is_path_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment.len() <= 255
        && !segment.contains('/')
        && !segment.contains('\\')
        && !segment.contains('\0')
}

/// A rule-side executable.
///
/// [`POLICY.md`] §3: `executable_in` is "name or (path, hash) membership", so
/// there are three spellings and each compares against a different part of the
/// resolved identity.
///
/// [`POLICY.md`]: ../../../../../docs/POLICY.md
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExecutableSpec {
    /// A bare name such as `git`, compared against the **final component** of
    /// the resolved path.
    ///
    /// Weaker than the other two, and deliberately so: it is what
    /// `allow-known-tools` is written with, and it is why that rule also
    /// carries `when.environment = "sandbox"`. Inside an execution environment
    /// the filesystem is the one the profile built; on the host, a name says
    /// much less than a path, and a profile allowlisting bare names for host
    /// execution would be trusting `$PATH` — which is why `power.toml` pins
    /// full paths where it permits host execution at all.
    Name(String),
    /// A full path, compared against the whole resolved path.
    Path(RulePath),
    /// A path and a digest, compared against the whole identity.
    ///
    /// The strongest form: `/usr/bin/git` before and after a package update
    /// are two different authorities, which is the property the hash is there
    /// to give.
    Pinned {
        /// Where it must be.
        path: RulePath,
        /// Sixty-four lowercase hex characters.
        digest: String,
    },
}

impl ExecutableSpec {
    /// Parse `name`, `/path`, `${ANCHOR}/path` or `<path>@<64 hex>`.
    ///
    /// # Errors
    ///
    /// [`ValueError::MalformedPath`] for a malformed path or digest, and
    /// [`ValueError::UnknownPathAnchor`] for an anchor outside the set.
    pub fn parse(text: &str) -> Result<Self, ValueError> {
        if let Some((path, digest)) = text.rsplit_once('@') {
            if !is_sha256_hex(digest) {
                return Err(ValueError::MalformedPath);
            }
            return Ok(Self::Pinned {
                path: RulePath::parse(path)?,
                digest: digest.to_owned(),
            });
        }
        if text.starts_with('/') || text.starts_with("${") || text.starts_with('~') {
            return Ok(Self::Path(RulePath::parse(text)?));
        }
        if !is_path_segment(text) {
            return Err(ValueError::MalformedPath);
        }
        Ok(Self::Name(text.to_owned()))
    }

    /// Whether this specification names `candidate`.
    ///
    /// # Errors
    ///
    /// The anchor, if the context does not resolve it.
    pub fn matches(
        &self,
        anchors: &PathAnchors,
        candidate: &ExecutableIdentity,
    ) -> Result<bool, PathAnchor> {
        match self {
            Self::Name(name) => Ok(candidate
                .path()
                .components()
                .last()
                .is_some_and(|component| component.as_str() == name)),
            // Equality, not containment: `executable_in` names executables,
            // and a rule listing `/usr/bin` must not thereby permit everything
            // under it.
            Self::Path(path) => Ok(path.is_exactly(anchors, candidate.path())?),
            Self::Pinned { path, digest } => Ok(path.is_exactly(anchors, candidate.path())?
                && candidate.digest().to_string() == *digest),
        }
    }
}

impl RulePath {
    /// Whether `candidate` *is* this path, rather than lying under it.
    ///
    /// # Errors
    ///
    /// The anchor, if the context does not resolve it.
    pub fn is_exactly(
        &self,
        anchors: &PathAnchors,
        candidate: &CanonicalPath,
    ) -> Result<bool, PathAnchor> {
        let root: &[_] = match self.anchor {
            PathAnchor::Absolute => &[],
            other => anchors.get(other).ok_or(other)?.components(),
        };
        let components = candidate.components();
        if components.len() == root.len() + self.segments.len() {
            self.contains(anchors, candidate)
        } else {
            Ok(false)
        }
    }
}

impl fmt::Display for ExecutableSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => f.write_str(name),
            Self::Path(path) => write!(f, "{path}"),
            Self::Pinned { path, digest } => write!(f, "{path}@{digest}"),
        }
    }
}

/// Whether a string is sixty-four lowercase hex characters.
///
/// Uppercase is refused for the reason `Sha256Digest::parse_hex` refuses it:
/// one digest, one spelling, so a rule and an audit record cannot disagree
/// about whether they name the same binary.
fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// An address range, as an address and a prefix length.
///
/// Compared against addresses somebody else resolved. There is no lookup here
/// and no `std::net`: see [`IpAddress`] for why the policy core holds octets
/// rather than the standard library's networking types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cidr {
    network: IpAddress,
    prefix: u32,
}

impl Cidr {
    /// Parse `<address>/<prefix>`.
    ///
    /// The prefix bound is per family and exact: `0..=32` for IPv4 and
    /// `0..=128` for IPv6. `10.0.0.0/33` is refused rather than clamped, and a
    /// clamped prefix would be a *wider* range than the author wrote.
    ///
    /// # Errors
    ///
    /// [`ValueError::MalformedCidr`] for anything that is not exactly that.
    pub fn parse(text: &str) -> Result<Self, ValueError> {
        let Some((address, prefix)) = text.split_once('/') else {
            return Err(ValueError::MalformedCidr);
        };
        if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ValueError::MalformedCidr);
        }
        let prefix: u32 = prefix.parse().map_err(|_| ValueError::MalformedCidr)?;
        let network = parse_address(address)?;
        if prefix > network.bits() {
            return Err(ValueError::MalformedCidr);
        }
        // A network address with host bits set names a range whose first
        // address is not the one written, so `10.0.0.1/24` would silently mean
        // `10.0.0.0/24`. Refusing it keeps one range to one spelling.
        if !host_bits_clear(&network, prefix) {
            return Err(ValueError::MalformedCidr);
        }
        Ok(Self { network, prefix })
    }

    /// The network address.
    #[must_use]
    pub const fn network(&self) -> IpAddress {
        self.network
    }

    /// The prefix length, in bits.
    #[must_use]
    pub const fn prefix(&self) -> u32 {
        self.prefix
    }

    /// Whether `address` lies in this range.
    ///
    /// An address of the other family never does: a v4 address is not in a v6
    /// range, and nothing here maps between them. `::ffff:10.0.0.1` and
    /// `10.0.0.1` are different values to this comparison, which is the
    /// fail-closed direction — a rule permitting a v4 range must not thereby
    /// permit a v4-mapped v6 address nobody reviewed.
    #[must_use]
    pub fn contains(&self, address: &IpAddress) -> bool {
        let (network, candidate) = (self.network.octets(), address.octets());
        if network.len() != candidate.len() {
            return false;
        }
        let (whole, remainder) = split_prefix(self.prefix);
        if network.iter().take(whole).ne(candidate.iter().take(whole)) {
            return false;
        }
        if remainder == 0 {
            return true;
        }
        // The high `remainder` bits of the next octet. `1u8 << 8` would be
        // undefined, which is why the zero case returns above.
        let mask = 0xFFu8 << (8 - remainder);
        match (network.get(whole), candidate.get(whole)) {
            (Some(a), Some(b)) => a & mask == b & mask,
            _ => true,
        }
    }
}

/// A prefix length as (whole octets, leftover bits).
///
/// One place for the division, so the two callers cannot disagree about it,
/// and one place for the conversion: a prefix is at most 128, so it always
/// fits, and `try_from` says that rather than `as` assuming it.
#[expect(
    clippy::integer_division,
    reason = "splitting a bit count into whole bytes and a remainder is what \
              integer division is; the remainder is the other half of the pair"
)]
fn split_prefix(prefix: u32) -> (usize, u32) {
    let whole = usize::try_from(prefix / 8).unwrap_or(usize::MAX);
    (whole, prefix % 8)
}

/// Whether every bit below the prefix is zero.
fn host_bits_clear(address: &IpAddress, prefix: u32) -> bool {
    let octets = address.octets();
    let (whole, remainder) = split_prefix(prefix);
    if remainder != 0 {
        let mask = 0xFFu8 << (8 - remainder);
        if octets.get(whole).is_some_and(|byte| byte & !mask != 0) {
            return false;
        }
    }
    let tail = if remainder == 0 { whole } else { whole + 1 };
    octets.iter().skip(tail).all(|byte| *byte == 0)
}

/// Parse a dotted-quad or a full or elided IPv6 address.
fn parse_address(text: &str) -> Result<IpAddress, ValueError> {
    if text.contains(':') {
        return parse_v6(text).map(IpAddress::V6);
    }
    let mut octets = [0u8; 4];
    let mut count = 0;
    for part in text.split('.') {
        let Some(slot) = octets.get_mut(count) else {
            return Err(ValueError::MalformedCidr);
        };
        *slot = parse_octet(part)?;
        count += 1;
    }
    if count == 4 {
        Ok(IpAddress::V4(octets))
    } else {
        Err(ValueError::MalformedCidr)
    }
}

/// One decimal octet, with no leading zero.
///
/// `010` is refused: it reads as 8 in some parsers and 10 in others, and an
/// address range whose meaning depends on the reader is not a range.
fn parse_octet(part: &str) -> Result<u8, ValueError> {
    if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ValueError::MalformedCidr);
    }
    if part.len() > 1 && part.starts_with('0') {
        return Err(ValueError::MalformedCidr);
    }
    part.parse().map_err(|_| ValueError::MalformedCidr)
}

/// Parse an IPv6 address in **full form**: eight groups, lowercase hex.
///
/// `::` elision is deliberately not accepted. It gives one address several
/// spellings, and the compression rules are a well-known source of parser
/// disagreement — two implementations that expand `::` differently are two
/// implementations that disagree about which range a rule names. The policy
/// file writes what [`IpAddress`]'s own `Display` produces, so a range in a
/// rule and a range in an audit record are the same string. The cost is
/// verbosity in a file an operator writes rarely, and the benefit is that this
/// parser is fifteen lines inside the trusted computing base.
fn parse_v6(text: &str) -> Result<[u8; 16], ValueError> {
    let mut octets = [0u8; 16];
    let mut groups = 0usize;
    for part in text.split(':') {
        let value = parse_v6_group(part)?;
        // Past the eighth group `get_mut` returns `None`, which is the length
        // check: nine groups is refused rather than written out of bounds.
        let Some(slot) = octets.get_mut(groups * 2..groups * 2 + 2) else {
            return Err(ValueError::MalformedCidr);
        };
        slot.copy_from_slice(&value.to_be_bytes());
        groups += 1;
    }
    if groups == 8 {
        Ok(octets)
    } else {
        Err(ValueError::MalformedCidr)
    }
}

/// One group of an IPv6 address: one to four lowercase hex digits.
///
/// Uppercase is refused for the same reason an uppercase digest is: one value,
/// one spelling.
fn parse_v6_group(part: &str) -> Result<u16, ValueError> {
    if part.is_empty() || part.len() > 4 {
        return Err(ValueError::MalformedCidr);
    }
    let mut value = 0u16;
    for byte in part.bytes() {
        let digit = match byte {
            b'0'..=b'9' => u16::from(byte - b'0'),
            b'a'..=b'f' => u16::from(byte - b'a') + 10,
            _ => return Err(ValueError::MalformedCidr),
        };
        value = value
            .checked_mul(16)
            .and_then(|v| v.checked_add(digit))
            .ok_or(ValueError::MalformedCidr)?;
    }
    Ok(value)
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}
