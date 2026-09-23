//! Canonical resource identities, and the module that alone may create them.
//!
//! # Why this is its own module
//!
//! [`CAPABILITIES.md`] §2 defines `fs` containment as a path prefix "**after**
//! canonicalisation to inode identity + NFC normalisation. **Never a string
//! prefix on raw input**", and an executable as `(resolved path, sha256)`. Those
//! are facts about the machine, obtained by `openat2` with symlinks refused, by
//! pinning the inode that was checked, and by hashing the file that was actually
//! opened. All of that is M4.
//!
//! [ADR-0037](../../../../../docs/adr/0037-capability-specifications-and-canonical-authority-identities.md)
//! therefore separates a capability as *declared* from a capability authority is
//! *compared with*. The first version of that split relied on `CanonicalPath`
//! having no constructor taking a path string — which stopped an accident, and
//! did not stop a caller who assembled the components by hand and presented the
//! result as if a resolver had produced it.
//!
//! This module closes that. **Every constructor of a canonical identity is
//! `pub(in crate::resource)`**, so:
//!
//! | caller | can construct? |
//! |---|---|
//! | `crate::capability` (the lattice, the parser, `CapabilitySpec`) | no |
//! | M3c's policy engine, M3d's admission and audit — any sibling module | no |
//! | another crate, including the daemon binary | no |
//! | a future `crate::resource::…` submodule — **M4's canonicaliser** | yes |
//!
//! `pub(crate)` would not have been enough: it is exactly the visibility that
//! lets M3c mint a path because it happens to live in the same crate.
//!
//! # The construction path, once M4 exists
//!
//! ```text
//! raw request spelling            "fs.read:/workspace"
//!   │                             (DeclaredPath — text somebody sent)
//!   ▼
//! M4 resource canonicaliser       crate::resource::<M4 module>
//!   │                             openat2 / RESOLVE_NO_SYMLINKS, fallback
//!   │                             walker, inode pinning, TOCTOU re-check,
//!   ▼                             executable hashing, NFC from the OS
//! private construction            CanonicalPath / ExecutableIdentity
//!   │                             (the constructors below — in-module only)
//!   ▼
//! M3b capability lattice          Scope::Path / Scope::Executable, compared
//! ```
//!
//! M3b owns the opaque value and its comparison semantics. **M4 owns the right
//! to create one.** Nothing between them may forge one.
//!
//! # The resolver (M4a)
//!
//! [`fs`] is that canonicaliser for filesystem paths
//! ([ADR-0042](../../../../../docs/adr/0042-m4a-canonical-filesystem-resolution.md)):
//! a workspace root pinned by identity, `openat2` one component at a time with
//! symlinks, magic links, mount crossings and escapes refused by the kernel,
//! every name verified against the directory that holds it, and the chain
//! re-verified. It is the first production code to construct a
//! [`PathComponent`] and a [`CanonicalPath`], and it does so as a submodule, so
//! the constructors below stay `pub(in crate::resource)`.
//!
//! The executable half — `(resolved path, sha256)` — is M4d's; nothing
//! constructs an [`ExecutableIdentity`] yet.
//!
//! # What this module deliberately does not do
//!
//! This file touches no filesystem; the I/O lives in [`fs`], and only there.
//! TX003 covers `capability/`, TX005 keeps the store out of everything here,
//! and TX011 lets only `crate::state` name the resolver.
//!
//! [`CAPABILITIES.md`]: ../../../../../docs/CAPABILITIES.md

pub mod fs;

use core::fmt;

/// One component of a canonical path: a single directory or file name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathComponent(String);

impl PathComponent {
    /// The longest component. `NAME_MAX` on Linux and macOS.
    pub const MAX_BYTES: usize = 255;

    /// A single name. Rejects the empty string, `.`, `..`, anything containing
    /// a separator or a NUL, and anything over `NAME_MAX`.
    ///
    /// The traversal names are rejected because a canonical path has already
    /// had them resolved away: a `..` in a *canonical* path is a contradiction,
    /// and accepting one would let a caller write a path that compares as a
    /// prefix but does not name the directory it appears to.
    ///
    /// **Visibility is the control.** In-module only, so nothing outside
    /// `crate::resource` can make one. Its production caller is the M4a
    /// resolver's grammar ([`fs`]), which accepts a name only after stricter
    /// checks of its own (NFC, no control or bidi characters).
    pub(in crate::resource) fn new(name: &str) -> Option<Self> {
        let ok = !name.is_empty()
            && name != "."
            && name != ".."
            && name.len() <= Self::MAX_BYTES
            && !name.contains('/')
            && !name.contains('\\')
            && !name.contains('\0');
        ok.then(|| Self(name.to_owned()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A canonical filesystem path: the identity a resolver produced.
///
/// **There is no way for production code outside `crate::resource` to build
/// one**, and that absence is the control. No `from_str`, no `From<&Path>`, no
/// `Default` — and [`CanonicalPath::from_components`], the real constructor, is
/// visible only inside this module, where M4a's canonicaliser, [`fs`], lives.
///
/// Containment is component-wise, so `/workspace` covers `/workspace/src` and
/// does not cover `/workspaceX`: the string-prefix bug is unrepresentable
/// rather than merely untested.
///
/// ```compile_fail
/// // An ordinary caller cannot assemble one from components.
/// use dwkd_authority::capability::CanonicalPath;
/// let _ = CanonicalPath::from_components(&["workspace", "src"]);
/// ```
///
/// ```compile_fail
/// // Nor from a string, by any spelling: there is no such constructor.
/// use dwkd_authority::capability::CanonicalPath;
/// let _: CanonicalPath = "/workspace".parse().unwrap();
/// ```
///
/// ```compile_fail
/// // Nor from a std::path::Path.
/// use dwkd_authority::capability::CanonicalPath;
/// let _ = CanonicalPath::from(std::path::Path::new("/workspace"));
/// ```
///
/// ```compile_fail
/// // Nor by naming the private field.
/// use dwkd_authority::capability::CanonicalPath;
/// let _ = CanonicalPath { components: Vec::new() };
/// ```
///
/// ```compile_fail
/// // Nor by `Default`, which is deliberately not derived: it would be a
/// // public constructor for the root, which covers every path there is.
/// use dwkd_authority::capability::CanonicalPath;
/// let _ = CanonicalPath::default();
/// ```
///
/// The positive counterpart, so none of the five above can pass for the wrong
/// reason: the path resolves, the type is public, and what a holder may do with
/// one compiles.
///
/// ```
/// use dwkd_authority::capability::CanonicalPath;
/// fn depth(p: &CanonicalPath) -> usize { p.components().len() }
/// fn covers(a: &CanonicalPath, b: &CanonicalPath) -> bool { a.contains(b) }
/// fn show(p: &CanonicalPath) -> String { p.to_string() }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalPath {
    components: Vec<PathComponent>,
}

impl CanonicalPath {
    /// The deepest path. A bound on work, not a security property.
    pub const MAX_COMPONENTS: usize = 64;

    /// The filesystem root, `/`. Covers every canonical path — which is why it
    /// is in-module only, like every other way to make one.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no production caller: M4a's resolver names nothing above /workspace"
        )
    )]
    pub(in crate::resource) fn root() -> Self {
        Self {
            components: Vec::new(),
        }
    }

    /// Build from already-resolved components, root first.
    ///
    /// Returns `None` if any component is not a valid name or the path is too
    /// deep. The caller is asserting these components came from a resolver; the
    /// type cannot check that claim, so **visibility decides who may make it**,
    /// and the answer is this module and its descendants only.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no production caller: M4a's resolver assembles components it verified"
        )
    )]
    pub(in crate::resource) fn from_components<S: AsRef<str>>(components: &[S]) -> Option<Self> {
        if components.len() > Self::MAX_COMPONENTS {
            return None;
        }
        let mut out = Vec::with_capacity(components.len());
        for component in components {
            out.push(PathComponent::new(component.as_ref())?);
        }
        Some(Self { components: out })
    }

    /// The components, root first.
    #[must_use]
    pub fn components(&self) -> &[PathComponent] {
        &self.components
    }

    /// Whether `self` is a path-prefix of `other`, component by component.
    #[must_use]
    pub fn contains(&self, other: &Self) -> bool {
        other.components.len() >= self.components.len()
            && self
                .components
                .iter()
                .zip(other.components.iter())
                .all(|(a, b)| a == b)
    }
}

impl fmt::Display for CanonicalPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.components.is_empty() {
            return f.write_str("/");
        }
        for component in &self.components {
            write!(f, "/{}", component.as_str())?;
        }
        Ok(())
    }
}

/// A SHA-256 digest. Thirty-two bytes, and no opinion about what they hash.
///
/// Constructors are in-module for the same reason the rest are: a digest is
/// half of an executable's identity, and nothing in M3b's production code needs
/// to make one. M4 will, when it has hashed a file it opened.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// From raw bytes.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "M4's canonicaliser is the first caller")
    )]
    pub(in crate::resource) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// From sixty-four lowercase hex characters. Uppercase is refused: one
    /// digest, one spelling.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "M4's canonicaliser is the first caller")
    )]
    pub(in crate::resource) fn parse_hex(text: &str) -> Option<Self> {
        if text.len() != 64 {
            return None;
        }
        let mut bytes = [0u8; 32];
        let mut source = text.bytes();
        for byte in &mut bytes {
            let hi = source.next().and_then(hex_digit)?;
            let lo = source.next().and_then(hex_digit)?;
            *byte = hi * 16 + lo;
        }
        Some(Self(bytes))
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One lowercase hex digit, as a nibble. Operates on bytes: hex is ASCII by
/// definition, so there is no character to convert and no conversion to get
/// wrong.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "reached only through parse_hex")
)]
fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256Digest({self})")
    }
}

/// An executable's authority identity: where it resolved to, and what it was.
///
/// The hash is why the path alone is not enough. `/usr/bin/git` today and
/// `/usr/bin/git` after a package update are different programs, and a
/// capability granted for one must not carry over to the other. Containment is
/// therefore equality: an executable identity covers itself and nothing else.
///
/// Like [`CanonicalPath`], it cannot be built from outside this module.
///
/// ```compile_fail
/// // No constructor is reachable, whatever the caller already holds.
/// use dwkd_authority::capability::{ExecutableIdentity, CanonicalPath, Sha256Digest};
/// fn forge(path: CanonicalPath, digest: Sha256Digest) -> ExecutableIdentity {
///     ExecutableIdentity::new(path, digest)
/// }
/// ```
///
/// ```compile_fail
/// // Nor from a raw path and an invented digest.
/// use dwkd_authority::capability::{ExecutableIdentity, Sha256Digest};
/// let digest = Sha256Digest::from_bytes([0u8; 32]);
/// let _ = ExecutableIdentity::new("/usr/bin/git", digest);
/// ```
///
/// ```compile_fail
/// // Nor by naming the private fields.
/// use dwkd_authority::capability::{ExecutableIdentity, CanonicalPath, Sha256Digest};
/// fn forge(path: CanonicalPath, digest: Sha256Digest) -> ExecutableIdentity {
///     ExecutableIdentity { path, digest }
/// }
/// ```
///
/// The positive counterpart, for the same reason as [`CanonicalPath`]'s:
///
/// ```
/// use dwkd_authority::capability::{ExecutableIdentity, CanonicalPath, Sha256Digest};
/// fn where_it_is(e: &ExecutableIdentity) -> &CanonicalPath { e.path() }
/// fn what_it_was(e: &ExecutableIdentity) -> &Sha256Digest { e.digest() }
/// fn show(e: &ExecutableIdentity) -> String { e.to_string() }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExecutableIdentity {
    path: CanonicalPath,
    digest: Sha256Digest,
}

impl ExecutableIdentity {
    /// Pair a resolved path with the hash of what was found there. In-module
    /// only: pairing two values is exactly the forgery this visibility stops.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "M4's canonicaliser is the first caller")
    )]
    pub(in crate::resource) const fn new(path: CanonicalPath, digest: Sha256Digest) -> Self {
        Self { path, digest }
    }

    /// Where it resolved to.
    #[must_use]
    pub const fn path(&self) -> &CanonicalPath {
        &self.path
    }

    /// What was there.
    #[must_use]
    pub const fn digest(&self) -> &Sha256Digest {
        &self.digest
    }
}

impl fmt::Display for ExecutableIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.path, self.digest)
    }
}

// ---------------------------------------------------------------------------
// Test-only construction.
// ---------------------------------------------------------------------------

/// Invented identities, for testing the lattice over the shape M4 will produce.
///
/// **`#[cfg(test)]`, so it does not exist in a production build** — not a
/// feature that could be switched on, not a `#[doc(hidden)] pub` somebody could
/// find, and not reachable from an integration test either, because an
/// integration test links the library compiled without `cfg(test)`. The tests
/// that need these values are therefore unit tests, which is where they belong:
/// they are about a type whose construction is private.
///
/// Everything here is **synthetic**. It shows the comparison is right given an
/// identity. It shows nothing whatever about deriving one from a real resource,
/// which is M4's and does not exist.
#[cfg(test)]
pub(crate) mod synthetic {
    use super::{CanonicalPath, ExecutableIdentity, Sha256Digest};

    /// A synthetic canonical path from components.
    pub(crate) fn path(components: &[&str]) -> Option<CanonicalPath> {
        CanonicalPath::from_components(components)
    }

    /// The root, `/`.
    pub(crate) fn root() -> CanonicalPath {
        CanonicalPath::root()
    }

    /// A digest of one repeated byte. Distinct `fill` values are distinct
    /// binaries; nothing was hashed.
    pub(crate) fn digest(fill: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([fill; 32])
    }

    /// A synthetic executable identity.
    pub(crate) fn executable(components: &[&str], fill: u8) -> Option<ExecutableIdentity> {
        Some(ExecutableIdentity::new(path(components)?, digest(fill)))
    }
}

#[cfg(test)]
mod tests {
    use super::{CanonicalPath, PathComponent, Sha256Digest, synthetic};

    #[test]
    fn a_path_contains_its_descendants_and_not_its_string_neighbours() {
        // The whole reason containment is component-wise. `starts_with` says
        // `/workspace` covers `/workspaceX`; components say it does not, and
        // `/workspaceX` is a directory an attacker can create.
        let Some(parent) = synthetic::path(&["workspace"]) else {
            unreachable!("valid components")
        };
        for (child, expected) in [
            (vec!["workspace"], true),
            (vec!["workspace", "src"], true),
            (vec!["workspace", "src", "main.rs"], true),
            (vec!["workspaceX"], false),
            (vec!["workspace-other"], false),
            (vec!["workspace2", "src"], false),
            (vec!["etc"], false),
        ] {
            let Some(child) = synthetic::path(&child) else {
                unreachable!("valid components")
            };
            assert_eq!(parent.contains(&child), expected, "{parent} vs {child}");
        }
    }

    #[test]
    fn a_deeper_path_does_not_contain_its_ancestor() {
        let (Some(deep), Some(shallow)) = (
            synthetic::path(&["workspace", "src"]),
            synthetic::path(&["workspace"]),
        ) else {
            unreachable!("valid components")
        };
        assert!(shallow.contains(&deep));
        assert!(!deep.contains(&shallow));
    }

    #[test]
    fn the_root_contains_every_path() {
        let root = synthetic::root();
        for child in [vec![], vec!["etc"], vec!["workspace", "src", "deep"]] {
            let Some(child) = synthetic::path(&child) else {
                unreachable!("valid components")
            };
            assert!(root.contains(&child), "{child}");
        }
        assert_eq!(root.to_string(), "/");
    }

    #[test]
    fn a_path_renders_component_wise() {
        let Some(p) = synthetic::path(&["workspace", "src"]) else {
            unreachable!("valid components")
        };
        assert_eq!(p.to_string(), "/workspace/src");
        assert_eq!(p.components().len(), 2);
    }

    #[test]
    fn traversal_and_separators_are_refused() {
        // A `..` in a canonical path is a contradiction, and a component
        // holding a separator is two components pretending to be one.
        for bad in ["", ".", "..", "a/b", "a\\b", "a\0b"] {
            assert!(PathComponent::new(bad).is_none(), "{bad:?}");
        }
        for bad in [vec![".."], vec!["workspace", "..", "etc"], vec![""]] {
            assert!(CanonicalPath::from_components(&bad).is_none(), "{bad:?}");
        }
        assert!(PathComponent::new("file.txt").is_some());
    }

    #[test]
    fn a_path_that_is_too_deep_is_refused_rather_than_truncated() {
        let deep: Vec<String> = (0..=CanonicalPath::MAX_COMPONENTS)
            .map(|i| format!("d{i}"))
            .collect();
        assert!(CanonicalPath::from_components(&deep).is_none());
        let ok: Vec<String> = (0..CanonicalPath::MAX_COMPONENTS)
            .map(|i| format!("d{i}"))
            .collect();
        assert!(CanonicalPath::from_components(&ok).is_some());
    }

    #[test]
    fn a_component_at_name_max_is_accepted_and_one_past_it_is_not() {
        let at = "n".repeat(PathComponent::MAX_BYTES);
        let past = "n".repeat(PathComponent::MAX_BYTES + 1);
        assert!(PathComponent::new(&at).is_some());
        assert!(PathComponent::new(&past).is_none());
    }

    #[test]
    fn an_executable_identity_is_both_halves_or_neither() {
        let (Some(git), Some(same), Some(updated), Some(moved)) = (
            synthetic::executable(&["usr", "bin", "git"], 0xAA),
            synthetic::executable(&["usr", "bin", "git"], 0xAA),
            synthetic::executable(&["usr", "bin", "git"], 0xBB),
            synthetic::executable(&["opt", "git"], 0xAA),
        ) else {
            unreachable!("valid components")
        };
        assert_eq!(git, same);
        // A package update is a different program.
        assert_ne!(git, updated);
        // And the same bytes somewhere else is a different authority.
        assert_ne!(git, moved);
        assert_eq!(git.path().to_string(), "/usr/bin/git");
    }

    #[test]
    fn a_digest_has_one_spelling() {
        let lower = "9f".repeat(32);
        assert_eq!(
            Sha256Digest::parse_hex(&lower).map(|d| d.to_string()),
            Some(lower)
        );
        for bad in [
            "9F".repeat(32),
            "9f".repeat(31),
            format!("{}g", "9f".repeat(31) + "9"),
        ] {
            assert!(Sha256Digest::parse_hex(&bad).is_none(), "{bad}");
        }
        assert_eq!(synthetic::digest(0).as_bytes(), &[0u8; 32]);
    }
}
