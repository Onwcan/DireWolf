//! The canonical filesystem resolver (M4a,
//! [ADR-0042](../../../../../../docs/adr/0042-m4a-canonical-filesystem-resolution.md)).
//!
//! > **A path spelling is not authority.**
//! > **The object used later must be the object that was checked.**
//!
//! This module turns an untrusted [`DeclaredPath`] into a filesystem object the
//! authority may reason about, **without performing any tool effect**. It is
//! the only production code that does so; everything that needs a canonical
//! filesystem identity — admission, `ToolInvoke`, `CanonicalPreview`, policy
//! simulation — must come through here (M4b wires the first two).
//!
//! # Three different things, kept apart
//!
//! | what | type | used for |
//! |---|---|---|
//! | the policy/capability name | [`CanonicalPath`] | component-prefix containment (`fs.read:/workspace/src`) |
//! | the operating-system object | [`FileIdentity`] — `(device, inode)` from `fstat` of the **opened** object | proving object continuity |
//! | the live checked object | a [`ResolvedResource`]'s handle — an `O_PATH` descriptor | what M4b's broker operates on |
//!
//! An inode is a point, not a subtree, so containment stays a component-prefix
//! relation over names that were **verified** against the directory that holds
//! them; the identity proves that the object checked is the object later used.
//!
//! # The namespace
//!
//! A canonical `fs` path lives in DireWolf's **logical** namespace, not the
//! host's: `/workspace` names the run's workspace root — the directory the
//! operator bound to the session's workspace, pinned by identity — and every
//! further component is a name found beneath it. This is the path an agent
//! sees inside its execution environment ([`SANDBOX.md`] mounts the workspace
//! at `/workspace`), and the path capabilities and policy rules are written in.
//! **No other top-level name resolves in M4a**: a host-absolute spelling
//! (`/etc/hosts`, `/home/…`) is refused with [`PathError::OutsideWorkspace`],
//! never looked up.
//!
//! # The contract, in the order it is enforced
//!
//! 1. **Grammar** ([`PathError`]): `/workspace` first; no empty component (so
//!    no `//`, no trailing `/`), no `.` or `..`, no backslash, no control,
//!    bidi or invisible-format character, at most 255 bytes a component and 63
//!    components below the anchor, and every component **already NFC**. There
//!    is one spelling of each path, and nothing is rewritten.
//! 2. **The pinned root.** Resolution starts from a descriptor opened when the
//!    root was pinned and verified against the identity the operator installed
//!    ([`RootFingerprint`]). Nothing reopens the root by name during a
//!    resolution, and the process working directory is never consulted.
//! 3. **One component at a time**, each with `openat2(parent, name,
//!    O_PATH | O_NOFOLLOW, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
//!    RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV)` relative to the previous
//!    component's descriptor. A symlink, a magic link, a mount point or an
//!    escape is refused by the kernel, not by string inspection.
//! 4. **The name is verified against its directory.** The parent is listed and
//!    must contain an entry whose bytes are exactly the requested name — which
//!    refuses case-folding and normalisation-insensitive aliases — and **no
//!    other entry that is canonically equivalent to it**
//!    ([`ResolveError::NormalizationAmbiguity`]).
//! 5. **The object is classified from its own descriptor** (`fstat`, never a
//!    stat of a path): a directory or a regular file; anything else is refused.
//! 6. **The chain is re-verified** from the leaf up: every name still binds to
//!    the object that was opened. A rename or swap anywhere in the chain during
//!    resolution is [`ResolveError::Race`].
//! 7. **The access is judged** ([`Access`]): a regular file with more than one
//!    hard link cannot be *modified* through the workspace, because the change
//!    would reach every other name for the same inode.
//!
//! # What this module does not do
//!
//! It performs no read, write, listing, execution or other tool effect. It
//! hands descriptors out only by **consuming** a checked resource into a
//! handoff, each with one fixed role, and only the broker link can take a
//! descriptor out of a handoff (TX014):
//!
//! | handoff | descriptor | for |
//! |---|---|---|
//! | [`ReadHandoff`] (M4b) | the regular file, open for reading | `fs.read`, `fs.search`, `fs.patch`'s base |
//! | [`ObjectHandoff`] | the object, `O_PATH`; or the directory, open for reading | `fs.stat`; `fs.list` |
//! | [`ParentHandoff`] | the parent directory, open for reading, and one validated name | `fs.write`, `fs.patch`, `fs.move`, `fs.delete` |
//!
//! A **vacant** name — one that does not exist yet, which a creating
//! `fs.write` or a move's destination names — is resolved by
//! [`PinnedRoot::resolve_target`] into a [`VacantResource`]: a checked parent
//! directory, a validated name, and proof that nothing, not even a
//! canonically equivalent spelling, occupies it (M4c, ADR-0044 §6). It is a
//! different type from a [`ResolvedResource`], so code cannot treat "absent"
//! as "the object that was checked". It writes no audit record — resolution is
//! an internal step of a decision, not an effect ([ADR-0027]). It does not
//! read `kernel.db`: the state layer loads the operator's root binding and
//! calls in (TX005, TX011). Only Linux is supported; elsewhere every call
//! refuses with [`ResolveError::Unsupported`] or [`RootError::Unsupported`].
//!
//! [`SANDBOX.md`]: ../../../../../../docs/SANDBOX.md
//! [ADR-0027]: ../../../../../../docs/adr/0027-audit-scope-boundary.md

mod grammar;
mod names;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as imp;

#[cfg(not(target_os = "linux"))]
mod unsupported;
#[cfg(not(target_os = "linux"))]
use unsupported as imp;

#[cfg(test)]
mod tests;

use core::fmt;

/// One component, by the same name checker a workspace path's components pass
/// (NFC, no control, bidi or invisible character, at most `NAME_MAX`): the
/// executable resolver's grammar for host names (M4d, ADR-0045).
pub(in crate::resource) use grammar::single_component;
pub use grammar::{MAX_DEPTH, PathError};

use super::{CanonicalPath, PathComponent};
use crate::capability::DeclaredPath;

/// The first component of every canonical workspace path: `/workspace` is the
/// run's pinned workspace root.
pub const WORKSPACE_ANCHOR: &str = "workspace";

/// The longest host path an operator may bind as a workspace root: `PATH_MAX`.
pub const MAX_ROOT_PATH_BYTES: usize = 4096;

/// A filesystem object's identity: the device and inode of the **opened**
/// object, from `fstat` of its descriptor.
///
/// There is no public constructor. A value exists only because this module
/// opened an object and asked the kernel what it was.
///
/// ```compile_fail
/// // Not from invented numbers.
/// use dwkd_authority::resource::fs::FileIdentity;
/// let _ = FileIdentity::new(1, 2);
/// ```
///
/// ```compile_fail
/// // Nor by naming its fields.
/// use dwkd_authority::resource::fs::FileIdentity;
/// let _ = FileIdentity { device: 1, inode: 2 };
/// ```
///
/// ```
/// // What a holder may do with one.
/// use dwkd_authority::resource::fs::FileIdentity;
/// fn show(i: FileIdentity) -> (u64, u64, String) { (i.device(), i.inode(), i.to_string()) }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    #[cfg_attr(
        not(target_os = "linux"),
        expect(dead_code, reason = "only the Linux resolver observes an identity")
    )]
    pub(in crate::resource) const fn new(device: u64, inode: u64) -> Self {
        Self { device, inode }
    }

    /// The device, as `st_dev`.
    #[must_use]
    pub const fn device(self) -> u64 {
        self.device
    }

    /// The inode, as `st_ino`.
    #[must_use]
    pub const fn inode(self) -> u64 {
        self.inode
    }
}

impl fmt::Display for FileIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.device, self.inode)
    }
}

/// A root directory's birth time, where the filesystem reports one (`statx`
/// `STATX_BTIME`). Recorded with a root binding so that a directory recreated
/// at the same path and handed the same, recycled inode number is still told
/// apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BirthTime {
    /// Seconds since the epoch.
    pub seconds: i64,
    /// Nanoseconds, below 1 000 000 000.
    pub nanoseconds: u32,
}

/// What an operator's workspace root was when it was installed: the value the
/// state layer records in `kernel.db` and hands back when the root is opened
/// again.
///
/// **An expectation, not an identity.** Anyone may build one from numbers,
/// and holding one grants nothing: [`PinnedRoot`] is produced only by opening
/// the directory and finding that it **is** this — device, inode and, where
/// recorded, birth time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootFingerprint {
    device: u64,
    inode: u64,
    birth: Option<BirthTime>,
}

impl RootFingerprint {
    /// An expectation, as recorded.
    #[must_use]
    pub const fn new(device: u64, inode: u64, birth: Option<BirthTime>) -> Self {
        Self {
            device,
            inode,
            birth,
        }
    }

    /// The device recorded at installation.
    #[must_use]
    pub const fn device(&self) -> u64 {
        self.device
    }

    /// The inode recorded at installation.
    #[must_use]
    pub const fn inode(&self) -> u64 {
        self.inode
    }

    /// The birth time recorded at installation, if the filesystem gave one.
    #[must_use]
    pub const fn birth(&self) -> Option<BirthTime> {
        self.birth
    }

    /// Whether an opened directory is the one this records. A recorded birth
    /// time must match; a missing one on either side is not a match for a
    /// recorded one.
    fn matches(&self, found: &Self) -> bool {
        self.device == found.device
            && self.inode == found.inode
            && match self.birth {
                None => true,
                Some(recorded) => found.birth == Some(recorded),
            }
    }
}

/// What the caller intends to do with the object — which decides whether a
/// hard-linked file is acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Access {
    /// Read, list or inspect. The object is the object at the verified name,
    /// however many names it has.
    Observe,
    /// Write, create beneath, delete, rename or change. A regular file with
    /// more than one hard link is refused: the change would be visible through
    /// every other name, including names outside the workspace.
    Modify,
}

/// What kind of object the caller needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Expect {
    /// A directory or a regular file.
    Any,
    /// A directory.
    Directory,
    /// A regular file.
    RegularFile,
}

/// The kinds of object the resolver returns. Everything else — a symlink,
/// FIFO, socket, device or an unknown type — is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceKind {
    /// A directory.
    Directory,
    /// A regular file.
    RegularFile,
}

impl ResourceKind {
    /// A stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::RegularFile => "regular-file",
        }
    }
}

/// How a resolution was performed. One value today, named so that a reduced
/// mechanism can never be mistaken for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Assurance {
    /// Linux `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
    /// RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV`, one component at a time from
    /// the pinned root, names verified against their directories, the chain
    /// re-verified. There is no fallback.
    LinuxOpenat2,
}

impl Assurance {
    /// A stable spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LinuxOpenat2 => "linux-openat2",
        }
    }
}

/// A live descriptor this module opened and checked. Never cloned, never
/// handed out, never rendered.
pub(in crate::resource) struct Handle(imp::Fd);

impl fmt::Debug for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Handle(..)")
    }
}

/// A workspace root, open and verified: the anchor every resolution starts
/// from.
///
/// Opened from the operator's recorded path **once** and then used only by
/// descriptor: renaming the directory away and putting another at its old
/// path does not redirect a root that is already pinned, and pinning again
/// through the replaced path fails with [`RootError::Replaced`].
///
/// Not `Clone`: duplicating the descriptor would extend its authority's
/// lifetime without anyone deciding to.
///
/// ```compile_fail
/// // No constructor is reachable from outside the crate.
/// use dwkd_authority::resource::fs::PinnedRoot;
/// let _ = PinnedRoot::install("/srv/project");
/// ```
///
/// ```compile_fail
/// // Nor by naming its fields.
/// use dwkd_authority::resource::fs::PinnedRoot;
/// fn forge(p: PinnedRoot) -> PinnedRoot { PinnedRoot { ..p } }
/// ```
pub struct PinnedRoot {
    handle: Handle,
    identity: FileIdentity,
}

impl fmt::Debug for PinnedRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedRoot")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl PinnedRoot {
    /// Open a directory the operator is binding as a workspace root, and
    /// measure what it is. The state layer's installation path.
    ///
    /// # Errors
    ///
    /// [`RootError`] when the path is not an absolute, bounded, NUL-free host
    /// path; does not name a directory; names a symlink; is on procfs or sysfs;
    /// or cannot be opened. [`RootError::Unsupported`] off Linux.
    pub(crate) fn install(host_path: &str) -> Result<(Self, RootFingerprint), RootError> {
        check_host_path(host_path)?;
        let (fd, identity, fingerprint) = imp::open_root(host_path)?;
        Ok((
            Self {
                handle: Handle(fd),
                identity,
            },
            fingerprint,
        ))
    }

    /// Open a bound root again and prove it is the directory that was
    /// installed. The state layer's pinning path.
    ///
    /// # Errors
    ///
    /// [`RootError::Replaced`] when the path now names a different directory —
    /// including a same-numbered one with a different birth time — and every
    /// error [`PinnedRoot::install`] can return.
    pub(crate) fn reopen(host_path: &str, expected: &RootFingerprint) -> Result<Self, RootError> {
        looked_up();
        let (root, found) = Self::install(host_path)?;
        if expected.matches(&found) {
            Ok(root)
        } else {
            Err(RootError::Replaced)
        }
    }

    /// The pinned directory's identity.
    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// `${WORKSPACE}` in canonical form: `/workspace`, the anchor every path
    /// resolved under this root hangs from.
    #[must_use]
    pub fn anchor(&self) -> CanonicalPath {
        workspace_anchor()
    }

    /// Resolve a declared path beneath this root.
    ///
    /// # Errors
    ///
    /// [`ResolveError`], naming the class of refusal and the depth at which it
    /// happened. Never the text of a name.
    pub fn resolve(
        &self,
        declared: &DeclaredPath,
        access: Access,
        expect: Expect,
    ) -> Result<ResolvedResource, ResolveError> {
        looked_up();
        let path = grammar::parse(declared).map_err(ResolveError::Path)?;
        let walked = imp::walk(&self.handle.0, self.identity, path.components())?;
        judge(walked.kind, walked.links, access, expect)?;
        Ok(ResolvedResource {
            canonical: path.canonical(),
            identity: walked.identity,
            kind: walked.kind,
            links: walked.links,
            root: self.identity,
            leaf: Handle(walked.leaf),
            parent: walked.parent.map(|(fd, name)| (Handle(fd), name)),
        })
    }
}

impl PinnedRoot {
    /// Resolve a declared path beneath this root where a **vacant** name is
    /// acceptable (M4c): a creating `fs.write`, a move's destination, a
    /// capability that may name what does not exist yet. An existing object is
    /// resolved exactly as [`PinnedRoot::resolve`] would, with `access` and
    /// `expect`; a vacant name is proved vacant ([`VacantResource`]).
    ///
    /// `/workspace` itself is never vacant.
    ///
    /// # Errors
    ///
    /// As [`PinnedRoot::resolve`], and — for a vacant name — the parent's
    /// refusals, [`ResolveError::NormalizationAmbiguity`] when an existing
    /// entry is canonically equivalent to it, and [`ResolveError::Race`] when
    /// it appears while being proved vacant.
    pub fn resolve_target(
        &self,
        declared: &DeclaredPath,
        access: Access,
        expect: Expect,
    ) -> Result<Target, ResolveError> {
        looked_up();
        let path = grammar::parse(declared).map_err(ResolveError::Path)?;
        let Some((leaf, parents)) = path.components().split_last() else {
            return self.resolve(declared, access, expect).map(Target::Existing);
        };
        match imp::probe_vacant(&self.handle.0, self.identity, parents, leaf)? {
            Probe::Exists => self.resolve(declared, access, expect).map(Target::Existing),
            Probe::Vacant {
                parent,
                parent_identity,
                guard,
            } => Ok(Target::Vacant(VacantResource {
                canonical: path.canonical(),
                parent: Handle(parent),
                parent_identity,
                guard: guard.map(|(fd, name)| (Handle(fd), name)),
                leaf: leaf.clone(),
                root: self.identity,
            })),
        }
    }
}

/// Classify the names a listing found (M4c, ADR-0044 §6): `true` for a name a
/// canonical path can name — UTF-8, one component the grammar accepts (NFC,
/// no control, bidi or invisible-format character, at most 255 bytes, not `.`
/// or `..`), and not canonically equivalent to another name in the listing —
/// and `false` for one it cannot. A name the grammar refuses is never
/// converted to one it accepts: it is counted, not rewritten.
#[must_use]
pub fn addressable_names(names: &[&[u8]]) -> Vec<bool> {
    let texts: Vec<Option<&str>> = names
        .iter()
        .map(|bytes| {
            let text = core::str::from_utf8(bytes).ok()?;
            grammar::single_component(text).ok().map(|_| text)
        })
        .collect();
    texts
        .iter()
        .enumerate()
        .map(|(index, text)| {
            text.is_some_and(|name| {
                // Ambiguous if any other examined name, UTF-8 or not, would
                // normalise to it.
                !names.iter().enumerate().any(|(other, bytes)| {
                    other != index
                        && core::str::from_utf8(bytes)
                            .is_ok_and(|sibling| names::equivalent(sibling, name))
                })
            })
        })
        .collect()
}

/// `${WORKSPACE}`: the canonical path `/workspace`.
///
/// For the state layer, which records that a run's workspace has a bound root
/// and fills the policy context's workspace anchor from it; nothing else may
/// name this module (TX011).
#[must_use]
pub(crate) fn workspace_anchor() -> CanonicalPath {
    grammar::LogicalPath::root().canonical()
}

/// The canonical path a **stored** grant's text spells, by the grammar alone —
/// without looking at any filesystem (M4b, ADR-0043).
///
/// **Only for re-reading what the authority itself already resolved and
/// wrote to `kernel.db`**: a grant minted from a path [`PinnedRoot::resolve`]
/// canonicalised, re-read after a restart or for a replay. It is the grammar
/// the resolver starts with, and the grammar never rewrites, so the stored
/// text reads back to exactly the path that was resolved.
///
/// **Never for a new declaration.** A declared path becomes authority only
/// through [`PinnedRoot::resolve`], where the filesystem supplies its meaning:
/// that it exists, crosses no symlink, magic link or mount, and is not
/// ambiguous under normalisation. One module may name this function (TX017).
///
/// # Errors
///
/// [`PathError`] for every spelling that is not one canonical workspace path.
pub(crate) fn stored_canonical_path(declared: &DeclaredPath) -> Result<CanonicalPath, PathError> {
    grammar::parse(declared).map(|path| path.canonical())
}

/// The accept/refuse decision that depends on intent, applied after the object
/// is known.
fn judge(
    kind: ResourceKind,
    links: u64,
    access: Access,
    expect: Expect,
) -> Result<(), ResolveError> {
    match (expect, kind) {
        (Expect::Directory, ResourceKind::RegularFile)
        | (Expect::RegularFile, ResourceKind::Directory) => {
            return Err(ResolveError::WrongKind { found: kind });
        }
        _ => {}
    }
    if access == Access::Modify && kind == ResourceKind::RegularFile && links > 1 {
        return Err(ResolveError::HardlinkAliased { links });
    }
    Ok(())
}

/// What the platform walk found. Internal: the public result is
/// [`ResolvedResource`].
pub(in crate::resource) struct Walked {
    pub(in crate::resource) identity: FileIdentity,
    pub(in crate::resource) kind: ResourceKind,
    pub(in crate::resource) links: u64,
    pub(in crate::resource) leaf: imp::Fd,
    pub(in crate::resource) parent: Option<(imp::Fd, PathComponent)>,
}

/// What [`imp::probe_vacant`] found. Internal. Off Linux nothing is found.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(in crate::resource) enum Probe {
    /// Something is there: resolve it the ordinary way.
    Exists,
    /// Nothing is there, and the parent was held and checked.
    Vacant {
        /// The parent directory, `O_PATH`.
        parent: imp::Fd,
        /// Its identity.
        parent_identity: FileIdentity,
        /// Where the parent was found, to re-check it still binds there.
        guard: Option<(imp::Fd, PathComponent)>,
    },
}

/// What a declared path names beneath the pinned root when a vacant name is
/// acceptable: an object that exists, or a name that does not — **two types**,
/// so that "nothing was there" can never be used as "the object that was
/// checked", and an object that appears in a vacant name is never mistaken
/// for one that was authorised.
#[derive(Debug)]
pub enum Target {
    /// An object exists at the name and was resolved.
    Existing(ResolvedResource),
    /// Nothing exists at the name; its parent does.
    Vacant(VacantResource),
}

#[cfg(test)]
thread_local! {
    /// Filesystem lookups this thread has begun: see [`lookups_on_this_thread`].
    static LOOKUPS: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

/// Count a filesystem lookup — in this crate's unit tests; nothing in any
/// other build.
#[cfg_attr(not(test), allow(clippy::missing_const_for_fn))]
fn looked_up() {
    #[cfg(test)]
    LOOKUPS.with(|count| count.set(count.get().saturating_add(1)));
}

/// How many filesystem lookups this thread has begun: every re-pinning of a
/// bound workspace root, and every resolution beneath one. **Test
/// observation, not an interface**: `#[cfg(test)]`, so it exists only in this
/// crate's unit tests, where it proves that a path which must not consult the
/// filesystem — an admission replay, a stored grant re-read — begins no lookup
/// at all (ADR-0044 §6; `state/lookup_tests.rs`), rather than inferring it
/// from an answer that happened not to change.
#[cfg(test)]
pub(crate) fn lookups_on_this_thread() -> u64 {
    LOOKUPS.with(core::cell::Cell::get)
}

/// A name that does not exist yet, beneath a checked parent directory (M4c,
/// ADR-0044 §6).
///
/// What it proves, at resolution: the parent resolved beneath the pinned root
/// as a directory, one component at a time, like any other object; the name
/// is one canonical component — valid, NFC, bounded; nothing is found at the
/// name; **no other entry in the parent is canonically equivalent to it**; and
/// the parent still binds where it was found. Its canonical path is the
/// parent's canonical path and the name — derived from what was checked, not
/// from the declaration's spelling.
///
/// Absence is re-proved before the name is handed on
/// ([`VacantResource::into_parent_handoff`]), and the broker creates with
/// `RENAME_NOREPLACE`, so an object that appears in the name meanwhile is
/// never replaced.
///
/// ```compile_fail
/// // Not constructible by naming its fields.
/// use dwkd_authority::resource::fs::VacantResource;
/// fn forge(v: VacantResource) -> VacantResource { VacantResource { ..v } }
/// ```
pub struct VacantResource {
    canonical: CanonicalPath,
    parent: Handle,
    parent_identity: FileIdentity,
    guard: Option<(Handle, PathComponent)>,
    leaf: PathComponent,
    root: FileIdentity,
}

impl fmt::Debug for VacantResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VacantResource")
            .field("canonical", &self.canonical)
            .field("parent_identity", &self.parent_identity)
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl VacantResource {
    /// The canonical path the name would have: the checked parent's, and the
    /// validated name.
    #[must_use]
    pub const fn canonical_path(&self) -> &CanonicalPath {
        &self.canonical
    }

    /// The parent directory's identity.
    #[must_use]
    pub const fn parent_identity(&self) -> FileIdentity {
        self.parent_identity
    }

    /// The validated name, in the parent.
    #[must_use]
    pub fn leaf_name(&self) -> &str {
        self.leaf.as_str()
    }

    /// The pinned root it was resolved beneath.
    #[must_use]
    pub const fn root_identity(&self) -> FileIdentity {
        self.root
    }

    /// How it was resolved.
    #[must_use]
    pub const fn assurance(&self) -> Assurance {
        Assurance::LinuxOpenat2
    }

    /// Hand the parent on for creating the name: the parent directory, opened
    /// for reading relative to the held descriptor and proved to be the one
    /// checked, after re-proving that the name is still vacant and the parent
    /// still where it was found.
    ///
    /// # Errors
    ///
    /// [`ResolveError::Race`] when the name is occupied now or the parent
    /// moved; the open's own refusals.
    pub fn into_parent_handoff(self) -> Result<ParentHandoff, ResolveError> {
        let Self {
            canonical,
            parent,
            parent_identity,
            guard,
            leaf,
            root,
        } = self;
        imp::still_vacant(
            &parent.0,
            parent_identity,
            guard.as_ref().map(|(handle, name)| (&handle.0, name)),
            &leaf,
        )?;
        let directory = imp::open_directory(&parent.0, parent_identity)?;
        Ok(ParentHandoff {
            directory: Handle(directory),
            directory_identity: parent_identity,
            leaf,
            target: None,
            canonical,
            root,
        })
    }
}

/// A declared path, resolved: the canonical name policy and capabilities
/// compare, the identity of the object that was opened, and the live, checked
/// descriptor for it.
///
/// **Nothing here is a path to reopen.** The canonical name is for
/// comparison; the object is the descriptor. M4b's broker receives the checked
/// object — or reopens the leaf **relative to the retained parent descriptor**
/// and proves, by identity, that it is the same object — and never opens the
/// canonical name again ([ADR-0042] §9).
///
/// Not `Clone`, for the same reason as [`PinnedRoot`], and its `Debug` shows
/// no descriptor.
///
/// ```compile_fail
/// // Not constructible by naming its fields.
/// use dwkd_authority::resource::fs::ResolvedResource;
/// fn forge(r: ResolvedResource) -> ResolvedResource { ResolvedResource { ..r } }
/// ```
///
/// ```compile_fail
/// // Not duplicable.
/// use dwkd_authority::resource::fs::ResolvedResource;
/// fn twice(r: &ResolvedResource) -> ResolvedResource { r.clone() }
/// ```
///
/// [ADR-0042]: ../../../../../../docs/adr/0042-m4a-canonical-filesystem-resolution.md
pub struct ResolvedResource {
    canonical: CanonicalPath,
    identity: FileIdentity,
    kind: ResourceKind,
    links: u64,
    root: FileIdentity,
    leaf: Handle,
    parent: Option<(Handle, PathComponent)>,
}

impl fmt::Debug for ResolvedResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedResource")
            .field("canonical", &self.canonical)
            .field("identity", &self.identity)
            .field("kind", &self.kind)
            .field("links", &self.links)
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl ResolvedResource {
    /// The canonical path — what capability containment and `path_under`
    /// compare, component by component.
    #[must_use]
    pub const fn canonical_path(&self) -> &CanonicalPath {
        &self.canonical
    }

    /// The identity of the opened object.
    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// Directory or regular file.
    #[must_use]
    pub const fn kind(&self) -> ResourceKind {
        self.kind
    }

    /// The hard-link count the opened object reported.
    #[must_use]
    pub const fn link_count(&self) -> u64 {
        self.links
    }

    /// The pinned root it was resolved beneath.
    #[must_use]
    pub const fn root_identity(&self) -> FileIdentity {
        self.root
    }

    /// How it was resolved.
    #[must_use]
    pub const fn assurance(&self) -> Assurance {
        Assurance::LinuxOpenat2
    }

    /// Whether the checked object is still the one its name binds to: the
    /// retained descriptor still refers to the identity that was checked, and
    /// the name in the retained parent still refers to it. The continuity
    /// check an effect path runs immediately before acting (M4b).
    ///
    /// # Errors
    ///
    /// [`ResolveError::Race`] when the name was renamed away, replaced or
    /// swapped since resolution.
    pub fn still_bound(&self) -> Result<(), ResolveError> {
        imp::still_bound(
            &self.leaf.0,
            self.parent.as_ref().map(|(handle, name)| (&handle.0, name)),
            self.identity,
        )
    }

    /// Whether this is the workspace root itself, which has no parent in the
    /// workspace and so cannot be written, moved or removed.
    #[must_use]
    pub const fn is_workspace_root(&self) -> bool {
        self.parent.is_none()
    }

    /// The verified name of the object in its parent — `None` for the
    /// workspace root.
    #[must_use]
    pub fn leaf_name(&self) -> Option<&str> {
        self.parent.as_ref().map(|(_, name)| name.as_str())
    }

    /// The identity of the parent directory the object was found in, from
    /// the held descriptor: the directory whose name would change.
    ///
    /// # Errors
    ///
    /// [`ResolveError::WrongKind`] for the workspace root, which has no
    /// parent; the `fstat`'s own failure.
    pub fn parent_identity(&self) -> Result<FileIdentity, ResolveError> {
        match &self.parent {
            Some((parent, _)) => imp::held_identity(&parent.0),
            None => Err(ResolveError::WrongKind { found: self.kind }),
        }
    }

    /// Hand the object on for `fs.stat`: its own `O_PATH` descriptor, which
    /// can name the object and nothing more — no read, no write, no
    /// enumeration — after re-proving the name still binds it.
    ///
    /// # Errors
    ///
    /// [`ResolveError::Race`] when the name no longer binds it.
    pub fn into_stat_handoff(self) -> Result<ObjectHandoff, ResolveError> {
        self.still_bound()?;
        Ok(ObjectHandoff {
            handle: self.leaf,
            identity: self.identity,
            kind: self.kind,
            role: HandoffRole::Stat,
            canonical: self.canonical,
            root: self.root,
        })
    }

    /// Hand a checked directory on for `fs.list`: the directory opened for
    /// reading relative to its own held descriptor and proved to be it. Not
    /// its parent, not the workspace root.
    ///
    /// # Errors
    ///
    /// [`ResolveError::WrongKind`] for a regular file; [`ResolveError::Race`]
    /// when the name no longer binds it; the open's own refusals.
    pub fn into_list_handoff(self) -> Result<ObjectHandoff, ResolveError> {
        if self.kind != ResourceKind::Directory {
            return Err(ResolveError::WrongKind { found: self.kind });
        }
        self.still_bound()?;
        let directory = imp::open_directory(&self.leaf.0, self.identity)?;
        Ok(ObjectHandoff {
            handle: Handle(directory),
            identity: self.identity,
            kind: self.kind,
            role: HandoffRole::List,
            canonical: self.canonical,
            root: self.root,
        })
    }

    /// Hand the object's **name** on, for replacing or removing it: its parent
    /// directory opened for reading and proved to be the parent that was
    /// checked, the one validated name, and the identity and kind the name
    /// must still bind. Namespace operations act on a name in a directory, so
    /// the object's own descriptor is not what they need.
    ///
    /// # Errors
    ///
    /// [`ResolveError::WrongKind`] for the workspace root, which has no
    /// parent; [`ResolveError::Race`] when the name no longer binds it.
    pub fn into_parent_handoff(self) -> Result<ParentHandoff, ResolveError> {
        self.still_bound()?;
        let Self {
            canonical,
            identity,
            kind,
            links: _,
            root,
            leaf: _,
            parent,
        } = self;
        let Some((parent, name)) = parent else {
            return Err(ResolveError::WrongKind { found: kind });
        };
        let parent_identity = imp::held_identity(&parent.0)?;
        let directory = imp::open_directory(&parent.0, parent_identity)?;
        Ok(ParentHandoff {
            directory: Handle(directory),
            directory_identity: parent_identity,
            leaf: name,
            target: Some((identity, kind)),
            canonical,
            root,
        })
    }

    /// Hand a checked regular file on for `fs.patch`: its parent, as
    /// [`ResolvedResource::into_parent_handoff`], and the file itself opened
    /// for reading, as [`ResolvedResource::into_read_handoff`] — the broker
    /// hashes the base through it and needs no permission to read the file
    /// itself.
    ///
    /// # Errors
    ///
    /// As the two handoffs.
    pub fn into_patch_handoff(self) -> Result<(ParentHandoff, ReadHandoff), ResolveError> {
        let Self {
            canonical,
            identity,
            kind,
            links: _,
            root,
            leaf,
            parent,
        } = self;
        if kind != ResourceKind::RegularFile {
            return Err(ResolveError::WrongKind { found: kind });
        }
        let Some((parent, name)) = parent else {
            return Err(ResolveError::WrongKind { found: kind });
        };
        let readable = imp::open_for_read(&leaf.0, &parent.0, &name, identity)?;
        let parent_identity = imp::held_identity(&parent.0)?;
        let directory = imp::open_directory(&parent.0, parent_identity)?;
        Ok((
            ParentHandoff {
                directory: Handle(directory),
                directory_identity: parent_identity,
                leaf: name,
                target: Some((identity, kind)),
                canonical: canonical.clone(),
                root,
            },
            ReadHandoff {
                file: Handle(readable),
                identity,
                canonical,
                root,
            },
        ))
    }

    /// Turn a checked regular file into the one thing an `fs.read` hands the
    /// broker: the file opened for reading, proved to be this object
    /// (M4b, ADR-0043).
    ///
    /// **Consumes the resource.** The `O_PATH` descriptors on the leaf and its
    /// parent are closed when this returns; what survives is one readable
    /// descriptor on one file. The name binding is re-checked, the file is
    /// opened relative to the retained parent by its verified name, and the
    /// opened file's own identity must be the checked one — never the
    /// canonical path, never the host root, never the process working
    /// directory.
    ///
    /// # Errors
    ///
    /// [`ResolveError::WrongKind`] for anything but a regular file,
    /// [`ResolveError::Race`] when the name no longer binds to the checked
    /// object or the file opened is another, and the open's own refusals.
    pub fn into_read_handoff(self) -> Result<ReadHandoff, ResolveError> {
        let Self {
            canonical,
            identity,
            kind,
            links: _,
            root,
            leaf,
            parent,
        } = self;
        if kind != ResourceKind::RegularFile {
            return Err(ResolveError::WrongKind { found: kind });
        }
        let Some((parent, name)) = parent else {
            return Err(ResolveError::WrongKind { found: kind });
        };
        let readable = imp::open_for_read(&leaf.0, &parent.0, &name, identity)?;
        Ok(ReadHandoff {
            file: Handle(readable),
            identity,
            canonical,
            root,
        })
    }
}

/// A regular file opened **for reading**, proved to be the object the
/// authority checked — the only descriptor an `fs.read` gives the broker
/// (M4b, ADR-0043).
///
/// One file, not the directory it is in and not the workspace root: the least
/// descriptor authority a read needs. Not `Clone`; its `Debug` shows no
/// descriptor; and the descriptor comes out only through a crate-private
/// method that one module — the broker channel — may call (TX014). Nothing in
/// the public API can obtain it.
///
/// ```compile_fail
/// // Not constructible by naming its fields.
/// use dwkd_authority::resource::fs::ReadHandoff;
/// fn forge(h: ReadHandoff) -> ReadHandoff { ReadHandoff { ..h } }
/// ```
///
/// ```compile_fail
/// // Not duplicable.
/// use dwkd_authority::resource::fs::ReadHandoff;
/// fn twice(h: &ReadHandoff) -> ReadHandoff { h.clone() }
/// ```
///
/// ```compile_fail
/// // The descriptor is not reachable from outside the crate.
/// use dwkd_authority::resource::fs::ReadHandoff;
/// fn steal(h: ReadHandoff) { let _ = h.into_transfer_descriptor(); }
/// ```
pub struct ReadHandoff {
    #[cfg_attr(
        not(target_os = "linux"),
        expect(
            dead_code,
            reason = "the descriptor leaves only through the Linux broker link"
        )
    )]
    file: Handle,
    identity: FileIdentity,
    canonical: CanonicalPath,
    root: FileIdentity,
}

impl fmt::Debug for ReadHandoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadHandoff")
            .field("canonical", &self.canonical)
            .field("identity", &self.identity)
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl ReadHandoff {
    /// The identity of the file, as checked and as re-proved on opening.
    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// The canonical path it was resolved at.
    #[must_use]
    pub const fn canonical_path(&self) -> &CanonicalPath {
        &self.canonical
    }

    /// The pinned root it was resolved beneath.
    #[must_use]
    pub const fn root_identity(&self) -> FileIdentity {
        self.root
    }

    /// Give up the readable descriptor, for sending to the broker. **Only the
    /// broker channel may call this** (TX014): it is the one place a checked
    /// descriptor leaves the authority, and it leaves by `SCM_RIGHTS`, never
    /// as a path or a number.
    #[cfg(target_os = "linux")]
    pub(crate) fn into_transfer_descriptor(self) -> (std::os::fd::OwnedFd, FileIdentity) {
        (self.file.0, self.identity)
    }
}

/// What an [`ObjectHandoff`]'s descriptor is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffRole {
    /// `fs.stat`: the object, `O_PATH`.
    Stat,
    /// `fs.list`: the directory, open for reading.
    List,
}

/// A checked object handed on by its own descriptor (M4c): `O_PATH` for
/// `fs.stat`, or a directory open for reading for `fs.list`. Not `Clone`; no
/// descriptor in its `Debug`; the descriptor leaves only through the broker
/// link (TX014).
pub struct ObjectHandoff {
    #[cfg_attr(
        not(target_os = "linux"),
        expect(
            dead_code,
            reason = "the descriptor leaves only through the Linux broker link"
        )
    )]
    handle: Handle,
    identity: FileIdentity,
    kind: ResourceKind,
    role: HandoffRole,
    canonical: CanonicalPath,
    root: FileIdentity,
}

impl fmt::Debug for ObjectHandoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectHandoff")
            .field("canonical", &self.canonical)
            .field("identity", &self.identity)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

impl ObjectHandoff {
    /// The object's identity.
    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// Directory or regular file.
    #[must_use]
    pub const fn kind(&self) -> ResourceKind {
        self.kind
    }

    /// What the descriptor is for.
    #[must_use]
    pub const fn role(&self) -> HandoffRole {
        self.role
    }

    /// The canonical path it was resolved at.
    #[must_use]
    pub const fn canonical_path(&self) -> &CanonicalPath {
        &self.canonical
    }

    /// The pinned root it was resolved beneath.
    #[must_use]
    pub const fn root_identity(&self) -> FileIdentity {
        self.root
    }

    /// Give up the descriptor, for sending to the broker. **Only the broker
    /// channel may call this** (TX014).
    #[cfg(target_os = "linux")]
    pub(crate) fn into_transfer_descriptor(self) -> (std::os::fd::OwnedFd, FileIdentity) {
        (self.handle.0, self.identity)
    }
}

/// A name handed on by its checked parent directory (M4c, ADR-0044 §8): the
/// directory, open for reading and proved to be the parent that was checked;
/// **one** validated name component in it; and, for an existing object, the
/// identity and kind the name must still bind when the broker acts. What a
/// namespace operation needs, and no more: not the object's own descriptor,
/// not the workspace root, never a path.
pub struct ParentHandoff {
    #[cfg_attr(
        not(target_os = "linux"),
        expect(
            dead_code,
            reason = "the descriptor leaves only through the Linux broker link"
        )
    )]
    directory: Handle,
    directory_identity: FileIdentity,
    leaf: PathComponent,
    target: Option<(FileIdentity, ResourceKind)>,
    canonical: CanonicalPath,
    root: FileIdentity,
}

impl fmt::Debug for ParentHandoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParentHandoff")
            .field("canonical", &self.canonical)
            .field("directory_identity", &self.directory_identity)
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl ParentHandoff {
    /// The parent directory's identity.
    #[must_use]
    pub const fn directory_identity(&self) -> FileIdentity {
        self.directory_identity
    }

    /// The one name, as the canonical grammar accepted it.
    #[must_use]
    pub fn leaf_name(&self) -> &str {
        self.leaf.as_str()
    }

    /// The object the name must bind, or `None` for a vacant name.
    #[must_use]
    pub const fn target(&self) -> Option<(FileIdentity, ResourceKind)> {
        self.target
    }

    /// The canonical path of the name.
    #[must_use]
    pub const fn canonical_path(&self) -> &CanonicalPath {
        &self.canonical
    }

    /// The pinned root it was resolved beneath.
    #[must_use]
    pub const fn root_identity(&self) -> FileIdentity {
        self.root
    }

    /// Give up the directory descriptor, for sending to the broker. **Only
    /// the broker channel may call this** (TX014).
    #[cfg(target_os = "linux")]
    pub(crate) fn into_transfer_descriptor(self) -> (std::os::fd::OwnedFd, FileIdentity) {
        (self.directory.0, self.directory_identity)
    }
}

/// Validate a host path before anything opens it.
fn check_host_path(host_path: &str) -> Result<(), RootError> {
    if host_path.contains('\0') {
        return Err(RootError::Nul);
    }
    if host_path.len() > MAX_ROOT_PATH_BYTES {
        return Err(RootError::TooLong);
    }
    if !host_path.starts_with('/') {
        return Err(RootError::NotAbsolute);
    }
    Ok(())
}

/// Why a workspace root could not be pinned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RootError {
    /// The path is not absolute. A relative root would mean whatever the
    /// working directory makes it mean.
    NotAbsolute,
    /// Longer than [`MAX_ROOT_PATH_BYTES`].
    TooLong,
    /// Contains a NUL byte.
    Nul,
    /// Nothing exists at the path.
    Missing,
    /// The path names something that is not a directory.
    NotADirectory,
    /// The path's final component is a symlink. A root is a directory, not a
    /// pointer to one.
    Symlink,
    /// The directory is on procfs or sysfs, whose entries are not files.
    UnsupportedFilesystem,
    /// The path now names a directory other than the one installed.
    Replaced,
    /// The authority may not open it.
    PermissionDenied,
    /// This platform has no resolver.
    Unsupported,
    /// Another operating-system error, by number.
    Io(i32),
}

impl RootError {
    /// A stable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotAbsolute => "ROOT_NOT_ABSOLUTE",
            Self::TooLong => "ROOT_TOO_LONG",
            Self::Nul => "ROOT_NUL",
            Self::Missing => "ROOT_MISSING",
            Self::NotADirectory => "ROOT_NOT_A_DIRECTORY",
            Self::Symlink => "ROOT_SYMLINK",
            Self::UnsupportedFilesystem => "ROOT_UNSUPPORTED_FILESYSTEM",
            Self::Replaced => "ROOT_REPLACED",
            Self::PermissionDenied => "ROOT_PERMISSION_DENIED",
            Self::Unsupported => "UNSUPPORTED_PLATFORM",
            Self::Io(_) => "ROOT_IO",
        }
    }
}

impl fmt::Display for RootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(errno) => write!(f, "{} (errno {errno})", self.code()),
            _ => f.write_str(self.code()),
        }
    }
}

impl std::error::Error for RootError {}

/// Why a declared path did not resolve.
///
/// A bounded class and, where it applies, the **depth** — the 1-based index of
/// the component below `/workspace` where resolution stopped. Never the text of
/// a name: a hostile name must not reach a log, an audit record or a reason
/// through an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResolveError {
    /// The declaration is not a canonical path spelling.
    Path(PathError),
    /// No entry by that name.
    NotFound {
        /// Where.
        depth: usize,
    },
    /// An intermediate component is not a directory.
    NotADirectory {
        /// Where.
        depth: usize,
    },
    /// A component is a symlink. Refused, never followed.
    Symlink {
        /// Where.
        depth: usize,
    },
    /// A component is a procfs magic link (`/proc/<pid>/cwd`, `…/root`,
    /// `…/fd/N`). Refused, never followed.
    MagicLink {
        /// Where.
        depth: usize,
    },
    /// A component is a mount point, or resolution would cross into another
    /// mount.
    MountCrossing {
        /// Where.
        depth: usize,
    },
    /// The directory holds no entry spelled exactly like the requested name:
    /// the filesystem matched another spelling (case folding, normalisation
    /// insensitivity).
    NameMismatch {
        /// Where.
        depth: usize,
    },
    /// The directory holds another entry that is canonically equivalent to the
    /// requested name. Two objects share one canonical spelling, so neither
    /// can be named.
    NormalizationAmbiguity {
        /// Where.
        depth: usize,
    },
    /// The object is a FIFO, socket, device or of unknown type.
    SpecialFile {
        /// Where.
        depth: usize,
    },
    /// The object is not the kind the caller required.
    WrongKind {
        /// What it is.
        found: ResourceKind,
    },
    /// A regular file with more than one hard link, requested for
    /// modification.
    HardlinkAliased {
        /// Its link count.
        links: u64,
    },
    /// A name stopped binding to the object opened for it while resolution was
    /// in progress: a rename, replacement or swap.
    Race {
        /// Where.
        depth: usize,
    },
    /// The authority may not traverse or list a directory on the path.
    PermissionDenied {
        /// Where.
        depth: usize,
    },
    /// A directory on the path has more entries than one resolution will list.
    DirectoryTooLarge {
        /// Where.
        depth: usize,
    },
    /// This platform or kernel cannot resolve with the required guarantees:
    /// not Linux, a kernel before 5.6, or `openat2` filtered out.
    Unsupported,
    /// Another operating-system error, by number.
    Io {
        /// Where.
        depth: usize,
        /// The error number, for diagnostics only.
        errno: i32,
    },
}

impl ResolveError {
    /// A stable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Path(error) => error.code(),
            Self::NotFound { .. } => "NOT_FOUND",
            Self::NotADirectory { .. } => "NOT_A_DIRECTORY",
            Self::Symlink { .. } => "SYMLINK",
            Self::MagicLink { .. } => "MAGIC_LINK",
            Self::MountCrossing { .. } => "MOUNT_CROSSING",
            Self::NameMismatch { .. } => "NAME_MISMATCH",
            Self::NormalizationAmbiguity { .. } => "NORMALIZATION_AMBIGUITY",
            Self::SpecialFile { .. } => "SPECIAL_FILE",
            Self::WrongKind { .. } => "WRONG_KIND",
            Self::HardlinkAliased { .. } => "HARDLINK_ALIASED",
            Self::Race { .. } => "RACE",
            Self::PermissionDenied { .. } => "PERMISSION_DENIED",
            Self::DirectoryTooLarge { .. } => "DIRECTORY_TOO_LARGE",
            Self::Unsupported => "UNSUPPORTED_PLATFORM",
            Self::Io { .. } => "IO",
        }
    }
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Path(error) => write!(f, "{error}"),
            Self::NotFound { depth }
            | Self::NotADirectory { depth }
            | Self::Symlink { depth }
            | Self::MagicLink { depth }
            | Self::MountCrossing { depth }
            | Self::NameMismatch { depth }
            | Self::NormalizationAmbiguity { depth }
            | Self::SpecialFile { depth }
            | Self::Race { depth }
            | Self::PermissionDenied { depth }
            | Self::DirectoryTooLarge { depth } => {
                write!(f, "{} at component {depth}", self.code())
            }
            Self::WrongKind { found } => write!(f, "{}: found a {}", self.code(), found.as_str()),
            Self::HardlinkAliased { links } => write!(f, "{}: {links} links", self.code()),
            Self::Unsupported => f.write_str(self.code()),
            Self::Io { depth, errno } => {
                write!(f, "{} at component {depth} (errno {errno})", self.code())
            }
        }
    }
}

impl std::error::Error for ResolveError {}
