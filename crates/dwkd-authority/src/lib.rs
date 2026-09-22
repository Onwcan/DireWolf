//! `dwkd-authority` — the authority plane's library half.
//!
//! The binary ([`main.rs`](../main.rs)) serves nothing yet: there is no DWKP
//! server and no peer authentication until M3e. Its one working command,
//! `verify-audit`, is a read-only check of an audit chain.
//!
//! # What is here
//!
//! [`capability`] (M3b): the typed vocabulary of authority and the `⊑` lattice
//! over it. A capability is a specific, scoped, checkable permission, and the
//! invariant it exists to establish is:
//!
//! > **Child authority never exceeds parent authority.**
//!
//! [`policy`] (M3c): the deterministic, fail-closed decision function — "should
//! this be allowed?" — which is the other gate and never a substitute for the
//! first.
//!
//! [`state`] (M3d): the authority's durable memory — `kernel.db`, fenced
//! epochs and leases, run admission and minting, the kernel-owned policy
//! inputs, the stored policy revision, and the hash-chained `audit.log`
//! ([ADR-0039]). It calls the two pure cores; they never call it, and neither
//! links `rusqlite` (TX005).
//!
//! # What is not here
//!
//! No socket or peer identity (M3e): [`state`]'s callers assert who they are,
//! and in this build only tests call it. No brokered effect (M4+), no
//! approvals (M6).
//!
//! Above all, this crate resolves no resource. `fs` and `process` scopes name
//! resources whose authority identity is an inode and an executable hash;
//! deriving those from untrusted text is M4's job, and doing it badly is the
//! bug class [`capability::scope`] is shaped to prevent. Admission withholds
//! such a request rather than guessing.
//!
//! [`resource`] is where that shape lives, and it is the only module that may
//! **create** a canonical identity. Its constructors are `pub(in crate::resource)`,
//! so the lattice, the parser, M3c's policy engine and M3d's admission can all
//! hold one and none of them can mint one. M4's canonicaliser will be a
//! submodule there, and that is how it inherits the right.
//!
//! [ADR-0039]: ../../../docs/adr/0039-durable-authority-state.md

// Pedantic lints on the security crates, per docs/LANGUAGE_SELECTION.md §7.
#![warn(clippy::pedantic)]

pub mod capability;
pub mod policy;
pub mod resource;
pub mod state;

// Real-file scratch directories for unit tests, kept outside `state/` (TX006).
#[cfg(test)]
mod scratch;

// `proptest` is a dev-dependency used by the integration tests in `tests/`, not
// by the library. `unused_crate_dependencies` sees the manifest edge and not
// the test crates that consume it, so it is acknowledged here rather than
// silenced with an allow.
#[cfg(test)]
use proptest as _;
