//! `dwkd-authority` — the authority plane's library half.
//!
//! The binary ([`main.rs`](../main.rs)) is still a skeleton: there is no DWKP
//! server, no `kernel.db` and no policy engine. This library exists so the
//! parts of the authority that are *pure* — value semantics with no state, no
//! I/O and no clock — can be written, tested and reasoned about before the
//! daemon that will call them exists.
//!
//! # What is here (M3b)
//!
//! [`capability`]: the typed vocabulary of authority and the `⊑` lattice over
//! it. A capability is a specific, scoped, checkable permission, and the one
//! invariant this milestone exists to establish is:
//!
//! > **Child authority never exceeds parent authority.**
//!
//! # What is not here
//!
//! No policy evaluation (M3c), no persistence (M3d), no socket or peer
//! identity (M3e), no brokered effect (M4+), and no minting: a capability the
//! parser accepts is an *interpreted request*, never a grant. Granting needs
//! the agent profile, the skill set, the parent run and the profile ceiling,
//! and none of those exist yet.
//!
//! Above all, this crate resolves no resource. `fs` and `process` scopes name
//! resources whose authority identity is an inode and an executable hash;
//! deriving those from untrusted text is M4's job, and doing it badly is the
//! bug class [`capability::scope`] is shaped to prevent.
//!
//! [`resource`] is where that shape lives, and it is the only module that may
//! **create** a canonical identity. Its constructors are `pub(in crate::resource)`,
//! so the lattice, the parser, M3c's policy engine and M3d's admission can all
//! hold one and none of them can mint one. M4's canonicaliser will be a
//! submodule there, and that is how it inherits the right.

// Pedantic lints on the security crates, per docs/LANGUAGE_SELECTION.md §7.
#![warn(clippy::pedantic)]

pub mod capability;
pub mod policy;
pub mod resource;

// `proptest` is a dev-dependency used by the integration tests in `tests/`, not
// by the library. `unused_crate_dependencies` sees the manifest edge and not
// the test crates that consume it, so it is acknowledged here rather than
// silenced with an allow.
#[cfg(test)]
use proptest as _;
