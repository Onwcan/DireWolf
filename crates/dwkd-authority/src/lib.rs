//! `dwkd-authority` — the authority plane's library half.
//!
//! The binary ([`main.rs`](../main.rs)) runs [`server`]: `dwkd-authority serve`
//! is the DWKP server on a Unix-domain socket, Linux only, admitting a peer
//! only after the kernel has reported its uid and the operator's peer policy
//! has named it. Its other command, `verify-audit`, is a read-only check of an
//! audit chain and runs everywhere.
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
//! [`server`] (M3e): the process boundary. It derives the subject from the
//! kernel (`SO_PEERCRED`), mints one lease holder per accepted connection,
//! requires a handshake before anything else, decodes every frame with
//! `dwk-proto`'s strict decoder, and hands each request to [`state`] unchanged
//! ([ADR-0041]). It decides nothing about authority itself.
//!
//! [`resource::fs`] (M4a): the canonical filesystem resolver — a declared
//! path, resolved beneath the run's operator-bound workspace root, pinned by
//! identity, with `openat2` relative to held descriptors, into a canonical
//! path, the opened object's identity and the checked descriptor; or refused
//! ([ADR-0042]). The state layer calls it; nothing else may (TX011).
//!
//! # What is not here
//!
//! No brokered effect (M4b+), no `ToolInvoke` or `CanonicalPreview` (reserved
//! until M4b), no executable resolution (M4d), no approvals (M6), no model
//! provider (M7).
//!
//! Above all, this crate performs no tool effect, and admission still resolves
//! no requested resource. `fs` and `process` scopes name resources whose
//! authority identity is an object and an executable hash; deriving those from
//! untrusted text badly is the bug class [`capability::scope`] is shaped to
//! prevent. M4a supplies the filesystem half of the derivation, and admission
//! keeps withholding such a request rather than guessing until M4b resolves
//! every term of a grant through it.
//!
//! [`resource`] is where that shape lives, and it is the only module that may
//! **create** a canonical identity. Its constructors are `pub(in crate::resource)`,
//! so the lattice, the parser, M3c's policy engine and M3d's admission can all
//! hold one and none of them can mint one. M4a's canonicaliser is a submodule
//! there, [`resource::fs`], and that is how it inherits the right.
//!
//! [ADR-0039]: ../../../docs/adr/0039-durable-authority-state.md
//! [ADR-0041]: ../../../docs/adr/0041-m3e-authenticated-dwkp-transport.md
//! [ADR-0042]: ../../../docs/adr/0042-m4a-canonical-filesystem-resolution.md

// Pedantic lints on the security crates, per docs/LANGUAGE_SELECTION.md §7.
#![warn(clippy::pedantic)]

pub mod capability;
pub mod policy;
pub mod resource;
pub mod server;
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
