//! Who is asking: an authenticated subject, and one live lease claimant.
//!
//! # Two identities, not one
//!
//! **[`AuthenticatedSubject`]** is the stable identity of a peer — on Unix, the
//! uid the kernel reports for the other end of the socket. It survives a
//! reconnect. It scopes `AdmitRun` idempotency ([ADR-0036] §8): a subject that
//! reconnects must still find the admission it already made.
//!
//! **[`LeaseHolder`]** is one specific live connection to *this* authority
//! process. It does not survive a reconnect, and it does not survive an
//! authority restart. It scopes the single-writer lease ([ADR-0011] point 2).
//!
//! They are different because the failure they guard against is different.
//! A retried process under the same uid is **not** evidence that it is the same
//! single writer: the old process may still be running, paused, or about to
//! wake. Handing it the live lease because "same uid" would put two writers
//! behind one fencing token, which is exactly the zombie-writer failure epoch
//! fencing exists to prevent. So a lease is held by a `LeaseHolder`, and a new
//! connection from the same subject is a new holder that has to wait for the
//! old lease to be released, to expire, or to be invalidated by a restart.
//!
//! # Where they come from — and where they do not
//!
//! **Neither is ever read from a DWKP message.** No envelope field, payload
//! field or string carries either, and none may ([ADR-0028]). The DWKP server
//! (`crate::server`, M3e, [ADR-0041]) derives the subject from the kernel's
//! peer credentials (`SO_PEERCRED`) for each accepted socket, before reading a
//! byte from it, and asks the authority for a holder exactly once per accepted
//! connection.
//!
//! **This module authenticates nobody itself.** An `AuthenticatedSubject` is a
//! trusted in-process value: whoever constructs one is asserting it. In the
//! server the assertion is the kernel's report; in the M3d state tests, which
//! call this module directly, it is the test's. The type is the right *shape*
//! for both; only the server's use of it is evidence that a peer was checked.
//!
//! A [`LeaseHolder`] cannot be constructed at all outside this module: the only
//! way to obtain one is [`Authority::connect`](super::Authority::connect),
//! which mints a fresh one bound to the current authority incarnation. Two
//! calls for the same subject yield two different holders.
//!
//! [ADR-0011]: ../../../../../docs/adr/0011-session-concurrency.md
//! [ADR-0028]: ../../../../../docs/adr/0028-policy-input-ownership.md
//! [ADR-0036]: ../../../../../docs/adr/0036-m3-authority-operations-and-the-capability-wire-form.md
//! [ADR-0041]: ../../../../../docs/adr/0041-m3e-authenticated-dwkp-transport.md

use core::fmt;

/// The stable identity of an authenticated peer.
///
/// A closed shape rather than a string: the only identity the M3e server
/// produces, on the one platform where it serves, is a Unix uid, and a
/// free-form string is the shape that would let "parse it from the request"
/// look reasonable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthenticatedSubject {
    uid: u32,
}

impl AuthenticatedSubject {
    /// The subject whose peer credentials report `uid`.
    ///
    /// **Trusted input.** Calling this asserts that `uid` came from the
    /// kernel's report about a real connection. The DWKP server's
    /// peer-credential gate is the production caller; the M3d state tests are
    /// the others.
    #[must_use]
    pub const fn unix_uid(uid: u32) -> Self {
        Self { uid }
    }

    /// The uid.
    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// The form stored in `kernel.db` and written to the audit log: `uid:N`.
    ///
    /// Not sensitive — a uid is not a secret — and not reversible into a
    /// subject by anything that reads it back: the store compares these keys,
    /// it never re-parses one into an identity.
    #[must_use]
    pub fn storage_key(&self) -> String {
        format!("uid:{}", self.uid)
    }
}

impl fmt::Display for AuthenticatedSubject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "uid:{}", self.uid)
    }
}

/// One live claimant of a session lease: one connection to one authority
/// incarnation.
///
/// `incarnation` is a counter in `kernel.db` that every authority start
/// increments, so a holder minted before a restart can never compare equal to
/// one minted after it. `connection` is unique within an incarnation.
///
/// No public constructor. See the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LeaseHolder {
    incarnation: u64,
    connection: u64,
}

impl LeaseHolder {
    /// Minted by [`super::Authority::connect`] only.
    pub(super) const fn new(incarnation: u64, connection: u64) -> Self {
        Self {
            incarnation,
            connection,
        }
    }

    /// Which authority incarnation this holder belongs to.
    #[must_use]
    pub const fn incarnation(&self) -> u64 {
        self.incarnation
    }

    /// Which connection within it.
    #[must_use]
    pub const fn connection(&self) -> u64 {
        self.connection
    }
}

impl fmt::Display for LeaseHolder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.incarnation, self.connection)
    }
}

/// The trusted caller context every state operation receives.
///
/// Both identities, together, because every operation needs one or the other
/// and some need both: the fence compares the holder, idempotency scopes by the
/// subject. Minted only by [`super::Authority::connect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CallerContext {
    subject: AuthenticatedSubject,
    holder: LeaseHolder,
}

impl CallerContext {
    pub(super) const fn new(subject: AuthenticatedSubject, holder: LeaseHolder) -> Self {
        Self { subject, holder }
    }

    /// Who the peer is.
    #[must_use]
    pub const fn subject(&self) -> AuthenticatedSubject {
        self.subject
    }

    /// Which live connection this is.
    #[must_use]
    pub const fn holder(&self) -> LeaseHolder {
        self.holder
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthenticatedSubject, CallerContext, LeaseHolder};

    #[test]
    fn the_subject_and_the_holder_are_different_identities() {
        let subject = AuthenticatedSubject::unix_uid(1000);
        let first = CallerContext::new(subject, LeaseHolder::new(1, 1));
        let second = CallerContext::new(subject, LeaseHolder::new(1, 2));
        assert_eq!(first.subject(), second.subject(), "one subject");
        assert_ne!(first.holder(), second.holder(), "two holders");
        assert_ne!(first, second);
    }

    #[test]
    fn a_holder_from_another_incarnation_is_a_different_holder() {
        // Connection 1 of incarnation 1 and connection 1 of incarnation 2 are
        // not the same claimant: a restart is not a reconnect.
        assert_ne!(LeaseHolder::new(1, 1), LeaseHolder::new(2, 1));
    }

    #[test]
    fn the_storage_forms_are_stable() {
        assert_eq!(
            AuthenticatedSubject::unix_uid(0).storage_key(),
            "uid:0",
            "root has a key like anyone else"
        );
        assert_eq!(LeaseHolder::new(3, 7).to_string(), "3:7");
    }
}
