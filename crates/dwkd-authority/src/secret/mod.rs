//! Secrets (M4e, [ADR-0046]): opaque handles, operator metadata, backend
//! resolution, secret material, injection-mode selection and return-path
//! redaction.
//!
//! **Invariant I3: the cognition plane never receives a plaintext long-lived
//! credential** ([`SECRETS.md`]). A handle is an identifier, never a
//! credential, a capability or a proof of authority; a leaked handle grants
//! nothing.
//!
//! # What lives here, and what does not
//!
//! | here | not here |
//! |---|---|
//! | the handle grammar and the operator's metadata ([`metadata`]) | the plaintext of a secret, anywhere but a [`material::SecretMaterial`] |
//! | the backends that read a value ([`backend`]): the OS keychain, age files | any API that returns a value to anyone but the injector |
//! | the injection-mode selector ([`select`]) | an `env` or `exec` backend (deferred, ADR-0046 §7) |
//! | the redaction index and the known-shape scanner ([`redact`]) | a network stack, a sandbox or an approval (M5, M6) |
//!
//! The durable index of handles lives in `kernel.db`, owned by the state layer
//! (`state::secrets`), which is the only caller of the backends (TX025): a
//! value is read **after** both gates allowed a use and its intent is durable,
//! never at admission, and never to answer a question.
//!
//! There is no secret-returning API at any privilege level, and none will be
//! added: not over DWKP, not for the CLI, not for diagnostics, not for export.
//!
//! [ADR-0046]: ../../../../docs/adr/0046-m4e-secret-handles-backends-injection-and-redaction.md
//! [`SECRETS.md`]: ../../../../docs/SECRETS.md

pub mod backend;
pub mod handoff;
pub mod material;
pub mod metadata;
pub mod redact;
pub mod select;

use core::fmt;

/// Why a secret could not be used. A closed vocabulary the operator can act
/// on, and nothing more: no variant carries text, and none says anything
/// about the structure of a credential's bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretError {
    /// No configured secret has this handle.
    NotConfigured,
    /// The handle is revoked: it resolves for nothing, whatever a stored
    /// grant says.
    Revoked,
    /// The handle now names a different secret (a new metadata revision) than
    /// the one the run was admitted with.
    Replaced,
    /// The configured storage is one this build does not implement (`env`,
    /// `exec`: ADR-0046 §7).
    BackendUnsupported,
    /// The backend cannot be reached on this host (no keyring, an unsupported
    /// platform).
    BackendUnavailable,
    /// The backend refused access.
    BackendDenied,
    /// The backend holds no item under the configured name.
    BackendItemMissing,
    /// The encrypted store is not one the authority can trust (owner, mode,
    /// kind, size).
    StoreUntrusted,
    /// Decryption failed: a wrong identity, a truncated or malformed file.
    DecryptFailed,
    /// The value exceeds [`material::MAX_SECRET_BYTES`]. Refused, never
    /// truncated.
    TooLarge,
    /// The value cannot be used as configured: empty, or holding a byte its
    /// injection mode forbids (NUL in an environment value, CR or LF in a
    /// header).
    MaterialInvalid,
    /// The consumer is not one the secret's metadata allows.
    ConsumerNotAllowed,
    /// The destination is not one of the secret's origins.
    OriginNotAllowed,
    /// No injection mode both the secret and the operation permit is
    /// available in this build and environment.
    InjectionModeUnavailable,
}

impl SecretError {
    /// The stable spelling: audit records and refusals carry this, never text.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotConfigured => "NOT_CONFIGURED",
            Self::Revoked => "REVOKED",
            Self::Replaced => "REPLACED",
            Self::BackendUnsupported => "BACKEND_UNSUPPORTED",
            Self::BackendUnavailable => "BACKEND_UNAVAILABLE",
            Self::BackendDenied => "BACKEND_DENIED",
            Self::BackendItemMissing => "BACKEND_ITEM_MISSING",
            Self::StoreUntrusted => "STORE_UNTRUSTED",
            Self::DecryptFailed => "DECRYPT_FAILED",
            Self::TooLarge => "SECRET_TOO_LARGE",
            Self::MaterialInvalid => "SECRET_MATERIAL_INVALID",
            Self::ConsumerNotAllowed => "CONSUMER_NOT_ALLOWED",
            Self::OriginNotAllowed => "ORIGIN_NOT_ALLOWED",
            Self::InjectionModeUnavailable => "INJECTION_MODE_UNAVAILABLE",
        }
    }
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for SecretError {}
