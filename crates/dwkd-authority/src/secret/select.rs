//! Injection-mode selection (ADR-0046 §15): **the kernel chooses**, from the
//! operator's metadata, the operation and the environment. Nothing a request
//! carries names a mode, so no request can ask for a weaker one.
//!
//! | operation | candidate modes, most restrictive first | host (M4e) |
//! |---|---|---|
//! | egress to an origin | (A) `egress` | the one-shot render primitive; the connection is M5's |
//! | spawn of a consumer | (C) `fd_at_spawn`, then (B) `env_at_spawn` | unavailable: SECRETS.md §3 puts B and C in a **sandboxed** child, and there is no sandbox before M5 |
//!
//! Mode D (`plaintext_to_model`) is not a candidate for anything: the metadata
//! parser refuses it, and it is unreachable until M6's approvals.

use crate::capability::Endpoint;
use crate::resource::ExecutableIdentity;

use super::SecretError;
use super::metadata::{InjectionMode, SecretMetadata};

/// Where an injected secret would run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionEnvironment {
    /// On the host, with the broker's privileges. The only environment this
    /// build has.
    Host,
}

/// The operation a secret would be consumed by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Consumption<'a> {
    /// An egress request to `origin` (mode A).
    Egress {
        /// The destination.
        origin: &'a Endpoint,
    },
    /// A spawned process, by the identity the authority resolved and hashed
    /// (modes B, C).
    Spawn {
        /// The consumer.
        consumer: &'a ExecutableIdentity,
        /// Where it runs.
        environment: InjectionEnvironment,
    },
}

/// Whether spawn injection may target the host. `false` in every build a
/// user runs; the crate's own unit tests exercise the spawn primitives on the
/// host through [`with_test_host_spawn`], labelled as the test-only injection
/// primitive it is — never as a sandbox.
fn host_spawn_permitted() -> bool {
    #[cfg(test)]
    {
        TEST_HOST_SPAWN.with(core::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        false
    }
}

#[cfg(test)]
thread_local! {
    static TEST_HOST_SPAWN: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// Run `work` with host spawn injection permitted. **`#[cfg(test)]`**: the
/// secret-injection primitive's own tests only. It is not a sandbox, it does
/// not call the host a sandbox, and no build a user runs contains it.
#[cfg(test)]
pub(crate) fn with_test_host_spawn<T>(work: impl FnOnce() -> T) -> T {
    TEST_HOST_SPAWN.with(|slot| slot.set(true));
    let result = work();
    TEST_HOST_SPAWN.with(|slot| slot.set(false));
    result
}

/// Select the mode for one consumption of `secret`, or refuse.
///
/// `consumers` are the identities the secret's metadata resolved to (the
/// state layer resolves the operator's paths when it loads the metadata); a
/// spawn consumer must be one of them **by identity** — canonical path and
/// SHA-256 — so a replaced binary is not the consumer the operator named
/// until the metadata is reloaded.
///
/// # Errors
///
/// [`SecretError::Revoked`], [`SecretError::OriginNotAllowed`],
/// [`SecretError::ConsumerNotAllowed`], or
/// [`SecretError::InjectionModeUnavailable`] when no allowed mode fits.
pub fn select(
    secret: &SecretMetadata,
    consumers: &[ExecutableIdentity],
    consumption: &Consumption<'_>,
) -> Result<InjectionMode, SecretError> {
    if secret.revoked {
        return Err(SecretError::Revoked);
    }
    match consumption {
        Consumption::Egress { origin } => {
            if !secret.injection.contains(&InjectionMode::Egress) {
                return Err(SecretError::InjectionModeUnavailable);
            }
            if !secret
                .origins
                .iter()
                .any(|allowed| allowed.contains(origin))
            {
                return Err(SecretError::OriginNotAllowed);
            }
            Ok(InjectionMode::Egress)
        }
        Consumption::Spawn {
            consumer,
            environment,
        } => {
            if !consumers.iter().any(|allowed| allowed == *consumer) {
                return Err(SecretError::ConsumerNotAllowed);
            }
            match environment {
                InjectionEnvironment::Host if !host_spawn_permitted() => {
                    return Err(SecretError::InjectionModeUnavailable);
                }
                InjectionEnvironment::Host => {}
            }
            // (C) before (B): a descriptor is not in `environ`.
            [InjectionMode::FdAtSpawn, InjectionMode::EnvAtSpawn]
                .into_iter()
                .find(|mode| secret.injection.contains(mode))
                .ok_or(SecretError::InjectionModeUnavailable)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::{Consumption, InjectionEnvironment, select, with_test_host_spawn};
    use crate::capability::Endpoint;
    use crate::resource::synthetic;
    use crate::secret::SecretError;
    use crate::secret::metadata::{InjectionMode, parse};

    const CONFIG: &str = r#"schema_version = 1
[secrets.egress-only]
type = "bearer"
storage = "keychain"
keychain = "e"
origins = ["api.example.com"]
header = "Authorization"
prefix = "Bearer "
injection = ["egress"]

[secrets.fd-only]
type = "ssh_private_key"
storage = "keychain"
keychain = "f"
injection = ["fd_at_spawn"]
consumers = ["/usr/bin/git"]

[secrets.both]
type = "generic"
storage = "keychain"
keychain = "b"
injection = ["env_at_spawn", "fd_at_spawn"]
consumers = ["/usr/bin/git"]
env = "TOKEN"

[secrets.env-only]
type = "generic"
storage = "keychain"
keychain = "v"
injection = ["env_at_spawn"]
consumers = ["/usr/bin/git"]
env = "TOKEN"
revoked = true
"#;

    #[test]
    fn the_kernel_selects_the_most_restrictive_allowed_mode_and_no_request_can_downgrade_it() {
        let config = parse(CONFIG).unwrap();
        let git = synthetic::executable(&["usr", "bin", "git"], 0x1a).unwrap();
        let git_b = synthetic::executable(&["usr", "bin", "git"], 0x2b).unwrap();
        let ssh = synthetic::executable(&["usr", "bin", "ssh"], 0x1a).unwrap();
        let consumers = [git.clone()];
        let get = |h: &str| {
            config
                .secrets
                .iter()
                .find(|s| s.handle.as_str() == h)
                .unwrap()
        };
        let spawn = |c| Consumption::Spawn {
            consumer: c,
            environment: InjectionEnvironment::Host,
        };
        let origin = Endpoint::parse("api.example.com").unwrap();
        let elsewhere = Endpoint::parse("api.example.com.evil.test").unwrap();

        // Egress: only for an egress secret, only to its origins.
        assert_eq!(
            select(
                get("egress-only"),
                &[],
                &Consumption::Egress { origin: &origin }
            ),
            Ok(InjectionMode::Egress)
        );
        assert_eq!(
            select(
                get("egress-only"),
                &[],
                &Consumption::Egress { origin: &elsewhere }
            ),
            Err(SecretError::OriginNotAllowed)
        );
        assert_eq!(
            select(
                get("fd-only"),
                &consumers,
                &Consumption::Egress { origin: &origin }
            ),
            Err(SecretError::InjectionModeUnavailable),
            "an fd-only secret never becomes a header"
        );
        // Spawn on the host: unavailable in every build a user runs.
        assert_eq!(
            select(get("fd-only"), &consumers, &spawn(&git)),
            Err(SecretError::InjectionModeUnavailable)
        );
        with_test_host_spawn(|| {
            assert_eq!(
                select(get("fd-only"), &consumers, &spawn(&git)),
                Ok(InjectionMode::FdAtSpawn)
            );
            assert_eq!(
                select(get("both"), &consumers, &spawn(&git)),
                Ok(InjectionMode::FdAtSpawn),
                "C before B"
            );
            assert_eq!(
                select(get("egress-only"), &consumers, &spawn(&git)),
                Err(SecretError::InjectionModeUnavailable),
                "an egress-only secret never reaches a process"
            );
            // Consumer binding is by identity: another binary, or the same
            // path with other bytes, is not the consumer.
            assert_eq!(
                select(get("fd-only"), &consumers, &spawn(&ssh)),
                Err(SecretError::ConsumerNotAllowed)
            );
            assert_eq!(
                select(get("fd-only"), &consumers, &spawn(&git_b)),
                Err(SecretError::ConsumerNotAllowed)
            );
            assert_eq!(
                select(get("env-only"), &consumers, &spawn(&git)),
                Err(SecretError::Revoked)
            );
        });
    }
}
