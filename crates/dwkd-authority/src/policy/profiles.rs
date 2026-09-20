//! The three shipped policy packs.
//!
//! `safe`, `balanced` and `power` are real TOML files under `policy/` at the
//! repository root, not strings embedded in a test. They are what an operator
//! reads, diffs and copies to start their own, and they are compiled into the
//! binary with [`include_str!`] so a build carries a known-good set.
//!
//! [`include_str!`] happens at **compile** time. The loader still takes text
//! and opens nothing; [`load`](super::load) has no path parameter and the
//! policy core imports no `std::fs`.
//!
//! # Mode profiles are policy packs, not prompts
//!
//! A mode is a capability ceiling plus one of these files. There is no
//! system-prompt-only safety mode anywhere in DireWolf, and the runtime cannot
//! choose which profile is in force — that is kernel and operator state. This
//! module exposes the *text*; selecting one is not M3c's, and there is no
//! function here that takes a request.
//!
//! # Not signed
//!
//! [`POLICY.md`] §7 says shipped profiles are signed. **They are not, yet.**
//! No signing key exists, no verifier exists, and nothing in this build checks
//! a signature. What this module gives is compiled-in text, which resists an
//! edit on disk and nothing else. Profile signing is future work and is not
//! claimed here.
//!
//! [`POLICY.md`]: ../../../../../docs/POLICY.md

/// `safe` — read the workspace, think, report. No writes, execution or egress.
pub const SAFE: &str = include_str!("../../../../policy/safe.toml");

/// `balanced` — the default. Workspace work proceeds; leaving it stops.
pub const BALANCED: &str = include_str!("../../../../policy/balanced.toml");

/// `power` — host execution of pinned binaries and broader egress, with every
/// hard denial intact.
pub const POWER: &str = include_str!("../../../../policy/power.toml");

/// Every shipped pack, as `(logical source name, text)`.
///
/// The source name is the file name, so a decision renders
/// `balanced.toml:63` — the spelling [`POLICY.md`] §5 uses.
///
/// [`POLICY.md`]: ../../../../../docs/POLICY.md
pub const ALL: [(&str, &str); 3] = [
    ("safe.toml", SAFE),
    ("balanced.toml", BALANCED),
    ("power.toml", POWER),
];

#[cfg(test)]
mod tests {
    use super::ALL;
    use crate::policy::{Effect, compose, load, rule::ProfileName};

    #[test]
    fn every_shipped_pack_loads() {
        for (name, text) in ALL {
            match load(name, text) {
                Ok(profile) => {
                    assert!(!profile.rules().is_empty(), "{name} has no rules");
                }
                Err(error) => unreachable!("{name} must load: {error}"),
            }
        }
    }

    #[test]
    fn every_shipped_pack_composes_and_ends_in_a_denying_default() {
        for (name, text) in ALL {
            let Ok(profile) = load(name, text) else {
                unreachable!("{name} loads")
            };
            let profile_name = profile.name().clone();
            let Ok(policy) = compose(&profile_name, &[profile]) else {
                unreachable!("{name} composes")
            };
            let Some(default) = policy.default_rule() else {
                unreachable!("{name} must end in the default rule")
            };
            assert_eq!(default.effect(), Effect::Deny, "{name}");
            assert!(default.when().is_empty(), "{name} default is conditional");
        }
    }

    #[test]
    fn the_packs_are_named_what_their_files_are_named() {
        for (file, text) in ALL {
            let Ok(profile) = load(file, text) else {
                unreachable!("{file} loads")
            };
            let Some(stem) = file.strip_suffix(".toml") else {
                unreachable!("every pack is a .toml")
            };
            let Ok(expected) = ProfileName::new(stem) else {
                unreachable!("a valid profile name")
            };
            assert_eq!(profile.name(), &expected);
        }
    }

    #[test]
    fn the_packs_are_standalone_rather_than_a_chain() {
        // safe/balanced/power are ceilings, not refinements of one another:
        // each permits a different set, and an extending profile may only add
        // denials (ADR-0038). If one of them ever gains an `extends`, the
        // composition tests have to cover the chain.
        for (name, text) in ALL {
            let Ok(profile) = load(name, text) else {
                unreachable!("{name} loads")
            };
            assert_eq!(profile.extends(), None, "{name} is standalone");
        }
    }

    #[test]
    fn every_pack_keeps_the_denials_that_are_not_negotiable_by_profile() {
        // A permissive profile is still a profile. These three ids must exist
        // in all of them, so "power turns the checks off" is false by
        // construction rather than by review.
        const REQUIRED: [&str; 3] = [
            "deny-direwolf-self-modification",
            "deny-credential-paths",
            "deny-container-socket",
        ];
        for (name, text) in ALL {
            let Ok(profile) = load(name, text) else {
                unreachable!("{name} loads")
            };
            for id in REQUIRED {
                let rule = profile.rules().iter().find(|r| r.id().as_str() == id);
                let Some(rule) = rule else {
                    unreachable!("{name} must carry {id}")
                };
                assert_eq!(rule.effect(), Effect::Deny, "{name}/{id}");
            }
        }
    }

    #[test]
    fn loading_is_deterministic_over_repeated_runs() {
        for (name, text) in ALL {
            let (Ok(first), Ok(second)) = (load(name, text), load(name, text)) else {
                unreachable!("{name} loads twice")
            };
            assert_eq!(first, second, "{name} compiled differently twice");
        }
    }

    #[test]
    fn a_crlf_checkout_compiles_to_the_same_policy() {
        // Rule source lines must not depend on how the file was checked out.
        for (name, text) in ALL {
            let crlf = text.replace('\n', "\r\n");
            let (Ok(lf), Ok(crlf)) = (load(name, text), load(name, &crlf)) else {
                unreachable!("{name} loads in both line endings")
            };
            assert_eq!(lf, crlf, "{name} differs between LF and CRLF");
        }
    }
}
