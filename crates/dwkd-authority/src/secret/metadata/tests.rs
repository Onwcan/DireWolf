//! The metadata grammar: every refusal class, and origin binding over the
//! capability layer's endpoint grammar (ADR-0046 §§2, 3, 15).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use super::{
    AgeIdentityKind, ConfigErrorKind, EnvName, HeaderName, HeaderPrefix, InjectionMode,
    SecretHandle, Storage, parse,
};
use crate::capability::Endpoint;

/// One line of the secret evidence (`make secret-broker-evidence`), printed
/// only after the assertions before it held.
fn evidence(suite: &str, case: &str, outcome: &str) {
    println!(
        "SECRET-EVIDENCE {{\"suite\":\"{suite}\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\"count\":1}}"
    );
}

const GOOD: &str = r#"schema_version = 1

[age]
identity_keychain = "direwolf-age-identity"

[secrets.github-primary]
type = "bearer"
description = "GitHub API"
storage = "keychain"
keychain = "direwolf/github-primary"
origins = ["api.github.com", "uploads.github.com"]
header = "Authorization"
prefix = "Bearer "
injection = ["egress"]
rotate_after = "90d"
sensitivity = "high"

[secrets.deploy-key]
type = "ssh_private_key"
storage = "age"
path = "/etc/direwolf/secrets/deploy-key.age"
injection = ["fd_at_spawn", "env_at_spawn"]
consumers = ["/usr/bin/ssh", "/usr/bin/git"]
env = "DEPLOY_KEY"
"#;

fn kind(text: &str) -> ConfigErrorKind {
    parse(text).expect_err("refused").kind
}

fn with(member: &str) -> String {
    format!(
        "schema_version = 1\n[secrets.s]\ntype = \"generic\"\nstorage = \"keychain\"\nkeychain = \"k\"\n{member}\n"
    )
}

#[test]
fn a_complete_document_parses_into_metadata_and_nothing_else() {
    let config = parse(GOOD).unwrap();
    assert_eq!(config.secrets.len(), 2);
    let deploy = &config.secrets[0];
    assert_eq!(deploy.handle.as_str(), "deploy-key");
    assert!(matches!(deploy.storage, Storage::Age(_)));
    assert_eq!(
        deploy.injection.iter().copied().collect::<Vec<_>>(),
        [InjectionMode::FdAtSpawn, InjectionMode::EnvAtSpawn]
    );
    let github = &config.secrets[1];
    assert_eq!(github.header.as_ref().unwrap().as_str(), "Authorization");
    assert_eq!(github.prefix.as_ref().unwrap().as_str(), "Bearer ");
    assert_eq!(github.rotate_after_days, Some(90));
    assert_eq!(config.age.unwrap().kind, AgeIdentityKind::X25519);
}

#[test]
fn unknown_members_deferred_backends_and_mode_d_are_refused() {
    // A value member does not exist: there is nowhere to put a secret.
    assert_eq!(
        kind(&with("injection = [\"egress\"]\nvalue = \"x\"")),
        ConfigErrorKind::UnknownField
    );
    assert_eq!(
        kind("schema_version = 1\nextra = 1\n"),
        ConfigErrorKind::UnknownField
    );
    assert_eq!(kind("schema_version = 2\n"), ConfigErrorKind::SchemaVersion);
    assert_eq!(kind("[secrets]\n"), ConfigErrorKind::SchemaVersion);
    assert_eq!(
        kind("schema_version = \"1\"\n"),
        ConfigErrorKind::SchemaVersion
    );
    for storage in ["env", "exec"] {
        let text = format!(
            "schema_version = 1\n[secrets.s]\ntype = \"generic\"\nstorage = \"{storage}\"\ninjection = [\"egress\"]\n"
        );
        assert_eq!(kind(&text), ConfigErrorKind::BackendDeferred, "{storage}");
    }
    assert_eq!(
        kind(&with("injection = [\"plaintext_to_model\"]")),
        ConfigErrorKind::ModeUnreachable
    );
    assert_eq!(
        kind(&with("injection = [\"telepathy\"]")),
        ConfigErrorKind::BadValue
    );
    assert_eq!(kind(&with("")), ConfigErrorKind::MissingField);
    // Duplicate handles are a TOML error before they are anything else.
    let twice = format!("{GOOD}\n[secrets.deploy-key]\ntype = \"generic\"\n");
    assert_eq!(kind(&twice), ConfigErrorKind::Syntax);
    // A handle outside the grammar.
    let upper = GOOD.replace("[secrets.github-primary]", "[secrets.GitHub]");
    assert_eq!(kind(&upper), ConfigErrorKind::BadValue);
    // age without an identity.
    let no_age = GOOD.replace("[age]\nidentity_keychain = \"direwolf-age-identity\"\n", "");
    assert_eq!(kind(&no_age), ConfigErrorKind::NoAgeIdentity);
    // A document too large is refused by length.
    assert_eq!(
        kind(&"#".repeat(super::MAX_CONFIG_BYTES + 1)),
        ConfigErrorKind::TooLarge
    );
    evidence("secret-metadata", "unknown-member", "refused");
    evidence("secret-metadata", "env-backend", "DEFERRED-refused");
    evidence("secret-metadata", "exec-backend", "DEFERRED-refused");
    evidence(
        "secret-metadata",
        "mode-d-plaintext-to-model",
        "UNREACHABLE-refused",
    );
}

#[test]
fn a_mode_needs_what_it_uses_and_nothing_it_does_not() {
    // Egress needs origins and a header.
    assert_eq!(
        kind(&with("injection = [\"egress\"]")),
        ConfigErrorKind::Incomplete
    );
    assert_eq!(
        kind(&with("injection = [\"egress\"]\norigins = [\"a.example\"]")),
        ConfigErrorKind::Incomplete
    );
    // Spawn needs consumers; env needs a name, and only env takes one.
    assert_eq!(
        kind(&with("injection = [\"fd_at_spawn\"]")),
        ConfigErrorKind::Incomplete
    );
    assert_eq!(
        kind(&with(
            "injection = [\"env_at_spawn\"]\nconsumers = [\"/usr/bin/git\"]"
        )),
        ConfigErrorKind::Incomplete
    );
    assert_eq!(
        kind(&with(
            "injection = [\"fd_at_spawn\"]\nconsumers = [\"/usr/bin/git\"]\nenv = \"TOKEN\""
        )),
        ConfigErrorKind::Incomplete
    );
    // A header without egress is a mode nobody allowed.
    assert_eq!(
        kind(&with(
            "injection = [\"fd_at_spawn\"]\nconsumers = [\"/usr/bin/git\"]\nheader = \"X\""
        )),
        ConfigErrorKind::Incomplete
    );
    // Consumers are absolute and canonical in spelling.
    for bad in ["git", "/usr/../bin/git", "/usr//bin/git"] {
        let text = with(&format!(
            "injection = [\"fd_at_spawn\"]\nconsumers = [\"{bad}\"]"
        ));
        assert_eq!(kind(&text), ConfigErrorKind::BadValue, "{bad}");
    }
    evidence("secret-metadata", "mode-fields", "exact");
}

#[test]
fn headers_prefixes_and_environment_names_are_refused_not_sanitised() {
    assert!(HeaderName::new("Authorization").is_some());
    assert!(HeaderName::new("X-Api-Key").is_some());
    for bad in ["", "Auth orization", "Auth:", "Auth\r\n", "Auth\0", "Ä"] {
        assert!(HeaderName::new(bad).is_none(), "{bad:?}");
    }
    assert!(HeaderPrefix::new("Bearer ").is_some());
    assert!(HeaderPrefix::new("").is_some());
    for bad in ["Bearer\r\n", "Bearer\n", "Bearer\0", "Bea\trer"] {
        assert!(HeaderPrefix::new(bad).is_none(), "{bad:?}");
    }
    assert!(EnvName::new("GITHUB_TOKEN").is_some());
    assert!(EnvName::new("_TOKEN").is_some());
    for control in [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "RUSTC_WRAPPER",
        "RUSTFLAGS",
        "PATH",
        "HOME",
        "BASH_ENV",
        "NODE_OPTIONS",
        "GIT_SSH_COMMAND",
        "GIT_EXEC_PATH",
        "GLIBC_TUNABLES",
        "LC_ALL",
    ] {
        assert!(
            EnvName::new(control).is_none(),
            "{control} is an execution-control variable"
        );
    }
    for malformed in ["", "token", "1TOKEN", "TO-KEN", "TOKEN=x"] {
        assert!(EnvName::new(malformed).is_none(), "{malformed:?}");
    }
    evidence("secret-metadata", "header-crlf", "refused-not-sanitised");
    evidence("secret-metadata", "env-control-variable", "refused");
}

#[test]
fn origin_binding_uses_the_endpoint_grammar_and_label_boundaries() {
    let allowed = Endpoint::parse("api.example.com").unwrap();
    let covers = |text: &str| Endpoint::parse(text).is_ok_and(|e| allowed.contains(&e));
    assert!(covers("api.example.com"));
    assert!(covers("api.example.com:443"), "no port means any port");
    for other in [
        "api.example.com.evil.test",
        "evil-api.example.com",
        "example.com",
        "user@api.example.com",
        "api.example.com:wrong-port",
        "x.api.example.com",
    ] {
        assert!(!covers(other), "{other}");
    }
    let pinned = Endpoint::parse("api.example.com:443").unwrap();
    assert!(!pinned.contains(&Endpoint::parse("api.example.com:8443").unwrap()));
    assert!(!pinned.contains(&Endpoint::parse("api.example.com").unwrap()));
    evidence("secret-metadata", "origin-binding", "label-boundaries");
}

#[test]
fn handles_are_a_strict_subset_of_the_capability_label_grammar() {
    for good in ["github-primary", "a", "deploy_key.v2", "x0"] {
        assert!(SecretHandle::new(good).is_some(), "{good}");
    }
    for bad in [
        "",
        "Github",
        "0start",
        "-start",
        "has space",
        "a<b>",
        "a@b",
        &"a".repeat(65),
    ] {
        assert!(SecretHandle::new(bad).is_none(), "{bad}");
    }
    evidence("secret-metadata", "handle-grammar", "subset-of-label");
}
