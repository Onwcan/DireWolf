//! The parser: what it accepts, and — mostly — what it refuses.
//!
//! Capability text arrives over DWKP from the least trusted process in the
//! system, so the negative corpus is the substance of this file and the
//! positive cases are the smaller half.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

// The authority links `toml` for the policy loader. This test binary does not
// use it, and `unused_crate_dependencies` sees the manifest edge rather than
// the target that consumes it. Acknowledged rather than silenced with an
// `#[allow]`, so the lint stays meaningful for the binaries that do use it.
use toml as _;
// Likewise the M3d state layer's storage and wire dependencies.
use dwk_proto as _;
use rusqlite as _;
use sha2 as _;

mod common;

use dwkd_authority::capability::{
    Action, CapabilityError, ConstraintName, MAX_CAPABILITY_CHARS, Namespace, PrivacyClass,
    ScopeError, UnresolvedScope, ValueError, parse,
};

fn err(text: &str) -> CapabilityError {
    parse(text).expect_err(&format!("`{text}` must be rejected"))
}

// ---------------------------------------------------------------------------
// The examples the specification itself gives.
// ---------------------------------------------------------------------------

#[test]
fn every_written_form_in_the_specification_parses() {
    // CAPABILITIES.md §2, "Written form", plus the §2 table's examples. If one
    // of these stopped parsing, the document and the code would disagree and
    // the document is the one people read.
    for text in [
        "fs.write:/workspace?max_bytes=10485760&no_symlink_targets=true",
        "network.https:*.github.com?methods=GET,POST&max_requests=100",
        "process.exec:/usr/bin/git?argv_allowlist=status,diff,log,show",
        "model.call:*?privacy_class=LOCAL_ONLY",
        "fs.write:/workspace/src",
        "process.exec:/usr/bin/git",
        "network.https:api.github.com:443",
        "secret.use:github-primary",
        "model.call:anthropic/*",
        "browser.use:*.github.com",
        "mcp.use:filesystem-server",
        "agent.spawn:researcher",
        "memory.promote:semantic",
        "scheduler.create:*",
        "artifact.export:*",
        "channel.send:telegram:<chat_id>",
    ] {
        assert!(parse(text).is_ok(), "{text}: {:?}", parse(text));
    }
}

#[test]
fn every_verb_the_architecture_defines_parses() {
    // The vocabulary is closed, so "every verb" is a list the compiler holds.
    // A namespace whose scope family rejected its own example would be a verb
    // nobody could ever use.
    use dwkd_authority::capability::Verb;
    let scope_for = |namespace: Namespace| match namespace {
        Namespace::Fs | Namespace::Process => "/tmp/x",
        Namespace::Network => "example.com",
        Namespace::Model => "anthropic/claude",
        Namespace::Browser => "example.com",
        Namespace::Channel => "telegram:<chat_id>",
        _ => "thing",
    };
    for verb in Verb::ALL {
        let text = format!("{verb}:{}", scope_for(verb.namespace()));
        assert!(parse(&text).is_ok(), "{text}: {:?}", parse(&text));
        // And `*` is valid for every verb.
        assert!(parse(&format!("{verb}:*")).is_ok(), "{verb}:*");
    }
}

#[test]
fn a_capability_is_not_a_grant() {
    // The parser answers "is this well-formed?" and nothing else. Whether the
    // caller may have it needs the agent profile, the skills, the parent run
    // and the ceiling, and none of those exist yet -- so parsing a capability
    // asking for everything succeeds, and means nothing.
    assert!(parse("fs.write:/?max_bytes=18446744073709551615").is_ok());
    assert!(parse("network.https:*").is_ok());
}

// ---------------------------------------------------------------------------
// Grammar.
// ---------------------------------------------------------------------------

#[test]
fn the_empty_string_is_not_a_capability() {
    assert_eq!(err(""), CapabilityError::Empty);
}

#[test]
fn a_capability_without_a_scope_is_refused() {
    // "Authority over everything" has a spelling -- `*` -- and it is written
    // out. Inferring it from an absent scope would make the widest capability
    // in the system the easiest one to write by accident.
    assert_eq!(err("fs.read"), CapabilityError::MissingScope);
}

#[test]
fn a_verb_needs_both_halves() {
    assert_eq!(err("fs:/workspace"), CapabilityError::MissingAction);
    assert_eq!(err(".read:/workspace"), CapabilityError::EmptyNamespace);
    assert_eq!(err("fs.:/workspace"), CapabilityError::EmptyAction);
}

#[test]
fn an_empty_scope_is_refused() {
    assert_eq!(err("fs.read:"), CapabilityError::EmptyScope);
}

#[test]
fn an_unknown_namespace_is_refused() {
    assert_eq!(err("quantum.read:*"), CapabilityError::UnknownNamespace);
}

#[test]
fn an_unknown_action_is_refused() {
    assert_eq!(
        err("fs.teleport:*"),
        CapabilityError::UnknownAction {
            namespace: Namespace::Fs
        }
    );
}

#[test]
fn an_action_from_another_namespace_is_refused() {
    // The failure a vocabulary of strings could not catch: `spawn` is a real
    // action and `fs` is a real namespace, and `fs.spawn` is authority over
    // nothing. Exhaustive pairs, not a cross product.
    for text in [
        "fs.spawn:*",
        "network.read:*",
        "agent.exec:*",
        "model.send:*",
    ] {
        assert!(
            matches!(err(text), CapabilityError::UnknownAction { .. }),
            "{text}"
        );
    }
}

#[test]
fn case_is_not_folded_anywhere_in_a_verb() {
    // `FS.READ` is not `fs.read`. Folding would give one authority two
    // spellings, and a system with two spellings has two vocabularies.
    assert_eq!(err("FS.READ:*"), CapabilityError::UnknownNamespace);
    assert_eq!(err("Fs.read:*"), CapabilityError::UnknownNamespace);
    assert_eq!(
        err("fs.READ:*"),
        CapabilityError::UnknownAction {
            namespace: Namespace::Fs
        }
    );
}

#[test]
fn a_third_verb_segment_is_refused() {
    assert!(matches!(
        err("fs.read.extra:*"),
        CapabilityError::UnknownAction { .. }
    ));
}

#[test]
fn trailing_input_is_never_ignored() {
    // A parser that accepts a prefix is a parser two implementations will
    // disagree about, and the disagreement is always in the attacker's favour.
    assert!(parse("model.call:*?privacy_class=LOCAL_ONLY trailing").is_err());
    assert!(parse("network.https:example.com extra").is_err());
    assert!(parse("agent.spawn:researcher?depth=1 ").is_err());
}

#[test]
fn a_capability_over_the_bound_is_refused_by_length_not_by_content() {
    let long = format!("fs.read:/{}", "a".repeat(MAX_CAPABILITY_CHARS));
    assert_eq!(err(&long), CapabilityError::TooLong);
    // And the bound matches the wire field, so nothing the protocol accepted
    // can be refused here for being long.
    assert_eq!(MAX_CAPABILITY_CHARS, 512);
}

// ---------------------------------------------------------------------------
// Constraints.
// ---------------------------------------------------------------------------

#[test]
fn a_question_mark_with_nothing_after_it_is_refused() {
    assert_eq!(err("fs.read:/w?"), CapabilityError::EmptyConstraints);
}

#[test]
fn a_second_question_mark_is_refused() {
    assert_eq!(
        err("fs.read:/w?max_bytes=1?max_bytes=2"),
        CapabilityError::RepeatedConstraintSeparator
    );
}

#[test]
fn a_constraint_needs_a_name_and_a_value() {
    assert_eq!(
        err("fs.read:/w?max_bytes"),
        CapabilityError::MalformedConstraint
    );
    assert_eq!(err("fs.read:/w?=10"), CapabilityError::EmptyConstraintName);
    assert_eq!(
        err("fs.read:/w?max_bytes="),
        CapabilityError::EmptyConstraintValue
    );
    assert_eq!(
        err("fs.read:/w?max_bytes=1&"),
        CapabilityError::MalformedConstraint
    );
    assert_eq!(
        err("fs.read:/w?&max_bytes=1"),
        CapabilityError::MalformedConstraint
    );
}

#[test]
fn an_unknown_constraint_is_refused() {
    assert_eq!(
        err("fs.read:/w?max_inodes=4"),
        CapabilityError::UnknownConstraint
    );
    // Including one that would be plausible in a later milestone. A ninth
    // constraint arrives as an enum variant and an ADR note, not as a string.
    assert_eq!(
        err("fs.read:/w?not_after=2026-01-01"),
        CapabilityError::UnknownConstraint
    );
}

#[test]
fn a_constraint_name_is_not_case_folded() {
    assert_eq!(
        err("fs.read:/w?MAX_BYTES=10"),
        CapabilityError::UnknownConstraint
    );
}

#[test]
fn a_duplicate_constraint_is_refused_rather_than_resolved() {
    // Never "last value wins". Two values for one constraint means the sender
    // does not know which it is asking for, and choosing for them picks the
    // wider one half the time.
    assert_eq!(
        err("fs.read:/w?max_bytes=10&max_bytes=20"),
        CapabilityError::DuplicateConstraint {
            name: ConstraintName::MaxBytes
        }
    );
    // Including when the two values agree: the ambiguity is in the shape.
    assert_eq!(
        err("fs.read:/w?max_bytes=10&max_bytes=10"),
        CapabilityError::DuplicateConstraint {
            name: ConstraintName::MaxBytes
        }
    );
}

// ---------------------------------------------------------------------------
// Numbers.
// ---------------------------------------------------------------------------

#[test]
fn a_malformed_number_is_refused() {
    for (text, reason) in [
        ("fs.read:/w?max_bytes=ten", ValueError::MalformedInteger),
        ("fs.read:/w?max_bytes=1.5", ValueError::MalformedInteger),
        ("fs.read:/w?max_bytes=-1", ValueError::MalformedInteger),
        ("fs.read:/w?max_bytes=+1", ValueError::MalformedInteger),
        ("fs.read:/w?max_bytes=1_000", ValueError::MalformedInteger),
        ("fs.read:/w?max_bytes=0x10", ValueError::MalformedInteger),
        ("fs.read:/w?max_bytes=010", ValueError::LeadingZero),
    ] {
        assert_eq!(
            err(text),
            CapabilityError::InvalidConstraintValue {
                name: ConstraintName::MaxBytes,
                reason
            },
            "{text}"
        );
    }
}

#[test]
fn an_overflowing_number_is_refused_and_never_truncated() {
    // A truncated limit is a wider limit. `999...9` must not become u64::MAX,
    // and a value that fits in u64 must not silently fit in u32.
    assert_eq!(
        err("fs.read:/w?max_bytes=999999999999999999999999999"),
        CapabilityError::InvalidConstraintValue {
            name: ConstraintName::MaxBytes,
            reason: ValueError::IntegerOverflow
        }
    );
    assert_eq!(
        err("network.https:example.com?max_requests=4294967296"),
        CapabilityError::InvalidConstraintValue {
            name: ConstraintName::MaxRequests,
            reason: ValueError::IntegerOverflow
        }
    );
    assert_eq!(
        err("agent.spawn:*?depth=65536"),
        CapabilityError::InvalidConstraintValue {
            name: ConstraintName::Depth,
            reason: ValueError::IntegerOverflow
        }
    );
}

#[test]
fn the_boundary_values_are_accepted() {
    for text in [
        "fs.read:/w?max_bytes=0",
        "fs.read:/w?max_bytes=18446744073709551615",
        "network.https:example.com?max_requests=4294967295",
        "agent.spawn:*?depth=0&fanout=0",
        "agent.spawn:*?depth=65535&fanout=65535",
    ] {
        assert!(parse(text).is_ok(), "{text}: {:?}", parse(text));
    }
}

// ---------------------------------------------------------------------------
// Sets and enums.
// ---------------------------------------------------------------------------

#[test]
fn a_malformed_set_is_refused() {
    for (text, name, reason) in [
        (
            "network.https:example.com?methods=GET,,POST",
            ConstraintName::Methods,
            ValueError::EmptySetMember,
        ),
        (
            "network.https:example.com?methods=GET,",
            ConstraintName::Methods,
            ValueError::EmptySetMember,
        ),
        (
            "network.https:example.com?methods=GET,GET",
            ConstraintName::Methods,
            ValueError::DuplicateSetMember,
        ),
        (
            "network.https:example.com?methods=FETCH",
            ConstraintName::Methods,
            ValueError::UnknownMethod,
        ),
        (
            "network.https:example.com?methods=get",
            ConstraintName::Methods,
            ValueError::UnknownMethod,
        ),
        (
            "process.exec:/bin/git?argv_allowlist=status,,diff",
            ConstraintName::ArgvAllowlist,
            ValueError::EmptySetMember,
        ),
        (
            "process.exec:/bin/git?argv_allowlist=status,status",
            ConstraintName::ArgvAllowlist,
            ValueError::DuplicateSetMember,
        ),
        (
            "process.exec:/bin/git?argv_allowlist=st*tus",
            ConstraintName::ArgvAllowlist,
            ValueError::MalformedArgvToken,
        ),
        (
            "process.exec:/bin/git?argv_allowlist=/usr/bin/x",
            ConstraintName::ArgvAllowlist,
            ValueError::MalformedArgvToken,
        ),
    ] {
        assert_eq!(
            err(text),
            CapabilityError::InvalidConstraintValue { name, reason },
            "{text}"
        );
    }
}

#[test]
fn an_unknown_privacy_class_is_refused() {
    for text in [
        "model.call:*?privacy_class=PUBLIC",
        "model.call:*?privacy_class=local_only",
        "model.call:*?privacy_class=Local_Only",
    ] {
        assert_eq!(
            err(text),
            CapabilityError::InvalidConstraintValue {
                name: ConstraintName::PrivacyClass,
                reason: ValueError::UnknownPrivacyClass
            },
            "{text}"
        );
    }
    for class in PrivacyClass::ALL {
        let text = format!("model.call:*?privacy_class={class}");
        assert!(parse(&text).is_ok(), "{text}");
    }
}

#[test]
fn no_symlink_targets_has_exactly_one_value() {
    assert!(parse("fs.read:/w?no_symlink_targets=true").is_ok());
    // `false` would mean the same as absent, giving one meaning two spellings
    // and canonical form two answers. Refused, and documented as a limitation.
    for text in [
        "fs.read:/w?no_symlink_targets=false",
        "fs.read:/w?no_symlink_targets=1",
        "fs.read:/w?no_symlink_targets=TRUE",
        "fs.read:/w?no_symlink_targets=yes",
    ] {
        assert_eq!(
            err(text),
            CapabilityError::InvalidConstraintValue {
                name: ConstraintName::NoSymlinkTargets,
                reason: ValueError::MalformedBoolean
            },
            "{text}"
        );
    }
}

// ---------------------------------------------------------------------------
// Applicability: §10's matrix, as rejections.
// ---------------------------------------------------------------------------

#[test]
fn a_constraint_on_the_wrong_verb_is_refused() {
    // Every example the M3b brief lists, plus the ones that would be easy to
    // get wrong because the namespace is right and the action is not.
    for (text, name) in [
        ("model.call:*?max_bytes=10", ConstraintName::MaxBytes),
        (
            "fs.read:/workspace?privacy_class=LOCAL_ONLY",
            ConstraintName::PrivacyClass,
        ),
        (
            "process.inspect:/bin/x?argv_allowlist=status",
            ConstraintName::ArgvAllowlist,
        ),
        ("agent.message:*?depth=2", ConstraintName::Depth),
        ("agent.cancel:*?fanout=2", ConstraintName::Fanout),
        ("fs.read:/w?methods=GET", ConstraintName::Methods),
        (
            "network.https:example.com?max_bytes=10",
            ConstraintName::MaxBytes,
        ),
        (
            "network.https:example.com?no_symlink_targets=true",
            ConstraintName::NoSymlinkTargets,
        ),
        (
            "secret.use:handle?max_requests=1",
            ConstraintName::MaxRequests,
        ),
        (
            "channel.send:telegram:<id>?max_bytes=10",
            ConstraintName::MaxBytes,
        ),
    ] {
        match err(text) {
            CapabilityError::ConstraintNotApplicable { name: got, .. } => {
                assert_eq!(got, name, "{text}");
            }
            other => panic!("{text}: expected ConstraintNotApplicable, got {other:?}"),
        }
    }
}

#[test]
fn a_constraint_applies_across_a_namespace_only_where_documented() {
    // `max_bytes` and `no_symlink_targets` say "fs verbs", so every fs action
    // takes them; `argv_allowlist` says `process.exec`, so only that one does.
    for action in [
        Action::Read,
        Action::Write,
        Action::Create,
        Action::Delete,
        Action::List,
        Action::Stat,
        Action::ExecBit,
    ] {
        let text = format!("fs.{action}:/w?max_bytes=10&no_symlink_targets=true");
        assert!(parse(&text).is_ok(), "{text}");
    }
    for action in [Action::Http, Action::Https, Action::Tcp, Action::Dns] {
        let text = format!("network.{action}:example.com?methods=GET&max_requests=1");
        assert!(parse(&text).is_ok(), "{text}");
    }
    assert!(parse("process.exec:/bin/git?argv_allowlist=status").is_ok());
    for action in [Action::Signal, Action::Inspect] {
        let text = format!("process.{action}:/bin/git?argv_allowlist=status");
        assert!(parse(&text).is_err(), "{text}");
    }
}

// ---------------------------------------------------------------------------
// Scopes.
// ---------------------------------------------------------------------------

#[test]
fn a_wildcard_may_not_stand_in_for_a_top_level_domain() {
    for text in [
        "network.https:*.com",
        "browser.use:*.org",
        "network.tcp:*.io",
    ] {
        assert_eq!(
            err(text),
            CapabilityError::InvalidScope(ScopeError::WildcardInTldPosition),
            "{text}"
        );
    }
    assert!(parse("network.https:*.example.com").is_ok());
}

#[test]
fn a_wildcard_is_refused_anywhere_but_the_front_of_a_host() {
    for text in [
        "network.https:api.*.example.com",
        "network.https:*api.example.com",
        "network.https:api.example.*",
        "browser.use:ex*ample.com",
    ] {
        assert!(parse(text).is_err(), "{text}");
    }
}

#[test]
fn a_malformed_host_is_refused() {
    for text in [
        "network.https:",
        "network.https:.example.com",
        "network.https:example..com",
        "network.https:-example.com",
        "network.https:example-.com",
        "network.https:EXAMPLE.com",
        "network.https:[::1]",
        "network.https:2001:db8::1",
    ] {
        assert!(parse(text).is_err(), "{text}");
    }
}

#[test]
fn a_malformed_port_is_refused() {
    for text in [
        "network.https:example.com:0",
        "network.https:example.com:65536",
        "network.https:example.com:443:443",
        "network.https:example.com:0443",
        "network.https:example.com:https",
        "network.https:example.com:",
    ] {
        assert!(parse(text).is_err(), "{text}");
    }
    assert!(parse("network.https:example.com:65535").is_ok());
    assert!(parse("network.https:example.com:1").is_ok());
}

#[test]
fn a_trailing_wildcard_is_the_only_pattern_wildcard() {
    assert!(parse("agent.spawn:research*").is_ok());
    assert!(parse("scheduler.create:daily*").is_ok());
    for text in [
        "agent.spawn:*researcher",
        "agent.spawn:res*archer",
        "agent.spawn:**",
        "scheduler.create:a*b*",
    ] {
        assert!(parse(text).is_err(), "{text}");
    }
}

#[test]
fn a_provider_model_needs_both_halves_and_an_exact_provider() {
    assert!(parse("model.call:anthropic/*").is_ok());
    assert!(parse("model.call:anthropic/claude-x").is_ok());
    for text in [
        "model.call:anthropic",
        "model.call:/claude",
        "model.call:anthropic/",
        "model.call:a/b/c",
        "model.call:*/claude",
    ] {
        assert!(parse(text).is_err(), "{text}");
    }
}

#[test]
fn a_channel_target_needs_both_halves() {
    assert!(parse("channel.send:telegram:<chat_id>").is_ok());
    for text in [
        "channel.send:telegram",
        "channel.send::id",
        "channel.send:tg:",
    ] {
        assert!(parse(text).is_err(), "{text}");
    }
}

#[test]
fn an_exact_match_family_takes_no_wildcard() {
    // `CAPABILITIES.md` defines no wildcard relation for a credential handle,
    // a server id, a memory scope or an artifact scope, so a pattern in one is
    // not a narrow capability written oddly -- it is a scope with no meaning.
    for text in [
        "secret.use:github-*",
        "mcp.use:file*",
        "memory.promote:sem*",
        "artifact.export:build-*",
    ] {
        assert!(parse(text).is_err(), "{text}");
    }
}

// ---------------------------------------------------------------------------
// The raw/canonical boundary.
// ---------------------------------------------------------------------------

#[test]
fn an_fs_capability_parses_and_refuses_to_become_authority() {
    // The heart of §15 of the brief. `/workspace` is well-formed text. It is
    // not an inode, and M3b will not pretend it can turn one into the other.
    let spec = parse("fs.read:/workspace").expect("well-formed");
    assert!(spec.needs_resolution());
    assert_eq!(spec.resolve(), Err(UnresolvedScope::CanonicalPath));
}

#[test]
fn a_process_capability_parses_and_refuses_to_become_authority() {
    let spec = parse("process.exec:/usr/bin/git").expect("well-formed");
    assert!(spec.needs_resolution());
    assert_eq!(spec.resolve(), Err(UnresolvedScope::ExecutableIdentity));
}

#[test]
fn the_ten_other_families_resolve_without_touching_anything() {
    for text in [
        "network.https:api.example.com:443",
        "secret.use:github-primary",
        "model.call:anthropic/*",
        "browser.use:*.example.com",
        "mcp.use:filesystem-server",
        "agent.spawn:researcher",
        "memory.promote:semantic",
        "scheduler.create:nightly",
        "artifact.export:build",
        "channel.send:telegram:<chat_id>",
    ] {
        let spec = parse(text).expect("well-formed");
        assert!(!spec.needs_resolution(), "{text}");
        assert!(spec.resolve().is_ok(), "{text}");
    }
}

#[test]
fn a_universal_fs_scope_needs_no_resolution() {
    // `fs.read:*` names no resource, so there is nothing to resolve and it is
    // comparable immediately. It is also the widest fs authority expressible,
    // which is why it has to be written out rather than inferred.
    let spec = parse("fs.read:*").expect("well-formed");
    assert!(!spec.needs_resolution());
    assert!(spec.resolve().is_ok());
}

#[test]
fn a_declared_path_must_be_absolute() {
    for text in [
        "fs.read:workspace",
        "fs.read:./workspace",
        "process.exec:git",
    ] {
        assert_eq!(
            err(text),
            CapabilityError::InvalidScope(ScopeError::MalformedPath),
            "{text}"
        );
    }
}

#[test]
fn a_declared_path_is_kept_verbatim_rather_than_cleaned_up() {
    // Rejecting `..` here would imply the survivor is safe, and it is not:
    // a path with no `..` can still traverse through a symlink. The value is
    // quarantined by its type instead of being laundered by a check.
    for text in ["fs.read:/workspace/../etc", "fs.read:/workspace/./src"] {
        let spec = parse(text).expect("well-formed as text");
        assert!(spec.resolve().is_err(), "{text}");
    }
}

// ---------------------------------------------------------------------------
// Canonical form.
// ---------------------------------------------------------------------------

#[test]
fn parsing_a_canonical_form_yields_the_same_specification() {
    for text in [
        "fs.write:/workspace?max_bytes=10485760&no_symlink_targets=true",
        "network.https:*.github.com?methods=GET,POST&max_requests=100",
        "process.exec:/usr/bin/git?argv_allowlist=status,diff,log,show",
        "model.call:*?privacy_class=LOCAL_ONLY",
        "agent.spawn:researcher?depth=2&fanout=4",
        "channel.send:telegram:<chat_id>",
        "network.https:api.github.com:443",
    ] {
        let once = parse(text).expect("well-formed");
        let canonical = once.to_canonical_string();
        let twice = parse(&canonical).expect("canonical form re-parses");
        assert_eq!(once, twice, "{text} -> {canonical}");
        assert_eq!(canonical, twice.to_canonical_string(), "idempotent");
    }
}

#[test]
fn constraint_order_and_set_order_do_not_survive_canonicalisation() {
    // Two spellings, one capability. If these produced different canonical text
    // the set type could hold both and call them different authorities.
    let a = parse("network.https:example.com?max_requests=5&methods=POST,GET").expect("a");
    let b = parse("network.https:example.com?methods=GET,POST&max_requests=5").expect("b");
    assert_eq!(a, b);
    assert_eq!(a.to_canonical_string(), b.to_canonical_string());
    assert_eq!(
        a.to_canonical_string(),
        "network.https:example.com?methods=GET,POST&max_requests=5"
    );

    let c = parse("process.exec:/bin/git?argv_allowlist=log,diff,status").expect("c");
    assert_eq!(
        c.to_canonical_string(),
        "process.exec:/bin/git?argv_allowlist=diff,log,status"
    );
}
