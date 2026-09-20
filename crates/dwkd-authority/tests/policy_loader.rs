//! The policy loader: what it accepts, and — mostly — what it refuses.
//!
//! The question this file is written around is the one from the hostile-loader
//! review:
//!
//! > **Could malformed policy become a valid *weaker* policy?**
//!
//! Every way that could happen gets a case: a typo makes a predicate
//! disappear; an overflow makes a large number small; a negative wraps; an
//! unknown enum falls back to a default variant; a duplicate resolves as
//! last-wins; a bad list member is dropped; an unknown obligation vanishes; a
//! parse failure yields a default policy. Each one must be a *refusal*, and a
//! refusal with a name and a line.
//!
//! These are integration tests, so they see exactly what a caller outside the
//! crate sees. They deliberately never build a canonical `fs` or `process`
//! identity — they cannot, since [ADR-0037] made those constructors
//! `pub(in crate::resource)`, and the absence is the point. Evaluation over
//! those values is unit-tested in `src/policy/fixtures.rs`.
//!
//! [ADR-0037]: ../../../docs/adr/0037-capability-specifications-and-canonical-authority-identities.md

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

// As above, for the property-test dev-dependency.
use proptest as _;

use dwkd_authority::capability::{Namespace, Verb};
use dwkd_authority::policy::{
    Effect, Expected, MatchValue, PolicyLoadError, Reason, SCHEMA_VERSION, ValueError, load,
    profiles,
};

/// The smallest policy that loads: a version, a name, and the mandatory rule.
const MINIMAL: &str = "\
schema_version = 1

[meta]
name = \"t\"

[[rule]]
id = \"default\"
effect = \"DENY\"
reason = \"NO_MATCHING_RULE\"
";

/// `MINIMAL` with `body` spliced in before the default rule.
fn with(body: &str) -> String {
    format!(
        "schema_version = 1\n\n[meta]\nname = \"t\"\n{body}\n\
         [[rule]]\nid = \"default\"\neffect = \"DENY\"\nreason = \"NO_MATCHING_RULE\"\n"
    )
}

fn err(source: &str) -> PolicyLoadError {
    load("t.toml", source).expect_err("this source must be refused")
}

fn err_with(body: &str) -> PolicyLoadError {
    err(&with(body))
}

// ---------------------------------------------------------------------------
// The minimum.
// ---------------------------------------------------------------------------

#[test]
fn the_minimal_policy_loads_and_is_a_denial() {
    let profile = load("t.toml", MINIMAL).expect("the minimal policy loads");
    assert_eq!(profile.rules().len(), 1);
    assert_eq!(profile.rules()[0].effect(), Effect::Deny);
    assert_eq!(profile.rules()[0].reason(), Reason::NoMatchingRule);
    assert!(profile.rules()[0].is_default());
    assert_eq!(profile.postconditions().len(), 0);
    assert_eq!(profile.extends(), None);
}

#[test]
fn empty_input_is_refused_rather_than_read_as_an_empty_policy() {
    // The most dangerous default of all: "no policy" must never mean "no
    // restrictions".
    assert!(matches!(
        err(""),
        PolicyLoadError::SchemaVersionMissing { .. }
    ));
    assert!(matches!(
        err("   \n\n# only a comment\n"),
        PolicyLoadError::SchemaVersionMissing { .. }
    ));
}

#[test]
fn a_policy_with_no_rules_at_all_is_refused() {
    let source = "schema_version = 1\n\n[meta]\nname = \"t\"\n";
    assert!(matches!(
        err(source),
        PolicyLoadError::DefaultRuleMissing { .. }
    ));
}

// ---------------------------------------------------------------------------
// Bounds, applied before the work they bound.
// ---------------------------------------------------------------------------

#[test]
fn an_oversized_source_is_refused_before_it_is_parsed() {
    // Deliberately not valid TOML past the first line. If the bound were
    // applied after parsing, the error would be a syntax error rather than a
    // size one -- which is how this test knows the order.
    let huge = format!("schema_version = 1\n{}", "x".repeat(300 * 1024));
    match err(&huge) {
        PolicyLoadError::SourceTooLarge { bytes, limit } => {
            assert!(bytes > limit, "{bytes} vs {limit}");
        }
        other => panic!("expected a size refusal before parsing, got {other}"),
    }
}

#[test]
fn a_source_name_that_could_not_be_rendered_is_refused() {
    assert!(matches!(
        load("", MINIMAL),
        Err(PolicyLoadError::SourceNameInvalid)
    ));
    let long = "x".repeat(200);
    assert!(matches!(
        load(&long, MINIMAL),
        Err(PolicyLoadError::SourceNameInvalid)
    ));
}

#[test]
fn too_many_rules_is_refused() {
    let mut body = String::new();
    for index in 0..600 {
        body.push_str(&format!(
            "\n[[rule]]\nid = \"r{index}\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\n"
        ));
    }
    assert!(matches!(
        err_with(&body),
        PolicyLoadError::TooManyRules { .. }
    ));
}

#[test]
fn an_over_long_list_or_string_is_refused() {
    let many: Vec<String> = (0..200).map(|i| format!("\"h{i}.example.com\"")).collect();
    let body = format!(
        "\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = \"network.https\"\n\
         when.host_matches = [{}]\n",
        many.join(", ")
    );
    assert!(matches!(
        err_with(&body),
        PolicyLoadError::BadValue {
            error: ValueError::TooManyListItems,
            ..
        }
    ));

    let long = "a".repeat(500);
    let body = format!(
        "\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = \"network.https\"\n\
         when.host_matches = [\"{long}.example.com\"]\n"
    );
    assert!(matches!(
        err_with(&body),
        PolicyLoadError::BadValue {
            error: ValueError::StringTooLong,
            ..
        }
    ));
}

// ---------------------------------------------------------------------------
// Syntax, and what the parser itself refuses.
// ---------------------------------------------------------------------------

#[test]
fn malformed_toml_is_a_syntax_error_at_a_real_line() {
    match err("schema_version = 1\n[meta\nname = \"t\"\n") {
        PolicyLoadError::Syntax { at, message } => {
            assert_eq!(at.source(), "t.toml");
            assert!(at.line() >= 2, "{at}");
            assert!(!message.is_empty());
        }
        other => panic!("expected a syntax error, got {other}"),
    }
}

#[test]
fn duplicate_keys_are_refused_by_the_parser_itself() {
    // Recorded rather than assumed: the loader relies on the TOML layer
    // refusing these, so the behaviour is pinned here. Last-value-wins on
    // security configuration is how a hardened rule becomes a permissive one.
    for source in [
        "schema_version = 1\nschema_version = 2\n",
        "schema_version = 1\n[meta]\nname = \"a\"\nname = \"b\"\n",
        "schema_version = 1\n[meta]\nname = \"a\"\n[meta]\nname = \"b\"\n",
        "schema_version = 1\n[[rule]]\nid = \"a\"\nid = \"b\"\n",
        "schema_version = 1\n[[rule]]\neffect = \"DENY\"\neffect = \"ALLOW\"\n",
    ] {
        match err(source) {
            PolicyLoadError::Syntax { message, .. } => {
                assert!(
                    message.contains("duplicate"),
                    "expected a duplicate-key refusal for {source:?}, got {message}"
                );
            }
            other => panic!("expected a syntax error for {source:?}, got {other}"),
        }
    }
}

// ---------------------------------------------------------------------------
// The schema version.
// ---------------------------------------------------------------------------

#[test]
fn the_schema_version_is_mandatory_exact_and_never_coerced() {
    assert!(matches!(
        err("[meta]\nname = \"t\"\n"),
        PolicyLoadError::SchemaVersionMissing { .. }
    ));

    // A later version is refused, not read as "probably compatible": the
    // fields version 2 would add are exactly the ones a version 1 reader would
    // silently ignore.
    for version in ["2", "0", "-1", "99"] {
        let source = MINIMAL.replace("schema_version = 1", &format!("schema_version = {version}"));
        match err(&source) {
            PolicyLoadError::SchemaVersionUnsupported { supported, .. } => {
                assert_eq!(supported, SCHEMA_VERSION);
            }
            other => panic!("expected an unsupported-version refusal for {version}, got {other}"),
        }
    }

    // And a string is not an integer.
    for bad in ["\"1\"", "1.0", "true", "[1]"] {
        let source = MINIMAL.replace("schema_version = 1", &format!("schema_version = {bad}"));
        assert!(
            matches!(
                err(&source),
                PolicyLoadError::TypeMismatch {
                    expected: Expected::Integer,
                    ..
                }
            ),
            "{bad} must not be coerced to an integer"
        );
    }
}

// ---------------------------------------------------------------------------
// Unknown fields. The most important refusal in the loader.
// ---------------------------------------------------------------------------

#[test]
fn an_unknown_field_is_refused_at_every_level() {
    let cases: [(&str, &str); 7] = [
        (
            "top level",
            "schema_version = 1\n[meta]\nname = \"t\"\nrogue = 1\n",
        ),
        (
            "meta",
            "schema_version = 1\n[meta]\nname = \"t\"\ndescription = \"x\"\n",
        ),
        (
            "rule",
            "schema_version = 1\n[meta]\nname = \"t\"\n[[rule]]\nid = \"a\"\neffect = \"DENY\"\nreason = \"SENSITIVE_PATH\"\npriority = 5\n",
        ),
        (
            "when",
            "schema_version = 1\n[meta]\nname = \"t\"\n[[rule]]\nid = \"a\"\neffect = \"DENY\"\nreason = \"SENSITIVE_PATH\"\nwhen.nonesuch = true\n",
        ),
        (
            "unless",
            "schema_version = 1\n[meta]\nname = \"t\"\n[[rule]]\nid = \"a\"\neffect = \"DENY\"\nreason = \"SENSITIVE_PATH\"\nunless.anything = true\n",
        ),
        (
            "approval",
            "schema_version = 1\n[meta]\nname = \"t\"\n[[rule]]\nid = \"a\"\neffect = \"REQUIRE_APPROVAL\"\nreason = \"UNKNOWN_EXECUTABLE\"\napproval.scope = \"exact_action\"\napproval.ttl = \"1h\"\napproval.max_uses = 1\napproval.forever = true\n",
        ),
        (
            // With a valid rule section, so the unknown member in the
            // postcondition is what fails rather than the missing default.
            "postcondition",
            "schema_version = 1\n[meta]\nname = \"t\"\n[[rule]]\nid = \"default\"\neffect = \"DENY\"\nreason = \"NO_MATCHING_RULE\"\n[[postcondition]]\nid = \"p\"\neffect = \"DENY\"\nreason = \"NO_HUMAN_AVAILABLE\"\nobligations = []\n",
        ),
    ];
    for (level, source) in cases {
        match err(source) {
            PolicyLoadError::UnknownField { field, at } => {
                assert_eq!(at.source(), "t.toml", "{level}");
                assert!(at.line() > 0, "{level}");
                assert!(!field.as_str().is_empty(), "{level}");
            }
            other => panic!("unknown field at {level} must be refused, got {other}"),
        }
    }
}

#[test]
fn a_misspelled_predicate_is_an_error_and_not_an_absent_one() {
    // The canonical case from the brief. If `destinatoin_novel` loaded as
    // "the predicate is absent", the rule would match every destination
    // instead of only novel ones.
    let body = "\n[[rule]]\nid = \"r\"\neffect = \"DENY\"\nreason = \"UNTRUSTED_CONTENT_IN_RUN\"\n\
                when.verb = \"network.https\"\nwhen.destinatoin_novel = true\n";
    match err_with(body) {
        PolicyLoadError::UnknownField { field, .. } => {
            assert!(field.as_str().ends_with("destinatoin_novel"), "{field}");
        }
        other => panic!("expected an unknown-field refusal, got {other}"),
    }
}

#[test]
fn a_rule_cannot_name_code_to_run() {
    // A policy file is data. There is no field that names a function, a
    // handler, a script or an evaluator, so each of these is an unknown field
    // rather than a thing that executes.
    for member in [
        "function = \"crate::x::y\"",
        "handler = \"policy.check\"",
        "eval = \"1 + 1\"",
        "script = \"/bin/sh\"",
        "plugin = \"libx.so\"",
        "exec = true",
    ] {
        let body = format!(
            "\n[[rule]]\nid = \"r\"\neffect = \"DENY\"\nreason = \"SENSITIVE_PATH\"\n{member}\n"
        );
        assert!(
            matches!(err_with(&body), PolicyLoadError::UnknownField { .. }),
            "{member} must be refused"
        );
    }
}

// ---------------------------------------------------------------------------
// Types are never coerced.
// ---------------------------------------------------------------------------

#[test]
fn a_boolean_predicate_refuses_the_string_that_looks_like_one() {
    let body = "\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\n\
                when.verb = \"process.exec\"\nwhen.argv_safe = \"true\"\n";
    assert!(matches!(
        err_with(body),
        PolicyLoadError::TypeMismatch {
            expected: Expected::Boolean,
            ..
        }
    ));
}

#[test]
fn a_numeric_field_refuses_a_float_rather_than_truncating_it() {
    let body = "\n[[rule]]\nid = \"r\"\neffect = \"REQUIRE_APPROVAL\"\nreason = \"UNKNOWN_EXECUTABLE\"\n\
                approval.scope = \"exact_action\"\napproval.ttl = \"1h\"\napproval.max_uses = 1.5\n";
    assert!(matches!(
        err_with(body),
        PolicyLoadError::TypeMismatch {
            expected: Expected::Integer,
            ..
        }
    ));
}

#[test]
fn a_negative_value_never_wraps_into_a_large_unsigned_one() {
    for (field, body) in [
        (
            "max_bytes",
            "\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = \"fs.read\"\nwhen.max_bytes = -1\n",
        ),
        (
            "max_uses",
            "\n[[rule]]\nid = \"r\"\neffect = \"REQUIRE_APPROVAL\"\nreason = \"UNKNOWN_EXECUTABLE\"\napproval.scope = \"exact_action\"\napproval.ttl = \"1h\"\napproval.max_uses = -5\n",
        ),
    ] {
        assert!(
            matches!(
                err_with(body),
                PolicyLoadError::BadValue {
                    error: ValueError::NumericRange,
                    ..
                }
            ),
            "{field} must refuse a negative value"
        );
    }
}

#[test]
fn an_integer_past_the_field_never_saturates() {
    // u64::MAX + 1 in max_bytes, and u32::MAX + 1 in max_uses. Both must be
    // refused rather than clamped to something plausible.
    let body = "\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = \"fs.read\"\n\
                when.max_bytes = 99999999999999999999\n";
    assert!(matches!(
        err_with(body),
        PolicyLoadError::BadValue {
            error: ValueError::NumericRange,
            ..
        }
    ));

    let body = "\n[[rule]]\nid = \"r\"\neffect = \"REQUIRE_APPROVAL\"\nreason = \"UNKNOWN_EXECUTABLE\"\n\
                approval.scope = \"exact_action\"\napproval.ttl = \"1h\"\napproval.max_uses = 4294967296\n";
    assert!(matches!(
        err_with(body),
        PolicyLoadError::BadValue {
            error: ValueError::NumericRange,
            ..
        }
    ));
}

#[test]
fn a_mixed_type_list_refuses_rather_than_dropping_the_odd_element() {
    let body = "\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = [\"fs.read\", 7]\n";
    assert!(matches!(
        err_with(body),
        PolicyLoadError::TypeMismatch {
            expected: Expected::StringOrArray,
            ..
        }
    ));
}

#[test]
fn an_empty_predicate_list_is_refused() {
    // `when.verb = []` is a predicate nothing satisfies, which is a rule that
    // never fires written as a rule that does.
    let body =
        "\n[[rule]]\nid = \"r\"\neffect = \"DENY\"\nreason = \"SENSITIVE_PATH\"\nwhen.verb = []\n";
    assert!(matches!(
        err_with(body),
        PolicyLoadError::BadValue {
            error: ValueError::EmptyList,
            ..
        }
    ));
}

#[test]
fn a_repeated_list_element_is_refused() {
    let body = "\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\n\
                when.verb = [\"fs.read\", \"fs.read\"]\n";
    assert!(matches!(
        err_with(body),
        PolicyLoadError::BadValue {
            error: ValueError::DuplicateListItem,
            ..
        }
    ));
}

// ---------------------------------------------------------------------------
// Scalar and list are two grammars, and the loader keeps them apart.
//
// POLICY.md section 3's operator table documents both spellings for a match
// predicate -- implicit scalar is equality, a list is membership -- so both
// load. What must NOT happen is the parser reading one as the other: that is
// a coercion, and a strict loader that coerces in one direction has a
// coercion. The variant stays observable in the compiled policy.
// ---------------------------------------------------------------------------

/// The `when.verb` of the first rule of a loaded profile.
fn first_verb(body: &str) -> dwkd_authority::policy::MatchValue<Verb> {
    let profile = load("t.toml", &with(body)).expect("loads");
    profile.rules()[0]
        .when()
        .verb
        .clone()
        .expect("the rule constrains its verbs")
}

#[test]
fn a_scalar_match_predicate_stays_a_scalar() {
    // Case A.
    let named =
        first_verb("\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\n");
    assert!(named.is_scalar(), "{named:?}");
    assert!(matches!(named, MatchValue::Eq(_)), "{named:?}");
    assert_eq!(named.len(), 1);
}

#[test]
fn a_one_element_list_stays_a_list() {
    // Case B. The case a coercing loader would flatten, and the reason this
    // whole family of tests exists.
    let named =
        first_verb("\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = [\"model.call\"]\n");
    assert!(!named.is_scalar(), "{named:?}");
    assert!(matches!(named, MatchValue::In(_)), "{named:?}");
    assert_eq!(named.len(), 1);
}

#[test]
fn the_two_spellings_do_not_compile_to_the_same_value() {
    // Case C. The property, stated directly.
    let scalar = "\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\n";
    let list = "\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = [\"model.call\"]\n";
    assert_ne!(first_verb(scalar), first_verb(list));
    assert_ne!(
        load("t.toml", &with(scalar)).expect("loads"),
        load("t.toml", &with(list)).expect("loads"),
        "two source shapes must not produce one compiled policy"
    );
}

#[test]
fn every_dual_form_field_keeps_both_spellings_apart() {
    // Case C, across the whole match-predicate vocabulary rather than one
    // field, so a future predicate added through the wrong helper is caught.
    for (field, scalar, list) in [
        ("verb", "\"model.call\"", "[\"model.call\"]"),
        ("path_under", "\"${WORKSPACE}\"", "[\"${WORKSPACE}\"]"),
        ("executable_in", "\"git\"", "[\"git\"]"),
        ("host_matches", "\"example.com\"", "[\"example.com\"]"),
        ("ip_in", "\"10.0.0.0/8\"", "[\"10.0.0.0/8\"]"),
        ("environment", "\"sandbox\"", "[\"sandbox\"]"),
        ("origin", "\"scheduled\"", "[\"scheduled\"]"),
        ("taint_level", "\"NONE\"", "[\"NONE\"]"),
        ("privacy_class", "\"ANY\"", "[\"ANY\"]"),
    ] {
        // A verb set the predicate applies to, so applicability passes.
        let verbs = match field {
            "path_under" => "when.verb = [\"fs.read\"]\n",
            "executable_in" => "when.verb = [\"process.exec\"]\n",
            "host_matches" | "ip_in" => "when.verb = [\"network.https\"]\n",
            "verb" => "",
            _ => "when.verb = [\"model.call\"]\n",
        };
        let body = |value: &str| {
            format!("\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\n{verbs}when.{field} = {value}\n")
        };
        let (a, b) = (
            load("t.toml", &with(&body(scalar))).unwrap_or_else(|e| panic!("{field} scalar: {e}")),
            load("t.toml", &with(&body(list))).unwrap_or_else(|e| panic!("{field} list: {e}")),
        );
        assert_ne!(a, b, "`when.{field}` collapsed its two spellings");
    }
}

#[test]
fn both_spellings_decide_the_same_way_for_one_value() {
    // Case D. The semantic equivalence is fine and expected -- `In([x])`
    // matches what `Eq(x)` matches. What was forbidden is the PARSER
    // obtaining it by turning one shape into the other, which case C pins.
    let scalar =
        first_verb("\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\n");
    let list =
        first_verb("\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = [\"model.call\"]\n");
    let call = Verb::parse_action(Namespace::Model, "call").expect("a documented verb");
    let read = Verb::parse_action(Namespace::Memory, "read").expect("a documented verb");
    assert!(scalar.matches(&call) && list.matches(&call));
    assert!(!scalar.matches(&read) && !list.matches(&read));
}

#[test]
fn a_list_only_field_refuses_a_scalar() {
    // Case E. `obligations` is an output set, not a match predicate: the
    // scalar spelling POLICY.md documents for `eq` does not apply to it, and
    // accepting one would be the coercion arriving through a different door.
    let body = "\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\n\
                obligations = \"network_deny\"\n";
    assert!(
        matches!(
            err_with(body),
            PolicyLoadError::TypeMismatch {
                expected: Expected::Array,
                ..
            }
        ),
        "obligations must be a list"
    );
    // And the list form still loads.
    load(
        "t.toml",
        &with("\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\nobligations = [\"network_deny\"]\n"),
    )
    .expect("the list form loads");
}

#[test]
fn a_scalar_only_field_refuses_a_list() {
    // Case F. A numeric bound and two canonicaliser-derived classifications
    // are not membership tests; `max_bytes = [1, 2]` names no bound.
    for (member, expected) in [
        ("when.max_bytes = [1, 2]", Expected::Integer),
        ("when.max_bytes = [1]", Expected::Integer),
        ("when.argv_safe = [true]", Expected::Boolean),
        ("when.destination_novel = [true]", Expected::Boolean),
    ] {
        let verbs = if member.contains("max_bytes") {
            "when.verb = [\"fs.read\"]\n"
        } else if member.contains("argv_safe") {
            "when.verb = [\"process.exec\"]\n"
        } else {
            "when.verb = [\"network.https\"]\n"
        };
        let body = format!("\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\n{verbs}{member}\n");
        match err_with(&body) {
            PolicyLoadError::TypeMismatch { expected: got, .. } => {
                assert_eq!(got, expected, "for {member}");
            }
            other => panic!("{member} must be a type mismatch, got {other}"),
        }
    }

    // `unless` is scalar too: a config key and a boolean.
    for member in [
        "unless.config = [\"security.allow_host_execution\"]",
        "unless.standing_grant = [true]",
    ] {
        let body = format!(
            "\n[[rule]]\nid = \"r\"\neffect = \"DENY\"\nreason = \"PROFILE_CEILING\"\n\
             when.verb = [\"model.call\"]\n{member}\n"
        );
        assert!(
            matches!(err_with(&body), PolicyLoadError::TypeMismatch { .. }),
            "{member} must be a type mismatch"
        );
    }
}

#[test]
fn a_dual_form_field_still_refuses_a_shape_that_is_neither() {
    // Case I. Both spellings are strings or arrays of strings; a table, an
    // integer or a boolean is neither, in either position.
    for value in ["1", "true", "{ a = 1 }", "[[1]]", "[{ a = 1 }]", "[true]"] {
        let body = format!("\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = {value}\n");
        assert!(
            matches!(
                err_with(&body),
                PolicyLoadError::TypeMismatch {
                    expected: Expected::StringOrArray,
                    ..
                }
            ),
            "`when.verb = {value}` must be refused"
        );
    }
}

#[test]
fn the_variant_survives_repeated_loads_of_the_same_source() {
    // Case J. Determinism over the shape, not only over the values.
    for body in [
        "\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\n",
        "\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = [\"model.call\"]\n",
    ] {
        let first = first_verb(body);
        for _ in 0..8 {
            assert_eq!(first_verb(body), first, "the variant must be stable");
        }
    }
}

#[test]
fn the_shipped_packs_use_both_spellings_and_keep_both() {
    // The regression this closeout is about, on the real files: `balanced`
    // writes `when.verb = "fs.delete"` in one rule and a list in another, so
    // a coercion would be observable in the shipped policy rather than only
    // in a fixture.
    let profile = load("balanced.toml", profiles::BALANCED).expect("the pack loads");
    let shapes: Vec<bool> = profile
        .rules()
        .iter()
        .filter_map(|rule| rule.when().verb.as_ref())
        .map(dwkd_authority::policy::MatchValue::is_scalar)
        .collect();
    assert!(shapes.contains(&true), "balanced.toml writes a scalar verb");
    assert!(shapes.contains(&false), "balanced.toml writes a list verb");
}

// ---------------------------------------------------------------------------
// Rule identity.
// ---------------------------------------------------------------------------

#[test]
fn a_duplicate_rule_id_is_refused_and_names_both_places() {
    let body = "\n[[rule]]\nid = \"twice\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\n\
                \n[[rule]]\nid = \"twice\"\neffect = \"DENY\"\nreason = \"PROFILE_CEILING\"\nwhen.verb = \"memory.read\"\n";
    match err_with(body) {
        PolicyLoadError::DuplicateRuleId { id, at, first } => {
            assert_eq!(id, "twice");
            assert!(at.line() > first.line(), "{at} should follow {first}");
        }
        other => panic!("expected a duplicate-id refusal, got {other}"),
    }
}

#[test]
fn a_postcondition_shares_the_rule_id_namespace() {
    let body = "\n[[rule]]\nid = \"shared\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\n\
                \n[[postcondition]]\nid = \"shared\"\neffect = \"DENY\"\nreason = \"NO_HUMAN_AVAILABLE\"\n";
    assert!(matches!(
        err_with(body),
        PolicyLoadError::DuplicateRuleId { .. }
    ));
}

#[test]
fn a_malformed_rule_id_is_refused() {
    for id in [
        "",
        "A",
        "1x",
        "-x",
        "x-",
        "a--b",
        "a_b",
        "has space",
        "a/b",
        "caf\u{e9}",
    ] {
        let body =
            format!("\n[[rule]]\nid = \"{id}\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\n");
        assert!(
            matches!(
                err_with(&body),
                PolicyLoadError::BadValue {
                    error: ValueError::MalformedRuleId,
                    ..
                }
            ),
            "{id:?} must be refused as a rule id"
        );
    }
    let over = "a".repeat(100);
    let body =
        format!("\n[[rule]]\nid = \"{over}\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\n");
    assert!(matches!(
        err_with(&body),
        PolicyLoadError::BadValue {
            error: ValueError::MalformedRuleId,
            ..
        }
    ));
}

// ---------------------------------------------------------------------------
// The mandatory default.
// ---------------------------------------------------------------------------

#[test]
fn the_default_rule_must_exist_be_last_deny_and_be_unconditional() {
    let head = "schema_version = 1\n\n[meta]\nname = \"t\"\n";

    // Missing.
    assert!(matches!(
        err(&format!(
            "{head}\n[[rule]]\nid = \"a\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\n"
        )),
        PolicyLoadError::DefaultRuleMissing { .. }
    ));

    // Not last: a rule after it can never match.
    assert!(matches!(
        err(&format!(
            "{head}\n[[rule]]\nid = \"default\"\neffect = \"DENY\"\nreason = \"NO_MATCHING_RULE\"\n\
             \n[[rule]]\nid = \"after\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\n"
        )),
        PolicyLoadError::DefaultRuleNotLast { followed_by: 1, .. }
    ));

    // ALLOW. This is the one that matters most: `default = ALLOW` is not a
    // permissive default, it is no default at all.
    assert!(matches!(
        err(&format!(
            "{head}\n[[rule]]\nid = \"default\"\neffect = \"ALLOW\"\n"
        )),
        PolicyLoadError::DefaultRuleNotDeny { .. }
    ));
    assert!(matches!(
        err(&format!(
            "{head}\n[[rule]]\nid = \"default\"\neffect = \"REQUIRE_APPROVAL\"\nreason = \"UNKNOWN_EXECUTABLE\"\n\
             approval.scope = \"exact_action\"\napproval.ttl = \"1h\"\napproval.max_uses = 1\n"
        )),
        PolicyLoadError::DefaultRuleNotDeny { .. }
    ));

    // Conditional: a default that sometimes does not match leaves the
    // evaluator falling off the end of the list.
    for predicate in ["when.verb = \"model.call\"", "unless.standing_grant = true"] {
        assert!(
            matches!(
                err(&format!(
                    "{head}\n[[rule]]\nid = \"default\"\neffect = \"DENY\"\nreason = \"NO_MATCHING_RULE\"\n{predicate}\n"
                )),
                PolicyLoadError::DefaultRuleConditional { .. }
            ),
            "a default with {predicate} must be refused"
        );
    }

    // Two of them is a duplicate id, caught earlier.
    assert!(matches!(
        err(&format!(
            "{head}\n[[rule]]\nid = \"default\"\neffect = \"DENY\"\nreason = \"NO_MATCHING_RULE\"\n\
             \n[[rule]]\nid = \"default\"\neffect = \"DENY\"\nreason = \"NO_MATCHING_RULE\"\n"
        )),
        PolicyLoadError::DuplicateRuleId { .. }
    ));
}

// ---------------------------------------------------------------------------
// Closed vocabularies.
// ---------------------------------------------------------------------------

#[test]
fn every_closed_vocabulary_refuses_a_near_miss() {
    let cases: [(&str, ValueError); 10] = [
        (
            "\n[[rule]]\nid = \"r\"\neffect = \"PERMIT\"\n",
            ValueError::UnknownEffect,
        ),
        (
            "\n[[rule]]\nid = \"r\"\neffect = \"allow\"\n",
            ValueError::UnknownEffect,
        ),
        (
            "\n[[rule]]\nid = \"r\"\neffect = \"DENY\"\nreason = \"NO_CAPABILITY\"\n",
            ValueError::UnknownReason,
        ),
        (
            "\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = \"fs.teleport\"\n",
            ValueError::UnknownVerb,
        ),
        (
            "\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = \"fs.spawn\"\n",
            ValueError::UnknownVerb,
        ),
        (
            "\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\nwhen.origin = \"cron\"\n",
            ValueError::UnknownOrigin,
        ),
        (
            "\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\nwhen.taint_level = \"TAINTED\"\n",
            ValueError::UnknownTaintLevel,
        ),
        (
            "\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\nwhen.privacy_class = \"PRIVATE\"\n",
            ValueError::UnknownPrivacyClass,
        ),
        (
            "\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = \"process.exec\"\nwhen.environment = \"container\"\n",
            ValueError::UnknownEnvironment,
        ),
        (
            "\n[[rule]]\nid = \"r\"\neffect = \"DENY\"\nreason = \"PROFILE_CEILING\"\nwhen.verb = \"process.exec\"\nunless.config = \"security.allow_anything\"\n",
            ValueError::UnknownConfigKey,
        ),
    ];
    for (body, expected) in cases {
        match err_with(body) {
            PolicyLoadError::BadValue { error, .. } => {
                assert_eq!(error, expected, "for {body:?}");
            }
            other => panic!("expected {expected} for {body:?}, got {other}"),
        }
    }
}

#[test]
fn the_evaluators_own_reasons_cannot_be_claimed_by_a_rule() {
    for reason in ["PERMITTED_BY_RULE", "UNRESOLVED_CANONICAL_INPUT"] {
        let body = format!(
            "\n[[rule]]\nid = \"r\"\neffect = \"DENY\"\nreason = \"{reason}\"\nwhen.verb = \"model.call\"\n"
        );
        assert!(
            matches!(
                err_with(&body),
                PolicyLoadError::BadValue {
                    error: ValueError::UnknownReason,
                    ..
                }
            ),
            "{reason} is the evaluator's, not a rule author's"
        );
    }
}

#[test]
fn a_refusal_must_say_why_and_a_permission_need_not() {
    // An ALLOW with no reason gets a typed one rather than an empty string.
    let profile = load(
        "t.toml",
        &with("\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\n"),
    )
    .expect("an ALLOW may omit its reason");
    assert_eq!(profile.rules()[0].reason(), Reason::PermittedByRule);

    for effect in ["DENY", "REQUIRE_APPROVAL"] {
        let body = format!(
            "\n[[rule]]\nid = \"r\"\neffect = \"{effect}\"\nwhen.verb = \"model.call\"\n\
             approval.scope = \"exact_action\"\napproval.ttl = \"1h\"\napproval.max_uses = 1\n"
        );
        let body = if effect == "DENY" {
            body.replace(
                "approval.scope = \"exact_action\"\napproval.ttl = \"1h\"\napproval.max_uses = 1\n",
                "",
            )
        } else {
            body
        };
        assert!(
            matches!(err_with(&body), PolicyLoadError::MissingField { .. }),
            "{effect} must state a reason"
        );
    }
}

// ---------------------------------------------------------------------------
// Obligations.
// ---------------------------------------------------------------------------

#[test]
fn an_obligation_is_never_silently_dropped() {
    for (body, expected) in [
        (
            "\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\nobligations = [\"netwok_deny\"]\n",
            ValueError::UnknownObligation,
        ),
        (
            "\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\nobligations = [\"max_output_bytes\"]\n",
            ValueError::ObligationParameter,
        ),
        (
            "\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\nobligations = [\"max_output_bytes=0\"]\n",
            ValueError::ObligationParameter,
        ),
        (
            "\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\nobligations = [\"network_deny\", \"network_deny\"]\n",
            ValueError::DuplicateObligation,
        ),
        (
            "\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\nobligations = [\"max_output_bytes=1\", \"max_output_bytes=2\"]\n",
            ValueError::DuplicateObligation,
        ),
        (
            "\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\nobligations = []\n",
            ValueError::EmptyList,
        ),
    ] {
        match err_with(body) {
            PolicyLoadError::BadValue { error, .. } => assert_eq!(error, expected, "for {body:?}"),
            other => panic!("expected {expected} for {body:?}, got {other}"),
        }
    }
}

// ---------------------------------------------------------------------------
// The approval specification.
// ---------------------------------------------------------------------------

#[test]
fn an_approval_specification_is_required_exactly_where_it_means_something() {
    // A REQUIRE_APPROVAL with no shape does not say what a human would be
    // granting, and APPROVALS.md section 3 has no default to supply.
    let body = "\n[[rule]]\nid = \"r\"\neffect = \"REQUIRE_APPROVAL\"\nreason = \"UNKNOWN_EXECUTABLE\"\nwhen.verb = \"model.call\"\n";
    assert!(matches!(
        err_with(body),
        PolicyLoadError::ApprovalSpecMismatch { .. }
    ));

    // And an ALLOW or a DENY carrying one is a rule whose author misunderstood
    // what it does.
    for effect in ["ALLOW", "DENY"] {
        let body = format!(
            "\n[[rule]]\nid = \"r\"\neffect = \"{effect}\"\nreason = \"PROFILE_CEILING\"\nwhen.verb = \"model.call\"\n\
             approval.scope = \"exact_action\"\napproval.ttl = \"1h\"\napproval.max_uses = 1\n"
        );
        let body = if effect == "ALLOW" {
            body.replace("reason = \"PROFILE_CEILING\"\n", "")
        } else {
            body
        };
        assert!(
            matches!(
                err_with(&body),
                PolicyLoadError::ApprovalSpecMismatch { .. }
            ),
            "{effect} must not carry an approval shape"
        );
    }
}

#[test]
fn a_malformed_approval_specification_is_refused() {
    let base = "\n[[rule]]\nid = \"r\"\neffect = \"REQUIRE_APPROVAL\"\nreason = \"UNKNOWN_EXECUTABLE\"\nwhen.verb = \"model.call\"\n";
    for (spec, expected) in [
        (
            "approval.scope = \"whatever\"\napproval.ttl = \"1h\"\napproval.max_uses = 1\n",
            ValueError::UnknownApprovalScope,
        ),
        (
            "approval.scope = \"exact_action\"\napproval.ttl = \"forever\"\napproval.max_uses = 1\n",
            ValueError::Ttl,
        ),
        (
            "approval.scope = \"exact_action\"\napproval.ttl = \"10d\"\napproval.max_uses = 1\n",
            ValueError::Ttl,
        ),
        (
            "approval.scope = \"exact_action\"\napproval.ttl = \"4294967295h\"\napproval.max_uses = 1\n",
            ValueError::Ttl,
        ),
        (
            "approval.scope = \"exact_action\"\napproval.ttl = \"0s\"\napproval.max_uses = 1\n",
            ValueError::Ttl,
        ),
        (
            "approval.scope = \"exact_action\"\napproval.ttl = \"1h\"\napproval.max_uses = 0\n",
            ValueError::ApprovalUses,
        ),
        (
            "approval.scope = \"exact_action\"\napproval.ttl = \"1h\"\napproval.max_uses = 100000\n",
            ValueError::ApprovalUses,
        ),
    ] {
        match err_with(&format!("{base}{spec}")) {
            PolicyLoadError::BadValue { error, .. } => assert_eq!(error, expected, "for {spec:?}"),
            other => panic!("expected {expected} for {spec:?}, got {other}"),
        }
    }

    // A missing member of the table is a missing field, not a default.
    for spec in [
        "approval.ttl = \"1h\"\napproval.max_uses = 1\n",
        "approval.scope = \"exact_action\"\napproval.max_uses = 1\n",
        "approval.scope = \"exact_action\"\napproval.ttl = \"1h\"\n",
    ] {
        assert!(
            matches!(
                err_with(&format!("{base}{spec}")),
                PolicyLoadError::MissingField { .. }
            ),
            "{spec:?} must be refused"
        );
    }
}

// ---------------------------------------------------------------------------
// Rule-side values.
// ---------------------------------------------------------------------------

#[test]
fn a_path_anchor_outside_the_closed_set_is_refused() {
    for path in [
        "${HOME}",
        "${PATH}",
        "${WORKSPACE",
        "${}",
        "${workspace}",
        "$WORKSPACE/x",
    ] {
        let body = format!(
            "\n[[rule]]\nid = \"r\"\neffect = \"DENY\"\nreason = \"SENSITIVE_PATH\"\n\
             when.verb = \"fs.read\"\nwhen.path_under = [\"{path}\"]\n"
        );
        match err_with(&body) {
            PolicyLoadError::BadValue { error, .. } => assert!(
                matches!(
                    error,
                    ValueError::UnknownPathAnchor | ValueError::MalformedPath
                ),
                "{path} gave {error}"
            ),
            other => panic!("{path} must be refused, got {other}"),
        }
    }
}

#[test]
fn a_rule_side_path_must_be_one_a_canonical_path_could_equal() {
    for path in [
        "relative/path",
        "",
        "/etc//shadow",
        "/etc/shadow/",
        "/etc/./shadow",
        "/etc/../etc/shadow",
        "/etc/..",
    ] {
        let body = format!(
            "\n[[rule]]\nid = \"r\"\neffect = \"DENY\"\nreason = \"SENSITIVE_PATH\"\n\
             when.verb = \"fs.read\"\nwhen.path_under = [\"{path}\"]\n"
        );
        assert!(
            matches!(
                err_with(&body),
                PolicyLoadError::BadValue {
                    error: ValueError::MalformedPath,
                    ..
                }
            ),
            "{path:?} must be refused"
        );
    }
}

#[test]
fn a_host_pattern_may_not_wildcard_the_tld() {
    for host in [
        "*",
        "*.com",
        "*.",
        "**.example.com",
        "ex ample.com",
        "",
        "a..b",
    ] {
        let body = format!(
            "\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\n\
             when.verb = \"network.https\"\nwhen.host_matches = [\"{host}\"]\n"
        );
        assert!(
            matches!(
                err_with(&body),
                PolicyLoadError::BadValue {
                    error: ValueError::MalformedHost,
                    ..
                }
            ),
            "{host:?} must be refused as a host pattern"
        );
    }
}

#[test]
fn a_cidr_prefix_is_bounded_per_family_and_never_clamped() {
    for cidr in [
        "10.0.0.0/33",
        "10.0.0.0/999",
        "10.0.0.0",
        "10.0.0.0/",
        "10.0.0.0/-1",
        "10.0.0/8",
        "10.0.0.0.0/8",
        "256.0.0.0/8",
        "010.0.0.0/8",
        "10.0.0.1/24",
        "0000:0000:0000:0000:0000:0000:0000:0000/129",
        "::1/128",
        "0000:0000:0000:0000:0000:0000:0000:0001/64",
        "FC00:0000:0000:0000:0000:0000:0000:0000/7",
    ] {
        let body = format!(
            "\n[[rule]]\nid = \"r\"\neffect = \"DENY\"\nreason = \"SANDBOX_ESCAPE_VECTOR\"\n\
             when.verb = \"network.https\"\nwhen.ip_in = [\"{cidr}\"]\n"
        );
        assert!(
            matches!(
                err_with(&body),
                PolicyLoadError::BadValue {
                    error: ValueError::MalformedCidr,
                    ..
                }
            ),
            "{cidr:?} must be refused"
        );
    }

    // The boundaries themselves are fine.
    for cidr in [
        "10.0.0.0/8",
        "0.0.0.0/0",
        "127.0.0.1/32",
        "fc00:0000:0000:0000:0000:0000:0000:0000/7",
    ] {
        let body = format!(
            "\n[[rule]]\nid = \"r\"\neffect = \"DENY\"\nreason = \"SANDBOX_ESCAPE_VECTOR\"\n\
             when.verb = \"network.https\"\nwhen.ip_in = [\"{cidr}\"]\n"
        );
        load("t.toml", &with(&body)).unwrap_or_else(|e| panic!("{cidr} must load: {e}"));
    }
}

// ---------------------------------------------------------------------------
// Predicate applicability.
// ---------------------------------------------------------------------------

#[test]
fn a_predicate_that_could_never_hold_is_refused_rather_than_shipped() {
    // A rule whose predicates cannot apply to its own verbs never fires. Left
    // to run, it is a denial that silently does nothing.
    let body = "\n[[rule]]\nid = \"r\"\neffect = \"DENY\"\nreason = \"SENSITIVE_PATH\"\n\
                when.verb = [\"network.https\"]\nwhen.path_under = [\"/etc\"]\n";
    assert!(matches!(
        err_with(body),
        PolicyLoadError::PredicateNotApplicable { .. }
    ));

    let body = "\n[[rule]]\nid = \"r\"\neffect = \"ALLOW\"\n\
                when.verb = [\"fs.read\"]\nwhen.argv_safe = true\n";
    assert!(matches!(
        err_with(body),
        PolicyLoadError::PredicateNotApplicable { .. }
    ));
}

#[test]
fn a_verb_specific_predicate_requires_the_rule_to_state_its_verbs() {
    let body = "\n[[rule]]\nid = \"r\"\neffect = \"DENY\"\nreason = \"SENSITIVE_PATH\"\n\
                when.path_under = [\"/etc\"]\n";
    assert!(matches!(
        err_with(body),
        PolicyLoadError::PredicateNeedsVerbs { .. }
    ));
}

// ---------------------------------------------------------------------------
// Phases.
// ---------------------------------------------------------------------------

#[test]
fn a_primary_rule_cannot_select_on_the_provisional_effect() {
    // `provisional_effect` is phase two's selector. On a primary rule it would
    // be circular: the answer depends on the evaluation the rule is part of.
    let body = "\n[[rule]]\nid = \"r\"\neffect = \"DENY\"\nreason = \"NO_HUMAN_AVAILABLE\"\n\
                when.provisional_effect = [\"REQUIRE_APPROVAL\"]\n";
    match err_with(body) {
        PolicyLoadError::UnknownField { field, .. } => {
            assert!(field.as_str().ends_with("provisional_effect"), "{field}");
        }
        other => panic!("expected an unknown-field refusal, got {other}"),
    }
}

#[test]
fn there_is_no_would_require_approval_predicate_anywhere() {
    // The field POLICY.md section 3 wrote. It is not a caller-supplied
    // boolean, and it is not a phase-one predicate either -- the fact lives
    // in the evaluator and is spelled `provisional_effect` in phase two.
    for table in ["rule", "postcondition"] {
        let body = format!(
            "\n[[{table}]]\nid = \"r\"\neffect = \"DENY\"\nreason = \"NO_HUMAN_AVAILABLE\"\n\
             when.would_require_approval = true\n"
        );
        match err_with(&body) {
            PolicyLoadError::UnknownField { field, .. } => {
                assert!(
                    field.as_str().ends_with("would_require_approval"),
                    "{field}"
                );
            }
            other => panic!("expected an unknown-field refusal in [[{table}]], got {other}"),
        }
    }
}

#[test]
fn a_postcondition_that_could_widen_is_refused_at_load() {
    for (effect, selects) in [
        ("ALLOW", "[\"REQUIRE_APPROVAL\"]"),
        ("ALLOW", "[\"DENY\"]"),
        ("REQUIRE_APPROVAL", "[\"DENY\"]"),
        ("REQUIRE_APPROVAL", "[\"ALLOW\", \"DENY\"]"),
        // No selector means all three, so only DENY is narrower than
        // everything it could select.
        ("ALLOW", ""),
        ("REQUIRE_APPROVAL", ""),
    ] {
        let selector = if selects.is_empty() {
            String::new()
        } else {
            format!("when.provisional_effect = {selects}\n")
        };
        let body = format!(
            "\n[[postcondition]]\nid = \"p\"\neffect = \"{effect}\"\nreason = \"NO_HUMAN_AVAILABLE\"\n{selector}"
        );
        assert!(
            matches!(err_with(&body), PolicyLoadError::WideningExtension { .. }),
            "a {effect} postcondition selecting {selects:?} must be refused"
        );
    }
}

#[test]
fn a_postcondition_that_narrows_or_holds_is_accepted() {
    for (effect, selects) in [
        ("DENY", "[\"REQUIRE_APPROVAL\"]"),
        ("DENY", "[\"ALLOW\", \"REQUIRE_APPROVAL\"]"),
        ("DENY", ""),
        ("REQUIRE_APPROVAL", "[\"REQUIRE_APPROVAL\"]"),
        ("REQUIRE_APPROVAL", "[\"ALLOW\", \"REQUIRE_APPROVAL\"]"),
    ] {
        let selector = if selects.is_empty() {
            String::new()
        } else {
            format!("when.provisional_effect = {selects}\n")
        };
        let body = format!(
            "\n[[postcondition]]\nid = \"p\"\neffect = \"{effect}\"\nreason = \"NO_HUMAN_AVAILABLE\"\n{selector}"
        );
        load("t.toml", &with(&body))
            .unwrap_or_else(|e| panic!("{effect} selecting {selects:?} must load: {e}"));
    }
}

#[test]
fn a_postcondition_cannot_be_the_default_and_cannot_carry_a_permission() {
    let body = "\n[[postcondition]]\nid = \"default\"\neffect = \"DENY\"\nreason = \"NO_HUMAN_AVAILABLE\"\n";
    assert!(matches!(
        err_with(body),
        PolicyLoadError::BadValue {
            error: ValueError::MalformedRuleId,
            ..
        }
    ));

    for member in [
        "obligations = [\"network_deny\"]",
        "approval.scope = \"exact_action\"",
    ] {
        let body = format!(
            "\n[[postcondition]]\nid = \"p\"\neffect = \"DENY\"\nreason = \"NO_HUMAN_AVAILABLE\"\n{member}\n"
        );
        assert!(
            matches!(err_with(&body), PolicyLoadError::UnknownField { .. }),
            "a postcondition must not carry {member}"
        );
    }
}

#[test]
fn too_many_postconditions_is_refused() {
    let mut body = String::new();
    for index in 0..40 {
        body.push_str(&format!(
            "\n[[postcondition]]\nid = \"p{index}\"\neffect = \"DENY\"\nreason = \"NO_HUMAN_AVAILABLE\"\n"
        ));
    }
    assert!(matches!(
        err_with(&body),
        PolicyLoadError::TooManyRules { .. }
    ));
}

// ---------------------------------------------------------------------------
// Determinism and source locations.
// ---------------------------------------------------------------------------

#[test]
fn a_rule_reports_the_line_its_header_is_on() {
    let source = "schema_version = 1\n\n[meta]\nname = \"t\"\n\n\
                  [[rule]]\nid = \"first\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\n\n\
                  [[rule]]\nid = \"default\"\neffect = \"DENY\"\nreason = \"NO_MATCHING_RULE\"\n";
    let profile = load("balanced.toml", source).expect("loads");
    // `[[rule]]` for `first` is line 6; for `default`, line 11.
    assert_eq!(profile.rules()[0].source().line(), 6);
    assert_eq!(profile.rules()[1].source().line(), 11);
    assert_eq!(profile.rules()[0].source().to_string(), "balanced.toml:6");
    // Not a placeholder: two rules in one file have two different lines.
    assert_ne!(
        profile.rules()[0].source().line(),
        profile.rules()[1].source().line()
    );
}

#[test]
fn source_lines_do_not_depend_on_the_line_endings() {
    let lf = "schema_version = 1\n\n[meta]\nname = \"t\"\n\n\
              [[rule]]\nid = \"default\"\neffect = \"DENY\"\nreason = \"NO_MATCHING_RULE\"\n";
    let crlf = lf.replace('\n', "\r\n");
    let (a, b) = (
        load("t.toml", lf).expect("LF loads"),
        load("t.toml", &crlf).expect("CRLF loads"),
    );
    assert_eq!(a, b);
    assert_eq!(a.rules()[0].source().line(), 6);
}

#[test]
fn loading_the_same_source_twice_gives_the_same_policy() {
    let source = with(
        "\n[[rule]]\nid = \"a\"\neffect = \"ALLOW\"\nwhen.verb = [\"model.call\", \"memory.read\"]\n\
         obligations = [\"network_deny\", \"read_only_workspace\"]\n",
    );
    let first = load("t.toml", &source).expect("loads");
    for _ in 0..16 {
        assert_eq!(load("t.toml", &source).expect("loads"), first);
    }
}

#[test]
fn the_order_a_list_is_written_in_does_not_change_the_obligations() {
    let one = load(
        "t.toml",
        &with("\n[[rule]]\nid = \"a\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\nobligations = [\"network_deny\", \"single_use_only\"]\n"),
    )
    .expect("loads");
    let two = load(
        "t.toml",
        &with("\n[[rule]]\nid = \"a\"\neffect = \"ALLOW\"\nwhen.verb = \"model.call\"\nobligations = [\"single_use_only\", \"network_deny\"]\n"),
    )
    .expect("loads");
    assert_eq!(one.rules()[0].obligations(), two.rules()[0].obligations());
}

// ---------------------------------------------------------------------------
// Nothing panics.
// ---------------------------------------------------------------------------

#[test]
fn no_malformed_input_panics() {
    // Everything above asserts a *specific* refusal. This asserts the weaker
    // property over a wider corpus: whatever happens, the loader returns.
    let corpus: Vec<String> = vec![
        String::new(),
        "\0".to_owned(),
        "\u{feff}schema_version = 1".to_owned(),
        "[".repeat(1000),
        "[[rule]]".repeat(500),
        "schema_version = 1\n[meta]\nname = \"\u{1f600}\"\n".to_owned(),
        "schema_version = 1\n[[rule]]\nid = \"a\"\neffect = \"\"\n".to_owned(),
        format!("schema_version = 1\n[meta]\nname = \"{}\"\n", "a".repeat(10_000)),
        "= 1".to_owned(),
        "schema_version = 1\nrule = 1\n".to_owned(),
        "schema_version = 1\nrule = [1, 2, 3]\n".to_owned(),
        "schema_version = 1\npostcondition = \"x\"\n".to_owned(),
        "schema_version = 1\n[meta]\nname = 1\n".to_owned(),
        "schema_version = 1\n[[rule]]\n".to_owned(),
        "schema_version = 1\n[[rule]]\nid = 1\n".to_owned(),
        "schema_version = 1\n[[rule]]\nid = \"a\"\neffect = \"DENY\"\nreason = \"SENSITIVE_PATH\"\nwhen = 1\n".to_owned(),
        "schema_version = 1\n[[rule]]\nid = \"a\"\neffect = \"DENY\"\nreason = \"SENSITIVE_PATH\"\nunless = []\n".to_owned(),
        "schema_version = 1\n[[rule]]\nid = \"a\"\neffect = \"DENY\"\nreason = \"SENSITIVE_PATH\"\napproval = 3\n".to_owned(),
        "schema_version = 1\n[[rule]]\nid = \"a\"\neffect = \"ALLOW\"\nobligations = \"network_deny\"\n".to_owned(),
        "schema_version = 1\n[[rule]]\nid = \"a\"\neffect = \"ALLOW\"\nwhen.max_bytes = 1970-01-01\n".to_owned(),
        "schema_version = 1\n[[rule]]\nid = \"a\"\neffect = \"ALLOW\"\nwhen.verb = { a = 1 }\n".to_owned(),
    ];
    for source in corpus {
        // Some of these load; most do not. Neither outcome may be a panic, and
        // an accepted one must still have a denying default.
        if let Ok(profile) = load("t.toml", &source) {
            assert!(profile.rules().last().is_some_and(|r| r.is_default()));
        }
    }
}
