//! The strict loader: bounded policy text in, a compiled [`Profile`] out.
//!
//! # It opens nothing
//!
//! [`load`] takes a logical source name and the source *text*. It does not
//! read a file, consult a directory, resolve a path or look at an environment
//! variable. Reading the operator's policy file belongs to the authority layer
//! that owns the policy directory; keeping it out of here makes the loader
//! pure, replayable and fuzzable, and means a policy file cannot cause the
//! trusted computing base to open anything.
//!
//! # Bounds come before the work they bound
//!
//! The length check happens before [`toml`] is called, not after it has
//! allocated. See [`limits`] for the numbers and for why a limit applied
//! afterwards is not a limit.
//!
//! # Strict means strict
//!
//! Every table has a closed member list and an unknown member is an error.
//! That single rule is the most valuable thing in this file:
//! `when.destinatoin_novel = true` must fail loading, because the alternative
//! is a rule that looks like it constrains something and does not.
//!
//! **No coercion of any kind.** `schema_version = "1"` is not `1`,
//! `argv_safe = "true"` is not `true`, `max_uses = 1.5` is not `1`, and —
//! the one that is easy to miss, because it looks like a convenience rather
//! than a conversion — `when.verb = "fs.read"` is not
//! `when.verb = ["fs.read"]`. [`POLICY.md`] §3 documents both spellings for a
//! match predicate, so both load, as [`MatchValue::Eq`] and
//! [`MatchValue::In`] respectively. A loader that read the first as the
//! second would have two source shapes entering the compiled policy as one,
//! and a strict loader that coerces in one direction has a coercion.
//!
//! So there are three shapes a field can take, and each field takes exactly
//! one of them:
//!
//! | shape | fields | a wrong shape is |
//! |---|---|---|
//! | **match** — scalar *or* list | the ten `when` predicates that name values | a type error |
//! | **scalar only** | `max_bytes`, `argv_safe`, `destination_novel`, `unless.*`, and every identifier and enum outside `when` | a type error |
//! | **list only** | `obligations` | a type error |
//!
//! A malformed policy never becomes a valid weaker policy.
//!
//! [`MatchValue::Eq`]: super::predicate::MatchValue::Eq
//! [`MatchValue::In`]: super::predicate::MatchValue::In
//! [`POLICY.md`]: ../../../../../docs/POLICY.md
//!
//! # Why the document API rather than `serde`
//!
//! [`toml::de::DeTable`] is the parsed document with a byte span on every key
//! and value, and it is available behind the `parse` feature alone. Walking it
//! by hand gives two things a derived deserializer cannot: the spans that make
//! `rule_source` a real line, and a closed member list at every level that is
//! *code* rather than an attribute someone can forget to write. It also keeps
//! `serde_core` out of the authority's dependency closure entirely — see
//! [ADR-0038] on why this milestone links one fewer crate than
//! [ADR-0035](../../../../../docs/adr/0035-m3-authority-dependency-set.md)
//! measured.
//!
//! [ADR-0038]: ../../../../../docs/adr/0038-policy-evaluation-phases-and-composition.md

use toml::de::{DeArray, DeTable, DeValue};

use crate::capability::{HostPattern, PrivacyClass, Verb};

use super::action::{ArgvSafety, Environment, Novelty};
use super::approval::{ApprovalScopeKind, ApprovalSpec, Ttl};
use super::context::{ConfigKey, Origin, TaintLevel};
use super::effect::Effect;
use super::error::{Expected, FieldPath, PolicyLoadError, ValueError};
use super::limits;
use super::obligation::{Obligation, Obligations};
use super::predicate::{MatchValue, PredicateName, Unless, When};
use super::reason::Reason;
use super::rule::{Postcondition, Profile, ProfileName, Rule};
use super::value::{Cidr, ExecutableSpec, RulePath};
use super::{RuleId, SourceLocation};

/// The only policy schema version this build implements.
pub const SCHEMA_VERSION: u32 = 1;

/// Members the document may have.
const TOP_LEVEL: &[&str] = &["schema_version", "meta", "rule", "postcondition"];
/// Members `[meta]` may have.
const META: &[&str] = &["name", "extends"];
/// Members a `[[rule]]` may have.
const RULE: &[&str] = &[
    "id",
    "effect",
    "reason",
    "when",
    "unless",
    "obligations",
    "approval",
];
/// Members a `[[postcondition]]` may have.
///
/// No `obligations` and no `approval`: a postcondition narrows a decision, and
/// a narrowing that added a permission's conditions or offered an approval
/// shape would be doing something other than narrowing.
const POSTCONDITION: &[&str] = &["id", "effect", "reason", "when", "unless"];
/// Members `unless` may have.
const UNLESS: &[&str] = &["config", "standing_grant"];
/// Members `approval` may have.
const APPROVAL: &[&str] = &["scope", "ttl", "max_uses"];

/// Compile one policy source.
///
/// # Errors
///
/// [`PolicyLoadError`], which is a closed enum of categories rather than a
/// message: a caller distinguishing "the operator made a mistake" from
/// "something tried to widen a profile" matches on the variant.
pub fn load(source_name: &str, source_text: &str) -> Result<Profile, PolicyLoadError> {
    // Before the parser. A 200 MB document is refused by length, not after
    // being parsed into a document nobody wanted.
    if source_text.len() > limits::MAX_SOURCE_BYTES {
        return Err(PolicyLoadError::SourceTooLarge {
            bytes: source_text.len(),
            limit: limits::MAX_SOURCE_BYTES,
        });
    }
    let Some(origin) = SourceLocation::new(source_name, 1) else {
        return Err(PolicyLoadError::SourceNameInvalid);
    };

    let walker = Walker {
        source_name,
        source_text,
        origin,
    };

    let document = DeTable::parse(source_text).map_err(|error| PolicyLoadError::Syntax {
        // The parser reports a byte span into the same source, so the line is
        // computed the same way every other location in this file is -- one
        // rule for line numbers, not two that could disagree.
        at: error
            .span()
            .map_or_else(|| walker.origin.clone(), |span| walker.at(span)),
        message: error.to_string(),
    })?;

    walker.profile(document.get_ref())
}

/// Walks a parsed document against the closed schema.
struct Walker<'a> {
    source_name: &'a str,
    source_text: &'a str,
    origin: SourceLocation,
}

impl Walker<'_> {
    /// The line a byte offset falls on, counting from one.
    ///
    /// `\n` only, so a CRLF file and an LF file with the same rules report the
    /// same lines. A location must not depend on how the file was checked out.
    fn line_of(&self, offset: usize) -> u32 {
        let counted = self
            .source_text
            .get(..offset)
            .map_or(0, |prefix| prefix.bytes().filter(|b| *b == b'\n').count());
        u32::try_from(counted).map_or(u32::MAX, |n| n.saturating_add(1))
    }

    /// The location of a span.
    fn at(&self, span: core::ops::Range<usize>) -> SourceLocation {
        SourceLocation::new(self.source_name, self.line_of(span.start))
            .unwrap_or_else(|| self.origin.clone())
    }

    /// The whole document.
    fn profile(&self, document: &DeTable<'_>) -> Result<Profile, PolicyLoadError> {
        let root = FieldPath::root();
        self.reject_unknown(document, TOP_LEVEL, &root)?;
        self.schema_version(document, &root)?;

        let (name, extends) = self.meta(document, &root)?;
        let rules = self.rules(document, &root, extends.is_some())?;
        let postconditions = self.postconditions(document, &root, &rules)?;

        Ok(Profile::new(
            name,
            self.origin.clone(),
            extends,
            rules,
            postconditions,
        ))
    }

    /// `schema_version = 1`, mandatory, exact.
    fn schema_version(
        &self,
        document: &DeTable<'_>,
        path: &FieldPath,
    ) -> Result<(), PolicyLoadError> {
        let field = path.member("schema_version");
        let Some((_, value)) = find(document, "schema_version") else {
            return Err(PolicyLoadError::SchemaVersionMissing {
                at: self.origin.clone(),
            });
        };
        let at = self.at(value.span());
        // Not `as_integer()`-with-a-fallback: a string "1" and a float 1.0 are
        // both refused, because a version this build cannot interpret must not
        // be interpreted.
        let DeValue::Integer(integer) = value.get_ref() else {
            return Err(PolicyLoadError::TypeMismatch {
                at,
                field,
                expected: Expected::Integer,
            });
        };
        let found = i64::from_str_radix(integer.as_str(), integer.radix()).unwrap_or(i64::MIN);
        if found != i64::from(SCHEMA_VERSION) {
            return Err(PolicyLoadError::SchemaVersionUnsupported {
                at,
                found,
                supported: SCHEMA_VERSION,
            });
        }
        Ok(())
    }

    /// `[meta]`.
    fn meta(
        &self,
        document: &DeTable<'_>,
        path: &FieldPath,
    ) -> Result<(ProfileName, Option<ProfileName>), PolicyLoadError> {
        let field = path.member("meta");
        let Some((_, value)) = find(document, "meta") else {
            return Err(PolicyLoadError::MissingField {
                at: self.origin.clone(),
                field,
            });
        };
        let table = self.expect_table(value, &field)?;
        self.reject_unknown(table, META, &field)?;

        let name = self.required_str(table, "name", &field)?;
        let name_field = field.member("name");
        let name = ProfileName::new(name.0).map_err(|error| PolicyLoadError::BadValue {
            at: name.1.clone(),
            field: name_field,
            error,
        })?;

        let extends = match self.optional_str(table, "extends", &field)? {
            None => None,
            Some((text, at)) => {
                Some(
                    ProfileName::new(text).map_err(|error| PolicyLoadError::BadValue {
                        at,
                        field: field.member("extends"),
                        error,
                    })?,
                )
            }
        };
        Ok((name, extends))
    }

    /// Every `[[rule]]`, in source order, with the default-rule rules applied.
    fn rules(
        &self,
        document: &DeTable<'_>,
        path: &FieldPath,
        extending: bool,
    ) -> Result<Vec<Rule>, PolicyLoadError> {
        let field = path.member("rule");
        let Some((_, value)) = find(document, "rule") else {
            // An extending profile that adds only postconditions is legal and
            // has no rules at all; a root profile with none has no default.
            return if extending {
                Ok(Vec::new())
            } else {
                Err(PolicyLoadError::DefaultRuleMissing {
                    at: self.origin.clone(),
                })
            };
        };
        let array = self.expect_array(value, &field)?;
        if array.len() > limits::MAX_RULES {
            return Err(PolicyLoadError::TooManyRules {
                at: self.at(value.span()),
                count: array.len(),
                limit: limits::MAX_RULES,
            });
        }

        let mut rules: Vec<Rule> = Vec::with_capacity(array.len());
        let mut seen: Vec<(String, SourceLocation)> = Vec::new();
        for (index, element) in array.iter().enumerate() {
            let field = field.index(index);
            let at = self.at(element.span());
            let table = self.expect_table(element, &field)?;
            self.reject_unknown(table, RULE, &field)?;
            let rule = self.rule(table, &field, &at)?;
            remember_id(&mut seen, rule.id(), &at)?;
            rules.push(rule);
        }
        self.check_default(&rules, extending)?;
        Ok(rules)
    }

    /// One `[[rule]]`.
    fn rule(
        &self,
        table: &DeTable<'_>,
        field: &FieldPath,
        at: &SourceLocation,
    ) -> Result<Rule, PolicyLoadError> {
        let id = self.rule_id(table, field)?;
        let effect = self.effect(table, field)?;
        let when = self.when(table, field, false)?;
        let unless = self.unless(table, field)?;
        let reason = self.reason(table, field, effect)?;
        let obligations = self.obligations(table, field)?;
        let approval = self.approval(table, field, effect, at)?;

        self.check_applicability(&when, &unless, field, at)?;

        Ok(Rule::new(
            id,
            at.clone(),
            effect,
            reason,
            when,
            unless,
            obligations,
            approval,
        ))
    }

    /// Every `[[postcondition]]`.
    fn postconditions(
        &self,
        document: &DeTable<'_>,
        path: &FieldPath,
        rules: &[Rule],
    ) -> Result<Vec<Postcondition>, PolicyLoadError> {
        let field = path.member("postcondition");
        let Some((_, value)) = find(document, "postcondition") else {
            return Ok(Vec::new());
        };
        let array = self.expect_array(value, &field)?;
        if array.len() > limits::MAX_POSTCONDITIONS {
            return Err(PolicyLoadError::TooManyRules {
                at: self.at(value.span()),
                count: array.len(),
                limit: limits::MAX_POSTCONDITIONS,
            });
        }

        // One namespace for both: a postcondition sharing an id with a rule
        // would make an audit record ambiguous about which fired.
        let mut seen: Vec<(String, SourceLocation)> = rules
            .iter()
            .map(|rule| (rule.id().as_str().to_owned(), rule.source().clone()))
            .collect();

        let mut out = Vec::with_capacity(array.len());
        for (index, element) in array.iter().enumerate() {
            let field = field.index(index);
            let at = self.at(element.span());
            let table = self.expect_table(element, &field)?;
            self.reject_unknown(table, POSTCONDITION, &field)?;

            let id = self.rule_id(table, &field)?;
            if id.is_default() {
                return Err(PolicyLoadError::BadValue {
                    at,
                    field: field.member("id"),
                    error: ValueError::MalformedRuleId,
                });
            }
            let effect = self.effect(table, &field)?;
            let when = self.when(table, &field, true)?;
            let unless = self.unless(table, &field)?;
            let reason = self.reason(table, &field, effect)?;
            self.check_applicability(&when, &unless, &field, &at)?;

            let post = Postcondition::new(id, at.clone(), effect, reason, when, unless);
            if !post.narrows() {
                return Err(PolicyLoadError::WideningExtension {
                    at,
                    id: post.id().to_string(),
                    detail: POSTCONDITION_WIDENS,
                });
            }
            remember_id(&mut seen, post.id(), &at)?;
            out.push(post);
        }
        Ok(out)
    }

    /// `id`, which must be the identifier grammar.
    fn rule_id(&self, table: &DeTable<'_>, field: &FieldPath) -> Result<RuleId, PolicyLoadError> {
        let (text, at) = self.required_str(table, "id", field)?;
        RuleId::new(text).ok_or(PolicyLoadError::BadValue {
            at,
            field: field.member("id"),
            error: ValueError::MalformedRuleId,
        })
    }

    /// `effect`, mandatory.
    fn effect(&self, table: &DeTable<'_>, field: &FieldPath) -> Result<Effect, PolicyLoadError> {
        let (text, at) = self.required_str(table, "effect", field)?;
        Effect::parse(text).ok_or(PolicyLoadError::BadValue {
            at,
            field: field.member("effect"),
            error: ValueError::UnknownEffect,
        })
    }

    /// `reason`, mandatory for a refusal and defaulted for a permission.
    ///
    /// An `ALLOW` that names no reason gets [`Reason::PermittedByRule`] rather
    /// than an empty string, because [`super::Decision`] carries a reason
    /// unconditionally and a blank one reads as a missing field.
    fn reason(
        &self,
        table: &DeTable<'_>,
        field: &FieldPath,
        effect: Effect,
    ) -> Result<Reason, PolicyLoadError> {
        let member = field.member("reason");
        match self.optional_str(table, "reason", field)? {
            Some((text, at)) => {
                let reason = Reason::parse(text).ok_or(PolicyLoadError::BadValue {
                    at: at.clone(),
                    field: member.clone(),
                    error: ValueError::UnknownReason,
                })?;
                if reason.is_authorable() {
                    Ok(reason)
                } else {
                    Err(PolicyLoadError::BadValue {
                        at,
                        field: member,
                        error: ValueError::UnknownReason,
                    })
                }
            }
            None => match effect {
                Effect::Allow => Ok(Reason::PermittedByRule),
                Effect::Deny | Effect::RequireApproval => Err(PolicyLoadError::MissingField {
                    at: self.origin.clone(),
                    field: member,
                }),
            },
        }
    }

    /// `obligations`, a list of closed names.
    fn obligations(
        &self,
        table: &DeTable<'_>,
        field: &FieldPath,
    ) -> Result<Obligations, PolicyLoadError> {
        let member = field.member("obligations");
        let Some((_, value)) = find(table, "obligations") else {
            return Ok(Obligations::none());
        };
        let at = self.at(value.span());
        // LIST ONLY. `obligations` is an output set, not a match predicate, so
        // the scalar spelling POLICY.md documents for `eq` does not apply to
        // it and `obligations = "network_deny"` is a type error.
        let texts = self.string_array(value, &member, Expected::Array)?;
        let mut parsed = Vec::with_capacity(texts.len());
        for (text, at) in texts {
            parsed.push(
                Obligation::parse(&text).map_err(|error| PolicyLoadError::BadValue {
                    at,
                    field: member.clone(),
                    error,
                })?,
            );
        }
        Obligations::new(parsed).map_err(|error| PolicyLoadError::BadValue {
            at,
            field: member,
            error,
        })
    }

    /// `[rule.approval]`, required on a `REQUIRE_APPROVAL` and refused
    /// elsewhere.
    fn approval(
        &self,
        table: &DeTable<'_>,
        field: &FieldPath,
        effect: Effect,
        at: &SourceLocation,
    ) -> Result<Option<ApprovalSpec>, PolicyLoadError> {
        let member = field.member("approval");
        let Some((_, value)) = find(table, "approval") else {
            return match effect {
                // APPROVALS.md section 3: scope breadth and max_uses must
                // scale together, so neither has a default the loader could
                // supply. A REQUIRE_APPROVAL with no shape is a rule whose
                // author did not say what a human would be granting.
                Effect::RequireApproval => Err(PolicyLoadError::ApprovalSpecMismatch {
                    at: at.clone(),
                    detail: "a REQUIRE_APPROVAL rule must have an [approval] table \
                             giving scope, ttl and max_uses",
                }),
                Effect::Allow | Effect::Deny => Ok(None),
            };
        };
        if effect != Effect::RequireApproval {
            return Err(PolicyLoadError::ApprovalSpecMismatch {
                at: self.at(value.span()),
                detail: "only a REQUIRE_APPROVAL rule may have an [approval] table",
            });
        }
        let table = self.expect_table(value, &member)?;
        self.reject_unknown(table, APPROVAL, &member)?;

        let (scope, scope_at) = self.required_str(table, "scope", &member)?;
        let scope = ApprovalScopeKind::parse(scope).ok_or(PolicyLoadError::BadValue {
            at: scope_at,
            field: member.member("scope"),
            error: ValueError::UnknownApprovalScope,
        })?;

        let (ttl, ttl_at) = self.required_str(table, "ttl", &member)?;
        let ttl = Ttl::parse(ttl).map_err(|error| PolicyLoadError::BadValue {
            at: ttl_at,
            field: member.member("ttl"),
            error,
        })?;

        let (uses, uses_at) = self.required_u64(table, "max_uses", &member)?;
        let uses = u32::try_from(uses).map_err(|_| PolicyLoadError::BadValue {
            at: uses_at.clone(),
            field: member.member("max_uses"),
            error: ValueError::NumericRange,
        })?;

        ApprovalSpec::new(scope, ttl, uses)
            .map(Some)
            .map_err(|error| PolicyLoadError::BadValue {
                at: uses_at,
                field: member.member("max_uses"),
                error,
            })
    }

    /// `[rule.when]`.
    fn when(
        &self,
        table: &DeTable<'_>,
        field: &FieldPath,
        postcondition: bool,
    ) -> Result<When, PolicyLoadError> {
        let member = field.member("when");
        let Some((_, value)) = find(table, "when") else {
            return Ok(When::default());
        };
        let table = self.expect_table(value, &member)?;

        // The closed predicate vocabulary, filtered by phase: only a
        // postcondition may select on the provisional effect, and a primary
        // rule that tried would be asking about an evaluation it is part of.
        let allowed: Vec<&str> = PredicateName::ALL
            .iter()
            .filter(|name| {
                !matches!(
                    name,
                    PredicateName::UnlessConfig | PredicateName::UnlessStandingGrant
                ) && (postcondition || **name != PredicateName::ProvisionalEffect)
            })
            .map(|name| name.as_str())
            .collect();
        self.reject_unknown(table, &allowed, &member)?;

        // One expression, so every predicate is visibly accounted for and a
        // new field added to `When` is a compile error here rather than a
        // predicate that silently stays `None`.
        // Ten MATCH predicates, each of which keeps the spelling it was
        // written in, and three SCALAR ones, each of which refuses a list.
        // One expression, so a new field on `When` is a compile error here
        // rather than a predicate that silently stays `None`.
        Ok(When {
            verb: self.match_value(table, "verb", &member, |text| {
                parse_verb(text).ok_or(ValueError::UnknownVerb)
            })?,
            path_under: self.match_value(table, "path_under", &member, RulePath::parse)?,
            max_bytes: self
                .optional_u64(table, "max_bytes", &member)?
                .map(|(value, _)| value),
            executable_in: self.match_value(
                table,
                "executable_in",
                &member,
                ExecutableSpec::parse,
            )?,
            argv_safe: self
                .optional_bool(table, "argv_safe", &member)?
                .map(|(flag, _)| ArgvSafety::from_rule_flag(flag)),
            host_matches: self.match_value(table, "host_matches", &member, |text| {
                HostPattern::parse(text).map_err(|_| ValueError::MalformedHost)
            })?,
            ip_in: self.match_value(table, "ip_in", &member, Cidr::parse)?,
            destination_novel: self
                .optional_bool(table, "destination_novel", &member)?
                .map(|(flag, _)| Novelty::from_rule_flag(flag)),
            environment: self.match_value(table, "environment", &member, |text| {
                Environment::parse(text).ok_or(ValueError::UnknownEnvironment)
            })?,
            origin: self.match_value(table, "origin", &member, |text| {
                Origin::parse(text).ok_or(ValueError::UnknownOrigin)
            })?,
            taint_level: self.match_value(table, "taint_level", &member, |text| {
                TaintLevel::parse(text).ok_or(ValueError::UnknownTaintLevel)
            })?,
            privacy_class: self.match_value(table, "privacy_class", &member, |text| {
                PrivacyClass::parse(text).ok_or(ValueError::UnknownPrivacyClass)
            })?,
            provisional_effect: self.match_value(table, "provisional_effect", &member, |text| {
                Effect::parse(text).ok_or(ValueError::UnknownEffect)
            })?,
        })
    }

    /// `[rule.unless]`.
    fn unless(&self, table: &DeTable<'_>, field: &FieldPath) -> Result<Unless, PolicyLoadError> {
        let member = field.member("unless");
        let Some((_, value)) = find(table, "unless") else {
            return Ok(Unless::default());
        };
        let table = self.expect_table(value, &member)?;
        self.reject_unknown(table, UNLESS, &member)?;

        let config = match self.optional_str(table, "config", &member)? {
            None => None,
            Some((text, at)) => Some(ConfigKey::parse(text).ok_or(PolicyLoadError::BadValue {
                at,
                field: member.member("config"),
                error: ValueError::UnknownConfigKey,
            })?),
        };
        let standing_grant = self
            .optional_bool(table, "standing_grant", &member)?
            .map(|(flag, _)| flag);
        Ok(Unless {
            config,
            standing_grant,
        })
    }

    // ---- schema mechanics -------------------------------------------------

    /// Refuse any member the schema does not define.
    ///
    /// The most valuable four lines in the loader.
    fn reject_unknown(
        &self,
        table: &DeTable<'_>,
        allowed: &[&str],
        path: &FieldPath,
    ) -> Result<(), PolicyLoadError> {
        for (key, _) in table {
            let name: &str = key.get_ref().as_ref();
            if !allowed.contains(&name) {
                return Err(PolicyLoadError::UnknownField {
                    at: self.at(key.span()),
                    field: path.member(name),
                });
            }
        }
        Ok(())
    }

    /// A member that must be a table.
    fn expect_table<'t>(
        &self,
        value: &'t toml::Spanned<DeValue<'t>>,
        field: &FieldPath,
    ) -> Result<&'t DeTable<'t>, PolicyLoadError> {
        match value.get_ref() {
            DeValue::Table(table) => Ok(table),
            _ => Err(PolicyLoadError::TypeMismatch {
                at: self.at(value.span()),
                field: field.clone(),
                expected: Expected::Table,
            }),
        }
    }

    /// A member that must be an array.
    fn expect_array<'t>(
        &self,
        value: &'t toml::Spanned<DeValue<'t>>,
        field: &FieldPath,
    ) -> Result<&'t DeArray<'t>, PolicyLoadError> {
        match value.get_ref() {
            DeValue::Array(array) => Ok(array),
            _ => Err(PolicyLoadError::TypeMismatch {
                at: self.at(value.span()),
                field: field.clone(),
                expected: Expected::Array,
            }),
        }
    }

    /// A mandatory string member.
    fn required_str<'t>(
        &self,
        table: &'t DeTable<'t>,
        name: &str,
        path: &FieldPath,
    ) -> Result<(&'t str, SourceLocation), PolicyLoadError> {
        match self.optional_str(table, name, path)? {
            Some(found) => Ok(found),
            None => Err(PolicyLoadError::MissingField {
                at: self.origin.clone(),
                field: path.member(name),
            }),
        }
    }

    /// An optional string member, bounded.
    fn optional_str<'t>(
        &self,
        table: &'t DeTable<'t>,
        name: &str,
        path: &FieldPath,
    ) -> Result<Option<(&'t str, SourceLocation)>, PolicyLoadError> {
        let Some((_, value)) = find(table, name) else {
            return Ok(None);
        };
        let at = self.at(value.span());
        let DeValue::String(text) = value.get_ref() else {
            return Err(PolicyLoadError::TypeMismatch {
                at,
                field: path.member(name),
                expected: Expected::String,
            });
        };
        let text: &str = text.as_ref();
        if text.chars().count() > limits::MAX_STRING_CHARS {
            return Err(PolicyLoadError::BadValue {
                at,
                field: path.member(name),
                error: ValueError::StringTooLong,
            });
        }
        Ok(Some((text, at)))
    }

    /// A mandatory unsigned integer member.
    fn required_u64(
        &self,
        table: &DeTable<'_>,
        name: &str,
        path: &FieldPath,
    ) -> Result<(u64, SourceLocation), PolicyLoadError> {
        match self.optional_u64(table, name, path)? {
            Some(found) => Ok(found),
            None => Err(PolicyLoadError::MissingField {
                at: self.origin.clone(),
                field: path.member(name),
            }),
        }
    }

    /// An optional unsigned integer member.
    ///
    /// A float is a type mismatch, not a truncation: `max_uses = 1.5` is
    /// refused rather than read as `1`. A negative value does not wrap —
    /// `from_str_radix` on a `u64` refuses the sign — and a value past
    /// `u64::MAX` does not saturate.
    fn optional_u64(
        &self,
        table: &DeTable<'_>,
        name: &str,
        path: &FieldPath,
    ) -> Result<Option<(u64, SourceLocation)>, PolicyLoadError> {
        let Some((_, value)) = find(table, name) else {
            return Ok(None);
        };
        let at = self.at(value.span());
        let DeValue::Integer(integer) = value.get_ref() else {
            return Err(PolicyLoadError::TypeMismatch {
                at,
                field: path.member(name),
                expected: Expected::Integer,
            });
        };
        let parsed = u64::from_str_radix(integer.as_str(), integer.radix()).map_err(|_| {
            PolicyLoadError::BadValue {
                at: at.clone(),
                field: path.member(name),
                error: ValueError::NumericRange,
            }
        })?;
        Ok(Some((parsed, at)))
    }

    /// An optional boolean member.
    ///
    /// A string `"true"` is a type mismatch. TOML distinguishes them and so
    /// does this: `argv_safe = "true"` is a rule whose author thought they had
    /// written a predicate.
    fn optional_bool(
        &self,
        table: &DeTable<'_>,
        name: &str,
        path: &FieldPath,
    ) -> Result<Option<(bool, SourceLocation)>, PolicyLoadError> {
        let Some((_, value)) = find(table, name) else {
            return Ok(None);
        };
        let at = self.at(value.span());
        match value.get_ref() {
            DeValue::Boolean(flag) => Ok(Some((*flag, at))),
            _ => Err(PolicyLoadError::TypeMismatch {
                at,
                field: path.member(name),
                expected: Expected::Boolean,
            }),
        }
    }

    /// The elements of a string ARRAY, bounded. The value must be an array.
    ///
    /// A scalar here is a type error, not a one-element list. See
    /// [`Walker::match_value`] for the fields whose grammar genuinely admits
    /// both spellings, and why they do not come through this function.
    fn string_array(
        &self,
        value: &toml::Spanned<DeValue<'_>>,
        field: &FieldPath,
        expected: Expected,
    ) -> Result<Vec<(String, SourceLocation)>, PolicyLoadError> {
        let at = self.at(value.span());
        let DeValue::Array(array) = value.get_ref() else {
            return Err(PolicyLoadError::TypeMismatch {
                at,
                field: field.clone(),
                expected,
            });
        };
        if array.len() > limits::MAX_LIST_ITEMS {
            return Err(PolicyLoadError::BadValue {
                at,
                field: field.clone(),
                error: ValueError::TooManyListItems,
            });
        }
        if array.is_empty() {
            // An empty predicate list is a predicate nothing satisfies, which
            // is a rule that never fires written as a rule that does.
            return Err(PolicyLoadError::BadValue {
                at,
                field: field.clone(),
                error: ValueError::EmptyList,
            });
        }
        let mut out = Vec::with_capacity(array.len());
        for element in array {
            let at = self.at(element.span());
            // A mixed-type list is refused element by element, so
            // `["fs.read", 1]` is a type mismatch rather than a list with one
            // element silently dropped.
            let DeValue::String(text) = element.get_ref() else {
                return Err(PolicyLoadError::TypeMismatch {
                    at,
                    field: field.clone(),
                    expected,
                });
            };
            out.push((Self::bounded(text.as_ref(), field, &at)?, at));
        }
        Ok(out)
    }

    /// A string value, bounded.
    ///
    /// A free function rather than a method: the bound is a property of the
    /// schema, not of the document being walked.
    fn bounded(
        text: &str,
        field: &FieldPath,
        at: &SourceLocation,
    ) -> Result<String, PolicyLoadError> {
        if text.chars().count() > limits::MAX_STRING_CHARS {
            return Err(PolicyLoadError::BadValue {
                at: at.clone(),
                field: field.clone(),
                error: ValueError::StringTooLong,
            });
        }
        Ok(text.to_owned())
    }

    /// A match predicate: `field = value` or `field = [a, b]`, **kept apart**.
    ///
    /// [`POLICY.md`] §3's operator table documents both spellings for a match
    /// predicate — implicit scalar is equality, a list is membership — so both
    /// load, and they load as *different values*:
    ///
    /// ```text
    ///     when.verb = "fs.read"      ->  MatchValue::Eq(fs.read)
    ///     when.verb = ["fs.read"]    ->  MatchValue::In([fs.read])
    /// ```
    ///
    /// An earlier version of this function read the first as the second. That
    /// is a parser coercion: two source shapes entering the compiled policy as
    /// one, and a strict loader that coerces in one direction has a coercion.
    /// The two may still *decide* alike — that is
    /// [`MatchValue::any`](super::predicate::MatchValue::any)'s business, and
    /// it looks at the variant to do it.
    ///
    /// [`POLICY.md`]: ../../../../../docs/POLICY.md
    fn match_value<T, F>(
        &self,
        table: &DeTable<'_>,
        name: &str,
        path: &FieldPath,
        parse: F,
    ) -> Result<Option<MatchValue<T>>, PolicyLoadError>
    where
        T: PartialEq,
        F: Fn(&str) -> Result<T, ValueError>,
    {
        let field = path.member(name);
        let Some((_, value)) = find(table, name) else {
            return Ok(None);
        };
        let at = self.at(value.span());

        let bad = |at: SourceLocation, error: ValueError| PolicyLoadError::BadValue {
            at,
            field: field.clone(),
            error,
        };

        // The scalar spelling. Equality.
        if let DeValue::String(text) = value.get_ref() {
            let text = Self::bounded(text.as_ref(), &field, &at)?;
            return parse(&text)
                .map(|parsed| Some(MatchValue::Eq(parsed)))
                .map_err(|error| bad(at, error));
        }

        // The list spelling. Membership.
        let texts = self.string_array(value, &field, Expected::StringOrArray)?;
        let mut out: Vec<T> = Vec::with_capacity(texts.len());
        for (text, at) in texts {
            let parsed = parse(&text).map_err(|error| bad(at.clone(), error))?;
            // Refused rather than collapsed. A repeated element means the
            // author believes they wrote two conditions, and the second one is
            // probably the one they meant to write differently.
            if out.contains(&parsed) {
                return Err(bad(at, ValueError::DuplicateListItem));
            }
            out.push(parsed);
        }
        Ok(Some(MatchValue::In(out)))
    }

    // ---- cross-field rules ------------------------------------------------

    /// Exactly one `default`, last, `DENY`, unconditional — in the profile
    /// that is the **root** of its chain.
    ///
    /// An extending profile must have none. The default is the rule every
    /// action reaches when nothing else matches, and a chain with two of them
    /// has two rules each claiming to be that one; the second would be
    /// unreachable, which is a denial an operator believes is in force and is
    /// not. So the root owns it, and a child declaring one is refused here,
    /// where it can be seen without resolving the chain.
    fn check_default(&self, rules: &[Rule], extending: bool) -> Result<(), PolicyLoadError> {
        let defaults: Vec<(usize, &Rule)> = rules
            .iter()
            .enumerate()
            .filter(|(_, rule)| rule.is_default())
            .collect();
        if extending {
            return match defaults.first() {
                Some((_, rule)) => Err(PolicyLoadError::ExtendsRedeclaresDefault {
                    at: rule.source().clone(),
                }),
                None => Ok(()),
            };
        }
        let Some((index, rule)) = defaults.first() else {
            return Err(PolicyLoadError::DefaultRuleMissing {
                at: self.origin.clone(),
            });
        };
        // A second `default` cannot happen -- the id namespace is unique -- but
        // asserting it costs one line and would catch a future change that
        // relaxed uniqueness.
        if defaults.len() > 1 {
            return Err(PolicyLoadError::DuplicateRuleId {
                at: rule.source().clone(),
                first: rule.source().clone(),
                id: RuleId::DEFAULT.to_owned(),
            });
        }
        let following = rules.len() - index - 1;
        if following > 0 {
            return Err(PolicyLoadError::DefaultRuleNotLast {
                at: rule.source().clone(),
                followed_by: following,
            });
        }
        if rule.effect() != Effect::Deny {
            return Err(PolicyLoadError::DefaultRuleNotDeny {
                at: rule.source().clone(),
            });
        }
        if !rule.when().is_empty() || !rule.unless().is_empty() {
            return Err(PolicyLoadError::DefaultRuleConditional {
                at: rule.source().clone(),
            });
        }
        Ok(())
    }

    /// Every predicate must be able to hold of some action the rule can match.
    ///
    /// A verb-specific predicate on a rule that constrains no verbs cannot be
    /// checked, so the rule must state its verbs; and a verb-specific
    /// predicate on a rule whose verbs all lack that scope family is a rule
    /// that never fires.
    #[expect(
        clippy::unused_self,
        reason = "a Walker method for symmetry with every other check; it needs \
                  no source text only because applicability is decided from the \
                  rule alone"
    )]
    fn check_applicability(
        &self,
        when: &When,
        unless: &Unless,
        field: &FieldPath,
        at: &SourceLocation,
    ) -> Result<(), PolicyLoadError> {
        let names: Vec<PredicateName> =
            when.present().into_iter().chain(unless.present()).collect();
        for name in names {
            let universal = Verb::ALL.iter().all(|verb| name.applies_to(*verb));
            if universal {
                continue;
            }
            let Some(verbs) = when.verb.as_ref() else {
                return Err(PolicyLoadError::PredicateNeedsVerbs {
                    at: at.clone(),
                    field: field.member("when").member(name.as_str()),
                });
            };
            if !verbs.any(|verb| name.applies_to(*verb)) {
                return Err(PolicyLoadError::PredicateNotApplicable {
                    at: at.clone(),
                    field: field.member("when").member(name.as_str()),
                    detail: name.requires(),
                });
            }
        }
        Ok(())
    }
}

const POSTCONDITION_WIDENS: &str = "a postcondition's effect must be narrower than or equal to every provisional \
     effect it selects, under DENY < REQUIRE_APPROVAL < ALLOW";

/// A member of a table, by name.
///
/// Linear over a table of at most fifteen members. Iteration order is the
/// parser's `BTreeMap`, so it is deterministic and does not depend on a hash
/// seed; nothing here ever iterates a `HashMap`.
fn find<'t>(
    table: &'t DeTable<'t>,
    name: &str,
) -> Option<(
    &'t toml::Spanned<toml::de::DeString<'t>>,
    &'t toml::Spanned<DeValue<'t>>,
)> {
    table
        .iter()
        .find(|(key, _)| AsRef::<str>::as_ref(key.get_ref()) == name)
}

/// `namespace.action`, both halves from the closed vocabulary.
fn parse_verb(text: &str) -> Option<Verb> {
    let (namespace, action) = text.split_once('.')?;
    Verb::parse_action(crate::capability::Namespace::parse(namespace)?, action)
}

/// Record a rule id, refusing a repeat.
fn remember_id(
    seen: &mut Vec<(String, SourceLocation)>,
    id: &RuleId,
    at: &SourceLocation,
) -> Result<(), PolicyLoadError> {
    if let Some((_, first)) = seen.iter().find(|(name, _)| name == id.as_str()) {
        return Err(PolicyLoadError::DuplicateRuleId {
            at: at.clone(),
            first: first.clone(),
            id: id.to_string(),
        });
    }
    seen.push((id.as_str().to_owned(), at.clone()));
    Ok(())
}
