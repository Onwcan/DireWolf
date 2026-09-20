//! Fixture suites for the three shipped packs.
//!
//! [`POLICY.md`] §6: "Every hard-denial rule has at least one test asserting it
//! denies, and — more importantly — at least one test asserting it does *not*
//! deny a legitimate neighbouring case, because a rule that denies everything
//! passes the first test."
//!
//! Every neighbour here is one somebody would plausibly write: `/workspaceX`
//! beside `${WORKSPACE}`, `~/.sshconfig` beside `~/.ssh`,
//! `evil-github.com` beside `*.github.com`. They are the shapes a
//! `starts_with` or an `ends_with` implementation would get wrong, which is
//! what makes them worth a test rather than decoration.
//!
//! Unit tests rather than integration tests because they build canonical `fs`
//! and `process` identities, and since [ADR-0037] only `crate::resource` may
//! create one — see [`super::testing`].
//!
//! [ADR-0037]: ../../../../../docs/adr/0037-capability-specifications-and-canonical-authority-identities.md
//! [`POLICY.md`]: ../../../../../docs/POLICY.md

use super::action::{ArgvSafety, CanonicalAction, IpAddress, Novelty};
use super::context::{ConfigFlags, Origin, PathAnchor, PathAnchors, PolicyContext, TaintLevel};
use super::effect::Effect;
use super::predicate::Unevaluable;
use super::reason::Reason;
use super::rule::CompiledPolicy;
use super::testing::{
    anchors, executable_capability, interactive, on_host, path_capability, sandboxed, scheduled,
    syntactic_capability, universal_capability,
};
use super::{Decision, compose, evaluate, load, profiles};

/// Compile one shipped pack.
fn pack(file: &str) -> CompiledPolicy {
    let Some((_, text)) = profiles::ALL.into_iter().find(|(name, _)| *name == file) else {
        unreachable!("{file} is a shipped pack")
    };
    let Ok(profile) = load(file, text) else {
        unreachable!("{file} loads")
    };
    let name = profile.name().clone();
    let Ok(policy) = compose(&name, &[profile]) else {
        unreachable!("{file} composes")
    };
    policy
}

/// `balanced`, which every suite below uses unless it says otherwise.
fn balanced() -> CompiledPolicy {
    pack("balanced.toml")
}

/// Assert an outcome, naming the rule that produced it.
#[track_caller]
fn expect(decision: &Decision, effect: Effect, rule: &str) {
    assert_eq!(
        (decision.effect(), decision.rule_id().as_str()),
        (effect, rule),
        "decision was:\n{decision}"
    );
    // POLICY.md section 1: every decision carries a source file and line.
    assert!(
        decision.rule_source().line() > 0,
        "a decision must name a real line"
    );
    assert!(
        std::path::Path::new(decision.rule_source().source())
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("toml"))
    );
}

/// An fs action over a synthetic canonical path.
fn fs(verb: &str, components: &[&str]) -> CanonicalAction {
    sandboxed(path_capability(verb, components))
}

// ===========================================================================
// Hard denials, each with the neighbour that must NOT be denied.
// ===========================================================================

#[test]
fn self_modification_is_denied_and_a_similarly_named_workspace_file_is_not() {
    let (policy, context) = (balanced(), interactive());
    for components in [
        vec!["opt", "direwolf", "config", "policy", "balanced.toml"],
        vec!["opt", "direwolf", "state", "kernel.db"],
        vec!["opt", "direwolf", "bin", "dwkd-authority"],
    ] {
        let action = fs("fs.write", &components);
        expect(
            &evaluate(&policy, &action, &context),
            Effect::Deny,
            "deny-direwolf-self-modification",
        );
        assert_eq!(
            evaluate(&policy, &action, &context).reason(),
            Reason::SelfModification
        );
    }

    // The neighbours. `/opt/direwolf-notes` is a string prefix of neither
    // anchor's path and a component-wise child of nothing -- a `starts_with`
    // implementation would deny the first two of these.
    for components in [
        vec!["workspace", "direwolf", "config", "notes.md"],
        vec!["opt", "direwolf-notes", "README.md"],
        vec!["opt", "direwolfX", "thing"],
    ] {
        let action = fs("fs.write", &components);
        let decision = evaluate(&policy, &action, &context);
        assert_ne!(
            decision.rule_id().as_str(),
            "deny-direwolf-self-modification",
            "{components:?} is not DireWolf's own:\n{decision}"
        );
    }

    // And a read of its own config is not a modification: the rule names
    // write verbs, so reading falls through rather than being denied here.
    let read = fs("fs.read", &["opt", "direwolf", "config", "policy.toml"]);
    let decision = evaluate(&policy, &read, &context);
    assert_ne!(
        decision.rule_id().as_str(),
        "deny-direwolf-self-modification"
    );
}

#[test]
fn credential_paths_are_denied_and_their_string_neighbours_are_not() {
    let (policy, context) = (balanced(), interactive());
    for components in [
        vec!["home", "agent", ".ssh", "id_ed25519"],
        vec!["home", "agent", ".aws", "credentials"],
        vec!["home", "agent", ".config", "gh", "hosts.yml"],
        vec!["etc", "shadow"],
        vec!["etc", "sudoers"],
    ] {
        let action = fs("fs.read", &components);
        expect(
            &evaluate(&policy, &action, &context),
            Effect::Deny,
            "deny-credential-paths",
        );
    }

    // `~/.sshconfig` is not `~/.ssh`, `/etc/shadowing` is not `/etc/shadow`,
    // and `~/.config/ghost` is not `~/.config/gh`. All three are what a string
    // prefix would get wrong, and all three are ordinary files.
    for components in [
        vec!["home", "agent", ".sshconfig"],
        vec!["home", "agent", ".ssh-backup", "notes"],
        vec!["etc", "shadowing"],
        vec!["home", "agent", ".config", "ghost", "config.yml"],
        vec!["home", "agent", ".awsome", "file"],
    ] {
        let action = fs("fs.read", &components);
        let decision = evaluate(&policy, &action, &context);
        assert_ne!(
            decision.rule_id().as_str(),
            "deny-credential-paths",
            "{components:?} is not a credential path:\n{decision}"
        );
    }
}

#[test]
fn container_sockets_are_denied_and_a_workspace_file_of_the_same_name_is_not() {
    let (policy, context) = (balanced(), interactive());
    for components in [
        vec!["var", "run", "docker.sock"],
        vec!["run", "podman", "podman.sock"],
    ] {
        expect(
            &evaluate(&policy, &fs("fs.write", &components), &context),
            Effect::Deny,
            "deny-container-socket",
        );
    }
    // A file the agent wrote that happens to be called docker.sock is not the
    // daemon's control socket.
    let decision = evaluate(
        &policy,
        &fs("fs.write", &["workspace", "fixtures", "docker.sock"]),
        &context,
    );
    assert_eq!(decision.effect(), Effect::Allow, "{decision}");
    assert_eq!(decision.rule_id().as_str(), "allow-workspace-write");
}

// ===========================================================================
// Allowances, each with a near miss.
// ===========================================================================

#[test]
fn a_workspace_read_is_allowed_and_a_string_prefix_neighbour_is_not() {
    let (policy, context) = (balanced(), interactive());
    let inside = fs("fs.read", &["workspace", "src", "main.rs"]).with_byte_count(1024);
    let decision = evaluate(&policy, &inside, &context);
    expect(&decision, Effect::Allow, "allow-workspace-read");
    assert_eq!(decision.reason(), Reason::PermittedByRule);

    // `/workspaceX` is the trap. It is a directory an attacker can create, it
    // is a string prefix match, and it is not under the workspace.
    for components in [
        vec!["workspaceX", "secrets"],
        vec!["workspace-other", "src", "main.rs"],
        vec!["home", "agent", "notes.md"],
    ] {
        let action = fs("fs.read", &components).with_byte_count(1024);
        let decision = evaluate(&policy, &action, &context);
        expect(&decision, Effect::Deny, "default");
        assert_eq!(decision.reason(), Reason::NoMatchingRule, "{components:?}");
    }
}

#[test]
fn a_read_past_the_byte_cap_falls_through_to_the_default_denial() {
    let (policy, context) = (balanced(), interactive());
    let path = ["workspace", "big.bin"];
    let at_cap = fs("fs.read", &path).with_byte_count(10_485_760);
    expect(
        &evaluate(&policy, &at_cap, &context),
        Effect::Allow,
        "allow-workspace-read",
    );

    let over = fs("fs.read", &path).with_byte_count(10_485_761);
    expect(&evaluate(&policy, &over, &context), Effect::Deny, "default");

    // And an action with no byte count at all does not match a rule that
    // constrains bytes: an absent fact is not a satisfied predicate.
    let unknown = fs("fs.read", &path);
    expect(
        &evaluate(&policy, &unknown, &context),
        Effect::Deny,
        "default",
    );
}

#[test]
fn a_workspace_write_is_allowed_and_carries_its_obligation() {
    let (policy, context) = (balanced(), interactive());
    let action = fs("fs.write", &["workspace", "out", "report.md"]);
    let decision = evaluate(&policy, &action, &context);
    expect(&decision, Effect::Allow, "allow-workspace-write");
    assert_eq!(decision.obligations().len(), 1);
    assert_eq!(
        decision.obligations().to_string(),
        "require_artifact_capture"
    );
    // An obligation is data. Nothing was captured by evaluating this.
    assert!(decision.approval().is_none());
}

#[test]
fn an_allowlisted_tool_runs_and_an_unknown_one_needs_approval() {
    let (policy, context) = (balanced(), interactive());
    let known = sandboxed(executable_capability(
        "process.exec",
        &["usr", "bin", "git"],
        0x11,
    ))
    .with_argv_safety(ArgvSafety::Safe);
    let decision = evaluate(&policy, &known, &context);
    expect(&decision, Effect::Allow, "allow-known-tools");
    assert_eq!(decision.obligations().len(), 2);

    // The near miss: same directory, a name nobody allowlisted.
    let unknown = sandboxed(executable_capability(
        "process.exec",
        &["usr", "bin", "curl"],
        0x22,
    ))
    .with_argv_safety(ArgvSafety::Safe);
    let decision = evaluate(&policy, &unknown, &context);
    expect(&decision, Effect::RequireApproval, "approve-novel-exec");
    assert_eq!(decision.reason(), Reason::UnknownExecutable);

    // And the other near miss: an allowlisted name whose argv would be
    // reinterpreted. `git` is on the list; `git` invoking a pager that runs a
    // shell is not what the list meant.
    let reinterpreting = sandboxed(executable_capability(
        "process.exec",
        &["usr", "bin", "git"],
        0x11,
    ))
    .with_argv_safety(ArgvSafety::Reinterpreting);
    let decision = evaluate(&policy, &reinterpreting, &context);
    expect(&decision, Effect::RequireApproval, "approve-novel-exec");
}

#[test]
fn the_executable_name_match_is_a_whole_component() {
    let (policy, context) = (balanced(), interactive());
    // `gitx` is not `git`, and `mygit` is not `git`. A `contains` or a
    // `starts_with` on the final component would allow both.
    for name in ["gitx", "mygit", "git-credential-helper", "Git"] {
        let action = sandboxed(executable_capability(
            "process.exec",
            &["usr", "bin", name],
            0x33,
        ))
        .with_argv_safety(ArgvSafety::Safe);
        let decision = evaluate(&policy, &action, &context);
        assert_ne!(
            decision.rule_id().as_str(),
            "allow-known-tools",
            "{name} is not on the allowlist:\n{decision}"
        );
    }
}

#[test]
fn host_execution_is_denied_until_the_operator_opts_in() {
    let policy = balanced();
    let action = on_host(executable_capability(
        "process.exec",
        &["usr", "bin", "git"],
        0x11,
    ))
    .with_argv_safety(ArgvSafety::Safe);

    let closed = interactive();
    let decision = evaluate(&policy, &action, &closed);
    expect(&decision, Effect::Deny, "deny-host-exec-unless-opted-in");
    assert_eq!(decision.reason(), Reason::HostExecutionDisabled);

    // Opting in suppresses the denial. It does not grant anything: `balanced`
    // has no rule permitting host execution, so the action now falls through
    // to the default. A profile that wanted to permit it would have to say so.
    let opted_in = interactive().with_config(ConfigFlags {
        security_allow_host_execution: true,
    });
    let decision = evaluate(&policy, &action, &opted_in);
    expect(&decision, Effect::Deny, "default");
    assert_eq!(decision.reason(), Reason::NoMatchingRule);
}

// ===========================================================================
// Egress and taint.
// ===========================================================================

#[test]
fn allowlisted_hosts_are_reachable_and_label_neighbours_are_not() {
    let (policy, context) = (balanced(), interactive());
    for host in [
        "github.com",
        "api.github.com",
        "static.crates.io",
        "crates.io",
    ] {
        let action = sandboxed(syntactic_capability(&format!("network.https:{host}")));
        let decision = evaluate(&policy, &action, &context);
        expect(&decision, Effect::Allow, "allow-package-registries");
    }

    // The suffix-confusion trap. `ends_with("github.com")` would match the
    // first of these, and it is a domain anyone can register.
    for host in [
        "evil-github.com",
        "github.com.attacker.test",
        "notgithub.com",
        "crates.io.evil.test",
    ] {
        let action = sandboxed(syntactic_capability(&format!("network.https:{host}")));
        let decision = evaluate(&policy, &action, &context);
        expect(&decision, Effect::Deny, "default");
    }
}

#[test]
fn a_tainted_run_reaching_somewhere_new_stops_even_for_an_allowlisted_host() {
    let policy = balanced();
    let tainted = PolicyContext::new(Origin::Interactive, TaintLevel::ExternalUntrusted)
        .with_anchors(anchors());
    let action = sandboxed(syntactic_capability("network.https:github.com"))
        .with_destination_novelty(Novelty::Novel);

    let decision = evaluate(&policy, &action, &tainted);
    expect(
        &decision,
        Effect::RequireApproval,
        "approve-egress-when-tainted",
    );
    assert_eq!(decision.reason(), Reason::UntrustedContentInRun);
    let Some(approval) = decision.approval() else {
        unreachable!("a REQUIRE_APPROVAL names the shape that would satisfy it")
    };
    assert_eq!(approval.ttl().to_string(), "10m");

    // Two neighbours, each of which must NOT stop. A destination this run has
    // already reached is not novel...
    let seen = sandboxed(syntactic_capability("network.https:github.com"))
        .with_destination_novelty(Novelty::Seen);
    expect(
        &evaluate(&policy, &seen, &tainted),
        Effect::Allow,
        "allow-package-registries",
    );

    // ...and a run holding only workspace content is LOCAL_UNVERIFIED, which
    // CONTEXT.md section 4 deliberately does not gate. A boolean taint would
    // have stopped this one, which is the failure that makes taint unusable.
    let local = PolicyContext::new(Origin::Interactive, TaintLevel::LocalUnverified)
        .with_anchors(anchors());
    expect(
        &evaluate(&policy, &action, &local),
        Effect::Allow,
        "allow-package-registries",
    );
}

#[test]
fn plaintext_http_is_refused_before_anything_can_approve_it() {
    let policy = balanced();
    let tainted = PolicyContext::new(Origin::Interactive, TaintLevel::ExternalUntrusted)
        .with_anchors(anchors());
    let action = sandboxed(syntactic_capability("network.http:github.com"))
        .with_destination_novelty(Novelty::Novel);
    // Rule order is the control: the denial is written above the taint rule,
    // so there is no approval that reaches it.
    let decision = evaluate(&policy, &action, &tainted);
    expect(&decision, Effect::Deny, "deny-plaintext-http");
    assert_eq!(decision.reason(), Reason::ProfileCeiling);
    assert!(decision.approval().is_none());
}

// ===========================================================================
// Phase two: the unattended postcondition.
// ===========================================================================

#[test]
fn an_unattended_run_cannot_be_approved_and_is_denied_instead() {
    let policy = balanced();
    let action = fs("fs.delete", &["workspace", "build", "stale.o"]);

    // Interactive: a human is there, so the approval stands.
    let decision = evaluate(&policy, &action, &interactive());
    expect(
        &decision,
        Effect::RequireApproval,
        "approve-workspace-delete",
    );
    assert!(decision.applied_postconditions().is_empty());

    // Scheduled: nobody is there. The same primary rule matches and the
    // postcondition narrows it.
    let decision = evaluate(&policy, &action, &scheduled());
    expect(
        &decision,
        Effect::Deny,
        "deny-approval-needed-when-unattended",
    );
    assert_eq!(decision.reason(), Reason::NoHumanAvailable);

    // POLICY.md section 5's explain output: both rules are named, in order.
    assert_eq!(
        decision.primary_rule().id().as_str(),
        "approve-workspace-delete"
    );
    assert_eq!(decision.applied_postconditions().len(), 1);
    let rendered = decision.to_string();
    assert!(rendered.contains("approve-workspace-delete"), "{rendered}");
    assert!(
        rendered.contains("deny-approval-needed-when-unattended"),
        "{rendered}"
    );
    assert!(rendered.contains("NO_HUMAN_AVAILABLE"), "{rendered}");

    // And no approval shape is offered for a denial: there is nothing a human
    // could click that would make this proceed.
    assert!(decision.approval().is_none());
    assert!(decision.obligations().is_empty());
}

#[test]
fn the_postcondition_only_fires_on_a_provisional_require_approval() {
    let policy = balanced();
    for (action, effect, rule) in [
        (
            fs("fs.read", &["workspace", "a.txt"]).with_byte_count(1),
            Effect::Allow,
            "allow-workspace-read",
        ),
        (
            fs("fs.read", &["etc", "shadow"]),
            Effect::Deny,
            "deny-credential-paths",
        ),
    ] {
        // Unattended, but the provisional decision is not REQUIRE_APPROVAL, so
        // the postcondition does not select it and nothing changes.
        let decision = evaluate(&policy, &action, &scheduled());
        expect(&decision, effect, rule);
        assert!(
            decision.applied_postconditions().is_empty(),
            "nothing should have fired:\n{decision}"
        );
    }
}

#[test]
fn every_origin_but_interactive_is_treated_as_unattended() {
    let policy = balanced();
    let action = fs("fs.delete", &["workspace", "tmp", "x"]);
    for origin in Origin::ALL {
        let context = PolicyContext::new(origin, TaintLevel::None).with_anchors(anchors());
        let decision = evaluate(&policy, &action, &context);
        if origin.attended() {
            assert_eq!(decision.effect(), Effect::RequireApproval, "{origin}");
        } else {
            assert_eq!(decision.effect(), Effect::Deny, "{origin}");
            assert_eq!(decision.reason(), Reason::NoHumanAvailable, "{origin}");
        }
    }
}

// ===========================================================================
// The `safe` and `power` packs.
// ===========================================================================

#[test]
fn safe_permits_reading_and_refuses_everything_that_changes_the_world() {
    let (policy, context) = (pack("safe.toml"), interactive());

    let read = fs("fs.read", &["workspace", "src", "main.rs"]).with_byte_count(2048);
    let decision = evaluate(&policy, &read, &context);
    expect(&decision, Effect::Allow, "allow-workspace-read");
    assert_eq!(decision.obligations().to_string(), "read_only_workspace");

    for (action, rule) in [
        (
            fs("fs.write", &["workspace", "a"]),
            "deny-workspace-mutation",
        ),
        (
            fs("fs.delete", &["workspace", "a"]),
            "deny-workspace-mutation",
        ),
        (
            sandboxed(universal_capability("network.https")),
            "deny-all-egress",
        ),
        (
            sandboxed(executable_capability(
                "process.exec",
                &["usr", "bin", "git"],
                1,
            )),
            "deny-all-execution",
        ),
        (
            sandboxed(universal_capability("memory.promote")),
            "deny-durable-memory-change",
        ),
    ] {
        let decision = evaluate(&policy, &action, &context);
        expect(&decision, Effect::Deny, rule);
        assert_eq!(decision.reason(), Reason::ProfileCeiling);
    }
}

#[test]
fn power_is_broader_and_still_refuses_what_no_profile_negotiates() {
    let (policy, context) = (pack("power.toml"), interactive());

    // Broader: a sandboxed exec needs no allowlist, and the byte cap is larger.
    let exec = sandboxed(executable_capability(
        "process.exec",
        &["usr", "bin", "curl"],
        0x44,
    ))
    .with_argv_safety(ArgvSafety::Safe);
    expect(
        &evaluate(&policy, &exec, &context),
        Effect::Allow,
        "allow-sandbox-exec",
    );

    let read = fs("fs.read", &["workspace", "big"]).with_byte_count(100_000_000);
    expect(
        &evaluate(&policy, &read, &context),
        Effect::Allow,
        "allow-workspace-read",
    );

    // Still refused: the three hard denials, in the most permissive profile.
    for (components, rule) in [
        (
            vec!["opt", "direwolf", "config", "policy.toml"],
            "deny-direwolf-self-modification",
        ),
        (
            vec!["home", "agent", ".ssh", "id_rsa"],
            "deny-credential-paths",
        ),
        (vec!["var", "run", "docker.sock"], "deny-container-socket"),
    ] {
        let verb = if rule == "deny-credential-paths" {
            "fs.read"
        } else {
            "fs.write"
        };
        expect(
            &evaluate(&policy, &fs(verb, &components), &context),
            Effect::Deny,
            rule,
        );
    }
}

#[test]
fn power_refuses_the_private_ranges_an_agent_should_never_reach() {
    let (policy, context) = (pack("power.toml"), interactive());
    for address in [
        IpAddress::V4([127, 0, 0, 1]),
        IpAddress::V4([10, 1, 2, 3]),
        IpAddress::V4([172, 16, 0, 1]),
        IpAddress::V4([172, 31, 255, 254]),
        IpAddress::V4([192, 168, 1, 1]),
        // The cloud metadata service, which is the whole reason for the rule.
        IpAddress::V4([169, 254, 169, 254]),
    ] {
        let action = sandboxed(syntactic_capability("network.https:internal.example.com"))
            .with_destination_ip(address);
        let decision = evaluate(&policy, &action, &context);
        expect(&decision, Effect::Deny, "deny-internal-ranges");
        assert_eq!(decision.reason(), Reason::SandboxEscapeVector);
    }

    // The neighbours. 172.32.0.1 is outside 172.16.0.0/12 and 11.0.0.1 is
    // outside 10.0.0.0/8; an off-by-one in the prefix arithmetic would deny
    // both.
    for address in [
        IpAddress::V4([172, 32, 0, 1]),
        IpAddress::V4([11, 0, 0, 1]),
        IpAddress::V4([93, 184, 216, 34]),
        IpAddress::V4([169, 253, 0, 1]),
    ] {
        let action = sandboxed(syntactic_capability("network.https:example.com"))
            .with_destination_ip(address);
        expect(
            &evaluate(&policy, &action, &context),
            Effect::Allow,
            "allow-https-egress",
        );
    }
}

#[test]
fn a_network_action_with_no_destination_address_is_refused_rather_than_allowed() {
    // This test is why `CanonicalAction` carries ONE address rather than a set.
    //
    // An earlier draft held `Vec<IpAddress>` and matched `ip_in` when *every*
    // member was in range. That is fail-closed for an ALLOW and fail-open for
    // a DENY: a host answering with one public and one loopback address did
    // not satisfy `deny-internal-ranges`, fell through, and was allowed --
    // which is DNS rebinding. Switching the quantifier to "any" just moves the
    // hole to the ALLOW rules. The architecture already pins one address at
    // the CONNECT proxy, so the canonical action names it and the ambiguity
    // does not arise.
    //
    // What remains is the case where nobody resolved anything, and that is
    // refused rather than read as a non-match.
    let (policy, context) = (pack("power.toml"), interactive());
    let unresolved = sandboxed(syntactic_capability("network.https:rebind.example.com"));
    let decision = evaluate(&policy, &unresolved, &context);
    assert_eq!(decision.effect(), Effect::Deny, "{decision}");
    assert_eq!(decision.reason(), Reason::UnresolvedCanonicalInput);
    assert_eq!(
        decision.unevaluable(),
        Some(Unevaluable::ResolvedAddress),
        "the explanation must name what was missing"
    );
    assert_eq!(decision.rule_id().as_str(), "deny-internal-ranges");

    // Given a public destination address, the same action is permitted.
    let resolved = unresolved.with_destination_ip(IpAddress::V4([93, 184, 216, 34]));
    expect(
        &evaluate(&policy, &resolved, &context),
        Effect::Allow,
        "allow-https-egress",
    );
}

#[test]
fn a_policy_decision_is_about_one_destination_and_binds_nothing_to_it() {
    // THE CONTRACT M4 AND THE BROKER OWE, made visible now so it cannot be
    // forgotten when the networking lands.
    //
    // M3c guarantees: one destination address per decision, deterministic CIDR
    // evaluation over it, and no ambiguous set quantifier.
    //
    // M3c does NOT guarantee: that the address came from a resolver, that DNS
    // was pinned, or that the connection the broker opens uses this address.
    // Nothing in `CanonicalAction` can establish any of those -- it holds four
    // or sixteen octets.
    //
    // So the same capability with a DIFFERENT destination is a DIFFERENT
    // action and must get its own decision. This test states that by showing
    // the two decisions genuinely differ; a broker that re-resolved a host and
    // reused an earlier ALLOW would be spending a decision that was never made
    // about the address it connects to.
    let (policy, context) = (pack("power.toml"), interactive());
    let capability = syntactic_capability("network.https:rebind.example.com");

    let public =
        sandboxed(capability.clone()).with_destination_ip(IpAddress::V4([93, 184, 216, 34]));
    let loopback = sandboxed(capability).with_destination_ip(IpAddress::V4([127, 0, 0, 1]));

    let allowed = evaluate(&policy, &public, &context);
    let denied = evaluate(&policy, &loopback, &context);
    expect(&allowed, Effect::Allow, "allow-https-egress");
    expect(&denied, Effect::Deny, "deny-internal-ranges");

    // Same verb, same host, same capability -- opposite decisions, decided
    // solely by the destination address. Which is why the address the effect
    // uses has to be the address the decision was made about.
    assert_eq!(allowed.required_capability(), denied.required_capability());
    assert_ne!(allowed.effect(), denied.effect());
}

// ===========================================================================
// The boundaries this milestone must not cross.
// ===========================================================================

#[test]
fn a_missing_path_anchor_denies_rather_than_disabling_the_rule() {
    // The failure mode this guards: `${DIREWOLF_CONFIG}` unresolved means
    // `deny-direwolf-self-modification` cannot be evaluated. Reading that as
    // "did not match" would silently turn off the denial.
    let policy = balanced();
    let empty = PolicyContext::new(Origin::Interactive, TaintLevel::None)
        .with_anchors(PathAnchors::empty());
    let action = fs("fs.write", &["workspace", "ordinary.txt"]);

    let decision = evaluate(&policy, &action, &empty);
    assert_eq!(decision.effect(), Effect::Deny, "{decision}");
    assert_eq!(decision.reason(), Reason::UnresolvedCanonicalInput);
    // And it says which rule needed it, and which anchor, so an operator can
    // act on it rather than guess.
    assert_eq!(
        decision.rule_id().as_str(),
        "deny-direwolf-self-modification"
    );
    assert_eq!(
        decision.unevaluable(),
        Some(Unevaluable::PathAnchor(PathAnchor::DirewolfHome))
    );
    assert!(decision.to_string().contains("not evaluated"), "{decision}");
}

#[test]
fn policy_allow_says_nothing_about_whether_the_capability_is_held() {
    // ADR-0006: two independent gates. This module returns policy truth and
    // only policy truth; `required_capability` is echoed from the action, not
    // checked against anything the run holds.
    let (policy, context) = (balanced(), interactive());
    let action = fs("fs.read", &["workspace", "a.txt"]).with_byte_count(10);
    let decision = evaluate(&policy, &action, &context);
    assert_eq!(decision.effect(), Effect::Allow);
    assert_eq!(decision.required_capability(), action.capability());

    // The other direction: a capability the run plainly holds -- the universal
    // fs.read -- is still denied by policy, because `*` is not a path and
    // `path_under` does not match it.
    let universal = sandboxed(universal_capability("fs.read")).with_byte_count(10);
    let decision = evaluate(&policy, &universal, &context);
    assert_eq!(decision.effect(), Effect::Deny, "{decision}");

    // There is no function in this module that takes a CapabilitySet, and no
    // field on a Decision saying whether one covers the action. That absence
    // is a compile-time property, so it is asserted by the compile_fail
    // doctests on `evaluate` rather than here; what a runtime test can show is
    // that the two answers genuinely differ for the same input, which the two
    // halves above do.
    assert_eq!(decision.reason(), Reason::NoMatchingRule);
}

#[test]
fn evaluation_is_deterministic_and_repeatable() {
    let (policy, context) = (balanced(), interactive());
    let actions = [
        fs("fs.read", &["workspace", "a"]).with_byte_count(1),
        fs("fs.delete", &["workspace", "a"]),
        fs("fs.read", &["etc", "shadow"]),
        sandboxed(syntactic_capability("network.https:github.com")),
    ];
    for action in &actions {
        let first = evaluate(&policy, action, &context);
        for _ in 0..8 {
            assert_eq!(evaluate(&policy, action, &context), first);
        }
        // And the same policy recompiled from the same text decides the same.
        let again = balanced();
        assert_eq!(evaluate(&again, action, &context), first);
    }
}

#[test]
fn a_decision_renders_deterministically_and_from_typed_state_only() {
    let (policy, context) = (balanced(), interactive());
    let action = fs("fs.delete", &["workspace", "a"]);
    let decision = evaluate(&policy, &action, &context);
    let rendered = decision.to_string();
    assert_eq!(rendered, decision.to_string());
    assert!(rendered.contains("REQUIRE_APPROVAL"));
    assert!(rendered.contains("balanced.toml:"));
    assert!(rendered.contains("path_set"));
}
