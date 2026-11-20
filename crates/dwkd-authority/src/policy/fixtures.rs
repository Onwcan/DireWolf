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
use super::context::{
    ConfigFlags, HostPlacement, Origin, PathAnchor, PathAnchors, PolicyContext, TaintLevel,
};
use super::effect::Effect;
use super::predicate::Unevaluable;
use super::reason::Reason;
use super::rule::CompiledPolicy;
use super::testing::{
    anchors, executable_capability, interactive, logical, on_host, path_capability, sandboxed,
    scheduled, syntactic_capability, universal_capability,
};
use super::{Decision, PolicyLoadError, ValueError, compose, evaluate, load, profiles};
use crate::capability::Capability;

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
        let action = sandboxed(syntactic_capability(&format!("network.https:{host}")))
            .with_destination_allowlisted(true);
        let decision = evaluate(&policy, &action, &context);
        expect(&decision, Effect::Allow, "allow-package-registries");
    }

    // The suffix-confusion trap. `ends_with("github.com")` would match the
    // first of these, and it is a domain anyone can register. The pack's list
    // still narrows what the operator's allowlist names (F-06).
    for host in [
        "evil-github.com",
        "github.com.attacker.test",
        "notgithub.com",
        "crates.io.evil.test",
    ] {
        let action = sandboxed(syntactic_capability(&format!("network.https:{host}")))
            .with_destination_allowlisted(true);
        let decision = evaluate(&policy, &action, &context);
        expect(&decision, Effect::Deny, "default");
    }
}

#[test]
fn no_shipped_pack_reaches_a_destination_the_operator_did_not_allowlist() {
    // F-06 (ADR-0071): a registry the pack names, and any HTTPS destination
    // POWER would take, are reached only where the operator's allowlist
    // names them. Not said (an action the authority built without it), or
    // said false: the shipped rule does not match, and the pack's default
    // denies -- the denial named, the rule source a real line.
    let context = interactive();
    for (pack_file, host) in [
        ("balanced.toml", "registry.npmjs.org"),
        ("balanced.toml", "github.com"),
        ("balanced.toml", "uploads.github.com"),
        ("balanced.toml", "upload.pypi.org"),
        ("power.toml", "example.com"),
        ("power.toml", "gist.github.com"),
    ] {
        let policy = pack(pack_file);
        let base = sandboxed(syntactic_capability(&format!("network.https:{host}")))
            .with_destination_novelty(Novelty::Seen)
            .with_destination_ip(IpAddress::V4([93, 184, 216, 34]));
        for action in [
            base.clone(),
            base.clone().with_destination_allowlisted(false),
        ] {
            let decision = evaluate(&policy, &action, &context);
            expect(&decision, Effect::Deny, "default");
            assert_eq!(
                decision.reason(),
                Reason::NoMatchingRule,
                "{pack_file} {host}"
            );
        }
        let allowed = base.with_destination_allowlisted(true);
        assert_eq!(
            evaluate(&policy, &allowed, &context).effect(),
            Effect::Allow,
            "{pack_file} {host}"
        );
    }
    // SAFE has no network rule to require it: denied whatever is said.
    let safe = pack("safe.toml");
    let action = sandboxed(syntactic_capability("network.https:github.com"))
        .with_destination_allowlisted(true);
    assert_eq!(evaluate(&safe, &action, &context).effect(), Effect::Deny);
}

#[test]
fn an_allowlisted_destination_widens_no_other_layer() {
    // The allowlist only narrows: the private ranges, taint and novelty, and
    // plaintext are decided before it is consulted, whatever it says.
    let context = interactive();
    let power = pack("power.toml");
    let metadata = sandboxed(syntactic_capability("network.https:metadata.example.com"))
        .with_destination_allowlisted(true)
        .with_destination_ip(IpAddress::V4([169, 254, 169, 254]));
    expect(
        &evaluate(&power, &metadata, &context),
        Effect::Deny,
        "deny-internal-ranges",
    );
    let tainted = PolicyContext::new(Origin::Interactive, TaintLevel::ExternalUntrusted)
        .with_anchors(anchors());
    for file in ["balanced.toml", "power.toml"] {
        let novel = sandboxed(syntactic_capability("network.https:github.com"))
            .with_destination_allowlisted(true)
            .with_destination_novelty(Novelty::Novel)
            .with_destination_ip(IpAddress::V4([93, 184, 216, 34]));
        expect(
            &evaluate(&pack(file), &novel, &tainted),
            Effect::RequireApproval,
            "approve-egress-when-tainted",
        );
    }
    let plaintext = sandboxed(syntactic_capability("network.http:github.com"))
        .with_destination_allowlisted(true);
    assert_eq!(
        evaluate(&balanced(), &plaintext, &context).effect(),
        Effect::Deny
    );
}

#[test]
fn a_tainted_run_reaching_somewhere_new_stops_even_for_an_allowlisted_host() {
    let policy = balanced();
    let tainted = PolicyContext::new(Origin::Interactive, TaintLevel::ExternalUntrusted)
        .with_anchors(anchors());
    let action = sandboxed(syntactic_capability("network.https:github.com"))
        .with_destination_novelty(Novelty::Novel)
        .with_destination_allowlisted(true);

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
        .with_destination_novelty(Novelty::Seen)
        .with_destination_allowlisted(true);
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
            .with_destination_ip(address)
            .with_destination_allowlisted(true);
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

    // Given a public destination address -- and the operator's allowlist
    // naming it (F-06) -- the same action is permitted.
    let resolved = unresolved
        .with_destination_ip(IpAddress::V4([93, 184, 216, 34]))
        .with_destination_allowlisted(true);
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

    // The operator's allowlist names the host (F-06); only the address differs.
    let public = sandboxed(capability.clone())
        .with_destination_ip(IpAddress::V4([93, 184, 216, 34]))
        .with_destination_allowlisted(true);
    let loopback = sandboxed(capability)
        .with_destination_ip(IpAddress::V4([127, 0, 0, 1]))
        .with_destination_allowlisted(true);

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

// ===========================================================================
// F-12: the logical namespace every live decision is made in. A candidate is
// a `/workspace/...` path; a host path a rule names is answered by where the
// state layer found it on the host, never by its spelling.
// ===========================================================================

/// Every host path the three shipped packs name -- the same twelve in each.
const SHIPPED_HOST_PATHS: [&str; 12] = [
    "${DIREWOLF_HOME}",
    "${DIREWOLF_CONFIG}",
    "${DIREWOLF_INSTALL}",
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
    "~/.config/gh",
    "~/.kube",
    "/etc/shadow",
    "/etc/sudoers",
    "/var/run/docker.sock",
    "/run/podman/podman.sock",
];

const SHIPPED: [&str; 3] = ["safe.toml", "balanced.toml", "power.toml"];

/// A live-shaped context: `${WORKSPACE}` resolved, every host path of
/// `policy` placed as `placed` says.
fn live(
    origin: Origin,
    policy: &CompiledPolicy,
    placed: impl Fn(&str) -> Option<HostPlacement>,
) -> PolicyContext {
    PolicyContext::new(origin, TaintLevel::None)
        .with_anchors(logical(policy, |path| placed(&path.to_string())))
}

/// Every host path disjoint from the workspace: the ordinary deployment.
#[allow(
    clippy::unnecessary_wraps,
    reason = "the shape every placement function of these tests has"
)]
fn disjoint(_: &str) -> Option<HostPlacement> {
    Some(HostPlacement::Disjoint)
}

#[test]
fn every_shipped_pack_names_the_same_twelve_host_paths() {
    let expected: std::collections::BTreeSet<String> =
        SHIPPED_HOST_PATHS.iter().map(|p| (*p).to_owned()).collect();
    for file in SHIPPED {
        let named: std::collections::BTreeSet<String> = pack(file)
            .host_paths()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(named, expected, "{file}");
    }
}

#[test]
fn a_workspace_read_is_allowed_in_every_pack_once_its_host_paths_are_placed() {
    for file in SHIPPED {
        let policy = pack(file);
        let context = live(Origin::Interactive, &policy, disjoint);
        let read = fs("fs.read", &["workspace", "src", "main.rs"]).with_byte_count(1024);
        expect(
            &evaluate(&policy, &read, &context),
            Effect::Allow,
            "allow-workspace-read",
        );
        // A live listing or stat moves no content: the state layer gives it a
        // byte count of zero, which every pack's read cap admits.
        for verb in ["fs.list", "fs.stat"] {
            let action = fs(verb, &["workspace", "src"]).with_byte_count(0);
            let decision = evaluate(&policy, &action, &context);
            expect(&decision, Effect::Allow, "allow-workspace-read");
        }
    }
}

#[test]
fn an_unplaced_host_path_denies_and_names_its_anchor_in_every_pack() {
    // Nothing placed, and then only `~` missing: a missing home anchor never
    // disables `deny-credential-paths`; the read is not evaluated.
    let only_home_missing =
        |path: &str| (!path.starts_with('~')).then_some(HostPlacement::Disjoint);
    for file in SHIPPED {
        let policy = pack(file);
        let read = fs("fs.read", &["workspace", "a.txt"]).with_byte_count(10);
        for context in [
            live(Origin::Interactive, &policy, |_| None),
            live(Origin::Interactive, &policy, only_home_missing),
        ] {
            let decision = evaluate(&policy, &read, &context);
            assert_eq!(decision.effect(), Effect::Deny, "{file}: {decision}");
            assert_eq!(decision.reason(), Reason::UnresolvedCanonicalInput);
            assert_eq!(decision.rule_id().as_str(), "deny-credential-paths");
            assert_eq!(
                decision.unevaluable(),
                Some(Unevaluable::PathAnchor(PathAnchor::Home))
            );
        }
        // A write meets `deny-direwolf-self-modification` first, and so its
        // missing anchor.
        let write = fs("fs.write", &["workspace", "a.txt"]);
        let decision = evaluate(
            &policy,
            &write,
            &live(Origin::Interactive, &policy, |_| None),
        );
        assert_eq!(
            decision.unevaluable(),
            Some(Unevaluable::PathAnchor(PathAnchor::DirewolfHome)),
            "{file}"
        );
    }
}

#[test]
fn a_workspace_inside_a_protected_location_denies_every_path_of_it() {
    // `Encloses`: the workspace root lies inside `~/.ssh`. Every path the run
    // can name is under it, so the credential rule denies -- by name.
    let inside_ssh = |path: &str| {
        Some(if path == "~/.ssh" {
            HostPlacement::Encloses
        } else {
            HostPlacement::Disjoint
        })
    };
    for file in SHIPPED {
        let policy = pack(file);
        let context = live(Origin::Interactive, &policy, inside_ssh);
        for components in [vec!["workspace", "id_ed25519"], vec!["workspace", "x", "y"]] {
            let decision = evaluate(
                &policy,
                &fs("fs.read", &components).with_byte_count(10),
                &context,
            );
            expect(&decision, Effect::Deny, "deny-credential-paths");
            assert_eq!(decision.reason(), Reason::SensitivePath, "{file}");
        }
    }
}

#[test]
fn a_protected_location_inside_the_workspace_is_not_evaluated_and_denies() {
    // `InsideWorkspace` and `Unexamined`: the rule cannot say which paths are
    // under the location, so it is not evaluated -- and that denies, naming
    // the rule, the anchor and why.
    for doubt in [HostPlacement::InsideWorkspace, HostPlacement::Unexamined] {
        let home_doubted = |path: &str| {
            Some(if path.starts_with('~') {
                doubt
            } else {
                HostPlacement::Disjoint
            })
        };
        for file in SHIPPED {
            let policy = pack(file);
            let context = live(Origin::Interactive, &policy, home_doubted);
            let decision = evaluate(
                &policy,
                &fs("fs.read", &["workspace", "notes.md"]).with_byte_count(10),
                &context,
            );
            assert_eq!(decision.effect(), Effect::Deny, "{file}: {decision}");
            assert_eq!(decision.rule_id().as_str(), "deny-credential-paths");
            assert_eq!(decision.reason(), Reason::UnresolvedCanonicalInput);
            assert_eq!(
                decision.unevaluable(),
                Some(Unevaluable::HostLocation(PathAnchor::Home, doubt))
            );
        }
    }
}

#[test]
fn an_absolute_protected_path_is_placed_on_the_host_not_compared_with_the_workspace() {
    // The defect F-12 found beneath the unresolved home anchor: compared by
    // spelling, `/etc/shadow` is never a prefix of a `/workspace/...` path, so
    // a workspace root bound at `/etc` exposed `/workspace/shadow` -- which is
    // `/etc/shadow` -- to `allow-workspace-read`. Placed, it lies inside the
    // workspace root, and the rule is not evaluated: refused.
    let etc_inside = |path: &str| {
        Some(if path.starts_with("/etc/") {
            HostPlacement::InsideWorkspace
        } else {
            HostPlacement::Disjoint
        })
    };
    let run_inside = |path: &str| {
        Some(
            if path == "/var/run/docker.sock" || path == "/run/podman/podman.sock" {
                HostPlacement::InsideWorkspace
            } else {
                HostPlacement::Disjoint
            },
        )
    };
    for file in SHIPPED {
        let policy = pack(file);
        let shadow = fs("fs.read", &["workspace", "shadow"]).with_byte_count(10);
        let decision = evaluate(
            &policy,
            &shadow,
            &live(Origin::Interactive, &policy, etc_inside),
        );
        assert_eq!(
            decision.rule_id().as_str(),
            "deny-credential-paths",
            "{file}"
        );
        assert_eq!(
            decision.unevaluable(),
            Some(Unevaluable::HostLocation(
                PathAnchor::Absolute,
                HostPlacement::InsideWorkspace
            ))
        );
        let socket = fs("fs.read", &["workspace", "docker.sock"]).with_byte_count(10);
        let decision = evaluate(
            &policy,
            &socket,
            &live(Origin::Interactive, &policy, run_inside),
        );
        assert_eq!(
            decision.rule_id().as_str(),
            "deny-container-socket",
            "{file}"
        );
        assert_eq!(decision.effect(), Effect::Deny);
    }
}

#[test]
fn a_logical_absolute_path_still_compares_by_components() {
    let Ok(profile) = load(
        "logical.toml",
        r#"schema_version = 1
[meta]
name = "logical"

[[rule]]
id = "deny-git-dir"
effect = "DENY"
reason = "SENSITIVE_PATH"
when.verb = "fs.read"
when.path_under = "/workspace/.git"

[[rule]]
id = "allow-workspace"
effect = "ALLOW"
when.verb = "fs.read"
when.path_under = "${WORKSPACE}"

[[rule]]
id = "default"
effect = "DENY"
reason = "NO_MATCHING_RULE"
"#,
    ) else {
        unreachable!("the fixture loads")
    };
    let name = profile.name().clone();
    let Ok(policy) = compose(&name, &[profile]) else {
        unreachable!("the fixture composes")
    };
    assert!(policy.host_paths().is_empty(), "/workspace/... is logical");
    let context = live(Origin::Interactive, &policy, |_| None);
    let git = evaluate(
        &policy,
        &fs("fs.read", &["workspace", ".git", "config"]),
        &context,
    );
    expect(&git, Effect::Deny, "deny-git-dir");
    let src = evaluate(&policy, &fs("fs.read", &["workspace", "src"]), &context);
    expect(&src, Effect::Allow, "allow-workspace");
}

#[test]
fn a_host_path_may_be_named_only_by_a_denial() {
    let profile = |effect: &str, path: &str, extra: &str| {
        format!(
            r#"schema_version = 1
[meta]
name = "hosted"

[[rule]]
id = "the-rule"
effect = "{effect}"
{extra}
when.verb = "fs.read"
when.path_under = "{path}"

[[rule]]
id = "default"
effect = "DENY"
reason = "NO_MATCHING_RULE"
"#
        )
    };
    let approval = "reason = \"SENSITIVE_PATH\"\napproval.scope = \"exact_action\"\n\
                    approval.ttl = \"10m\"\napproval.max_uses = 1";
    for (effect, extra) in [("ALLOW", ""), ("REQUIRE_APPROVAL", approval)] {
        for path in ["~/notes", "${DIREWOLF_CONFIG}", "/srv/shared", "/"] {
            match load("hosted.toml", &profile(effect, path, extra)) {
                Err(super::PolicyLoadError::BadValue { error, field, .. }) => {
                    assert_eq!(
                        error,
                        super::ValueError::HostPathOutsideDenial,
                        "{effect} {path}"
                    );
                    assert_eq!(field.as_str(), "rule[0].when.path_under");
                }
                other => unreachable!("{effect} naming {path} loaded: {other:?}"),
            }
        }
        // The workspace's own spellings are not host paths.
        for path in ["${WORKSPACE}/src", "/workspace/src"] {
            assert!(
                load("hosted.toml", &profile(effect, path, extra)).is_ok(),
                "{effect} {path}"
            );
        }
    }
    let deny = "reason = \"SENSITIVE_PATH\"";
    for path in ["~/notes", "${DIREWOLF_CONFIG}", "/srv/shared", "/"] {
        assert!(
            load("hosted.toml", &profile("DENY", path, deny)).is_ok(),
            "DENY {path}"
        );
    }
}

#[test]
fn an_executable_path_is_still_compared_on_the_host() {
    // `executable_in` names executables by their canonical HOST path, so F-12
    // leaves it as it was: the logical namespace changes only `path_under`.
    let Ok(profile) = load(
        "exec.toml",
        r#"schema_version = 1
[meta]
name = "exec"

[[rule]]
id = "allow-git"
effect = "ALLOW"
when.verb = "process.exec"
when.executable_in = ["/usr/bin/git"]

[[rule]]
id = "default"
effect = "DENY"
reason = "NO_MATCHING_RULE"
"#,
    ) else {
        unreachable!("the fixture loads")
    };
    let name = profile.name().clone();
    let Ok(policy) = compose(&name, &[profile]) else {
        unreachable!("the fixture composes")
    };
    let git = on_host(executable_capability(
        "process.exec",
        &["usr", "bin", "git"],
        7,
    ));
    let decision = evaluate(&policy, &git, &live(Origin::Interactive, &policy, |_| None));
    expect(&decision, Effect::Allow, "allow-git");
}

#[test]
fn each_pack_keeps_its_ceiling_once_the_host_paths_are_placed() {
    let write = fs("fs.write", &["workspace", "src", "main.rs"]);
    let delete = fs("fs.delete", &["workspace", "old.txt"]);

    let safe = pack("safe.toml");
    let context = live(Origin::Interactive, &safe, disjoint);
    let decision = evaluate(&safe, &write, &context);
    expect(&decision, Effect::Deny, "deny-workspace-mutation");
    assert_eq!(decision.reason(), Reason::ProfileCeiling);

    // BALANCED allows the write in policy and attaches the obligation the
    // state layer cannot enforce yet (F-12, M8): policy truth only.
    let balanced = balanced();
    let context = live(Origin::Interactive, &balanced, disjoint);
    let decision = evaluate(&balanced, &write, &context);
    expect(&decision, Effect::Allow, "allow-workspace-write");
    assert!(
        decision
            .obligations()
            .as_slice()
            .contains(&super::Obligation::RequireArtifactCapture)
    );
    // A delete still needs a human, and nobody is there for a scheduled run.
    expect(
        &evaluate(&balanced, &delete, &context),
        Effect::RequireApproval,
        "approve-workspace-delete",
    );
    let unattended = live(Origin::Scheduled, &balanced, disjoint);
    let decision = evaluate(&balanced, &delete, &unattended);
    assert_eq!(decision.effect(), Effect::Deny, "{decision}");
    assert_eq!(decision.reason(), Reason::NoHumanAvailable);

    let power = pack("power.toml");
    let context = live(Origin::Interactive, &power, disjoint);
    expect(
        &evaluate(&power, &write, &context),
        Effect::Allow,
        "allow-workspace-write",
    );
    expect(
        &evaluate(&power, &delete, &context),
        Effect::Allow,
        "allow-workspace-write",
    );
    // POWER is still policy: a workspace inside DireWolf's own state is
    // self-modification, and reading it is not.
    let in_state = |path: &str| {
        Some(if path == "${DIREWOLF_HOME}" {
            HostPlacement::Encloses
        } else {
            HostPlacement::Disjoint
        })
    };
    let context = live(Origin::Interactive, &power, in_state);
    let decision = evaluate(&power, &write, &context);
    expect(&decision, Effect::Deny, "deny-direwolf-self-modification");
    assert_eq!(decision.reason(), Reason::SelfModification);
    let read = fs("fs.read", &["workspace", "kernel.db"]).with_byte_count(10);
    expect(
        &evaluate(&power, &read, &context),
        Effect::Allow,
        "allow-workspace-read",
    );
}

// ===========================================================================
// F-06 OF-2 (ADR-0073): the operator's egress ceiling, which no rule reaches.
// ===========================================================================

/// An operator's own policy: every HTTPS action allowed, and reading; no rule
/// in it requires `destination_allowlisted`.
const OPERATOR_ALLOWS_EVERY_HOST: &str = "schema_version = 1\n\n[meta]\nname = \"operator\"\n\n\
    [[rule]]\nid = \"allow-every-host\"\neffect = \"ALLOW\"\nwhen.verb = [\"network.https\"]\n\n\
    [[rule]]\nid = \"allow-reading\"\neffect = \"ALLOW\"\nwhen.verb = [\"fs.read\"]\n\n\
    [[rule]]\nid = \"default\"\neffect = \"DENY\"\nreason = \"NO_MATCHING_RULE\"\n";

fn operator(text: &str) -> CompiledPolicy {
    let Ok(profile) = load("operator.toml", text) else {
        unreachable!("the operator's policy loads")
    };
    let name = profile.name().clone();
    let Ok(policy) = compose(&name, &[profile]) else {
        unreachable!("the operator's policy composes")
    };
    policy
}

/// A decision the operator's ceiling made: `DENY`, by the reserved rule and
/// reason, from the operator's file, with what the policy matched still on
/// the record and nothing offered.
#[track_caller]
fn beyond_ceiling(decision: &Decision, matched: &str) {
    assert_eq!(
        (decision.effect(), decision.rule_id().as_str()),
        (Effect::Deny, "operator-egress-ceiling"),
        "decision was:\n{decision}"
    );
    assert_eq!(decision.reason(), Reason::OutsideEgressAllowlist);
    assert_eq!(decision.rule_source().to_string(), "--egress-allowlist:1");
    assert_eq!(decision.primary_rule().id().as_str(), matched);
    assert!(
        decision.approval().is_none(),
        "nobody is asked past the ceiling"
    );
    assert!(decision.obligations().as_slice().is_empty());
}

#[test]
fn an_operator_policy_allowing_every_host_is_under_the_operator_egress_ceiling() {
    let (policy, context) = (operator(OPERATOR_ALLOWS_EVERY_HOST), interactive());
    let builds: [fn(Capability) -> CanonicalAction; 2] = [sandboxed, on_host];
    for build in builds {
        let base = build(syntactic_capability("network.https:api.example.com:443"))
            .with_destination_ip(IpAddress::V4([93, 184, 216, 34]));
        // Not said (an action no authority placed), or said false: denied,
        // whatever the rule said.
        for outside in [
            base.clone(),
            base.clone().with_destination_allowlisted(false),
        ] {
            beyond_ceiling(&evaluate(&policy, &outside, &context), "allow-every-host");
        }
        // Said true: the operator's rule stands.
        expect(
            &evaluate(&policy, &base.with_destination_allowlisted(true), &context),
            Effect::Allow,
            "allow-every-host",
        );
    }
    // Not a network action: the ceiling is not consulted.
    expect(
        &evaluate(
            &policy,
            &fs("fs.read", &["workspace", "notes.md"]),
            &context,
        ),
        Effect::Allow,
        "allow-reading",
    );
}

#[test]
fn an_approval_cannot_lift_the_ceiling_and_a_denial_keeps_its_own_name() {
    // A tainted run's novel destination: BALANCED and POWER would ask a human
    // (their approval rule does not require the allowlist). Outside the
    // ceiling nobody is asked: it denies, and offers no approval.
    let tainted = PolicyContext::new(Origin::Interactive, TaintLevel::ExternalUntrusted)
        .with_anchors(anchors());
    for file in ["balanced.toml", "power.toml"] {
        let novel = sandboxed(syntactic_capability("network.https:github.com"))
            .with_destination_novelty(Novelty::Novel)
            .with_destination_ip(IpAddress::V4([140, 82, 112, 3]));
        for outside in [
            novel.clone(),
            novel.clone().with_destination_allowlisted(false),
        ] {
            beyond_ceiling(
                &evaluate(&pack(file), &outside, &tainted),
                "approve-egress-when-tainted",
            );
        }
        expect(
            &evaluate(
                &pack(file),
                &novel.with_destination_allowlisted(true),
                &tainted,
            ),
            Effect::RequireApproval,
            "approve-egress-when-tainted",
        );
    }
    // A rule that denies keeps its own name, inside the ceiling or out.
    let context = interactive();
    let metadata = sandboxed(syntactic_capability("network.https:metadata.example.com"))
        .with_destination_ip(IpAddress::V4([169, 254, 169, 254]));
    for action in [
        metadata.clone(),
        metadata.with_destination_allowlisted(true),
    ] {
        expect(
            &evaluate(&pack("power.toml"), &action, &context),
            Effect::Deny,
            "deny-internal-ranges",
        );
    }
    let deny = OPERATOR_ALLOWS_EVERY_HOST.replace(
        "id = \"allow-every-host\"\neffect = \"ALLOW\"",
        "id = \"deny-every-host\"\neffect = \"DENY\"\nreason = \"PROFILE_CEILING\"",
    );
    assert_ne!(deny, OPERATOR_ALLOWS_EVERY_HOST);
    let named = sandboxed(syntactic_capability("network.https:api.example.com:443"))
        .with_destination_allowlisted(true);
    expect(
        &evaluate(&operator(&deny), &named, &context),
        Effect::Deny,
        "deny-every-host",
    );
}

#[test]
fn no_policy_file_may_name_the_ceiling_or_claim_its_reason() {
    let refused = |text: &str| {
        matches!(
            load("operator.toml", text),
            Err(PolicyLoadError::BadValue {
                error: ValueError::MalformedRuleId | ValueError::UnknownReason,
                ..
            })
        )
    };
    let as_rule = OPERATOR_ALLOWS_EVERY_HOST.replace(
        "id = \"allow-every-host\"",
        "id = \"operator-egress-ceiling\"",
    );
    assert_ne!(as_rule, OPERATOR_ALLOWS_EVERY_HOST);
    assert!(refused(&as_rule));
    let as_postcondition = format!(
        "{OPERATOR_ALLOWS_EVERY_HOST}\n[[postcondition]]\nid = \"operator-egress-ceiling\"\n\
         effect = \"DENY\"\nreason = \"PROFILE_CEILING\"\nwhen.provisional_effect = [\"ALLOW\"]\n"
    );
    assert!(refused(&as_postcondition));
    let reason = OPERATOR_ALLOWS_EVERY_HOST.replace(
        "reason = \"NO_MATCHING_RULE\"",
        "reason = \"OUTSIDE_EGRESS_ALLOWLIST\"",
    );
    assert_ne!(reason, OPERATOR_ALLOWS_EVERY_HOST);
    assert!(refused(&reason));
    // A neighbouring name is a name like any other.
    let near = OPERATOR_ALLOWS_EVERY_HOST.replace(
        "id = \"allow-every-host\"",
        "id = \"operator-egress-ceilings\"",
    );
    assert!(load("operator.toml", &near).is_ok());
}
