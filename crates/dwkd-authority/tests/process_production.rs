//! M4d's production floor, end to end (ADR-0045 §2, evidence A): the released
//! `dwkd-authority` and `dwkd-broker`, this process as the runtime speaking
//! DWKP version 3 — and **no process is ever started**.
//!
//! A host `process.exec` needs the operator's opt-in *and* a per-invocation
//! approval (SANDBOX.md §4). Approvals are M6's; no build of M4d has one. So
//! a production `process.exec` — planned, both gates run, the executable
//! resolved and hashed, the decision audited — is always denied: with the
//! opt-in absent `HOST_EXECUTION_DISABLED`, with it present
//! `APPROVAL_REQUIRED`. That is the security property, and these tests are
//! its evidence, not a gap in them.
//!
//! "The broker was not contacted" is measured from the broker's own event
//! lines: it writes one `connection` event for every connection the kernel
//! attributes to the authority, before it reads a byte.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use dwk_proto as _;
use proptest as _;
use rusqlite as _;
#[cfg(target_os = "linux")]
use rustix as _;
use sha2 as _;
use toml as _;
use unicode_normalization as _;

#[cfg(target_os = "linux")]
mod broker_support;
mod state_support;
#[cfg(target_os = "linux")]
mod transport_support;

#[cfg(target_os = "linux")]
mod linux {
    use dwk_proto::dwkp::DwkpBody;
    use dwk_proto::wire::scalar::{ProcessDecisionReason, ToolRefusalReasonV3};

    use super::broker_support::{Broker, Runtime, Setup};
    use super::state_support::raw;
    use super::transport_support::{Server, own_uid};

    /// A policy that allows every host process verb outright: the most
    /// permissive an operator could write. The floor must hold anyway.
    const ALLOW_HOST: &str = r#"schema_version = 1

[meta]
name = "m4d"

[[rule]]
id = "allow-host-process"
effect = "ALLOW"
when.verb = ["process.exec", "process.inspect", "process.signal"]
when.environment = "host"

[[rule]]
id = "default"
effect = "DENY"
reason = "NO_MATCHING_RULE"
"#;

    const CAPS: &[&str] = &["process.exec:*", "process.inspect:*", "process.signal:*"];

    fn evidence(case: &str, outcome: &str, broker_contacts: usize) {
        println!(
            "PROC-EVIDENCE {{\"suite\":\"production-floor\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\
             \"broker_contacts\":{broker_contacts},\"count\":1}}"
        );
    }

    fn exec(path: &str, args: &[&str]) -> String {
        let args: Vec<String> = args.iter().map(|a| format!("\"{a}\"")).collect();
        format!(
            r#"{{"process_exec":{{"executable":"{path}","args":[{}]}}}}"#,
            args.join(",")
        )
    }

    /// The decision reason of a v3 denial or preview.
    fn reason(body: &DwkpBody) -> ProcessDecisionReason {
        let plan = match body {
            DwkpBody::ToolDeniedV3(denial) => &denial.plan,
            DwkpBody::ToolPreviewedV3(preview) => &preview.plan,
            other => panic!("a denial or a preview: {other:?}"),
        };
        let action = plan.actions.iter().next().unwrap();
        action.process.as_ref().unwrap().decision.reason
    }

    fn start(setup: &Setup, extra: &[&str]) -> (Broker, Server) {
        let broker = Broker::start(
            &setup.broker_socket(),
            own_uid(),
            &["--allow-shared-authority-uid"],
        );
        let server = Server::start(&setup.authority_args(Some(own_uid()), extra));
        (broker, server)
    }

    #[test]
    fn a_released_authority_launches_nothing_before_approvals_exist() {
        // Opted out (the default): HOST_EXECUTION_DISABLED.
        let setup = Setup::process("proc-floor-off", ALLOW_HOST);
        let (broker, _server) = start(&setup, &[]);
        let mut rt = Runtime::admit_as(&setup.kernel_socket(), 1, "operator", CAPS);
        let denied = rt.invoke_v3(&exec("/usr/bin/python3", &["-c", "print(1)"]), "x1");
        assert_eq!(
            reason(&denied.body),
            ProcessDecisionReason::HostExecutionDisabled
        );
        assert_eq!(broker.count("connection"), 0);
        evidence("released-opted-out", "HOST_EXECUTION_DISABLED", 0);

        // Opted in, capability granted, policy ALLOW: APPROVAL_REQUIRED.
        let setup = Setup::process("proc-floor-on", ALLOW_HOST);
        let (broker, _server) = start(&setup, &["--allow-host-execution"]);
        let mut rt = Runtime::admit_as(&setup.kernel_socket(), 1, "operator", CAPS);
        let denied = rt.invoke_v3(&exec("/usr/bin/python3", &["-c", "print(1)"]), "x1");
        let DwkpBody::ToolDeniedV3(denial) = &denied.body else {
            panic!("denied: {denied:?}")
        };
        let action = denial.plan.actions.iter().next().unwrap();
        let process = action.process.as_ref().unwrap();
        assert_eq!(
            process.decision.reason,
            ProcessDecisionReason::ApprovalRequired
        );
        // The plan is complete: the executable resolved and hashed, argv
        // counted and classified, both gates satisfied — and still denied.
        assert!(
            process
                .executable
                .path
                .as_str()
                .starts_with("/usr/bin/python3")
        );
        assert_eq!(process.executable.sha256.as_str().len(), 64);
        assert_eq!(process.arg_count.map(|c| c.get()), Some(2));
        assert_eq!(
            process.decision.capability_result,
            dwk_proto::wire::scalar::GateResult::Satisfied
        );
        assert_eq!(
            process.decision.policy_result,
            dwk_proto::wire::scalar::GateResult::Satisfied
        );
        // A preview: the same, and nothing more.
        let previewed = rt.preview_v3(&exec("/usr/bin/python3", &["-c", "print(1)"]));
        assert_eq!(
            reason(&previewed.body),
            ProcessDecisionReason::ApprovalRequired
        );
        // No process id exists, so a status or a kill names none.
        let invented = "prc_01M24BB8G4E87TVJX9GX248ADD";
        for (payload, key) in [
            (
                format!(r#"{{"process_status":{{"process_id":"{invented}"}}}}"#),
                "s1",
            ),
            (
                format!(r#"{{"process_kill":{{"process_id":"{invented}"}}}}"#),
                "k1",
            ),
        ] {
            let refused = rt.invoke_v3(&payload, key);
            let DwkpBody::ToolRefusedV3(refusal) = &refused.body else {
                panic!("refused: {refused:?}")
            };
            assert_eq!(refusal.reason, ToolRefusalReasonV3::UnknownProcess);
        }
        assert_eq!(
            broker.count("connection"),
            0,
            "the broker was never contacted"
        );
        let conn = raw(&setup.state());
        let count = |sql: &str| -> i64 { conn.query_row(sql, [], |row| row.get(0)).unwrap() };
        assert_eq!(count("SELECT count(*) FROM process_invocation"), 0);
        assert_eq!(count("SELECT count(*) FROM tool_process"), 0);
        // The decision is audited, argv included.
        let denied_records = setup.events("tool.denied");
        assert!(!denied_records.is_empty());
        evidence("released-opted-in", "APPROVAL_REQUIRED", 0);
        evidence("released-preview", "APPROVAL_REQUIRED-no-rows", 0);
        evidence("released-status-kill-no-process", "UNKNOWN_PROCESS", 0);
    }

    #[test]
    fn the_shipped_profiles_never_launch_on_the_host_either() {
        // Each for its own reason: balanced has no opt-in; power's pinned
        // host rule requires approval, and its postcondition denies an
        // approval nobody is present to give; safe denies all execution.
        for (profile, extra, expected, rule) in [
            (
                "balanced",
                &[][..],
                ProcessDecisionReason::HostExecutionDisabled,
                "deny-host-exec-unless-opted-in",
            ),
            (
                "power",
                &["--allow-host-execution"][..],
                ProcessDecisionReason::DeniedByRule,
                "deny-approval-needed-when-unattended",
            ),
            (
                "safe",
                &["--allow-host-execution"][..],
                ProcessDecisionReason::DeniedByRule,
                "deny-all-execution",
            ),
        ] {
            let text = dwkd_authority::state::PolicySet::shipped(profile)
                .unwrap()
                .sources
                .remove(0)
                .text;
            let setup = Setup::process(&format!("proc-shipped-{profile}"), &text)
                .with_profile_name(profile);
            let (broker, _server) = start(&setup, extra);
            let mut rt = Runtime::admit_as(&setup.kernel_socket(), 1, "operator", CAPS);
            let denied = rt.invoke_v3(&exec("/usr/bin/python3", &["-V"]), "x1");
            assert_eq!(reason(&denied.body), expected, "{profile}");
            let DwkpBody::ToolDeniedV3(denial) = &denied.body else {
                unreachable!("a denial")
            };
            let action = denial.plan.actions.iter().next().unwrap();
            assert_eq!(
                action.process.as_ref().unwrap().decision.rule_id.as_str(),
                rule,
                "{profile}"
            );
            assert_eq!(broker.count("connection"), 0, "{profile}");
            evidence(
                &format!("shipped-{profile}"),
                &format!("{}:{rule}", expected.as_str()),
                0,
            );
        }
    }
}
