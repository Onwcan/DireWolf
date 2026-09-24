//! M4b end to end: the runtime asks, the authority decides and records, the
//! broker reads the object the authority opened, and the result comes back
//! through the authority (ADR-0043).
//!
//! Every test spawns the released `dwkd-authority` and `dwkd-broker` and talks
//! DWKP to the authority from this process. Locally they share one uid, which
//! is stated to both daemons with their development flags; the three-identity
//! evidence is the hosted CI job's.
//!
//! "The broker saw nothing" is measured from the broker's own event lines: it
//! writes one `connection` event for every connection the kernel attributes to
//! the authority, before it reads a byte.

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
    use std::io::Read as _;
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::net::UnixListener;
    use std::time::Duration;

    use dwk_proto::dwkp::messages::{
        CanonicalPreviewResult, ToolDenial, ToolFailure, ToolRefusal, ToolResult,
    };
    use dwk_proto::dwkp::{DwkpBody, DwkpMessage};
    use dwk_proto::error::ErrorCode;
    use dwk_proto::wire::scalar::{
        ActionEnvironment, DecisionEffect, GateResult, ToolDecisionReason, ToolFailureReason,
        ToolOperation, ToolRefusalReason,
    };
    use sha2::{Digest as _, Sha256};

    use super::broker_support::{Broker, Runtime, Setup, every_byte, evidence};
    use super::transport_support::{Client, PROMPT, Server, own_uid};

    const SUITE: &str = "broker-fs-read";

    fn result(message: &DwkpMessage) -> &ToolResult {
        match &message.body {
            DwkpBody::ToolResult(result) => result,
            other => panic!("expected a tool result, got {other:?}"),
        }
    }

    fn denial(message: &DwkpMessage) -> &ToolDenial {
        match &message.body {
            DwkpBody::ToolDenied(denial) => denial,
            other => panic!("expected a denial, got {other:?}"),
        }
    }

    fn refusal(message: &DwkpMessage) -> &ToolRefusal {
        match &message.body {
            DwkpBody::ToolRefused(refusal) => refusal,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    fn failure(message: &DwkpMessage) -> &ToolFailure {
        match &message.body {
            DwkpBody::ToolFailed(failure) => failure,
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    fn previewed(message: &DwkpMessage) -> &CanonicalPreviewResult {
        match &message.body {
            DwkpBody::ToolPreviewed(preview) => preview,
            other => panic!("expected a preview, got {other:?}"),
        }
    }

    /// Send `text` as one frame on a fresh connection and return the
    /// protocol error it earns. A frame that does not decode closes its
    /// connection (ADR-0032), so each gets its own.
    fn rejected(setup: &Setup, text: &str) -> ErrorCode {
        let mut client = Client::connect(&setup.kernel_socket());
        client.handshake();
        client.body(text.as_bytes()).unwrap();
        let answer = client.recv(PROMPT).message();
        let DwkpBody::ProtocolError(error) = answer.body else {
            panic!("expected a protocol error, got {:?}", answer.body)
        };
        assert!(client.recv(PROMPT).is_closed(), "the connection closes");
        error.code
    }

    /// The audit record's content digest, recomputed independently: the
    /// domain, a zero byte, then the length-prefixed content.
    fn sha256_hex(bytes: &[u8]) -> String {
        Sha256::new()
            .chain_update(b"direwolf.tool.fs_read.content.v1")
            .chain_update([0u8])
            .chain_update(u64::try_from(bytes.len()).unwrap().to_be_bytes())
            .chain_update(bytes)
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    #[test]
    fn fs_read_end_to_end_returns_the_exact_bytes_through_the_authority() {
        let setup = Setup::new("m4b-e2e");
        let (broker, server) = setup.start_both();
        let mut rt = Runtime::admit(&setup.kernel_socket(), 1, &["fs.read:/workspace"]);

        let answer = rt.invoke("/workspace/bytes.bin", 4096);
        let got = result(&answer);
        assert_eq!(got.fs_read.content.to_bytes(), every_byte(), "lossless");
        assert!(got.fs_read.eof_observed, "512 bytes read of a 4096 bound");
        assert_eq!(got.action.canonical_path.as_str(), "/workspace/bytes.bin");
        assert_eq!(got.action.byte_count.get(), 4096);
        assert_eq!(got.action.environment, ActionEnvironment::Host);
        assert_eq!(got.decision.effect, DecisionEffect::Allow);
        assert_eq!(got.decision.reason, ToolDecisionReason::AllowedByRule);
        assert_eq!(got.decision.capability_result, GateResult::Satisfied);
        assert_eq!(got.decision.policy_result, GateResult::Satisfied);
        assert_eq!(got.decision.rule_id.as_str(), "allow-workspace-read");
        broker.wait_for("executed", 1);
        assert_eq!(broker.count("connection"), 1, "{}", broker.stderr());
        assert_eq!(
            broker.count(&format!(
                "executed invocation={} bytes=512 eof_observed=true",
                got.invocation_id.as_str()
            )),
            1,
            "{}",
            broker.stderr()
        );

        // Durable intent before the effect, durable outcome before the answer,
        // and the taint the content brings raised in that outcome.
        let audit = setup.audit();
        let events: Vec<&str> = audit.iter().map(|r| r.event()).collect();
        let intent = events
            .iter()
            .position(|e| *e == "tool.intent_recorded")
            .expect("an intent record");
        let done = events
            .iter()
            .position(|e| *e == "tool.completed")
            .expect("an outcome record");
        assert!(intent < done);
        let intent = &audit[intent];
        let done = &audit[done];
        let inv = got.invocation_id.as_str();
        assert_eq!(intent.text("invocation_id"), Some(inv));
        assert_eq!(done.text("invocation_id"), Some(inv));
        let meta = std::fs::metadata(setup.root.join("bytes.bin")).unwrap();
        assert_eq!(
            intent.text("object_inode"),
            Some(meta.ino().to_string().as_str())
        );
        assert_eq!(
            intent.text("object_device"),
            Some(meta.dev().to_string().as_str())
        );
        assert_eq!(intent.text("canonical_path"), Some("/workspace/bytes.bin"));
        assert_eq!(
            intent.text("required_capability"),
            Some("fs.read:/workspace/bytes.bin?max_bytes=4096&no_symlink_targets=true")
        );
        assert_eq!(intent.text("environment"), Some("host"));
        assert_eq!(intent.int("byte_count"), Some(4096));
        assert_eq!(done.int("bytes_returned"), Some(512));
        assert_eq!(done.flag("eof_observed"), Some(true));
        assert_eq!(done.text("taint"), Some("LOCAL_UNVERIFIED"));
        assert_eq!(
            done.text("content_sha256"),
            Some(sha256_hex(&every_byte()).as_str())
        );
        // The broker writes no audit: every record is the authority's chain,
        // and the broker's stderr carries ids and counts, never content.
        assert!(!broker.stderr().contains("hello, workspace"));
        drop(server);
        evidence(SUITE, "fs-read-end-to-end", "bytes-exact", 1);
    }

    #[test]
    fn max_bytes_bounds_the_read_and_reaches_both_gates_first() {
        let setup = Setup::new("m4b-bound");
        let (broker, _server) = setup.start_both();
        let mut rt = Runtime::admit(&setup.kernel_socket(), 1, &["fs.read:/workspace"]);

        // Exactly the bound was read: the end is not proven, because nothing
        // past the bound is read to prove it.
        let got = rt.invoke("/workspace/a.txt", 5);
        assert_eq!(result(&got).fs_read.content.to_bytes(), b"hello");
        assert!(!result(&got).fs_read.eof_observed);
        // An exact fit is still exactly the bound: not observed.
        let exact = rt.invoke("/workspace/a.txt", 17);
        assert_eq!(
            result(&exact).fs_read.content.to_bytes(),
            b"hello, workspace\n"
        );
        assert!(!result(&exact).fs_read.eof_observed);
        // Fewer bytes than the bound, and an empty file: the end was observed.
        let short = rt.invoke("/workspace/a.txt", 18);
        assert_eq!(
            result(&short).fs_read.content.to_bytes(),
            b"hello, workspace\n"
        );
        assert!(result(&short).fs_read.eof_observed);
        let empty = rt.invoke("/workspace/empty", 1);
        assert!(result(&empty).fs_read.content.to_bytes().is_empty());
        assert!(result(&empty).fs_read.eof_observed);
        broker.wait_for("executed", 4);
        let contacts = broker.count("connection");

        // Policy decides on the requested bound, before anything is read:
        // capped/ is allowed at 16 bytes and denied at 17.
        let small = rt.invoke("/workspace/capped/f", 16);
        assert_eq!(
            result(&small).fs_read.content.to_bytes(),
            b"0123456789abcdef"
        );
        let big = rt.invoke("/workspace/capped/f", 17);
        let big = denial(&big);
        assert_eq!(big.decision.rule_id.as_str(), "deny-capped");
        assert_eq!(big.decision.policy_result, GateResult::NotSatisfied);
        assert_eq!(big.action.byte_count.get(), 17);
        broker.wait_for("executed", 4);
        assert_eq!(
            broker.count("connection"),
            contacts + 1,
            "the denial reached no broker"
        );

        // The capability gate reads the same bound: a grant capped at 8 bytes
        // covers a read of 8 and not of 9.
        let capped_run = rt.admit_another("k-capped", &["fs.read:/workspace/capped?max_bytes=8"]);
        let epoch = rt.epoch;
        let ok = rt.invoke_as(&capped_run, epoch, "/workspace/capped/f", 8);
        assert_eq!(result(&ok).fs_read.content.to_bytes(), b"01234567");
        let over = rt.invoke_as(&capped_run, epoch, "/workspace/capped/f", 9);
        let over = denial(&over);
        assert_eq!(over.decision.capability_result, GateResult::NotSatisfied);
        assert_eq!(over.decision.reason, ToolDecisionReason::NoCapability);
        let elsewhere = rt.invoke_as(&capped_run, epoch, "/workspace/a.txt", 4);
        assert_eq!(
            denial(&elsewhere).decision.capability_result,
            GateResult::NotSatisfied
        );
        broker.wait_for("executed", 5);
        assert_eq!(broker.count("connection"), contacts + 2);

        // Above the wire bound is not a request at all.
        let text = rt.tool_json(
            "direwolf.tool.invoke",
            &rt.run.clone(),
            rt.epoch,
            "/workspace/a.txt",
            262_145,
        );
        assert!(dwk_proto::dwkp::decode_body(text.as_bytes()).is_err());
        assert_eq!(rejected(&setup, &text), ErrorCode::SchemaViolation);
        assert_eq!(broker.count("connection"), contacts + 2);
        evidence(SUITE, "max-bytes-before-effect", "bounded", contacts + 2);
    }

    #[test]
    fn denials_refusals_and_dead_runs_never_reach_the_broker() {
        let setup = Setup::new("m4b-zero");
        let (broker, _server) = setup.start_both();
        let mut rt = Runtime::admit(&setup.kernel_socket(), 1, &["fs.read:/workspace"]);

        let denied = rt.invoke("/workspace/secret/key", 64);
        let denied = denial(&denied);
        assert_eq!(denied.decision.rule_id.as_str(), "deny-secret");
        assert_eq!(denied.decision.reason, ToolDecisionReason::DeniedByRule);
        for (path, reason) in [
            ("/etc/passwd", ToolRefusalReason::PathOutsideWorkspace),
            ("/workspace/../etc/passwd", ToolRefusalReason::PathTraversal),
            ("/workspace//a.txt", ToolRefusalReason::PathNotCanonical),
            ("/workspace/./a.txt", ToolRefusalReason::PathTraversal),
            ("/workspace/missing", ToolRefusalReason::NotFound),
            ("/workspace/link", ToolRefusalReason::Symlink),
            ("/workspace/src", ToolRefusalReason::WrongKind),
            ("/workspace/a.txt/x", ToolRefusalReason::NotADirectory),
        ] {
            let got = rt.invoke(path, 64);
            let got = refusal(&got);
            assert_eq!(got.operation, ToolOperation::ToolInvoke, "{path}");
            assert_eq!(got.reason, reason, "{path}");
        }
        // A stale epoch and a run that is not this caller's.
        let run = rt.run.clone();
        let stale = rt.invoke_as(&run, rt.epoch + 1, "/workspace/a.txt", 4);
        assert_eq!(refusal(&stale).reason, ToolRefusalReason::StaleEpoch);
        let ghost = dwk_proto::wire::id::RunId::from_uuid(super::state_support::uuid(999)).unwrap();
        let unknown = rt.invoke_as(&ghost, rt.epoch, "/workspace/a.txt", 4);
        assert_eq!(refusal(&unknown).reason, ToolRefusalReason::UnknownRun);
        // A released run is not a live one.
        let released = rt.client.call(&super::state_support::release_run_msg(
            &rt.session,
            &run,
            dwk_proto::wire::scalar::Epoch::new(rt.epoch).unwrap(),
        ));
        assert!(matches!(released.body, DwkpBody::Ack(_)));
        let ended = rt.invoke_as(&run, rt.epoch, "/workspace/a.txt", 4);
        assert_eq!(refusal(&ended).reason, ToolRefusalReason::UnknownRun);

        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            broker.count("connection"),
            0,
            "the broker saw a connection:\n{}",
            broker.stderr()
        );
        assert!(setup.events("tool.intent_recorded").is_empty());
        assert_eq!(setup.events("tool.denied").len(), 1);
        assert!(setup.events("tool.refused").len() >= 11);
        evidence(SUITE, "zero-broker-contact-for-non-effects", "zero", 0);
    }

    #[test]
    fn shipped_packs_deny_every_read_before_the_broker() {
        // The shipped packs name `~/.ssh` in their first fs rule, and no run
        // has a home anchor: that rule cannot be evaluated, so the pack denies
        // (UNRESOLVED_POLICY_INPUT) rather than guessing. Fail-closed, and
        // documented; an operator policy is how a deployment reads files.
        let setup = Setup::new("m4b-shipped");
        let broker = Broker::start(
            &setup.broker_socket(),
            own_uid(),
            &["--allow-shared-authority-uid"],
        );
        let mut args = setup.authority_args(Some(own_uid()), &[]);
        let at = args.iter().position(|a| a == "--policy-file").unwrap();
        args.splice(
            at..at + 4,
            ["--policy-shipped".to_owned(), "balanced".to_owned()],
        );
        let _server = Server::start(&args);
        let mut rt = Runtime::admit(&setup.kernel_socket(), 1, &["fs.read:/workspace"]);
        let got = rt.invoke("/workspace/a.txt", 64);
        let got = denial(&got);
        assert_eq!(
            got.decision.reason,
            ToolDecisionReason::UnresolvedPolicyInput
        );
        assert_eq!(got.decision.capability_result, GateResult::Satisfied);
        assert_eq!(got.decision.policy_result, GateResult::NotSatisfied);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(broker.count("connection"), 0);
        evidence(SUITE, "shipped-pack-denies-unevaluable", "denied", 0);
    }

    #[test]
    fn preview_performs_nothing_and_decides_exactly_as_invoke() {
        let setup = Setup::new("m4b-preview");
        let (broker, _server) = setup.start_both();
        let mut rt = Runtime::admit(&setup.kernel_socket(), 1, &["fs.read:/workspace"]);

        for (path, max) in [
            ("/workspace/a.txt", 64),
            ("/workspace/secret/key", 64),
            ("/workspace/capped/f", 17),
            ("/workspace/capped/f", 16),
        ] {
            let preview = rt.preview(path, max);
            let preview = previewed(&preview).clone();
            let before = broker.count("connection");
            std::thread::sleep(Duration::from_millis(50));
            assert_eq!(
                broker.count("connection"),
                before,
                "a preview reached the broker"
            );
            let invoked = rt.invoke(path, max);
            let (action, decision) = match &invoked.body {
                DwkpBody::ToolResult(r) => (r.action.clone(), r.decision.clone()),
                DwkpBody::ToolDenied(d) => (d.action.clone(), d.decision.clone()),
                other => panic!("{path}: {other:?}"),
            };
            assert_eq!(preview.action, action, "{path}");
            assert_eq!(preview.decision, decision, "{path}");
        }
        // A preview of a missing object is a refusal, as an invocation's is:
        // both resolve before either gate. It opened nothing and the broker
        // saw nothing.
        let missing = rt.preview("/workspace/missing", 4);
        let missing = refusal(&missing);
        assert_eq!(missing.operation, ToolOperation::CanonicalPreview);
        assert_eq!(missing.reason, ToolRefusalReason::NotFound);
        let executed = broker.count("executed");
        let contacts = broker.count("connection");
        for _ in 0..20 {
            let _ = rt.preview("/workspace/a.txt", 64);
        }
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(broker.count("connection"), contacts);
        assert_eq!(broker.count("executed"), executed);
        // Previews mint no invocation and record no intent.
        let intents = setup.events("tool.intent_recorded").len();
        let previews = setup.events("tool.previewed");
        assert_eq!(intents, 2, "only the two allowed invocations");
        assert!(previews.len() >= 24);
        assert!(previews.iter().all(|r| r.text("invocation_id").is_none()));
        evidence(
            SUITE,
            "preview-zero-effect-and-differential",
            "identical",
            contacts,
        );
    }

    #[test]
    fn a_broker_that_is_down_fails_closed_after_a_durable_intent() {
        let setup = Setup::new("m4b-down");
        let (mut broker, _server) = setup.start_both();
        let mut rt = Runtime::admit(&setup.kernel_socket(), 1, &["fs.read:/workspace"]);
        assert!(matches!(
            rt.invoke("/workspace/a.txt", 64).body,
            DwkpBody::ToolResult(_)
        ));

        broker.kill();
        let down = rt.invoke("/workspace/a.txt", 64);
        let down = failure(&down);
        assert_eq!(down.reason, ToolFailureReason::BrokerUnavailable);
        let failed = setup.events("tool.failed");
        assert_eq!(failed.len(), 1);
        assert_eq!(
            failed[0].text("invocation_id"),
            Some(down.invocation_id.as_str())
        );
        let intents = setup.events("tool.intent_recorded");
        assert!(
            intents
                .iter()
                .any(|r| r.text("invocation_id") == Some(down.invocation_id.as_str())),
            "the failed invocation's intent is on the record"
        );

        // A restarted broker serves the next invocation; the authority did
        // not need to restart, and the failed one is not retried.
        let broker = Broker::start(
            &setup.broker_socket(),
            own_uid(),
            &["--allow-shared-authority-uid"],
        );
        let again = rt.invoke("/workspace/a.txt", 64);
        assert_eq!(
            result(&again).fs_read.content.to_bytes(),
            b"hello, workspace\n"
        );
        assert_ne!(result(&again).invocation_id, down.invocation_id);
        broker.wait_for("executed", 1);
        assert_eq!(broker.count("connection"), 1);
        evidence(
            SUITE,
            "broker-down-and-restart",
            "fail-closed-then-served",
            1,
        );
    }

    #[test]
    fn without_a_broker_an_allowed_invocation_fails_and_nothing_is_read() {
        let setup = Setup::new("m4b-none");
        let _server = Server::start(&setup.authority_args(None, &[]));
        let mut rt = Runtime::admit(&setup.kernel_socket(), 1, &["fs.read:/workspace"]);
        let got = rt.invoke("/workspace/a.txt", 64);
        assert_eq!(failure(&got).reason, ToolFailureReason::BrokerUnavailable);
        let failed = setup.events("tool.failed");
        assert_eq!(failed[0].text("broker_failure"), Some("not_configured"));
        evidence(SUITE, "no-broker-configured", "fail-closed", 0);
    }

    #[test]
    fn the_authority_sends_nothing_to_a_listener_of_the_wrong_uid() {
        // A socket at the broker's path whose owner is not the configured
        // broker uid. Locally the impostor is this process (our uid) and the
        // configured broker uid is one we are not: the kernel reports the
        // difference, and the authority closes without writing a byte.
        let setup = Setup::new("m4b-impostor");
        let path = setup.broker_socket();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let impostor = UnixListener::bind(&path).unwrap();
        let expected_uid = own_uid().wrapping_add(4242);
        let _server = Server::start(&setup.authority_args(Some(expected_uid), &[]));
        let mut rt = Runtime::admit(&setup.kernel_socket(), 1, &["fs.read:/workspace"]);

        let seen = std::thread::spawn(move || {
            let (mut stream, _) = impostor.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut got = Vec::new();
            let _ = stream.read_to_end(&mut got);
            got
        });
        let answer = rt.invoke("/workspace/a.txt", 64);
        assert_eq!(
            failure(&answer).reason,
            ToolFailureReason::BrokerUnavailable
        );
        let received = seen.join().unwrap();
        assert!(
            received.is_empty(),
            "the impostor received {} bytes",
            received.len()
        );
        let failed = setup.events("tool.failed");
        assert_eq!(failed[0].text("broker_failure"), Some("peer_refused"));
        assert_eq!(failed[0].int("observed_uid"), Some(u64::from(own_uid())));
        evidence(SUITE, "authority-verifies-broker-uid", "sent-nothing", 0);
    }

    #[test]
    fn require_approval_is_a_denial_and_reaches_no_broker_before_approvals_exist() {
        // Approvals are M6's. Until then a rule that asks for one fails the
        // policy gate: the action is denied, no intent is recorded, nothing is
        // opened for reading, the broker is never contacted, and a preview
        // reports the same decision.
        let policy = super::broker_support::POLICY.replacen(
            "[[rule]]\nid = \"deny-secret\"",
            "[[rule]]\nid = \"approve-source-reads\"\neffect = \"REQUIRE_APPROVAL\"\n\
             reason = \"SENSITIVE_PATH\"\nwhen.verb = \"fs.read\"\n\
             when.path_under = \"${WORKSPACE}/src\"\napproval.scope = \"exact_action\"\n\
             approval.ttl = \"10m\"\napproval.max_uses = 1\n\n[[rule]]\nid = \"deny-secret\"",
            1,
        );
        assert!(policy.contains("REQUIRE_APPROVAL"));
        let setup = Setup::with_policy("m4b-approval", &policy);
        let (broker, _server) = setup.start_both();
        let mut rt = Runtime::admit(&setup.kernel_socket(), 1, &["fs.read:/workspace"]);
        let preview = rt.preview("/workspace/src/main.rs", 64);
        let preview = previewed(&preview).clone();
        let invoked = rt.invoke("/workspace/src/main.rs", 64);
        let invoked = denial(&invoked);
        assert_eq!(invoked.decision.effect, DecisionEffect::Deny);
        assert_eq!(invoked.decision.capability_result, GateResult::Satisfied);
        assert_eq!(invoked.decision.policy_result, GateResult::NotSatisfied);
        assert_eq!(invoked.decision.rule_id.as_str(), "approve-source-reads");
        assert_eq!(preview.decision, invoked.decision);
        let denied = setup.events("tool.denied");
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].text("policy_effect"), Some("REQUIRE_APPROVAL"));
        assert!(setup.events("tool.intent_recorded").is_empty());
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(broker.count("connection"), 0, "{}", broker.stderr());
        evidence(SUITE, "require-approval-not-performed", "denied", 0);
    }

    #[test]
    fn the_authority_refuses_a_broker_uid_it_shares_unless_told_twice() {
        // The broker must be its own identity: the authority's uid, or an
        // allowed DWKP peer's, is refused at start-up without the explicit
        // development flag -- and with it, the reduced assurance is logged.
        let setup = Setup::new("m4b-shared");
        let mut args = setup.authority_args(None, &[]);
        args.extend([
            "--broker-socket".to_owned(),
            setup.broker_socket().display().to_string(),
            "--broker-uid".to_owned(),
            own_uid().to_string(),
        ]);
        let Err((_, stderr)) = Server::try_start(&args) else {
            panic!("an authority started with a shared broker uid")
        };
        assert!(stderr.contains("--allow-shared-broker-uid"), "{stderr}");
        args.push("--allow-shared-broker-uid".to_owned());
        let server = Server::start(&args);
        assert!(server.stderr().contains("REDUCED ASSURANCE"));
        evidence(
            SUITE,
            "shared-broker-uid-refused",
            "refused-without-flag",
            0,
        );
    }

    #[test]
    fn the_largest_read_fits_one_dwkp_frame_end_to_end() {
        let setup = Setup::new("m4b-frame");
        let big: Vec<u8> = (0..300 * 1024u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        std::fs::write(setup.root.join("big.bin"), &big).unwrap();
        let (broker, _server) = setup.start_both();
        let mut rt = Runtime::admit(&setup.kernel_socket(), 1, &["fs.read:/workspace"]);
        let got = rt.invoke("/workspace/big.bin", 262_144);
        let got = result(&got);
        assert_eq!(got.fs_read.content.to_bytes(), &big[..262_144]);
        assert!(!got.fs_read.eof_observed);
        broker.wait_for("executed", 1);
        evidence(SUITE, "largest-result-one-frame", "fits", 1);
    }

    #[test]
    fn the_object_read_is_the_object_checked_while_the_tree_is_raced() {
        // A second process-level actor (a thread with the runtime's powers
        // over the workspace) swaps names under the authority while the
        // runtime reads: a regular file is replaced by a symlink to a file
        // outside the workspace, and a directory by a symlink to one outside
        // it. Whatever the interleaving, every answer is the checked object's
        // bytes, a refusal before the intent, or -- when the name changed
        // between the durable intent and the open -- a recorded failure that
        // reached no broker. Never the outside file's bytes.
        let setup = Setup::new("m4b-race");
        std::fs::create_dir_all(setup.root.join("d")).unwrap();
        std::fs::write(setup.root.join("d/f"), b"inside-d").unwrap();
        std::fs::write(setup.root.join("r.txt"), b"inside-r").unwrap();
        std::fs::create_dir_all(setup.outside.join("d")).unwrap();
        std::fs::write(setup.outside.join("d/f"), b"OUTSIDE-SECRET").unwrap();
        let (broker, _server) = setup.start_both();
        let mut rt = Runtime::admit(&setup.kernel_socket(), 1, &["fs.read:/workspace"]);

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let racer = {
            let stop = stop.clone();
            let root = setup.root.clone();
            let outside = setup.outside.clone();
            std::thread::spawn(move || {
                let mut swaps = 0u64;
                while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                    let _ = std::fs::rename(root.join("r.txt"), root.join("r.old"));
                    let _ = std::os::unix::fs::symlink(outside.join("secret"), root.join("r.txt"));
                    let _ = std::fs::remove_file(root.join("r.txt"));
                    let _ = std::fs::rename(root.join("r.old"), root.join("r.txt"));
                    let _ = std::fs::rename(root.join("d"), root.join("d.old"));
                    let _ = std::os::unix::fs::symlink(outside.join("d"), root.join("d"));
                    let _ = std::fs::remove_file(root.join("d"));
                    let _ = std::fs::rename(root.join("d.old"), root.join("d"));
                    swaps += 1;
                }
                swaps
            })
        };
        let (mut read, mut refused, mut changed) = (0usize, 0usize, 0usize);
        for i in 0..300 {
            let path = if i % 2 == 0 {
                "/workspace/r.txt"
            } else {
                "/workspace/d/f"
            };
            let answer = rt.invoke(path, 64);
            match &answer.body {
                DwkpBody::ToolResult(r) => {
                    let bytes = r.fs_read.content.to_bytes();
                    assert!(
                        bytes == b"inside-r" || bytes == b"inside-d",
                        "{path} returned {:?}",
                        String::from_utf8_lossy(&bytes)
                    );
                    read += 1;
                }
                DwkpBody::ToolRefused(r) => {
                    assert!(
                        matches!(
                            r.reason,
                            ToolRefusalReason::NotFound
                                | ToolRefusalReason::Symlink
                                | ToolRefusalReason::Race
                                | ToolRefusalReason::NameMismatch
                                | ToolRefusalReason::NotADirectory
                                | ToolRefusalReason::WrongKind
                        ),
                        "{path}: {:?}",
                        r.reason
                    );
                    refused += 1;
                }
                DwkpBody::ToolFailed(f) => {
                    assert_eq!(f.reason, ToolFailureReason::ObjectChanged, "{path}");
                    changed += 1;
                }
                other => panic!("{path}: {other:?}"),
            }
        }
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let swaps = racer.join().unwrap();
        assert!(
            read > 0,
            "some reads completed ({refused} refused, {swaps} swaps)"
        );
        assert!(!broker.stderr().contains("IDENTITY_MISMATCH"));
        // A failure after the intent is recorded, and told the broker nothing:
        // one broker exchange per completed read, no more.
        broker.wait_for("executed", read);
        assert_eq!(broker.count("connection"), read);
        let failed = setup.events("tool.failed");
        assert_eq!(failed.len(), changed);
        assert!(
            failed
                .iter()
                .all(|f| f.text("failure") == Some("OBJECT_CHANGED"))
        );
        // Every completed read's content hash is one of the inside files'.
        let allowed = [sha256_hex(b"inside-r"), sha256_hex(b"inside-d")];
        for done in setup.events("tool.completed") {
            let hash = done.text("content_sha256").unwrap().to_owned();
            assert!(allowed.contains(&hash), "an unexpected content hash");
        }
        println!("race: {read} read, {refused} refused, {changed} changed, {swaps} swaps");
        evidence(
            SUITE,
            "cross-process-toctou",
            "never-outside",
            broker.count("connection"),
        );
    }

    #[test]
    fn a_restarted_authority_serves_through_the_same_broker() {
        let setup = Setup::new("m4b-restart");
        let (broker, server) = setup.start_both();
        {
            let mut rt = Runtime::admit(&setup.kernel_socket(), 1, &["fs.read:/workspace"]);
            assert!(matches!(
                rt.invoke("/workspace/a.txt", 4).body,
                DwkpBody::ToolResult(_)
            ));
        }
        drop(server);
        let _server = Server::start(&setup.authority_args(Some(own_uid()), &[]));
        let mut rt = Runtime::admit(&setup.kernel_socket(), 2, &["fs.read:/workspace"]);
        let got = rt.invoke("/workspace/a.txt", 4);
        assert_eq!(result(&got).fs_read.content.to_bytes(), b"hell");
        broker.wait_for("executed", 2);
        assert_eq!(broker.count("connection"), 2);
        evidence(SUITE, "authority-restart", "served", 2);
    }

    #[test]
    fn a_tool_request_the_decoder_refuses_never_reaches_the_state_layer() {
        let setup = Setup::new("m4b-hostile");
        let (broker, _server) = setup.start_both();
        let mut rt = Runtime::admit(&setup.kernel_socket(), 1, &["fs.read:/workspace"]);
        let base = rt.tool_json(
            "direwolf.tool.invoke",
            &rt.run.clone(),
            rt.epoch,
            "/workspace/a.txt",
            4,
        );
        let fs_read = r#""fs_read":{"path":"/workspace/a.txt","max_bytes":4}"#;
        assert!(base.contains(fs_read));
        for replacement in &[
            r#""fs_write":{"path":"/workspace/a.txt","max_bytes":4}"#,
            r#""fs_read":{"path":"/workspace/a.txt","max_bytes":4,"cap_id":"cap_01M24BB8G3E0A851TRWE3M8FZF"}"#,
            r#""fs_read":{"path":"/workspace/a.txt","max_bytes":4},"environment":"SANDBOX""#,
            r#""fs_read":{"path":"/workspace/a.txt","max_bytes":0}"#,
            r#""fs_read":{"path":"/workspace/a.txt","max_bytes":-1}"#,
            r#""fs_read":{"path":"/workspace/a.txt","max_bytes":4.0}"#,
            r#""fs_read":{"path":"/workspace/a.txt"}"#,
            r#""fs_read":{"path":"workspace/a.txt","max_bytes":4}"#,
            r#""fs_read":{"path":"/workspace/a.txt","max_bytes":4,"max_bytes":4}"#,
            r#""tool":"fs.read","args":{"path":"/workspace/a.txt"}"#,
            r#""fs_read":{"path":"/workspace/a\u0000.txt","max_bytes":4}"#,
        ] {
            let text = base.replace(fs_read, replacement);
            let code = rejected(&setup, &text);
            assert!(
                matches!(
                    code,
                    ErrorCode::SchemaViolation
                        | ErrorCode::InvalidJson
                        | ErrorCode::NumberOutOfDomain
                        | ErrorCode::DuplicateKey
                ),
                "{replacement}: {code:?}"
            );
        }
        // Still serving, and nothing was invoked.
        assert!(matches!(
            rt.invoke("/workspace/a.txt", 4).body,
            DwkpBody::ToolResult(_)
        ));
        assert_eq!(setup.events("tool.intent_recorded").len(), 1);
        broker.wait_for("executed", 1);
        assert_eq!(broker.count("connection"), 1);
        evidence(SUITE, "public-protocol-hostile", "rejected", 1);
    }
}
