//! Version 3 of the tool messages (M4d, ADR-0045): the process tools beside
//! the filesystem tools, each process request and result proved to fit one
//! frame — the unchanged 1 MiB frame — at its worst, with the margin the
//! limits derive.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

mod common;

use dwk_proto::dwkp::{self, DwkpBody};
use dwk_proto::limits::{
    MAX_FRAME_BODY, MAX_PLAN_ACTIONS, MAX_PROCESS_ARG_BYTES, MAX_PROCESS_ARGS,
    MAX_PROCESS_ARGV_BYTES, MAX_PROCESS_OUTPUT_BYTES, MAX_PROCESS_REQUEST_ENCODED_BYTES,
    MAX_PROCESS_RESULT_ENCODED_BYTES, MAX_PROCESS_STREAM_BYTES, PROCESS_REQUEST_FRAME_MARGIN_BYTES,
    PROCESS_RESULT_FRAME_MARGIN_BYTES,
};
use dwk_proto::{Violation, frame};

/// A request envelope with every optional header field present at its
/// longest: correlation and causation ids, the largest epoch, and a
/// 128-character idempotency key.
fn worst_request(version: u16, payload: &str) -> String {
    let key = format!("k{}", "-".repeat(127));
    format!(
        r#"{{"v":1,"id":"msg_01M24BB8G0E87TVJX9GX248ADD","type":"request","schema":"direwolf.tool.invoke","schema_version":{version},"ts":"2026-09-12T09:14:22.481Z","correlation_id":"msg_01M24BB8G1FQR94D2PF2XVQDV4","causation_id":"msg_01M24BB8G1FQR94D2PF2XVQDV5","session_id":"ses_01M24BB8G1FQR94D2PF2XVQDV4","run_id":"run_01M24BB8G3E0A851TRWE3M8FZF","epoch":9007199254740991,"idempotency_key":"{key}","payload":{payload}}}"#
    )
}

fn response(payload: &str) -> String {
    format!(
        r#"{{"v":1,"id":"msg_01M24BB8G0E87TVJX9GX248ADD","type":"response","schema":"direwolf.tool.result","schema_version":3,"ts":"2026-09-12T09:14:22.481Z","causation_id":"msg_01M24BB8G1FQR94D2PF2XVQDV4","correlation_id":"msg_01M24BB8G1FQR94D2PF2XVQDV5","payload":{payload}}}"#
    )
}

/// A host path of `PATH_MAX` bytes that canonical JSON escapes to the most
/// bytes: `/` and 4 095 control characters, six bytes each once escaped.
fn worst_host_path() -> String {
    format!("/{}", "\\u0001".repeat(4095))
}

/// A workspace path of 384 characters at six escaped bytes each.
fn worst_workspace_path() -> String {
    format!("/{}", "\\u0001".repeat(383))
}

fn fits(text: &str) -> usize {
    let message = dwkp::decode_body(text.as_bytes()).expect("the largest message decodes");
    let frame = message.to_frame().expect("and frames");
    assert!(frame.len() <= frame::HEADER_LEN + MAX_FRAME_BODY);
    frame.len()
}

/// One line of M4d evidence for `make process-broker-evidence`.
fn frame_evidence(case: &str, encoded: usize) {
    println!(
        "PROC-EVIDENCE {{\"suite\":\"process-frame\",\"case\":\"{case}\",\"outcome\":\"fits\",\"encoded_bytes\":{encoded},\"frame_bytes\":{MAX_FRAME_BODY},\"margin_bytes\":{}}}",
        MAX_FRAME_BODY - encoded
    );
}

/// The largest valid set of arguments, at its worst: the whole aggregate
/// bound in control characters (six bytes each once escaped), split into
/// arguments of the largest size, and the rest of the argument count spent on
/// empty arguments.
fn worst_args() -> Vec<String> {
    let full = MAX_PROCESS_ARGV_BYTES
        .checked_div(MAX_PROCESS_ARG_BYTES)
        .unwrap();
    let mut args: Vec<String> = (0..full)
        .map(|_| "\\u0001".repeat(MAX_PROCESS_ARG_BYTES))
        .collect();
    args.resize(MAX_PROCESS_ARGS, String::new());
    args
}

fn exec_payload(executable: &str, args: &[String], cwd: &str) -> String {
    let args: Vec<String> = args.iter().map(|a| format!("\"{a}\"")).collect();
    format!(
        r#"{{"process_exec":{{"executable":"{executable}","args":[{}],"cwd":"{cwd}"}}}}"#,
        args.join(",")
    )
}

#[test]
fn the_largest_valid_launch_request_fits_one_frame_with_its_margin() {
    let text = worst_request(
        3,
        &exec_payload(&worst_host_path(), &worst_args(), &worst_workspace_path()),
    );
    let message = dwkp::decode_body(text.as_bytes()).unwrap();
    assert!(matches!(message.body, DwkpBody::ToolInvokeV3(_)));
    let framed = fits(&text);
    assert!(
        framed <= MAX_PROCESS_REQUEST_ENCODED_BYTES,
        "the largest launch request is {framed} bytes, over the derived {MAX_PROCESS_REQUEST_ENCODED_BYTES}"
    );
    assert!(framed + PROCESS_REQUEST_FRAME_MARGIN_BYTES <= frame::HEADER_LEN + MAX_FRAME_BODY);
    frame_evidence("largest-valid-launch-request", framed);
}

#[test]
fn an_argument_or_an_argument_count_past_its_bound_does_not_decode() {
    // One argument one byte too long.
    let long = vec!["a".repeat(MAX_PROCESS_ARG_BYTES + 1)];
    let err = dwkp::decode_body(
        worst_request(3, &exec_payload("/usr/bin/git", &long, "/workspace")).as_bytes(),
    )
    .unwrap_err();
    assert_eq!(err.violation, Some(Violation::TooLong));
    // One argument too many.
    let many = vec![String::new(); MAX_PROCESS_ARGS + 1];
    let err = dwkp::decode_body(
        worst_request(3, &exec_payload("/usr/bin/git", &many, "/workspace")).as_bytes(),
    )
    .unwrap_err();
    assert_eq!(err.violation, Some(Violation::TooManyItems));
    // An executable path past PATH_MAX.
    let path = format!("/{}", "a".repeat(4096));
    let err =
        dwkp::decode_body(worst_request(3, &exec_payload(&path, &[], "/workspace")).as_bytes())
            .unwrap_err();
    assert_eq!(err.violation, Some(Violation::TooLong));
    // The aggregate bound is the authority's to enforce (ARGV_TOO_LARGE, before
    // anything is resolved): the decoder accepts what each field allows.
    let over: Vec<String> = (0..=MAX_PROCESS_ARGV_BYTES
        .checked_div(MAX_PROCESS_ARG_BYTES)
        .unwrap())
        .map(|_| "a".repeat(MAX_PROCESS_ARG_BYTES))
        .collect();
    assert!(
        dwkp::decode_body(
            worst_request(3, &exec_payload("/usr/bin/git", &over, "/workspace")).as_bytes()
        )
        .is_ok()
    );
}

fn worst_process_plan(tool: &str, verb: &str) -> String {
    let rule_id = format!("a{}", "-".repeat(63));
    let rule_source = format!("{}:{}", "a".repeat(240), "9".repeat(8));
    let action = format!(
        r#"{{"process":{{"role":"TARGET","verb":"{verb}","executable":{{"path":"{}","sha256":"{}"}},"process_id":"prc_01M24BB8G4E87TVJX9GX248ADD","cwd":"{}","arg_count":128,"argv_sha256":"{}","argv_safety":"REINTERPRETING","decision":{{"effect":"DENY","reason":"OBLIGATION_UNENFORCEABLE","capability_result":"NOT_SATISFIED","policy_result":"NOT_SATISFIED","rule_id":"{rule_id}","rule_source":"{rule_source}"}}}}}}"#,
        worst_host_path(),
        "f".repeat(64),
        worst_workspace_path(),
        "f".repeat(64),
    );
    // A process plan has one action; the wire admits four, so bound all four.
    let actions = vec![action; MAX_PLAN_ACTIONS].join(",");
    format!(r#"{{"tool":"{tool}","environment":"SANDBOX","effect":"DENY","actions":[{actions}]}}"#)
}

#[test]
fn the_largest_status_result_fits_one_frame_with_its_margin() {
    let stream = format!(
        r#"{{"content":"{}","observed":9007199254740991,"truncated":true}}"#,
        "ff".repeat(MAX_PROCESS_STREAM_BYTES)
    );
    let payload = format!(
        r#"{{"invocation_id":"inv_01M24BB8G4E87TVJX9GX248ADD","plan":{},"output":{{"process_status":{{"process_id":"prc_01M24BB8G4E87TVJX9GX248ADD","state":"SIGNALED","exit_code":255,"signal":64,"timed_out":true,"stdout":{stream},"stderr":{stream}}}}}}}"#,
        worst_process_plan("process.status", "process.inspect")
    );
    let framed = fits(&response(&payload));
    assert!(
        framed <= MAX_PROCESS_RESULT_ENCODED_BYTES,
        "the largest status result is {framed} bytes, over the derived {MAX_PROCESS_RESULT_ENCODED_BYTES}"
    );
    assert!(framed + PROCESS_RESULT_FRAME_MARGIN_BYTES <= frame::HEADER_LEN + MAX_FRAME_BODY);
    assert_eq!(2 * MAX_PROCESS_STREAM_BYTES, MAX_PROCESS_OUTPUT_BYTES);
    frame_evidence("largest-status-result", framed);
}

#[test]
fn a_stream_past_its_bound_does_not_decode() {
    let status = |bytes: usize| {
        let stream = format!(
            r#"{{"content":"{}","observed":1,"truncated":false}}"#,
            "ff".repeat(bytes)
        );
        response(&format!(
            r#"{{"invocation_id":"inv_01M24BB8G4E87TVJX9GX248ADD","plan":{},"output":{{"process_status":{{"process_id":"prc_01M24BB8G4E87TVJX9GX248ADD","state":"RUNNING","timed_out":false,"stdout":{stream},"stderr":{{"content":"","observed":0,"truncated":false}}}}}}}}"#,
            worst_process_plan("process.status", "process.inspect")
        ))
    };
    assert!(dwkp::decode_body(status(MAX_PROCESS_STREAM_BYTES).as_bytes()).is_ok());
    let err = dwkp::decode_body(status(MAX_PROCESS_STREAM_BYTES + 1).as_bytes()).unwrap_err();
    assert_eq!(err.violation, Some(Violation::TooLong));
}

#[test]
fn a_launch_and_a_kill_result_are_small() {
    for (tool, verb, output) in [
        (
            "process.exec",
            "process.exec",
            r#"{"process_exec":{"process_id":"prc_01M24BB8G4E87TVJX9GX248ADD","state":"EXITED","exit_code":255}}"#,
        ),
        (
            "process.kill",
            "process.signal",
            r#"{"process_kill":{"process_id":"prc_01M24BB8G4E87TVJX9GX248ADD","outcome":"ALREADY_EXITED"}}"#,
        ),
    ] {
        let payload = format!(
            r#"{{"invocation_id":"inv_01M24BB8G4E87TVJX9GX248ADD","plan":{},"output":{output}}}"#,
            worst_process_plan(tool, verb)
        );
        let framed = fits(&response(&payload));
        assert!(framed < 128 * 1024, "{tool}: {framed} bytes");
    }
}

#[test]
fn a_plan_action_is_exactly_one_of_filesystem_and_process() {
    let fs_action = r#"{"role":"TARGET","verb":"fs.read","canonical_path":"/workspace/a","object":"EXISTING","byte_count":4,"decision":{"effect":"ALLOW","reason":"ALLOWED_BY_RULE","capability_result":"SATISFIED","policy_result":"SATISFIED","rule_id":"allow-read","rule_source":"p.toml:1"}}"#;
    let ok = format!(
        r#"{{"invocation_id":"inv_01M24BB8G4E87TVJX9GX248ADD","plan":{{"tool":"fs.read","environment":"HOST","effect":"ALLOW","actions":[{{"fs":{fs_action}}}]}},"output":{{"fs_read":{{"content":"00","eof_observed":true}}}}}}"#
    );
    assert!(dwkp::decode_body(response(&ok).as_bytes()).is_ok());
    // Unwrapped (the version-2 shape) is not a version-3 action.
    let bare = format!(
        r#"{{"invocation_id":"inv_01M24BB8G4E87TVJX9GX248ADD","plan":{{"tool":"fs.read","environment":"HOST","effect":"ALLOW","actions":[{fs_action}]}},"output":{{"fs_read":{{"content":"00","eof_observed":true}}}}}}"#
    );
    assert!(dwkp::decode_body(response(&bare).as_bytes()).is_err());
}
