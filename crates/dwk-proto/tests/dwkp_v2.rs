//! Version 2 of the tool messages (M4c, ADR-0044): two versions of one schema
//! side by side, each decoded under its own rules, and every new result shape
//! proved to fit one frame at its worst.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

mod common;

use dwk_proto::dwkp::{self, DwkpBody};
use dwk_proto::limits::{
    MAX_FRAME_BODY, MAX_FS_READ_BYTES, MAX_FS_WRITE_BYTES, MAX_LIST_ENTRIES, MAX_PATCH_EDITS,
    MAX_PATCH_FILE_BYTES, MAX_PATCH_INSERT_BYTES_TOTAL, MAX_PATCH_REQUEST_ENCODED_BYTES,
    MAX_PATCH_REQUEST_OVERHEAD_BYTES, MAX_PLAN_ACTIONS, MAX_SEARCH_MATCHES,
    PATCH_FRAME_MARGIN_BYTES,
};
use dwk_proto::{ErrorCode, Violation, frame};

const RUN_ENVELOPE: &str = r#""session_id":"ses_01M24BB8G1FQR94D2PF2XVQDV4","run_id":"run_01M24BB8G3E0A851TRWE3M8FZF","epoch":3"#;

fn request(schema: &str, version: u16, extra: &str, payload: &str) -> String {
    format!(
        r#"{{"v":1,"id":"msg_01M24BB8G0E87TVJX9GX248ADD","type":"request","schema":"{schema}","schema_version":{version},"ts":"2026-09-12T09:14:22.481Z",{RUN_ENVELOPE}{extra},"payload":{payload}}}"#
    )
}

fn response(schema: &str, version: u16, payload: &str) -> String {
    format!(
        r#"{{"v":1,"id":"msg_01M24BB8G0E87TVJX9GX248ADD","type":"response","schema":"{schema}","schema_version":{version},"ts":"2026-09-12T09:14:22.481Z","causation_id":"msg_01M24BB8G1FQR94D2PF2XVQDV4","payload":{payload}}}"#
    )
}

const KEY: &str = r#","idempotency_key":"k-01""#;
const READ: &str = r#"{"fs_read":{"path":"/workspace/a","max_bytes":4}}"#;

#[test]
fn version_one_is_kept_exactly_and_version_two_beside_it() {
    // M4b's message, byte for byte, still decodes as version 1.
    let v1 = request("direwolf.tool.invoke", 1, "", READ);
    assert!(matches!(
        dwkp::decode_body(v1.as_bytes()).unwrap().body,
        DwkpBody::ToolInvoke(_)
    ));
    // The same call at version 2 is the typed sum, and needs a key.
    let v2 = request("direwolf.tool.invoke", 2, KEY, READ);
    assert!(matches!(
        dwkp::decode_body(v2.as_bytes()).unwrap().body,
        DwkpBody::ToolInvokeV2(_)
    ));
    let unkeyed = request("direwolf.tool.invoke", 2, "", READ);
    let err = dwkp::decode_body(unkeyed.as_bytes()).unwrap_err();
    assert_eq!(err.violation, Some(Violation::MissingField));
    assert_eq!(err.path, "/idempotency_key");
    // Version 1 still forbids one.
    let keyed_v1 = request("direwolf.tool.invoke", 1, KEY, READ);
    assert_eq!(
        dwkp::decode_body(keyed_v1.as_bytes())
            .unwrap_err()
            .violation,
        Some(Violation::ForbiddenField)
    );
    // A new tool is not a version-1 message, whatever it is called.
    let write = r#"{"fs_write":{"path":"/workspace/a","content":"00"}}"#;
    assert!(dwkp::decode_body(request("direwolf.tool.invoke", 1, "", write).as_bytes()).is_err());
    assert!(dwkp::decode_body(request("direwolf.tool.invoke", 2, KEY, write).as_bytes()).is_ok());
    // A process call is not a version-2 message, whatever it is called
    // (ADR-0045): to version 2 it is an undeclared member. Version 3 has it.
    let exec = r#"{"process_exec":{"executable":"/usr/bin/git","args":["status"]}}"#;
    assert!(dwkp::decode_body(request("direwolf.tool.invoke", 2, KEY, exec).as_bytes()).is_err());
    assert!(matches!(
        dwkp::decode_body(request("direwolf.tool.invoke", 3, KEY, exec).as_bytes())
            .unwrap()
            .body,
        DwkpBody::ToolInvokeV3(_)
    ));
    // A version this build does not know names the range it does.
    let v4 = request("direwolf.tool.invoke", 4, KEY, READ);
    let err = dwkp::decode_body(v4.as_bytes()).unwrap_err();
    assert_eq!(err.code, ErrorCode::VersionUnsupported);
    assert_eq!(err.supported.map(|r| (r.min, r.max)), Some((1, 3)));
}

#[test]
fn a_preview_names_no_invocation_at_either_version() {
    for version in [1, 2] {
        let keyed = request("direwolf.tool.preview", version, KEY, READ);
        assert_eq!(
            dwkp::decode_body(keyed.as_bytes()).unwrap_err().violation,
            Some(Violation::ForbiddenField),
            "v{version}"
        );
        assert!(
            dwkp::decode_body(request("direwolf.tool.preview", version, "", READ).as_bytes())
                .is_ok()
        );
    }
}

#[test]
fn a_version_two_call_is_exactly_one_typed_member() {
    for bad in [
        "{}",
        r#"{"fs_read":{"path":"/workspace/a","max_bytes":1},"fs_stat":{"path":"/workspace/a"}}"#,
        r#"{"fs_copy":{"source":"/workspace/a","destination":"/workspace/b"}}"#,
        r#"{"tool":"fs.write","args":{"path":"/workspace/a"}}"#,
        // A runtime-asserted fact.
        r#"{"fs_write":{"path":"/workspace/a","content":"00","create":true}}"#,
        r#"{"fs_move":{"source":"/workspace/a","destination":"/workspace/b","replace":true}}"#,
        r#"{"fs_delete":{"path":"/workspace/a","recursive":true}}"#,
        // Out of range.
        r#"{"fs_list":{"path":"/workspace","max_entries":513}}"#,
        r#"{"fs_search":{"path":"/workspace/a","needle":"","max_scan_bytes":1,"max_matches":1}}"#,
        r#"{"fs_search":{"path":"/workspace/a","needle":"0A","max_scan_bytes":1,"max_matches":1}}"#,
        r#"{"fs_search":{"path":"/workspace/a","needle":"0a","max_scan_bytes":16777217,"max_matches":1}}"#,
        r#"{"fs_patch":{"path":"/workspace/a","base":{"sha256":"00","length":0},"post":{"sha256":"00","length":0},"edits":[]}}"#,
    ] {
        assert!(
            dwkp::decode_body(request("direwolf.tool.invoke", 2, KEY, bad).as_bytes()).is_err(),
            "{bad} decoded"
        );
    }
}

/// A canonical path of 384 characters that canonical JSON escapes to the most
/// bytes (a control character is six).
fn worst_path() -> String {
    format!("/{}", "\\u0001".repeat(383))
}

fn worst_plan(tool: &str) -> String {
    let rule_id = format!("a{}", "-".repeat(63));
    let rule_source = format!("{}:{}", "a".repeat(240), "9".repeat(8));
    let action = format!(
        r#"{{"role":"DESTINATION","verb":"fs.create","canonical_path":"{}","object":"EXISTING","byte_count":9007199254740991,"decision":{{"effect":"DENY","reason":"OBLIGATION_UNENFORCEABLE","capability_result":"NOT_SATISFIED","policy_result":"NOT_SATISFIED","rule_id":"{rule_id}","rule_source":"{rule_source}"}}}}"#,
        worst_path()
    );
    let actions = vec![action; MAX_PLAN_ACTIONS].join(",");
    format!(r#"{{"tool":"{tool}","environment":"SANDBOX","effect":"DENY","actions":[{actions}]}}"#)
}

fn fits(text: &str) -> usize {
    let message = dwkp::decode_body(text.as_bytes()).expect("the largest message decodes");
    let frame = message.to_frame().expect("and frames");
    assert!(frame.len() <= frame::HEADER_LEN + MAX_FRAME_BODY);
    frame.len()
}

#[test]
fn the_largest_version_two_read_result_fits_one_frame() {
    let content = "ff".repeat(MAX_FS_READ_BYTES);
    let payload = format!(
        r#"{{"invocation_id":"inv_01M24BB8G4E87TVJX9GX248ADD","plan":{},"output":{{"fs_read":{{"content":"{content}","eof_observed":false}}}}}}"#,
        worst_plan("fs.read")
    );
    let len = fits(&response("direwolf.tool.result", 2, &payload));
    let overhead = len - 2 * MAX_FS_READ_BYTES;
    assert!(
        overhead < 32 * 1024,
        "everything but the content is {overhead} bytes"
    );
}

#[test]
fn the_largest_listing_fits_one_frame() {
    // The wire bounds a name at 255 characters. The worst is 255 characters
    // of four UTF-8 bytes each, which canonical JSON writes as themselves:
    // 1020 bytes a name. (The authority emits only canonical names, at most
    // 255 bytes, so what it sends is under a quarter of this.)
    for name in ["\u{1F600}".repeat(255), "\\\"".repeat(255)] {
        let entry = format!(r#"{{"name":"{name}","kind":"UNKNOWN"}}"#);
        let entries = vec![entry; MAX_LIST_ENTRIES].join(",");
        let payload = format!(
            r#"{{"invocation_id":"inv_01M24BB8G4E87TVJX9GX248ADD","plan":{},"output":{{"fs_list":{{"entries":[{entries}],"unaddressable":512,"complete":false}}}}}}"#,
            worst_plan("fs.list")
        );
        let len = fits(&response("direwolf.tool.result", 2, &payload));
        assert!(
            len + 256 * 1024 < MAX_FRAME_BODY,
            "a worst-case listing is {len} bytes"
        );
    }
}

#[test]
fn the_largest_search_result_fits_one_frame() {
    let offsets = vec!["9007199254740991"; MAX_SEARCH_MATCHES].join(",");
    let payload = format!(
        r#"{{"invocation_id":"inv_01M24BB8G4E87TVJX9GX248ADD","plan":{},"output":{{"fs_search":{{"offsets":[{offsets}],"scanned":16777216,"eof_observed":false,"matches_truncated":true}}}}}}"#,
        worst_plan("fs.search")
    );
    let len = fits(&response("direwolf.tool.result", 2, &payload));
    assert!(len < 64 * 1024, "a worst-case search result is {len} bytes");
}

#[test]
fn the_largest_write_request_fits_one_frame() {
    let path = worst_path();
    let content = "ff".repeat(MAX_FS_WRITE_BYTES);
    let payload = format!(r#"{{"fs_write":{{"path":"{path}","content":"{content}"}}}}"#);
    let len = fits(&request(
        "direwolf.tool.invoke",
        2,
        r#","idempotency_key":"k""#,
        &payload,
    ));
    assert!(len - 2 * MAX_FS_WRITE_BYTES < 8 * 1024);
    // One byte more is not a write.
    let over = "ff".repeat(MAX_FS_WRITE_BYTES + 1);
    let payload = format!(r#"{{"fs_write":{{"path":"/workspace/a","content":"{over}"}}}}"#);
    let err = dwkp::decode_body(request("direwolf.tool.invoke", 2, KEY, &payload).as_bytes())
        .unwrap_err();
    assert_eq!(err.violation, Some(Violation::TooLong));
}

#[test]
fn a_body_is_only_ever_sent_as_its_own_version() {
    // Encoding re-checks the header against the body's own version: a
    // version-2 body cannot be sent under a version-1 header.
    let v2 = request("direwolf.tool.invoke", 2, KEY, READ);
    let mut message = dwkp::decode_body(v2.as_bytes()).unwrap();
    assert!(message.to_frame().is_ok());
    message.header.schema_version = dwk_proto::wire::scalar::Version::new(1).unwrap();
    assert_eq!(
        message.to_frame().unwrap_err().violation,
        Some(Violation::Inconsistent)
    );
}

// ---------------------------------------------------------------------------
// fs.patch: the whole request, inline, in one frame (ADR-0044 §12).
// ---------------------------------------------------------------------------

/// A request envelope with every optional header field present at its
/// longest: correlation and causation ids, the largest epoch, and a
/// 128-character idempotency key.
fn worst_request(payload: &str) -> String {
    let key = format!("k{}", "-".repeat(127));
    format!(
        r#"{{"v":1,"id":"msg_01M24BB8G0E87TVJX9GX248ADD","type":"request","schema":"direwolf.tool.invoke","schema_version":2,"ts":"2026-09-12T09:14:22.481Z","correlation_id":"msg_01M24BB8G1FQR94D2PF2XVQDV4","causation_id":"msg_01M24BB8G1FQR94D2PF2XVQDV5","session_id":"ses_01M24BB8G1FQR94D2PF2XVQDV4","run_id":"run_01M24BB8G3E0A851TRWE3M8FZF","epoch":9007199254740991,"idempotency_key":"{key}","payload":{payload}}}"#
    )
}

/// A patch payload: `edits` as `(offset, delete, inserted bytes)`.
fn patch_payload(
    path: &str,
    base: (&str, u32),
    post: (&str, u32),
    edits: &[(u32, u32, usize)],
) -> String {
    let edits: Vec<String> = edits
        .iter()
        .map(|(offset, delete, insert)| {
            format!(
                r#"{{"offset":{offset},"delete":{delete},"insert":"{}"}}"#,
                "ff".repeat(*insert)
            )
        })
        .collect();
    format!(
        r#"{{"fs_patch":{{"path":"{path}","base":{{"sha256":"{}","length":{}}},"post":{{"sha256":"{}","length":{}}},"edits":[{}]}}}}"#,
        base.0,
        base.1,
        post.0,
        post.1,
        edits.join(",")
    )
}

/// One line of evidence for `make filesystem-operations-evidence`.
fn frame_evidence(case: &str, encoded: usize) {
    println!(
        "FSOP-EVIDENCE {{\"suite\":\"patch-frame\",\"case\":\"{case}\",\"outcome\":\"fits\",\"encoded_bytes\":{encoded},\"frame_bytes\":{MAX_FRAME_BODY},\"margin_bytes\":{}}}",
        MAX_FRAME_BODY - encoded
    );
}

#[test]
fn the_largest_patch_request_any_decoder_accepts_fits_one_frame_with_its_margin() {
    // An upper bound on every valid patch: each field at the largest the wire
    // admits, whether or not it could mean anything — a path of 384 control
    // characters (six bytes each once escaped), 64 edits with seven-digit
    // offsets and lengths, and the whole inline bound inserted.
    let digest = "f".repeat(64);
    let mut edits = vec![(1_048_576, 1_048_576, 1); MAX_PATCH_EDITS];
    edits[0].2 = MAX_PATCH_INSERT_BYTES_TOTAL - (MAX_PATCH_EDITS - 1);
    let text = worst_request(&patch_payload(
        &worst_path(),
        (&digest, 1_048_576),
        (&digest, 1_048_576),
        &edits,
    ));
    let framed = fits(&text);
    assert!(
        framed <= MAX_PATCH_REQUEST_ENCODED_BYTES,
        "the largest patch request is {framed} bytes, over the derived {MAX_PATCH_REQUEST_ENCODED_BYTES}"
    );
    assert!(framed + PATCH_FRAME_MARGIN_BYTES <= frame::HEADER_LEN + MAX_FRAME_BODY);
    assert!(
        framed - 2 * MAX_PATCH_INSERT_BYTES_TOTAL <= MAX_PATCH_REQUEST_OVERHEAD_BYTES,
        "everything but the inserted content is {} bytes",
        framed - 2 * MAX_PATCH_INSERT_BYTES_TOTAL
    );
    frame_evidence("largest-decodable-patch-request", framed);
}

#[test]
fn the_largest_semantically_valid_patch_request_fits_one_frame() {
    // A patch the authority would accept: a canonical 384-character path of
    // four-byte characters (each component 63 of them, 252 bytes), 64
    // ascending, non-overlapping edits over a 786 432-byte base, each deleting
    // one byte, inserting the whole bound between them — and the lengths
    // adding up: 786 432 - 64 + 262 144 = 1 048 512, within the file bound.
    let component = "\u{1F600}".repeat(63);
    let mut path = String::from("/workspace");
    for _ in 0..5 {
        path.push('/');
        path.push_str(&component);
    }
    path.push('/');
    path.push_str(&"\u{1F600}".repeat(53));
    assert_eq!(path.chars().count(), 384);
    let base_length: u32 = 786_432;
    let edit_count = u32::try_from(MAX_PATCH_EDITS).unwrap();
    let inserted = u32::try_from(MAX_PATCH_INSERT_BYTES_TOTAL).unwrap();
    let post_length = base_length - edit_count + inserted;
    assert!(usize::try_from(post_length).unwrap() <= MAX_PATCH_FILE_BYTES);
    let mut edits: Vec<(u32, u32, usize)> = (0..edit_count).map(|i| (12_288 * i, 1, 1)).collect();
    edits[0].2 = MAX_PATCH_INSERT_BYTES_TOTAL - (MAX_PATCH_EDITS - 1);
    let base_digest = "a".repeat(64);
    let post_digest = "b".repeat(64);
    let text = worst_request(&patch_payload(
        &path,
        (&base_digest, base_length),
        (&post_digest, post_length),
        &edits,
    ));
    let framed = fits(&text);
    assert!(framed <= MAX_PATCH_REQUEST_ENCODED_BYTES);
    frame_evidence("largest-valid-patch-request", framed);
}

#[test]
fn a_single_edit_is_bounded_by_its_type_and_a_frame_by_its_header() {
    // One edit cannot carry more than the whole inline bound by itself: its
    // hexadecimal is bounded at decode...
    let digest = "f".repeat(64);
    let over = request(
        "direwolf.tool.invoke",
        2,
        KEY,
        &patch_payload(
            "/workspace/a",
            (&digest, 1),
            (&digest, 1),
            &[(0, 0, MAX_PATCH_INSERT_BYTES_TOTAL + 1)],
        ),
    );
    assert_eq!(
        dwkp::decode_body(over.as_bytes()).unwrap_err().violation,
        Some(Violation::TooLong)
    );
    // ...and a body past the frame is refused from the header, before a byte
    // of it is buffered (tests/framing.rs), so no edit count can smuggle more
    // in. What is between the two — several edits that together insert more
    // than the bound, in a frame that fits — decodes, and is refused by the
    // authority as PATCH_TOO_LARGE before anything is resolved or recorded
    // (state::plan and tests/broker_fs_ops.rs).
    let digest = "f".repeat(64);
    let split = request(
        "direwolf.tool.invoke",
        2,
        KEY,
        &patch_payload(
            "/workspace/a",
            (&digest, 1),
            (&digest, 1),
            &[(0, 0, MAX_PATCH_INSERT_BYTES_TOTAL), (1, 0, 1)],
        ),
    );
    assert!(dwkp::decode_body(split.as_bytes()).is_ok());
}
