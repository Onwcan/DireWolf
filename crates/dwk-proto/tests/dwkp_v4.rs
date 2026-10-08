//! Version 4 of the tool messages (M5c, ADR-0050): `net.http` beside the
//! filesystem and process tools, its largest request and result proved to fit
//! one frame — the unchanged 1 MiB frame — at their worst, and the wire
//! refusing what no runtime may say.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

mod common;

use dwk_proto::dwkp::{self, DwkpBody};
use dwk_proto::limits::{
    MAX_FRAME_BODY, MAX_NET_REQUEST_BODY_BYTES, MAX_NET_REQUEST_ENCODED_BYTES,
    MAX_NET_RESPONSE_BODY_BYTES, MAX_NET_RESULT_ENCODED_BYTES, MAX_PLAN_ACTIONS,
};
use dwk_proto::wire::http::{MAX_HOPS, MAX_KEPT_HEADER_VALUE_BYTES, MAX_KEPT_RESPONSE_HEADERS};
use dwk_proto::{ErrorCode, Violation, frame};

const KEY: &str = "k-1";

fn request(version: u16, key: &str, payload: &str) -> String {
    let key = if key.is_empty() {
        String::new()
    } else {
        format!(r#","idempotency_key":"{key}""#)
    };
    format!(
        r#"{{"v":1,"id":"msg_01M24BB8G0E87TVJX9GX248ADD","type":"request","schema":"direwolf.tool.invoke","schema_version":{version},"ts":"2026-09-12T09:14:22.481Z","session_id":"ses_01M24BB8G1FQR94D2PF2XVQDV4","run_id":"run_01M24BB8G3E0A851TRWE3M8FZF","epoch":1{key},"payload":{payload}}}"#
    )
}

fn response(payload: &str) -> String {
    format!(
        r#"{{"v":1,"id":"msg_01M24BB8G0E87TVJX9GX248ADD","type":"response","schema":"direwolf.tool.result","schema_version":4,"ts":"2026-09-12T09:14:22.481Z","causation_id":"msg_01M24BB8G1FQR94D2PF2XVQDV4","correlation_id":"msg_01M24BB8G1FQR94D2PF2XVQDV5","payload":{payload}}}"#
    )
}

fn fits(text: &str) -> usize {
    let message = dwkp::decode_body(text.as_bytes()).expect("the largest message decodes");
    let frame = message.to_frame().expect("and frames");
    assert!(frame.len() <= frame::HEADER_LEN + MAX_FRAME_BODY);
    frame.len()
}

/// One line of M5c evidence for `make net-http-evidence`.
fn frame_evidence(case: &str, encoded: usize) {
    println!(
        "NET-EVIDENCE {{\"suite\":\"net-frame\",\"case\":\"{case}\",\"outcome\":\"fits\",\"layer\":\"wire\",\"encoded_bytes\":{encoded},\"frame_bytes\":{MAX_FRAME_BODY},\"margin_bytes\":{}}}",
        MAX_FRAME_BODY - encoded
    );
}

/// The worst valid `net_http`: an 8 KiB URL of `"`-free characters canonical
/// JSON escapes (`\`, twice the bytes), 32 headers of the longest name and a
/// value whose every character escapes, the largest body, a handle.
fn worst_net_call() -> String {
    let url = format!("https://a.b/{}", "\\\\".repeat(8192 - 12));
    let headers: Vec<String> = (0..32)
        .map(|i| {
            let name = format!("x-{i:02}{}", "a".repeat(64 - 4));
            let value = format!("a{}a", "\\\\".repeat(4094));
            format!(r#"{{"name":"{name}","value":"{value}"}}"#)
        })
        .collect();
    let handle = format!("a{}", "-".repeat(63));
    format!(
        r#"{{"net_http":{{"method":"POST","url":"{url}","headers":[{}],"body":"{}","credential_handle":"{handle}","follow_redirects":true,"max_response_bytes":262144}}}}"#,
        headers.join(","),
        "ff".repeat(MAX_NET_REQUEST_BODY_BYTES),
    )
}

#[test]
fn the_largest_valid_network_request_fits_one_frame() {
    let text = request(4, &format!("k{}", "-".repeat(127)), &worst_net_call());
    let message = dwkp::decode_body(text.as_bytes()).unwrap();
    assert!(matches!(message.body, DwkpBody::ToolInvokeV4(_)));
    let framed = fits(&text);
    assert!(
        framed <= MAX_NET_REQUEST_ENCODED_BYTES,
        "the largest network request is {framed} bytes, over the derived {MAX_NET_REQUEST_ENCODED_BYTES}"
    );
    frame_evidence("largest-valid-network-request", framed);
}

/// The longest canonical host: 253 characters.
fn longest_host() -> String {
    format!("{}.{}", vec!["a".repeat(63); 3].join("."), "a".repeat(61))
}

fn worst_net_plan() -> String {
    let rule_id = format!("a{}", "-".repeat(63));
    let rule_source = format!("{}:{}", "a".repeat(240), "9".repeat(8));
    let decision = format!(
        r#"{{"effect":"DENY","reason":"OBLIGATION_UNENFORCEABLE","capability_result":"NOT_SATISFIED","policy_result":"NOT_SATISFIED","rule_id":"{rule_id}","rule_source":"{rule_source}"}}"#
    );
    let host = longest_host();
    let net = format!(
        r#"{{"net":{{"host":"{host}","port":65535,"method":"OPTIONS","url_sha256":"{}","body_bytes":9007199254740991,"decision":{decision}}}}}"#,
        "f".repeat(64)
    );
    let injection = format!(
        r#"{{"injection":{{"handle":"a{}","host":"{host}","port":65535,"decision":{decision}}}}}"#,
        "-".repeat(63)
    );
    let mut actions = vec![net.clone(); MAX_PLAN_ACTIONS - 1];
    actions.push(injection);
    format!(
        r#"{{"tool":"net.http","environment":"HOST","effect":"DENY","actions":[{}]}}"#,
        actions.join(",")
    )
}

#[test]
fn the_largest_network_result_fits_one_frame() {
    let host = longest_host();
    let headers: Vec<String> = (0..MAX_KEPT_RESPONSE_HEADERS)
        .map(|_| {
            format!(
                r#"{{"name":"link","value":"a{}a"}}"#,
                "\\\\".repeat(MAX_KEPT_HEADER_VALUE_BYTES - 2)
            )
        })
        .collect();
    let hops: Vec<String> = (1..=MAX_HOPS)
        .map(|hop| {
            format!(
                r#"{{"hop":{hop},"host":"{host}","port":65535,"method":"OPTIONS","status":599,"injected":true}}"#
            )
        })
        .collect();
    let payload = format!(
        r#"{{"invocation_id":"inv_01M24BB8G4E87TVJX9GX248ADD","plan":{},"output":{{"net_http":{{"status":599,"headers":[{}],"body":"{}","truncated":true,"hops":[{}],"redirect_ended":"REDIRECT_WOULD_RESEND_BODY"}}}}}}"#,
        worst_net_plan(),
        headers.join(","),
        "ff".repeat(MAX_NET_RESPONSE_BODY_BYTES),
        hops.join(",")
    );
    let framed = fits(&response(&payload));
    assert!(
        framed <= MAX_NET_RESULT_ENCODED_BYTES,
        "the largest network result is {framed} bytes, over the derived {MAX_NET_RESULT_ENCODED_BYTES}"
    );
    frame_evidence("largest-network-result", framed);
}

#[test]
fn a_network_call_belongs_to_version_four_only() {
    let call = r#"{"net_http":{"method":"GET","url":"https://api.example.com/","follow_redirects":false}}"#;
    for version in [2, 3] {
        assert!(
            dwkp::decode_body(request(version, KEY, call).as_bytes()).is_err(),
            "v{version}"
        );
    }
    assert!(matches!(
        dwkp::decode_body(request(4, KEY, call).as_bytes())
            .unwrap()
            .body,
        DwkpBody::ToolInvokeV4(_)
    ));
    // The key is mandatory, as for every effect-bearing version.
    let err = dwkp::decode_body(request(4, "", call).as_bytes()).unwrap_err();
    assert_eq!(err.violation, Some(Violation::MissingField));
    // Version 4 still carries the eleven earlier tools.
    let exec = r#"{"process_exec":{"executable":"/usr/bin/git","args":["status"]}}"#;
    assert!(dwkp::decode_body(request(4, KEY, exec).as_bytes()).is_ok());
    let v5 = request(5, KEY, call);
    let err = dwkp::decode_body(v5.as_bytes()).unwrap_err();
    assert_eq!(err.code, ErrorCode::VersionUnsupported);
    assert_eq!(err.supported.map(|r| (r.min, r.max)), Some((1, 4)));
}

#[test]
fn hostile_spellings_do_not_decode() {
    let base = |member: &str| {
        request(
            4,
            KEY,
            &format!(
                r#"{{"net_http":{{"method":"GET","url":"https://a.b/","follow_redirects":false{member}}}}}"#
            ),
        )
    };
    assert!(dwkp::decode_body(base("").as_bytes()).is_ok());
    for (case, member) in [
        ("raw-address", r#","address":"127.0.0.1""#),
        ("resolver", r#","resolve":"a.b=127.0.0.1""#),
        ("proxy", r#","proxy":"socks5://p""#),
        ("insecure", r#","insecure":true"#),
        ("trust-root", r#","ca":"x""#),
        ("credential-value", r#","authorization":"Bearer x""#),
        ("credential-header", r#","credential_header":"x-api-key""#),
        ("cookie-jar", r#","cookies":{}"#),
        ("timeout", r#","timeout_ms":999999"#),
        ("mode", r#","mode":"egress""#),
        (
            "header-crlf",
            r#","headers":[{"name":"x-a","value":"a\r\nb"}]"#,
        ),
        (
            "header-nul",
            r#","headers":[{"name":"x-a","value":"a\u0000b"}]"#,
        ),
        (
            "header-tab",
            r#","headers":[{"name":"x-a","value":"a\tb"}]"#,
        ),
        ("header-upper", r#","headers":[{"name":"X-A","value":"b"}]"#),
        ("header-utf8", r#","headers":[{"name":"x-a","value":"é"}]"#),
        (
            "header-space-name",
            r#","headers":[{"name":"x a","value":"b"}]"#,
        ),
        ("body-odd", r#","body":"f""#),
        ("body-upper", r#","body":"FF""#),
        ("limit-zero", r#","max_response_bytes":0"#),
        ("limit-huge", r#","max_response_bytes":262145"#),
        ("handle-upper", r#","credential_handle":"Token""#),
    ] {
        assert!(
            dwkp::decode_body(base(member).as_bytes()).is_err(),
            "{case}"
        );
    }
    let too_many: Vec<String> = (0..33)
        .map(|i| format!(r#"{{"name":"x-h{i}","value":"v"}}"#))
        .collect();
    let headers = format!(r#","headers":[{}]"#, too_many.join(","));
    assert!(dwkp::decode_body(base(&headers).as_bytes()).is_err());
    let big_body = format!(
        r#","body":"{}""#,
        "ff".repeat(MAX_NET_REQUEST_BODY_BYTES + 1)
    );
    assert!(dwkp::decode_body(base(&big_body).as_bytes()).is_err());
    let long_url = request(
        4,
        KEY,
        &format!(
            r#"{{"net_http":{{"method":"GET","url":"https://a.b/{}","follow_redirects":false}}}}"#,
            "a".repeat(8192)
        ),
    );
    assert!(dwkp::decode_body(long_url.as_bytes()).is_err());
}

#[test]
fn a_result_header_has_one_spelling() {
    let payload = |name: &str| {
        response(&format!(
            r#"{{"invocation_id":"inv_01M24BB8G4E87TVJX9GX248ADD","plan":{{"tool":"net.http","environment":"HOST","effect":"ALLOW","actions":[]}},"output":{{"net_http":{{"status":200,"headers":[{{"name":"{name}","value":"v"}}],"body":"","truncated":false,"hops":[]}}}}}}"#
        ))
    };
    // The wire types accept any spelled header: the keep-list is the
    // authority's and the broker's (`wire::http`), applied before a result
    // exists. What the wire refuses is a header not in its one spelling.
    assert!(dwkp::decode_body(payload("content-type").as_bytes()).is_ok());
    assert!(dwkp::decode_body(payload("Set-Cookie").as_bytes()).is_err());
}
