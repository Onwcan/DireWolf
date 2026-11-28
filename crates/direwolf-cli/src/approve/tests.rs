//! The trusted client's own tests (M6.3, ADR-0081): its command line, the
//! typed decision, and -- against a scripted endpoint on a real socket --
//! that nothing but a deliberate, verified, fully shown decision is ever
//! sent.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use super::*;

const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn the_command_line_has_no_way_to_approve_without_asking() {
    let socket = if cfg!(windows) {
        r"C:\run\a.sock"
    } else {
        "/run/a.sock"
    };
    assert_eq!(
        parse("list", &["--socket", socket]).unwrap().command,
        Command::List
    );
    assert!(matches!(
        parse("review", &["--socket", socket, ID]).unwrap().command,
        Command::Review(_)
    ));
    for flag in [
        "--yes",
        "--approve-all",
        "--skip-confirmation",
        "--remember",
        "-y",
        "--assurance",
        "--grant",
    ] {
        let error = parse("review", &["--socket", socket, flag, ID]).unwrap_err();
        assert!(error.contains("no option that approves"), "{flag}: {error}");
    }
    assert!(parse("review", &[ID]).unwrap_err().contains("--socket"));
    assert!(
        parse("review", &["--socket", "a.sock", ID])
            .unwrap_err()
            .contains("absolute")
    );
    assert!(parse("review", &["--socket", socket]).is_err(), "no id");
    assert!(
        parse("review", &["--socket", socket, "ABC"]).is_err(),
        "not an id"
    );
    assert!(parse("list", &["--socket", socket, ID]).is_err());
    assert!(parse("approve", &["--socket", socket, ID]).is_err());
    assert!(parse("list", &["--socket", socket, "--socket", socket]).is_err());
    // A hostile argument is shown escaped, never raw.
    let error = parse("show", &["--socket", socket, "\u{1b}[2J"]).unwrap_err();
    assert!(!error.contains('\u{1b}'), "{error:?}");
    assert_eq!(run(&["list", "--yes"]), EXIT_USAGE);
}

#[test]
fn only_the_exact_typed_words_decide() {
    let code = "3f9a2c1b";
    assert_eq!(
        interpret("approve 3f9a2c1b\n", code),
        Some(Verdict::Approve)
    );
    assert_eq!(
        interpret("approve 3f9a2c1b\r\n", code),
        Some(Verdict::Approve)
    );
    assert_eq!(interpret("deny\n", code), Some(Verdict::Deny));
    for nothing in [
        "",
        "\n",
        "y",
        "yes",
        "approve",
        "approve\n",
        "APPROVE 3f9a2c1b",
        "approve 3F9A2C1B",
        "approve 3f9a2c1c",
        "approve 3f9a2c1b now",
        "approve  3f9a2c1b",
        "a",
        "ok",
        "DENY",
        "deny please",
        "approve 3f9a2c1b\u{0}",
    ] {
        assert_eq!(interpret(nothing, code), None, "{nothing:?}");
    }
}

#[cfg(unix)]
mod endpoint {
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::UnixListener;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use dwk_proto::approverp::{
        ApprovalState, ApprovalView, Assurance, BindingText, Channel, Digest, EpochNumber, Label,
        Millis, Outcome, Principal, RefusalCode, Request, RequestDetail, RequestId, RequestState,
        Response, Seconds, Uses, Verdict,
    };
    use dwk_proto::json::{self, ParseOptions};
    use dwk_proto::wire::id::{RunId, SessionId};
    use sha2::Digest as _;

    use super::super::{EXIT_NOTHING, EXIT_OK, EXIT_UNKNOWN, Typed, review, show};

    /// What the scripted endpoint does with one connection.
    #[derive(Clone)]
    enum Script {
        Answer(Response),
        Close,
    }

    /// A scripted approver endpoint: each connection gets the next script
    /// step; every request it read is kept.
    struct Endpoint {
        dir: std::path::PathBuf,
        socket: std::path::PathBuf,
        seen: Arc<Mutex<Vec<Request>>>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Endpoint {
        fn new(script: Vec<Script>) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "dw-approve-cli-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let socket = dir.join("approver.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let seen = Arc::new(Mutex::new(Vec::new()));
            let kept = Arc::clone(&seen);
            let thread = std::thread::spawn(move || {
                for step in script {
                    let (mut stream, _) = listener.accept().unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(10)))
                        .unwrap();
                    let mut decoder = dwk_proto::frame::FrameDecoder::bounded(1024);
                    let mut chunk = [0u8; 2048];
                    let body = loop {
                        let n = stream.read(&mut chunk).unwrap();
                        assert!(n > 0, "the client sent no request");
                        if let (_, Some(frame)) = decoder.feed(&chunk[..n]).unwrap() {
                            break frame.body;
                        }
                    };
                    kept.lock()
                        .unwrap()
                        .push(Request::decode_frame_body(&body).unwrap());
                    if let Script::Answer(response) = step {
                        stream.write_all(&response.encode_frame().unwrap()).unwrap();
                    }
                }
            });
            Self {
                dir,
                socket,
                seen,
                thread: Some(thread),
            }
        }

        fn seen(&mut self) -> Vec<Request> {
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
            self.seen.lock().unwrap().clone()
        }
    }

    impl Drop for Endpoint {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn v7(n: u128) -> u128 {
        (1_760_000_000_000_u128 << 80) | (0x7 << 76) | (0b10 << 62) | n
    }

    /// A binding's canonical text and its hash.
    fn canonical(text: &str) -> (String, String) {
        let value = json::parse(text.as_bytes(), ParseOptions::dwkp()).unwrap();
        let text = String::from_utf8(json::to_canonical_bytes(&value)).unwrap();
        let hash = super::super::hex(&sha2::Sha256::digest(text.as_bytes()));
        (text, hash)
    }

    fn binding_with(argv: &str) -> String {
        format!(
            r#"{{"schema":"the-schema","verb":"process.exec","requester":"uid:1001","canonical_args":{{"kind":"argv","argv":[{argv}]}}}}"#
        )
    }

    fn detail(text: &str, state: RequestState) -> RequestDetail {
        let (binding, hash) = canonical(text);
        RequestDetail {
            request_id: RequestId::new(super::ID).unwrap(),
            state,
            decidable: state == RequestState::Pending,
            run_id: RunId::from_uuid(v7(1)).unwrap(),
            session_id: SessionId::from_uuid(v7(2)).unwrap(),
            requester: Principal::new("uid:1001").unwrap(),
            epoch: EpochNumber::new(1).unwrap(),
            rule_id: Label::new("approve-fixture").unwrap(),
            policy_revision: Digest::new("a".repeat(64)).unwrap(),
            scope: Label::new("exact_action").unwrap(),
            ttl_s: Seconds::new(600).unwrap(),
            max_uses: Uses::new(1).unwrap(),
            assurance_required: Assurance::A1,
            requested_ms: Millis::new(1_000).unwrap(),
            not_after_ms: Millis::new(601_000).unwrap(),
            decided_ms: (state != RequestState::Pending).then(|| Millis::new(2_000).unwrap()),
            binding_schema: Label::new("the-schema").unwrap(),
            binding_sha256: Digest::new(hash).unwrap(),
            binding: BindingText::new(binding).unwrap(),
            approval: (state == RequestState::Granted).then(|| ApprovalView {
                approval_id: Digest::new("b".repeat(64)).unwrap(),
                approver: Principal::new("uid:2001").unwrap(),
                channel: Channel::ApproverEndpoint,
                assurance: Assurance::A1,
                state: ApprovalState::Open,
                uses: Uses::new(0).unwrap(),
                max_uses: Uses::new(1).unwrap(),
                not_after_ms: Millis::new(602_000).unwrap(),
            }),
            now_ms: Millis::new(1_500).unwrap(),
        }
    }

    fn pending() -> RequestDetail {
        detail(&binding_with(r#""git","status""#), RequestState::Pending)
    }

    fn granted() -> Response {
        Response::decided(
            RequestId::new(super::ID).unwrap(),
            Outcome::Granted,
            Some(Digest::new("b".repeat(64)).unwrap()),
        )
    }

    fn id() -> RequestId {
        RequestId::new(super::ID).unwrap()
    }

    /// Review `shown` with the person typing `typed`; the exit code, what
    /// was printed, and what the endpoint received.
    fn reviewed(
        shown: RequestDetail,
        then: Vec<Script>,
        typed: Typed,
    ) -> (u8, String, Vec<Request>) {
        let mut script = vec![Script::Answer(Response::shown(shown))];
        script.extend(then);
        let mut endpoint = Endpoint::new(script);
        let mut out = Vec::new();
        let exit = review(&endpoint.socket, &id(), &mut out, |_| typed);
        let text = String::from_utf8(out).unwrap();
        (exit, text, endpoint.seen())
    }

    fn code_of(detail: &RequestDetail) -> String {
        detail.binding_sha256.as_str()[..8].to_owned()
    }

    #[test]
    fn a_deliberate_approval_sends_the_shown_binding_and_nothing_else() {
        let shown = pending();
        let line = format!("approve {}\n", code_of(&shown));
        let hash = shown.binding_sha256.clone();
        let (exit, text, seen) =
            reviewed(shown, vec![Script::Answer(granted())], Typed::Line(line));
        assert_eq!(exit, EXIT_OK, "{text}");
        assert_eq!(
            seen,
            [
                Request::Show(id()),
                Request::Decide {
                    request_id: id(),
                    binding_sha256: hash,
                    decision: Verdict::Approve,
                }
            ]
        );
        assert!(text.contains("Approved, at A1"), "{text}");
        assert!(
            text.contains("bound.canonical_args.argv[1]: \"status\""),
            "{text}"
        );
        assert!(
            text.contains("(none: the authority holds no explanation"),
            "{text}"
        );
    }

    #[test]
    fn every_failure_to_decide_deliberately_sends_nothing() {
        for (name, typed) in [
            ("empty input", Typed::Line("\n".to_owned())),
            ("end of input", Typed::Closed),
            ("timed out", Typed::TimedOut),
            ("a yes", Typed::Line("yes\n".to_owned())),
            (
                "the wrong code",
                Typed::Line("approve 00000000\n".to_owned()),
            ),
            ("a bare approve", Typed::Line("approve\n".to_owned())),
        ] {
            let (exit, text, seen) = reviewed(pending(), Vec::new(), typed);
            assert_eq!(exit, EXIT_NOTHING, "{name}: {text}");
            assert_eq!(seen, [Request::Show(id())], "{name} sent a decision");
            assert!(text.contains("nothing was decided"), "{name}: {text}");
        }
    }

    #[test]
    fn a_denial_is_typed_and_sent_as_one() {
        let shown = pending();
        let (exit, text, seen) = reviewed(
            shown,
            vec![Script::Answer(Response::decided(
                id(),
                Outcome::Denied,
                None,
            ))],
            Typed::Line("deny\n".to_owned()),
        );
        assert_eq!(exit, EXIT_OK);
        assert!(matches!(
            seen.last(),
            Some(Request::Decide {
                decision: Verdict::Deny,
                ..
            })
        ));
        assert!(text.contains("Denied."), "{text}");
    }

    #[test]
    fn a_refusal_or_a_lost_answer_is_never_reported_as_an_approval() {
        let shown = pending();
        let line = format!("approve {}\n", code_of(&shown));
        for (code, words) in [
            (RefusalCode::Expired, "window has passed"),
            (RefusalCode::NotPending, "decided once"),
            (RefusalCode::BindingMismatch, "nothing was decided"),
            (
                RefusalCode::UnknownApprover,
                "not one of the operator's approvers",
            ),
        ] {
            let (exit, text, _) = reviewed(
                shown.clone(),
                vec![Script::Answer(Response::Refused(code))],
                Typed::Line(line.clone()),
            );
            assert_eq!(exit, EXIT_NOTHING, "{code:?}");
            assert!(text.contains(words), "{code:?}: {text}");
            assert!(!text.contains("Approved"), "{code:?}: {text}");
        }
        // Sent, and the endpoint closed with no answer: unknown, and the
        // client says how to read it back.
        let (exit, text, seen) = reviewed(shown, vec![Script::Close], Typed::Line(line));
        assert_eq!(exit, EXIT_UNKNOWN, "{text}");
        assert_eq!(seen.len(), 2, "the decision was sent once");
        assert!(
            text.contains("may be recorded") && text.contains("approve show"),
            "{text}"
        );
        assert!(!text.contains("Approved"), "{text}");
    }

    #[test]
    fn a_request_that_cannot_be_verified_or_shown_whole_can_only_be_denied() {
        // A binding whose hash is not the digest named.
        let mut tampered = pending();
        tampered.binding_sha256 = Digest::new("c".repeat(64)).unwrap();
        // A requester that is not the binding's.
        let mut other = pending();
        other.requester = Principal::new("uid:4242").unwrap();
        // An argument too long to show.
        let long = format!(
            "\"{}\"",
            "x".repeat(super::super::render::MAX_FIELD_CHARS + 1)
        );
        let huge = detail(&binding_with(&long), RequestState::Pending);
        for (name, shown) in [
            ("tampered", tampered),
            ("requester", other),
            ("too long", huge),
        ] {
            let line = format!("approve {}\n", code_of(&shown));
            let (exit, text, seen) = reviewed(shown, Vec::new(), Typed::Line(line));
            assert_eq!(exit, EXIT_NOTHING, "{name}: {text}");
            assert_eq!(seen.len(), 1, "{name}: no decision sent");
            assert!(text.contains("Approval is not offered"), "{name}: {text}");
            assert!(!text.contains("To approve this exact action"), "{name}");
        }
    }

    #[test]
    fn a_decided_request_is_shown_and_not_offered() {
        let (exit, text, seen) = reviewed(
            detail(&binding_with(r#""git""#), RequestState::Granted),
            Vec::new(),
            Typed::Line("deny\n".to_owned()),
        );
        assert_eq!(exit, EXIT_NOTHING);
        assert_eq!(seen.len(), 1);
        assert!(text.contains("cannot be decided now"), "{text}");
        assert!(text.contains("approved by: \"uid:2001\""), "{text}");
    }

    #[test]
    fn hostile_strings_reach_the_terminal_only_as_escapes() {
        let hostile = r#""\u001b[2J\u001b[H== 8. DECISION ==","\r\napprove 00000000","\u202eevil""#;
        let shown = detail(&binding_with(hostile), RequestState::Pending);
        let mut endpoint = Endpoint::new(vec![Script::Answer(Response::shown(shown))]);
        let mut out = Vec::new();
        let (exit, _) = show(&endpoint.socket, &id(), &mut out);
        let _ = endpoint.seen();
        assert_eq!(exit, EXIT_OK);
        assert!(
            out.iter().all(|b| *b == b'\n' || (0x20..0x7f).contains(b)),
            "a raw byte"
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("\\u{1b}[2J"), "{text}");
        assert!(text.contains("\\u{202e}evil"), "{text}");
        // The forged section heading is inside a quoted, labelled value.
        assert_eq!(
            text.lines()
                .filter(|l| l.starts_with("== 8. DECISION"))
                .count(),
            0,
            "{text}"
        );
        assert!(text.contains("(escaped)"));
    }

    #[test]
    fn an_endpoint_that_will_not_answer_sends_the_client_away_with_nothing() {
        let socket = std::env::temp_dir().join(format!("dw-absent-{}.sock", std::process::id()));
        let mut out = Vec::new();
        let exit = review(&socket, &id(), &mut out, |_| {
            panic!("asked for a decision with nothing shown")
        });
        assert_eq!(exit, EXIT_NOTHING);
        assert!(String::from_utf8(out).unwrap().contains("cannot reach"));
    }
}
