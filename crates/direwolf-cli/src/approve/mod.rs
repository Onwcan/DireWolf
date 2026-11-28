//! `direwolf approve` -- the trusted approver client (M6.3, ADR-0081,
//! Proposed).
//!
//! ```text
//! direwolf approve list   --socket <PATH>
//! direwolf approve show   --socket <PATH> <REQUEST_ID>
//! direwolf approve review --socket <PATH> <REQUEST_ID>
//! ```
//!
//! It speaks the approver protocol (`dwk_proto::approverp`) to the
//! authority's **approver endpoint** -- never DWKP -- one request per
//! connection, and it must run as one of the operator's approver uids: the
//! endpoint knows who connected from the kernel, not from anything this
//! program sends, and closes any other uid unread. This program switches no
//! user, starts no other program and keeps no state.
//!
//! # What it proves, and what it does not
//!
//! It renders the authority's own record of a request -- the canonical
//! binding, checked here to be canonical and to hash to the digest the
//! authority named -- and asks for a deliberate, typed decision. It never
//! computes an approval binding, never sends a level, a scope, a life or a
//! use count, and has no option that approves without asking. An approval
//! it sends is recorded at **A1**: a dedicated approver account answered.
//! That is not proof that a person read the screen -- any process running as
//! the approver uid can speak this protocol (ADR-0077 §2) -- and no A2 class
//! is approvable at all.
//!
//! # A decision
//!
//! `review` shows the request, then waits for one line:
//!
//! * `approve <code>`, where `<code>` is the first eight characters of the
//!   binding hash shown above it -- an approval of that exact action, once;
//! * `deny` -- a denial;
//! * anything else, nothing, the end of input, an interrupted read or the
//!   request's window running out -- **nothing is decided** and the request
//!   stays pending until its window ends.
//!
//! Approval is never the default, and is not offered at all for a request
//! the client could not show in full or verify. The decision is sent on a new
//! connection; if its answer is lost the client says the outcome is unknown,
//! and `show` reads back what was recorded -- a request is decided once, so
//! sending it again can never decide it twice.

mod render;

use std::io::Write;
use std::time::Duration;

use dwk_proto::approverp::{
    self, Digest, Outcome, RefusalCode, Request, RequestDetail, RequestId, RequestState, Response,
    Verdict,
};
use dwk_proto::json::{self, Object, ParseOptions, Value};
use sha2::Digest as _;

/// The command succeeded: listed, shown, or a decision recorded.
const EXIT_OK: u8 = 0;
/// Nothing was decided: refused, cancelled, unreadable, or not decidable.
const EXIT_NOTHING: u8 = 1;
/// A usage error.
const EXIT_USAGE: u8 = 2;
/// A decision was sent and its answer lost: it may be recorded. `show` says.
const EXIT_UNKNOWN: u8 = 3;

/// The longest the client waits for a person's answer, whatever the
/// request's window.
const MAX_WAIT: Duration = Duration::from_secs(5 * 60);

/// How long one exchange with the endpoint may take.
const EXCHANGE: Duration = Duration::from_secs(10);

const USAGE: &str = "\
direwolf approve - the trusted approver client (ADR-0081)

USAGE:
    direwolf approve list   --socket <PATH>
    direwolf approve show   --socket <PATH> <REQUEST_ID>
    direwolf approve review --socket <PATH> <REQUEST_ID>

Run it as one of the operator's approver uids (dwkd-authority serve
--approver-uid). It talks only to the approver endpoint (--approver-socket).

    list     the approval requests that wait for a decision
    show     one request as the authority recorded it, whatever its state
    review   show one request, then decide it: type `approve <code>`, with
             the code shown, to approve that exact action once, or `deny`.
             Anything else decides nothing. Needs an interactive terminal.

An approval is recorded at A1: a dedicated approver account answered. It is
not proof that a person was present, and no A2 class can be approved.
";

/// `direwolf approve ...`.
pub(crate) fn run(args: &[&str]) -> u8 {
    match args {
        [] | ["-h" | "--help" | "help"] => {
            print!("{USAGE}");
            EXIT_OK
        }
        [command, rest @ ..] => match parse(command, rest) {
            Ok(parsed) => execute(&parsed),
            Err(why) => {
                eprintln!("direwolf approve: {why}\n\n{USAGE}");
                EXIT_USAGE
            }
        },
    }
}

/// A parsed command.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    List,
    Show(RequestId),
    Review(RequestId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Parsed {
    socket: std::path::PathBuf,
    command: Command,
}

fn parse(command: &str, rest: &[&str]) -> Result<Parsed, String> {
    let mut socket = None;
    let mut positional = Vec::new();
    let mut words = rest.iter();
    while let Some(word) = words.next() {
        match *word {
            "--socket" => {
                let Some(path) = words.next() else {
                    return Err("--socket needs a path".to_owned());
                };
                if socket.replace(std::path::PathBuf::from(path)).is_some() {
                    return Err("--socket is given twice".to_owned());
                }
            }
            flag if flag.starts_with('-') => {
                return Err(format!(
                    "unknown option {}: there is no option that approves without asking",
                    render::escape(flag).text
                ));
            }
            other => positional.push(other),
        }
    }
    let socket = socket.ok_or("--socket <PATH> is required: the approver endpoint's socket")?;
    if !socket.is_absolute() {
        return Err("--socket must be an absolute path".to_owned());
    }
    let id = |positional: &[&str]| -> Result<RequestId, String> {
        match positional {
            [id] => RequestId::new(*id).ok_or_else(|| {
                format!(
                    "{} is not a request id: 64 lowercase hexadecimal characters",
                    render::escape(id).text
                )
            }),
            _ => Err("exactly one request id is needed".to_owned()),
        }
    };
    let command = match command {
        "list" if positional.is_empty() => Command::List,
        "list" => return Err("list takes no request id".to_owned()),
        "show" => Command::Show(id(&positional)?),
        "review" => Command::Review(id(&positional)?),
        other => {
            return Err(format!("unknown command {}", render::escape(other).text));
        }
    };
    Ok(Parsed { socket, command })
}

/// What one exchange with the endpoint gave.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Exchanged {
    /// The endpoint's answer.
    Answer(Response),
    /// Nothing could be sent: nothing reached the authority.
    Unsent(String),
    /// The request was sent and no answer came back.
    Lost(String),
}

/// One request on one connection to the approver endpoint.
#[cfg(unix)]
fn exchange(socket: &std::path::Path, request: &Request) -> Exchanged {
    use std::io::Read as _;
    use std::os::unix::net::UnixStream;

    let frame = match request.encode_frame() {
        Ok(frame) => frame,
        Err(error) => return Exchanged::Unsent(error.detail),
    };
    let mut stream = match UnixStream::connect(socket) {
        Ok(stream) => stream,
        Err(error) => {
            return Exchanged::Unsent(format!("cannot reach the approver endpoint: {error}"));
        }
    };
    let _ = stream.set_read_timeout(Some(EXCHANGE));
    let _ = stream.set_write_timeout(Some(EXCHANGE));
    if let Err(error) = stream.write_all(&frame) {
        return Exchanged::Unsent(format!(
            "the endpoint closed before the request was sent: {error}"
        ));
    }
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                bytes.extend_from_slice(chunk.get(..n).unwrap_or_default());
                if bytes.len() > approverp::MAX_RESPONSE_BODY + dwk_proto::frame::HEADER_LEN {
                    return Exchanged::Lost(
                        "the answer is larger than any the endpoint sends".to_owned(),
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Exchanged::Lost(if bytes.is_empty() {
                    format!(
                        "no answer: {error} (an approver uid the endpoint refused is closed unread)"
                    )
                } else {
                    format!("the answer was cut off: {error}")
                });
            }
        }
    }
    if bytes.is_empty() {
        return Exchanged::Lost(
            "the endpoint closed with no answer: is this program running as an approver uid?"
                .to_owned(),
        );
    }
    match dwk_proto::frame::decode_all(&bytes) {
        Ok(frames) => match frames.as_slice() {
            [frame] => match Response::decode_frame_body(&frame.body) {
                Ok(response) => Exchanged::Answer(response),
                Err(_) => Exchanged::Lost("the answer is not the approver protocol's".to_owned()),
            },
            _ => Exchanged::Lost("the endpoint sent more than one answer".to_owned()),
        },
        Err(error) => Exchanged::Lost(format!("the answer is not one frame: {}", error.detail)),
    }
}

#[cfg(not(unix))]
fn exchange(_socket: &std::path::Path, _request: &Request) -> Exchanged {
    Exchanged::Unsent(
        "the approver endpoint is a Unix-domain socket on the authority's host; this platform \
         has none"
            .to_owned(),
    )
}

/// A person's answer to the prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Typed {
    /// One line.
    Line(String),
    /// The end of input, or a read that failed.
    Closed,
    /// No line before the wait ended.
    TimedOut,
}

/// What a typed line decides.
fn interpret(line: &str, code: &str) -> Option<Verdict> {
    let line = line.strip_suffix('\n').unwrap_or(line);
    let line = line.strip_suffix('\r').unwrap_or(line).trim();
    if line == format!("approve {code}") {
        Some(Verdict::Approve)
    } else if line == "deny" {
        Some(Verdict::Deny)
    } else {
        None
    }
}

/// Read one line from standard input within `wait`.
fn read_line(wait: Duration) -> Typed {
    let (send, receive) = std::sync::mpsc::channel();
    let _ = std::thread::Builder::new()
        .name("approve-input".to_owned())
        .spawn(move || {
            let mut line = String::new();
            let answer = match std::io::stdin().read_line(&mut line) {
                Ok(0) | Err(_) => Typed::Closed,
                Ok(_) => Typed::Line(line),
            };
            let _ = send.send(answer);
        });
    receive.recv_timeout(wait).unwrap_or(Typed::TimedOut)
}

fn execute(parsed: &Parsed) -> u8 {
    let mut out = std::io::stdout();
    match &parsed.command {
        Command::List => list(&parsed.socket, &mut out),
        Command::Show(id) => show(&parsed.socket, id, &mut out).0,
        Command::Review(id) => {
            use std::io::IsTerminal as _;
            if !std::io::stdin().is_terminal() {
                eprintln!(
                    "direwolf approve: review needs an interactive terminal on its input; \
                     nothing was decided"
                );
                return EXIT_NOTHING;
            }
            review(&parsed.socket, id, &mut out, read_line)
        }
    }
}

fn say(out: &mut dyn Write, line: &str) {
    let _ = writeln!(out, "{line}");
}

fn refusal_text(code: RefusalCode) -> &'static str {
    match code {
        RefusalCode::MalformedRequest => "the endpoint could not read the request",
        RefusalCode::UnsupportedProtocol => "the endpoint speaks another protocol version",
        RefusalCode::UnknownRequest => "no such request",
        RefusalCode::NotPending => "the request is already decided or expired; it is decided once",
        RefusalCode::Expired => "the request's window has passed; it is now expired",
        RefusalCode::RunEnded => "the request's run has ended; it is now expired",
        RefusalCode::BindingMismatch => {
            "the binding shown is not the request's: nothing was decided"
        }
        RefusalCode::UnknownApprover => "this uid is not one of the operator's approvers now",
        RefusalCode::SelfApproval => "the approver is the requester",
        RefusalCode::AssuranceUnavailable => {
            "the request needs a level no approver can give here (A2)"
        }
        RefusalCode::Unavailable => "the authority could not answer",
    }
}

fn list(socket: &std::path::Path, out: &mut dyn Write) -> u8 {
    match exchange(socket, &Request::List) {
        Exchanged::Answer(Response::Listed(listed)) => {
            say(
                out,
                &format!(
                    "{} request(s) wait for a decision; {} shown, oldest first.",
                    listed.waiting.get(),
                    listed.requests.len()
                ),
            );
            for summary in listed.requests.iter() {
                let remaining = seconds(
                    summary
                        .not_after_ms
                        .get()
                        .saturating_sub(listed.now_ms.get()),
                );
                say(
                    out,
                    &format!(
                        "  {}  requester {}  rule \"{}\"  window ends in {remaining}s",
                        summary.request_id.as_str(),
                        summary.requester.as_str(),
                        render::escape(summary.rule_id.as_str()).text,
                    ),
                );
            }
            if listed.requests.is_empty() {
                say(out, "  (none)");
            } else {
                say(
                    out,
                    "Review one with: direwolf approve review --socket <PATH> <REQUEST_ID>",
                );
            }
            EXIT_OK
        }
        Exchanged::Answer(Response::Refused(code)) => {
            say(out, &format!("refused: {}", refusal_text(code)));
            EXIT_NOTHING
        }
        Exchanged::Answer(_) => {
            say(
                out,
                "the endpoint answered with something other than a listing",
            );
            EXIT_NOTHING
        }
        Exchanged::Unsent(why) | Exchanged::Lost(why) => {
            say(out, &format!("direwolf approve: {why}"));
            EXIT_NOTHING
        }
    }
}

/// Whole seconds in `ms` milliseconds, rounded down.
fn seconds(ms: u64) -> u64 {
    ms.checked_div(1000).unwrap_or(0)
}

/// Lowercase hexadecimal.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(64), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// A request as `show` displayed it: the detail, its verified binding (or
/// why not), and the rendering.
type Displayed = (RequestDetail, Result<Object, String>, render::Rendered);

/// Why a request cannot be approved from this client, if it cannot.
fn verify(detail: &RequestDetail) -> Result<Object, String> {
    let text = detail.binding.as_str();
    let value = json::parse(text.as_bytes(), ParseOptions::dwkp())
        .map_err(|_| "the binding is not strict JSON".to_owned())?;
    if json::to_canonical_bytes(&value) != text.as_bytes() {
        return Err("the binding is not in its canonical form".to_owned());
    }
    if hex(&sha2::Sha256::digest(text.as_bytes())) != detail.binding_sha256.as_str() {
        return Err("the binding does not hash to the digest the authority named".to_owned());
    }
    let Value::Object(object) = value else {
        return Err("the binding is not an object".to_owned());
    };
    let member = |name: &str| match object.get(name) {
        Some(Value::String(text)) => Some(text.as_str()),
        _ => None,
    };
    if member("schema") != Some(detail.binding_schema.as_str()) {
        return Err("the binding's schema is not the one the request names".to_owned());
    }
    if member("requester") != Some(detail.requester.as_str()) {
        return Err("the binding's requester is not the request's".to_owned());
    }
    Ok(object)
}

/// The authority's request fields, for the renderer.
fn facts(detail: &RequestDetail) -> render::Facts {
    let pair = |label: &str, value: String| (label.to_owned(), value);
    let remaining = seconds(
        detail
            .not_after_ms
            .get()
            .saturating_sub(detail.now_ms.get()),
    );
    let mut identity = vec![
        pair("request_id", detail.request_id.as_str().to_owned()),
        pair("binding_sha256", detail.binding_sha256.as_str().to_owned()),
        pair("state", detail.state.as_str().to_owned()),
        pair(
            "decidable now",
            if detail.decidable { "yes" } else { "no" }.to_owned(),
        ),
        pair("rule", detail.rule_id.as_str().to_owned()),
        pair(
            "policy_revision",
            detail.policy_revision.as_str().to_owned(),
        ),
    ];
    if let Some(approval) = &detail.approval {
        identity.push(pair(
            "approval_id",
            approval.approval_id.as_str().to_owned(),
        ));
        identity.push(pair("approved by", approval.approver.as_str().to_owned()));
        identity.push(pair(
            "approval",
            format!(
                "{} at {}, {} of {} uses spent",
                approval.state.as_str(),
                approval.assurance.as_str(),
                approval.uses.get(),
                approval.max_uses.get()
            ),
        ));
    }
    render::Facts {
        identity,
        context: vec![
            pair("run", detail.run_id.as_str().to_owned()),
            pair("session", detail.session_id.as_str().to_owned()),
            pair("lease epoch", detail.epoch.get().to_string()),
        ],
        assurance: vec![pair(
            "assurance required",
            format!(
                "{} ({})",
                detail.assurance_required.as_str(),
                match detail.assurance_required {
                    approverp::Assurance::A1 => {
                        "a dedicated approver account answers; not proof of a person"
                    }
                    approverp::Assurance::A2 => "a verified presence factor; none exists here",
                }
            ),
        )],
        lifetime: vec![
            pair("approval scope", detail.scope.as_str().to_owned()),
            pair(
                "approval life",
                format!("{} seconds from the decision", detail.ttl_s.get()),
            ),
            pair("use limit", detail.max_uses.get().to_string()),
            pair(
                "request window",
                if detail.state == RequestState::Pending {
                    format!("ends in {remaining} seconds; no decision by then is no execution")
                } else {
                    "ended".to_owned()
                },
            ),
        ],
    }
}

/// Show one request; its exit code, and the detail and verified binding if
/// it was shown.
fn show(socket: &std::path::Path, id: &RequestId, out: &mut dyn Write) -> (u8, Option<Displayed>) {
    match exchange(socket, &Request::Show(id.clone())) {
        Exchanged::Answer(Response::Shown(detail)) => {
            let verified = verify(&detail);
            let empty = Object::new();
            let binding = verified.as_ref().unwrap_or(&empty);
            let rendered = render::request(&facts(&detail), binding, None);
            for line in &rendered.lines {
                say(out, line);
            }
            if let Err(why) = &verified {
                say(out, "");
                say(
                    out,
                    &format!(
                        "  WARNING: {why}. The binding is not shown and cannot be approved here."
                    ),
                );
            }
            (EXIT_OK, Some((*detail, verified, rendered)))
        }
        Exchanged::Answer(Response::Refused(code)) => {
            say(out, &format!("refused: {}", refusal_text(code)));
            (EXIT_NOTHING, None)
        }
        Exchanged::Answer(_) => {
            say(
                out,
                "the endpoint answered with something other than the request",
            );
            (EXIT_NOTHING, None)
        }
        Exchanged::Unsent(why) | Exchanged::Lost(why) => {
            say(out, &format!("direwolf approve: {why}"));
            (EXIT_NOTHING, None)
        }
    }
}

/// Show a request, ask for one typed line through `typed`, and send the
/// decision it names, if it names one.
fn review(
    socket: &std::path::Path,
    id: &RequestId,
    out: &mut dyn Write,
    typed: impl FnOnce(Duration) -> Typed,
) -> u8 {
    let (code, shown) = show(socket, id, out);
    let Some((detail, verified, rendered)) = shown else {
        return code;
    };
    say(out, "");
    say(out, "== 8. DECISION ==");
    if detail.state != RequestState::Pending || !detail.decidable {
        say(
            out,
            "  This request cannot be decided now; nothing was sent.",
        );
        return EXIT_NOTHING;
    }
    let approvable = verified.is_ok() && rendered.complete;
    let code = detail
        .binding_sha256
        .as_str()
        .get(..8)
        .unwrap_or_default()
        .to_owned();
    if approvable {
        say(
            out,
            &format!("  To approve this exact action, once, type:   approve {code}"),
        );
    } else {
        say(
            out,
            "  Approval is not offered: the request could not be verified or shown in full.",
        );
    }
    say(out, "  To deny it, type:                            deny");
    say(out, "  Anything else, or nothing, decides nothing.");
    let _ = write!(out, "> ");
    let _ = out.flush();
    let remaining = Duration::from_millis(
        detail
            .not_after_ms
            .get()
            .saturating_sub(detail.now_ms.get()),
    );
    let verdict = match typed(remaining.min(MAX_WAIT)) {
        Typed::Line(line) => interpret(&line, &code),
        Typed::Closed => {
            say(out, "");
            say(out, "The input ended: nothing was decided.");
            return EXIT_NOTHING;
        }
        Typed::TimedOut => {
            say(out, "");
            say(out, "No answer in time: nothing was decided.");
            return EXIT_NOTHING;
        }
    };
    let verdict = match verdict {
        Some(Verdict::Approve) if !approvable => {
            say(
                out,
                "Approval is not offered for this request: nothing was decided.",
            );
            return EXIT_NOTHING;
        }
        Some(verdict) => verdict,
        None => {
            say(out, "Not a decision: nothing was decided.");
            return EXIT_NOTHING;
        }
    };
    let decide = Request::Decide {
        request_id: detail.request_id.clone(),
        binding_sha256: Digest::new(detail.binding_sha256.as_str())
            .unwrap_or(detail.binding_sha256.clone()),
        decision: verdict,
    };
    match exchange(socket, &decide) {
        Exchanged::Answer(Response::Decided(decided))
            if decided.request_id == detail.request_id =>
        {
            match (decided.outcome, decided.approval_id) {
                (Outcome::Granted, Some(approval)) => say(
                    out,
                    &format!(
                        "Approved, at A1: approval {} for this exact action, its life and uses \
                         as shown. Nothing runs until the agent asks again.",
                        approval.as_str()
                    ),
                ),
                _ => say(out, "Denied. The request is closed; nothing runs."),
            }
            EXIT_OK
        }
        Exchanged::Answer(Response::Refused(code)) => {
            say(out, &format!("Refused: {}.", refusal_text(code)));
            EXIT_NOTHING
        }
        Exchanged::Answer(_) => {
            say(
                out,
                "The endpoint answered with something other than this decision: its outcome is \
                 unknown. Read it back with `direwolf approve show`.",
            );
            EXIT_UNKNOWN
        }
        Exchanged::Unsent(why) => {
            say(
                out,
                &format!("Nothing was sent ({why}): nothing was decided."),
            );
            EXIT_NOTHING
        }
        Exchanged::Lost(why) => {
            say(
                out,
                &format!(
                    "The decision was sent and its answer lost ({why}): it may be recorded. \
                     Read it back with `direwolf approve show --socket <PATH> {}`; it is \
                     never recorded twice.",
                    detail.request_id.as_str()
                ),
            );
            EXIT_UNKNOWN
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
