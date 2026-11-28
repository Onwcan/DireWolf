//! The approver protocol (M6.3, ADR-0081, Proposed): the trusted approver
//! client and the authority's approver endpoint. **Not DWKP.**
//!
//! One request on one connection, and nothing else:
//!
//! ```text
//! direwolf approve                       dwkd-authority (approver socket)
//!    connect ────────────────────────────▶ accept
//!                                          SO_PEERCRED: an operator-declared
//!                                          approver? (else: close, nothing read)
//!    approver.list | approver.show | ─────▶ one frame, its length checked from
//!    approver.decide                       its header (MAX_REQUEST_BODY)
//!                                          the registry, in one transaction
//!    ◀──── approver.listed | approver.request | approver.decided | approver.refused
//!    close                                 close
//! ```
//!
//! Framing is DWKP's -- a 5-byte header and canonical JSON -- and every
//! message is a strict `reject` type, but nothing else is shared: no
//! envelope, no handshake, no registry entry, no emitted schema, no Python
//! binding. A runtime cannot speak it to the authority, because the endpoint
//! asks the kernel who connected before it reads a byte, and no runtime is an
//! approver.
//!
//! # Three operations, and no other
//!
//! * `approver.list` -- the requests that wait for a decision, oldest first,
//!   at most [`MAX_LISTED`] of them, and how many wait in all.
//! * `approver.show` -- one request, by its id, as the authority stored it:
//!   its canonical binding text, its hash, its run, requester, rule, policy
//!   revision, scope, window, life and uses; and, once decided, its outcome.
//! * `approver.decide` -- approve or deny one request, naming its id and
//!   echoing its binding hash. The request id is the challenge: unique to
//!   one request and decided once (APPROVALS.md §5, ADR-0080 §3).
//!
//! There is no field for an approver, an assurance level, a scope, a life, a
//! use count, a grant, a policy or anything else a decision could be widened
//! by: the approver is the uid the kernel reported, the level is the one the
//! authority records (A1), and the rest is the request's. A member this
//! module does not declare is refused.
//!
//! This module is wire types and nothing else: no socket, no file, no
//! decision. The authority and the client do the I/O.

use crate::error::{ErrorCode, ProtocolError, Violation};
use crate::frame::{self, ContentType};
use crate::json::{self, Number, ParseOptions, Value};
use crate::limits::MAX_SAFE_INTEGER;
use crate::schema::{Defs, int, obj, string};
use crate::wire::id::{RunId, SessionId};
use crate::wire::list::BoundedList;
use crate::wire::macros::wire_struct;
use crate::wire::scalar::{wire_enum, wire_int, wire_text};
use crate::wire::{Cx, WireType, expect_integer, expect_string};

/// The protocol version this build speaks. The client and the authority ship
/// together, so 1 is the only version either accepts; another is answered
/// `UNSUPPORTED_PROTOCOL`, never half-understood.
pub const PROTOCOL: u16 = 1;

/// The largest request body the authority reads, checked from the frame's
/// header before a body byte is buffered. A decision is a request id, a hash
/// and a word.
pub const MAX_REQUEST_BODY: usize = 1024;

/// The largest response body the client reads: one DWKP frame.
pub const MAX_RESPONSE_BODY: usize = crate::limits::MAX_FRAME_BODY;

/// The most requests one listing names. More may wait: the listing says how
/// many in all.
pub const MAX_LISTED: usize = 64;

/// The largest canonical binding text a request carries, in bytes. A
/// binding's argv is at most [`crate::limits::MAX_PROCESS_ARGV_BYTES`], which
/// canonical JSON's escapes can grow sixfold at worst; this bound holds that
/// and the binding's other members, and fits a frame once escaped again.
pub const MAX_BINDING_BYTES: usize = 448 * 1024;

wire_int! {
    /// The approver protocol's version.
    ApproverProtocol(u16), min = 1, max = 1
}

const _: () = assert!(ApproverProtocol::MIN == PROTOCOL && ApproverProtocol::MAX == PROTOCOL);

wire_enum! {
    /// Which approver message this is. Checked on decode, so no message can
    /// be read as another even where their fields would allow it.
    ApproverKind {
        /// List the requests that wait.
        List = "approver.list",
        /// Show one request.
        Show = "approver.show",
        /// Decide one request.
        Decide = "approver.decide",
        /// The waiting requests.
        Listed = "approver.listed",
        /// One request, as stored.
        Shown = "approver.request",
        /// A decision, recorded.
        Decided = "approver.decided",
        /// A request refused, with why.
        Refused = "approver.refused",
    }
}

fn lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

wire_text! {
    /// A request's id: the registry's `DomainHash` of its run, its binding
    /// hash and its sequence, as 64 lowercase hexadecimal characters. Unique
    /// to one request and decided once: the challenge a decision names.
    RequestId,
    max_chars = 64,
    pattern = Some("^[0-9a-f]{64}$"),
    format = None,
    validate = |s| lower_hex(s, 64)
}

wire_text! {
    /// A SHA-256, as 64 lowercase hexadecimal characters: a binding's hash,
    /// a policy revision, an approval's id.
    Digest,
    max_chars = 64,
    pattern = Some("^[0-9a-f]{64}$"),
    format = None,
    validate = |s| lower_hex(s, 64)
}

fn valid_principal(s: &str) -> bool {
    s.strip_prefix("uid:").is_some_and(|n| {
        !n.is_empty()
            && n.len() <= 10
            && n.bytes().all(|b| b.is_ascii_digit())
            && (n == "0" || !n.starts_with('0'))
            && n.parse::<u32>().is_ok()
    })
}

wire_text! {
    /// A principal as the authority stores it: `uid:` and the decimal uid the
    /// kernel reported.
    Principal,
    max_chars = 14,
    pattern = Some("^uid:(0|[1-9][0-9]{0,9})$"),
    format = None,
    validate = valid_principal
}

fn valid_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}

wire_text! {
    /// A short authority-chosen word: a rule's id, a scope's name, the
    /// binding's schema. ASCII letters, digits, `.`, `_`, `-` and `:`.
    Label,
    max_chars = 128,
    pattern = Some("^[A-Za-z0-9._:-]{1,128}$"),
    format = None,
    validate = valid_label
}

fn valid_binding(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_BINDING_BYTES
}

wire_text! {
    /// A request's canonical binding, exactly the bytes the authority stored
    /// and hashed (ADR-0079): RFC 8785 JSON, as text. The client parses it
    /// strictly, re-canonicalises it and hashes it, and renders it; it never
    /// builds one.
    BindingText,
    max_chars = MAX_BINDING_BYTES,
    pattern = None,
    format = None,
    validate = valid_binding
}

wire_int! {
    /// An instant on the authority's registry clock, in milliseconds: a
    /// JSON integer, so at most 2^53 - 1.
    Millis(u64), min = 0, max = 9_007_199_254_740_991
}

const _: () = assert!(Millis::MAX == MAX_SAFE_INTEGER.unsigned_abs());

wire_int! {
    /// A rule's TTL in seconds.
    Seconds(u32), min = 0, max = 4_294_967_295
}

wire_int! {
    /// A use count or limit.
    Uses(u32), min = 0, max = 4_294_967_295
}

wire_int! {
    /// How many requests wait across the store: at most its bound (1024,
    /// ADR-0080 OD-3), and never more than this.
    Waiting(u16), min = 0, max = 65_535
}

wire_int! {
    /// A lease epoch.
    EpochNumber(u64), min = 0, max = 9_007_199_254_740_991
}

wire_enum! {
    /// Where a request stands.
    RequestState {
        /// Waiting for a decision.
        Pending = "PENDING",
        /// Approved: an approval was recorded.
        Granted = "GRANTED",
        /// Denied by an approver.
        Denied = "DENIED",
        /// Its window passed, or its run's authority ended, with no
        /// decision. Not a denial.
        Expired = "EXPIRED",
    }
}

wire_enum! {
    /// An assurance level (ADR-0077 §3). There is no A0.
    Assurance {
        /// A dedicated approver account answered.
        A1 = "A1",
        /// A1 and a presence factor the authority verified. None exists.
        A2 = "A2",
    }
}

wire_enum! {
    /// The channel an approval arrived on (ADR-0077 OD-1).
    Channel {
        /// The approver endpoint, from the trusted approver client.
        ApproverEndpoint = "APPROVER_ENDPOINT",
    }
}

wire_enum! {
    /// Where an approval stands.
    ApprovalState {
        /// Spendable while its guards hold.
        Open = "OPEN",
        /// Every use spent.
        Exhausted = "EXHAUSTED",
        /// Its life passed.
        Expired = "EXPIRED",
        /// Revoked.
        Revoked = "REVOKED",
    }
}

wire_enum! {
    /// What an approver decides. There is no third word.
    Verdict {
        /// Approve this request, once, as it is bound.
        Approve = "APPROVE",
        /// Deny it.
        Deny = "DENY",
    }
}

wire_enum! {
    /// What a decision recorded.
    Outcome {
        /// An approval, of the request's scope, life and uses.
        Granted = "GRANTED",
        /// A denial.
        Denied = "DENIED",
    }
}

wire_enum! {
    /// Why a request was refused. Closed: nothing a peer sent is echoed.
    RefusalCode {
        /// Not one of this protocol's requests, or not well formed.
        MalformedRequest = "MALFORMED_REQUEST",
        /// Another protocol version.
        UnsupportedProtocol = "UNSUPPORTED_PROTOCOL",
        /// No such request.
        UnknownRequest = "UNKNOWN_REQUEST",
        /// Decided already, or expired: a request is decided once.
        NotPending = "NOT_PENDING",
        /// Its window has passed: it is now `EXPIRED`.
        Expired = "EXPIRED",
        /// Its run's authority has ended: it is now `EXPIRED`.
        RunEnded = "RUN_ENDED",
        /// The echoed binding hash is not the request's.
        BindingMismatch = "BINDING_MISMATCH",
        /// Not one of the operator's approvers at the moment of the decision.
        UnknownApprover = "UNKNOWN_APPROVER",
        /// The approver is the requester.
        SelfApproval = "SELF_APPROVAL",
        /// The request needs a level no approver here can give (A2).
        AssuranceUnavailable = "ASSURANCE_UNAVAILABLE",
        /// The authority could not answer truthfully; nothing was decided.
        Unavailable = "UNAVAILABLE",
    }
}

wire_struct! {
    /// List the requests that wait for a decision.
    ListRequest: reject {
        /// Always `approver.list`.
        required kind: ApproverKind,
        /// The protocol version.
        required protocol: ApproverProtocol,
    }
}

wire_struct! {
    /// Show one request.
    ShowRequest: reject {
        /// Always `approver.show`.
        required kind: ApproverKind,
        /// The protocol version.
        required protocol: ApproverProtocol,
        /// The request.
        required request_id: RequestId,
    }
}

wire_struct! {
    /// Decide one request: its id -- the challenge -- and the binding hash
    /// the client showed, echoed. Nothing else.
    DecideRequest: reject {
        /// Always `approver.decide`.
        required kind: ApproverKind,
        /// The protocol version.
        required protocol: ApproverProtocol,
        /// The request.
        required request_id: RequestId,
        /// The request's binding hash, as shown.
        required binding_sha256: Digest,
        /// Approve, or deny.
        required decision: Verdict,
    }
}

wire_struct! {
    /// One waiting request, in a listing.
    Summary: reject {
        /// The request.
        required request_id: RequestId,
        /// Its run.
        required run_id: RunId,
        /// The run's subject: who asked.
        required requester: Principal,
        /// The rule that required an approval.
        required rule_id: Label,
        /// Its binding hash.
        required binding_sha256: Digest,
        /// When it was asked.
        required requested_ms: Millis,
        /// When its window ends.
        required not_after_ms: Millis,
    }
}

/// At most [`MAX_LISTED`] waiting requests.
pub type Summaries = BoundedList<Summary, MAX_LISTED>;

wire_struct! {
    /// The requests that wait, oldest first.
    Listed: reject {
        /// Always `approver.listed`.
        required kind: ApproverKind,
        /// The protocol version.
        required protocol: ApproverProtocol,
        /// How many wait across the store; more than are listed if over
        /// [`MAX_LISTED`].
        required waiting: Waiting,
        /// The oldest of them.
        required requests: Summaries,
        /// The authority's registry clock when it listed them.
        required now_ms: Millis,
    }
}

wire_struct! {
    /// The approval a request's grant recorded.
    ApprovalView: reject {
        /// The approval.
        required approval_id: Digest,
        /// Who granted it, as the kernel reported them.
        required approver: Principal,
        /// The channel it arrived on.
        required channel: Channel,
        /// The level it records.
        required assurance: Assurance,
        /// Where it stands.
        required state: ApprovalState,
        /// Uses spent.
        required uses: Uses,
        /// Its use limit.
        required max_uses: Uses,
        /// When its life ends.
        required not_after_ms: Millis,
    }
}

wire_struct! {
    /// One request, as the authority stored it. Every field is the
    /// authority's: the binding as it was hashed, the row's own columns, and
    /// the approval a grant recorded. No field is a runtime's prose.
    RequestDetail: reject {
        /// The request: the challenge a decision names.
        required request_id: RequestId,
        /// Where it stands.
        required state: RequestState,
        /// Whether a decision can be recorded now: pending, inside its
        /// window, its run still holding its authority.
        required decidable: bool,
        /// Its run.
        required run_id: RunId,
        /// The run's session.
        required session_id: SessionId,
        /// Who asked: the run's subject.
        required requester: Principal,
        /// The lease epoch it was asked under.
        required epoch: EpochNumber,
        /// The rule that required an approval.
        required rule_id: Label,
        /// The active policy's revision when it was asked.
        required policy_revision: Digest,
        /// The approval scope: `exact_action`.
        required scope: Label,
        /// The rule's TTL: an approval's life.
        required ttl_s: Seconds,
        /// The rule's use limit.
        required max_uses: Uses,
        /// The level an approval of it needs.
        required assurance_required: Assurance,
        /// When it was asked.
        required requested_ms: Millis,
        /// When its window ends.
        required not_after_ms: Millis,
        /// When it was decided or ended, if it was.
        optional decided_ms: Millis,
        /// The binding's schema.
        required binding_schema: Label,
        /// The binding's hash: what a decision echoes.
        required binding_sha256: Digest,
        /// The canonical binding, as hashed.
        required binding: BindingText,
        /// The approval its grant recorded, if it was granted.
        optional approval: ApprovalView,
        /// The authority's registry clock when it answered.
        required now_ms: Millis,
    }
}

wire_struct! {
    /// One request, shown.
    Shown: reject {
        /// Always `approver.request`.
        required kind: ApproverKind,
        /// The protocol version.
        required protocol: ApproverProtocol,
        /// The request.
        required request: RequestDetail,
    }
}

wire_struct! {
    /// A decision, recorded.
    Decided: reject {
        /// Always `approver.decided`.
        required kind: ApproverKind,
        /// The protocol version.
        required protocol: ApproverProtocol,
        /// The request decided.
        required request_id: RequestId,
        /// What was recorded.
        required outcome: Outcome,
        /// The approval a grant recorded.
        optional approval_id: Digest,
    }
}

wire_struct! {
    /// A request refused, and why. Nothing was decided.
    Refused: reject {
        /// Always `approver.refused`.
        required kind: ApproverKind,
        /// The protocol version.
        required protocol: ApproverProtocol,
        /// Why.
        required code: RefusalCode,
    }
}

/// A request a client sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// `approver.list`.
    List,
    /// `approver.show`.
    Show(RequestId),
    /// `approver.decide`.
    Decide {
        /// The request: the challenge.
        request_id: RequestId,
        /// Its binding hash, echoed.
        binding_sha256: Digest,
        /// Approve, or deny.
        decision: Verdict,
    },
}

/// A response the authority sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// `approver.listed`.
    Listed(Listed),
    /// `approver.request`.
    Shown(Box<RequestDetail>),
    /// `approver.decided`.
    Decided(Decided),
    /// `approver.refused`.
    Refused(RefusalCode),
}

fn protocol() -> ApproverProtocol {
    // PROTOCOL is the type's only value.
    ApproverProtocol(PROTOCOL)
}

/// The members a message names before its type is known: its kind, and
/// whether its protocol is this one. A body over `max` is refused before it
/// is parsed.
fn preamble(bytes: &[u8], max: usize) -> Result<(Value, ApproverKind), Malformed> {
    if bytes.len() > max {
        return Err(Malformed::Refused(ProtocolError::new(
            ErrorCode::FrameTooLarge,
            format!("an approver message of {} bytes exceeds {max}", bytes.len()),
        )));
    }
    let value = json::parse(bytes, ParseOptions::dwkp()).map_err(Malformed::Refused)?;
    let Value::Object(object) = &value else {
        return Err(Malformed::Refused(ProtocolError::schema(
            Violation::WrongType,
            "",
            "an approver message is an object",
        )));
    };
    match object.get("protocol") {
        Some(Value::Number(Number::Int(n))) if *n == i64::from(PROTOCOL) => {}
        Some(Value::Number(Number::Int(_))) => return Err(Malformed::OtherProtocol),
        _ => {
            return Err(Malformed::Refused(ProtocolError::schema(
                Violation::MissingField,
                "/protocol",
                "an approver message names its protocol version",
            )));
        }
    }
    let kind = match object.get("kind") {
        Some(kind) => {
            ApproverKind::decode(kind.clone(), &mut Cx::new()).map_err(Malformed::Refused)?
        }
        None => {
            return Err(Malformed::Refused(ProtocolError::schema(
                Violation::MissingField,
                "/kind",
                "an approver message names its kind",
            )));
        }
    };
    Ok((value, kind))
}

/// Why a message did not decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Malformed {
    /// Another protocol version: answered `UNSUPPORTED_PROTOCOL`.
    OtherProtocol,
    /// Not this protocol's message: answered `MALFORMED_REQUEST`.
    Refused(ProtocolError),
}

impl Malformed {
    /// The refusal a request that did not decode is answered with.
    #[must_use]
    pub const fn code(&self) -> RefusalCode {
        match self {
            Self::OtherProtocol => RefusalCode::UnsupportedProtocol,
            Self::Refused(_) => RefusalCode::MalformedRequest,
        }
    }
}

fn wrong_kind(found: ApproverKind) -> Malformed {
    Malformed::Refused(ProtocolError::schema(
        Violation::Inconsistent,
        "/kind",
        format!("{} is not a request", found.as_str()),
    ))
}

impl Request {
    /// Decode one request body, strictly, refusing anything over
    /// [`MAX_REQUEST_BODY`], any other protocol version, any undeclared
    /// member and any response.
    ///
    /// # Errors
    ///
    /// [`Malformed`], with the refusal it is answered with.
    pub fn decode_frame_body(bytes: &[u8]) -> Result<Self, Malformed> {
        let (value, kind) = preamble(bytes, MAX_REQUEST_BODY)?;
        let cx = &mut Cx::new();
        match kind {
            ApproverKind::List => {
                ListRequest::decode(value, cx).map_err(Malformed::Refused)?;
                Ok(Self::List)
            }
            ApproverKind::Show => {
                let show = ShowRequest::decode(value, cx).map_err(Malformed::Refused)?;
                Ok(Self::Show(show.request_id))
            }
            ApproverKind::Decide => {
                let decide = DecideRequest::decode(value, cx).map_err(Malformed::Refused)?;
                Ok(Self::Decide {
                    request_id: decide.request_id,
                    binding_sha256: decide.binding_sha256,
                    decision: decide.decision,
                })
            }
            other => Err(wrong_kind(other)),
        }
    }

    /// This request as a complete frame, re-decoded first: a request this
    /// module would refuse is one it never sends.
    ///
    /// # Errors
    ///
    /// The request does not survive its own round trip.
    pub fn encode_frame(&self) -> Result<Vec<u8>, ProtocolError> {
        let value = match self {
            Self::List => ListRequest {
                kind: ApproverKind::List,
                protocol: protocol(),
            }
            .encode()?,
            Self::Show(request_id) => ShowRequest {
                kind: ApproverKind::Show,
                protocol: protocol(),
                request_id: request_id.clone(),
            }
            .encode()?,
            Self::Decide {
                request_id,
                binding_sha256,
                decision,
            } => DecideRequest {
                kind: ApproverKind::Decide,
                protocol: protocol(),
                request_id: request_id.clone(),
                binding_sha256: binding_sha256.clone(),
                decision: *decision,
            }
            .encode()?,
        };
        let bytes = json::to_canonical_bytes(&value);
        if Self::decode_frame_body(&bytes).as_ref() != Ok(self) {
            return Err(round_trip());
        }
        frame::encode(ContentType::Json, &bytes)
    }
}

fn round_trip() -> ProtocolError {
    ProtocolError::schema(
        Violation::Inconsistent,
        "",
        "an approver message does not survive its own round trip",
    )
}

impl Response {
    /// A listing.
    #[must_use]
    pub fn listed(waiting: Waiting, requests: Summaries, now_ms: Millis) -> Self {
        Self::Listed(Listed {
            kind: ApproverKind::Listed,
            protocol: protocol(),
            waiting,
            requests,
            now_ms,
        })
    }

    /// One request, shown.
    #[must_use]
    pub fn shown(request: RequestDetail) -> Self {
        Self::Shown(Box::new(request))
    }

    /// A decision, recorded.
    #[must_use]
    pub fn decided(request_id: RequestId, outcome: Outcome, approval_id: Option<Digest>) -> Self {
        Self::Decided(Decided {
            kind: ApproverKind::Decided,
            protocol: protocol(),
            request_id,
            outcome,
            approval_id,
        })
    }

    /// Decode one response body, strictly, refusing anything over
    /// [`MAX_RESPONSE_BODY`], any other protocol version, any undeclared
    /// member and any request. A `Decided` must say an approval exactly when
    /// it granted one.
    ///
    /// # Errors
    ///
    /// [`Malformed`].
    pub fn decode_frame_body(bytes: &[u8]) -> Result<Self, Malformed> {
        let (value, kind) = preamble(bytes, MAX_RESPONSE_BODY)?;
        let cx = &mut Cx::new();
        let inconsistent = |what: &str| {
            Malformed::Refused(ProtocolError::schema(
                Violation::Inconsistent,
                "",
                what.to_owned(),
            ))
        };
        match kind {
            ApproverKind::Listed => {
                let listed = Listed::decode(value, cx).map_err(Malformed::Refused)?;
                if usize::from(listed.waiting.get()) < listed.requests.len() {
                    return Err(inconsistent("a listing names more requests than wait"));
                }
                Ok(Self::Listed(listed))
            }
            ApproverKind::Shown => {
                let shown = Shown::decode(value, cx).map_err(Malformed::Refused)?;
                let detail = shown.request;
                let granted = detail.state == RequestState::Granted;
                if granted != detail.approval.is_some() {
                    return Err(inconsistent("an approval is shown exactly for a grant"));
                }
                if detail.decidable && detail.state != RequestState::Pending {
                    return Err(inconsistent("only a pending request is decidable"));
                }
                Ok(Self::Shown(Box::new(detail)))
            }
            ApproverKind::Decided => {
                let decided = Decided::decode(value, cx).map_err(Malformed::Refused)?;
                let granted = decided.outcome == Outcome::Granted;
                if granted != decided.approval_id.is_some() {
                    return Err(inconsistent("an approval id is named exactly for a grant"));
                }
                Ok(Self::Decided(decided))
            }
            ApproverKind::Refused => {
                let refused = Refused::decode(value, cx).map_err(Malformed::Refused)?;
                Ok(Self::Refused(refused.code))
            }
            other => Err(Malformed::Refused(ProtocolError::schema(
                Violation::Inconsistent,
                "/kind",
                format!("{} is not a response", other.as_str()),
            ))),
        }
    }

    /// This response as a complete frame, re-decoded first.
    ///
    /// # Errors
    ///
    /// The response does not survive its own round trip, or is too large.
    pub fn encode_frame(&self) -> Result<Vec<u8>, ProtocolError> {
        let value = match self {
            Self::Listed(listed) => listed.encode()?,
            Self::Shown(detail) => Shown {
                kind: ApproverKind::Shown,
                protocol: protocol(),
                request: (**detail).clone(),
            }
            .encode()?,
            Self::Decided(decided) => decided.encode()?,
            Self::Refused(code) => Refused {
                kind: ApproverKind::Refused,
                protocol: protocol(),
                code: *code,
            }
            .encode()?,
        };
        let bytes = json::to_canonical_bytes(&value);
        if Self::decode_frame_body(&bytes).as_ref() != Ok(self) {
            return Err(round_trip());
        }
        frame::encode(ContentType::Json, &bytes)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

    use super::*;
    use crate::frame::{FrameDecoder, HEADER_LEN};

    const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const HASH: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    fn body(frame: &[u8]) -> &[u8] {
        &frame[HEADER_LEN..]
    }

    fn request(text: &str) -> Result<Request, Malformed> {
        Request::decode_frame_body(text.as_bytes())
    }

    #[test]
    fn each_request_has_one_canonical_spelling() {
        // Golden vectors: the exact bytes the client sends, and the authority
        // decodes, for each of the three operations.
        let cases = [
            (
                Request::List,
                r#"{"kind":"approver.list","protocol":1}"#.to_owned(),
            ),
            (
                Request::Show(RequestId::new(ID).unwrap()),
                format!(r#"{{"kind":"approver.show","protocol":1,"request_id":"{ID}"}}"#),
            ),
            (
                Request::Decide {
                    request_id: RequestId::new(ID).unwrap(),
                    binding_sha256: Digest::new(HASH).unwrap(),
                    decision: Verdict::Approve,
                },
                format!(
                    r#"{{"binding_sha256":"{HASH}","decision":"APPROVE","kind":"approver.decide","protocol":1,"request_id":"{ID}"}}"#
                ),
            ),
        ];
        for (request, golden) in cases {
            let frame = request.encode_frame().unwrap();
            assert_eq!(body(&frame), golden.as_bytes(), "{request:?}");
            assert_eq!(Request::decode_frame_body(golden.as_bytes()), Ok(request));
        }
    }

    #[test]
    fn a_request_claims_nothing_the_authority_decides() {
        // No approver, no level, no scope, no life, no use count, no grant:
        // each is an undeclared member, and refused.
        for extra in [
            r#""approver":"uid:2001""#,
            r#""assurance":"A2""#,
            r#""scope":"path_subtree""#,
            r#""ttl_s":86400"#,
            r#""max_uses":100"#,
            r#""standing_grant":true"#,
            r#""uid":2001"#,
            r#""tty":"/dev/pts/3""#,
            r#""remember":true"#,
        ] {
            let text = format!(
                r#"{{"binding_sha256":"{HASH}","decision":"APPROVE","kind":"approver.decide","protocol":1,"request_id":"{ID}",{extra}}}"#
            );
            assert!(
                matches!(request(&text), Err(Malformed::Refused(_))),
                "{extra} decoded"
            );
        }
    }

    #[test]
    fn every_malformed_request_is_refused_and_says_so() {
        let malformed = [
            // Not an object, not JSON, not UTF-8.
            "[]".to_owned(),
            "approve".to_owned(),
            String::from_utf8_lossy(b"{\"kind\":\"approver.list\",\"protocol\":1,\"x\":\"\xff\"}")
                .into_owned(),
            // Missing members.
            r#"{"kind":"approver.list"}"#.to_owned(),
            r#"{"protocol":1}"#.to_owned(),
            r#"{"kind":"approver.show","protocol":1}"#.to_owned(),
            format!(
                r#"{{"kind":"approver.decide","protocol":1,"request_id":"{ID}","decision":"APPROVE"}}"#
            ),
            // A duplicate member.
            r#"{"kind":"approver.list","kind":"approver.list","protocol":1}"#.to_owned(),
            // An unknown operation, and a response sent as a request.
            r#"{"kind":"approver.revoke","protocol":1}"#.to_owned(),
            r#"{"kind":"approver.refused","protocol":1,"code":"EXPIRED"}"#.to_owned(),
            // An id that is not one: upper case, short, long, with a NUL.
            format!(
                r#"{{"kind":"approver.show","protocol":1,"request_id":"{}"}}"#,
                ID.to_uppercase()
            ),
            format!(
                r#"{{"kind":"approver.show","protocol":1,"request_id":"{}"}}"#,
                &ID[1..]
            ),
            format!(r#"{{"kind":"approver.show","protocol":1,"request_id":"{ID}0"}}"#),
            format!(
                r#"{{"kind":"approver.show","protocol":1,"request_id":"{}\u0000"}}"#,
                &ID[1..]
            ),
            // A third word for a decision, and a lower-case one.
            format!(
                r#"{{"binding_sha256":"{HASH}","decision":"ALWAYS","kind":"approver.decide","protocol":1,"request_id":"{ID}"}}"#
            ),
            format!(
                r#"{{"binding_sha256":"{HASH}","decision":"approve","kind":"approver.decide","protocol":1,"request_id":"{ID}"}}"#
            ),
            // The protocol as a string, or a float.
            r#"{"kind":"approver.list","protocol":"1"}"#.to_owned(),
            r#"{"kind":"approver.list","protocol":1.5}"#.to_owned(),
            // Nesting past the depth bound.
            format!(
                r#"{{"kind":"approver.list","protocol":1,"x":{}1{}}}"#,
                "[".repeat(40),
                "]".repeat(40)
            ),
            // Trailing bytes after the one value.
            r#"{"kind":"approver.list","protocol":1} {}"#.to_owned(),
        ];
        for text in &malformed {
            assert_eq!(
                request(text).map_err(|m| m.code()),
                Err(RefusalCode::MalformedRequest),
                "{text}"
            );
        }
        let raw_invalid_utf8 = b"{\"kind\":\"approver.list\",\"protocol\":1,\"x\":\"\xff\"}";
        assert_eq!(
            Request::decode_frame_body(raw_invalid_utf8).map_err(|m| m.code()),
            Err(RefusalCode::MalformedRequest)
        );
    }

    #[test]
    fn another_protocol_version_is_named_as_such() {
        for version in [0, 2, 65_535] {
            let text = format!(r#"{{"kind":"approver.list","protocol":{version}}}"#);
            assert_eq!(request(&text), Err(Malformed::OtherProtocol), "{version}");
            assert_eq!(
                Malformed::OtherProtocol.code(),
                RefusalCode::UnsupportedProtocol
            );
        }
    }

    #[test]
    fn a_request_over_its_bound_is_refused_unparsed() {
        let padding = "a".repeat(MAX_REQUEST_BODY);
        let text = format!(r#"{{"kind":"approver.list","protocol":1,"p":"{padding}"}}"#);
        let Err(Malformed::Refused(error)) = request(&text) else {
            panic!("decoded")
        };
        assert_eq!(error.code, ErrorCode::FrameTooLarge);
        // The bound is the header's: a decoder bounded to it refuses a frame
        // declaring more before a body byte is stored.
        let mut decoder = FrameDecoder::bounded(MAX_REQUEST_BODY);
        let declared = u32::try_from(MAX_REQUEST_BODY + 1).unwrap().to_be_bytes();
        let header = [declared[0], declared[1], declared[2], declared[3], 0x01];
        let error = decoder.feed(&header).unwrap_err();
        assert_eq!(error.code, ErrorCode::FrameTooLarge);
    }

    fn detail(state: RequestState) -> RequestDetail {
        RequestDetail {
            request_id: RequestId::new(ID).unwrap(),
            state,
            decidable: state == RequestState::Pending,
            run_id: RunId::from_uuid(
                (1_760_000_000_000_u128 << 80) | (0x7 << 76) | (0b10 << 62) | 1,
            )
            .unwrap(),
            session_id: SessionId::from_uuid(
                (1_760_000_000_000_u128 << 80) | (0x7 << 76) | (0b10 << 62) | 2,
            )
            .unwrap(),
            requester: Principal::new("uid:1001").unwrap(),
            epoch: EpochNumber::new(3).unwrap(),
            rule_id: Label::new("approve-fixture").unwrap(),
            policy_revision: Digest::new(HASH).unwrap(),
            scope: Label::new("exact_action").unwrap(),
            ttl_s: Seconds::new(600).unwrap(),
            max_uses: Uses::new(1).unwrap(),
            assurance_required: Assurance::A1,
            requested_ms: Millis::new(1_000).unwrap(),
            not_after_ms: Millis::new(601_000).unwrap(),
            decided_ms: (state != RequestState::Pending).then(|| Millis::new(2_000).unwrap()),
            binding_schema: Label::new("the-binding-schema").unwrap(),
            binding_sha256: Digest::new(HASH).unwrap(),
            binding: BindingText::new(r#"{"schema":"x"}"#).unwrap(),
            approval: (state == RequestState::Granted).then(|| ApprovalView {
                approval_id: Digest::new(ID).unwrap(),
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

    #[test]
    fn every_response_survives_its_round_trip() {
        let summary = Summary {
            request_id: RequestId::new(ID).unwrap(),
            run_id: detail(RequestState::Pending).run_id,
            requester: Principal::new("uid:1001").unwrap(),
            rule_id: Label::new("approve-fixture").unwrap(),
            binding_sha256: Digest::new(HASH).unwrap(),
            requested_ms: Millis::new(1).unwrap(),
            not_after_ms: Millis::new(2).unwrap(),
        };
        let responses = [
            Response::listed(
                Waiting::new(1).unwrap(),
                Summaries::new(vec![summary]).unwrap(),
                Millis::new(5).unwrap(),
            ),
            Response::listed(
                Waiting::new(0).unwrap(),
                Summaries::new(Vec::new()).unwrap(),
                Millis::new(5).unwrap(),
            ),
            Response::shown(detail(RequestState::Pending)),
            Response::shown(detail(RequestState::Granted)),
            Response::shown(detail(RequestState::Denied)),
            Response::decided(
                RequestId::new(ID).unwrap(),
                Outcome::Granted,
                Some(Digest::new(HASH).unwrap()),
            ),
            Response::decided(RequestId::new(ID).unwrap(), Outcome::Denied, None),
            Response::Refused(RefusalCode::BindingMismatch),
        ];
        for response in responses {
            let frame = response.encode_frame().unwrap();
            assert_eq!(Response::decode_frame_body(body(&frame)), Ok(response));
        }
        let refused = Response::Refused(RefusalCode::NotPending)
            .encode_frame()
            .unwrap();
        assert_eq!(
            body(&refused),
            br#"{"code":"NOT_PENDING","kind":"approver.refused","protocol":1}"#
        );
    }

    #[test]
    fn an_inconsistent_response_is_refused() {
        // A grant without its approval, a denial with one, a decided request
        // called decidable, a listing longer than what waits.
        let mut granted = detail(RequestState::Granted);
        granted.approval = None;
        let mut denied = detail(RequestState::Denied);
        denied.approval = detail(RequestState::Granted).approval;
        let mut decidable = detail(RequestState::Denied);
        decidable.decidable = true;
        for bad in [granted, denied, decidable] {
            let value = Shown {
                kind: ApproverKind::Shown,
                protocol: protocol(),
                request: bad,
            }
            .encode()
            .unwrap();
            let bytes = json::to_canonical_bytes(&value);
            assert!(Response::decode_frame_body(&bytes).is_err());
        }
        let lying = Decided {
            kind: ApproverKind::Decided,
            protocol: protocol(),
            request_id: RequestId::new(ID).unwrap(),
            outcome: Outcome::Denied,
            approval_id: Some(Digest::new(HASH).unwrap()),
        };
        let bytes = json::to_canonical_bytes(&lying.encode().unwrap());
        assert!(Response::decode_frame_body(&bytes).is_err());
        // A request is never read as a response, nor a response as a request.
        assert!(Response::decode_frame_body(br#"{"kind":"approver.list","protocol":1}"#).is_err());
        assert!(
            Request::decode_frame_body(
                br#"{"kind":"approver.listed","now_ms":1,"protocol":1,"requests":[],"waiting":0}"#
            )
            .is_err()
        );
    }

    #[test]
    fn a_principal_is_one_spelling_of_one_uid() {
        for good in ["uid:0", "uid:1001", "uid:4294967295"] {
            assert!(Principal::new(good).is_some(), "{good}");
        }
        for bad in [
            "uid:",
            "uid:01",
            "uid:4294967296",
            "user:1001",
            "uid:-1",
            "uid: 1",
            "uid:1001\n",
        ] {
            assert!(Principal::new(bad).is_none(), "{bad}");
        }
    }
}
