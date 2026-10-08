//! Version 4 of the tool messages (M5c, ADR-0050): the eleven tools of version
//! 3 and `net.http`, the kernel-performed HTTPS request, as one closed, typed
//! sum.
//!
//! Versions 1 to 3 are kept exactly. Version 4 is a new version rather than a
//! new member of version 3 because a network call changes what a plan is: its
//! action names an **origin** and a method, and — when a credential is asked
//! for — a second action, the `secret.use` of a handle at that origin. A
//! version-3 decoder never sees a network call: to it, `net_http` is an
//! undeclared member.
//!
//! Like every earlier version, a request carries what the runtime proposes and
//! nothing the authority decides (ADR-0050 §3): a method from a closed set, a
//! URL the authority canonicalises, the caller's headers (an allowlist,
//! `crate::wire::http`), an inline body, at most a credential **handle**,
//! whether to follow redirects, and a narrowing of the response bound. Never an
//! address, a resolver, a proxy, a timeout, trust material, a cookie, a
//! credential value or header, a mode, or an origin for the credential: each
//! would be the runtime choosing something the authority decides.

use crate::error::{ProtocolError, Violation};
use crate::json::{Number, Value};
use crate::limits::{MAX_PLAN_ACTIONS, MAX_SAFE_INTEGER};
use crate::schema::{Defs, int, obj, string};
use crate::wire::host;
use crate::wire::http;
use crate::wire::id::InvocationId;
use crate::wire::list::BoundedList;
use crate::wire::macros::wire_struct;
use crate::wire::scalar::{
    ActionEnvironment, ByteCount, ContentDigest, DecisionEffect, GateResult, HexContent, RuleId,
    RuleSource, ToolOperation, wire_enum, wire_int, wire_text,
};
use crate::wire::{Cx, WireType, expect_integer, expect_string};

use super::fsops::{
    FsDeleteCall, FsDeleteResult, FsListCall, FsListResult, FsMoveCall, FsMoveResult, FsPatchCall,
    FsPatchResult, FsSearchCall, FsSearchResult, FsStatCall, FsStatResult, FsWriteCall,
    FsWriteResult, PlannedAction,
};
use super::messages::{FsReadCall, FsReadResult};
use super::procops::{
    PlannedProcessAction, ProcessExecCall, ProcessExecResult, ProcessKillCall, ProcessKillResult,
    ProcessStatusCall, ProcessStatusResult,
};

// ---------------------------------------------------------------------------
// Scalars.
// ---------------------------------------------------------------------------

wire_enum! {
    /// An HTTP method: the closed set the capability layer's `methods`
    /// constraint names (`CAPABILITIES.md` §2). No `CONNECT`, no `TRACE`, no
    /// extension method: a method this build lacks cannot be spelled.
    HttpMethod {
        /// `GET`.
        Get = "GET",
        /// `HEAD`.
        Head = "HEAD",
        /// `POST`.
        Post = "POST",
        /// `PUT`.
        Put = "PUT",
        /// `PATCH`.
        Patch = "PATCH",
        /// `DELETE`.
        Delete = "DELETE",
        /// `OPTIONS`.
        Options = "OPTIONS",
    }
}

impl HttpMethod {
    /// Whether a request with this method may carry a body.
    #[must_use]
    pub const fn permits_body(self) -> bool {
        matches!(self, Self::Post | Self::Put | Self::Patch | Self::Delete)
    }
}

/// A URL's text on the wire: visible ASCII only, at most
/// [`crate::wire::url::MAX_URL_BYTES`] bytes.
fn valid_url_text(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= crate::wire::url::MAX_URL_BYTES
        && s.bytes().all(|b| b.is_ascii_graphic())
}

wire_text! {
    /// The URL a `net.http` names, as the runtime spelled it: visible ASCII, at
    /// most 8 KiB.
    ///
    /// **Lexical bounds only.** Whether it is an `https` URL with one reading
    /// is the authority's canonicaliser's question (`crate::wire::url`): this
    /// type admits `http://x`, `https://a@b` and `https://127.0.0.1`, and the
    /// authority refuses them (`PLAINTEXT_UNSUPPORTED`, `URL_INVALID`) before
    /// anything is resolved.
    HttpUrlText,
    max_chars = 8192,
    pattern = Some("^[!-~]{1,8192}$"),
    format = None,
    validate = valid_url_text
}

wire_text! {
    /// A header name in its one spelling: a lowercase RFC 9110 token
    /// ([`crate::wire::http::is_header_name`]).
    HttpHeaderName,
    max_chars = 64,
    pattern = Some("^[a-z0-9!#$%&'*+.^_`|~-]{1,64}$"),
    format = None,
    validate = http::is_header_name
}

wire_text! {
    /// A header value in its one spelling: visible ASCII and interior spaces,
    /// no leading or trailing space, no control
    /// ([`crate::wire::http::is_header_value`]).
    HttpHeaderValue,
    max_chars = 4096,
    pattern = Some("^(?:[!-~](?:[ -~]{0,4094}[!-~])?)?$"),
    format = None,
    validate = http::is_header_value
}

/// A credential handle: `[a-z][a-z0-9._-]{0,63}`.
fn valid_handle(s: &str) -> bool {
    let mut bytes = s.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && s.len() <= 64
        && bytes.all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

wire_text! {
    /// The handle of a credential the operator configured: a name, never a
    /// value. The header it becomes, its prefix, its mode and the origins it
    /// may reach are the operator's metadata, not the request's (ADR-0046 §§11,
    /// 15).
    CredentialHandle,
    max_chars = 64,
    pattern = Some("^[a-z][a-z0-9._-]{0,63}$"),
    format = None,
    validate = valid_handle
}

wire_text! {
    /// A host the authority states, in the one canonical spelling
    /// (`crate::wire::host`): lowercase LDH labels, no trailing dot, no
    /// Unicode, never an address literal. The pattern is exactly
    /// `host::is_host` and not `host::is_address_literal`: at most 253
    /// characters, one to sixteen labels, the last neither all digits nor
    /// `0x` and hexadecimal.
    NetHost,
    max_chars = 253,
    pattern = Some(concat!(
        "^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.){0,15}",
        "(?![0-9]+$)(?!0x[0-9a-f]*$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
    )),
    format = None,
    validate = |s| host::is_host(s) && !host::is_address_literal(s)
}

wire_int! {
    /// A TCP port, never 0.
    NetPort(u16), min = 1, max = 65535
}

wire_int! {
    /// How many bytes of a response body the caller wants at most: a narrowing
    /// of the authority's bound, never a widening.
    /// [`crate::limits::MAX_NET_RESPONSE_BODY_BYTES`] is derived from the frame.
    ResponseLimit(u32), min = 1, max = 262_144
}

wire_int! {
    /// An HTTP status code a response carried. A broker refuses a response
    /// whose status is outside this range as malformed.
    HttpStatus(u16), min = 100, max = 599
}

wire_int! {
    /// A hop of one request, from 1: the first request, then each redirect.
    HopNumber(u8), min = 1, max = 6
}

// The wire bounds above are the shared constants', spelled as literals because
// a macro bound must be one.
const _: () = assert!(http::MAX_HOPS == 6);
const _: () = assert!(crate::limits::MAX_NET_RESPONSE_BODY_BYTES == 262_144);

wire_struct! {
    /// One header: a name and a value, each in its one spelling.
    HttpHeader: reject {
        /// The name.
        required name: HttpHeaderName,
        /// The value.
        required value: HttpHeaderValue,
    }
}

/// A request's caller headers.
pub type RequestHeaders = BoundedList<HttpHeader, { http::MAX_REQUEST_HEADERS }>;

/// The response headers that come back: the keep-list's, at most sixteen.
pub type ResponseHeaders = BoundedList<HttpHeader, { http::MAX_KEPT_RESPONSE_HEADERS }>;

// ---------------------------------------------------------------------------
// The call.
// ---------------------------------------------------------------------------

wire_struct! {
    /// A `net.http`: one HTTPS request the kernel performs (ADR-0050 §3).
    ///
    /// The authority canonicalises the URL to one origin, decides
    /// `network.https:<host>:<port>?methods=<method>` through both gates —
    /// and `secret.use:<handle>` when a credential is asked for — resolves the
    /// host through the broker, judges every address with the one address
    /// guard, and only then records the intent and has the broker perform the
    /// exchange to the pinned addresses. A redirect is a new hop the authority
    /// decides from the start; the broker never follows one.
    NetHttpCall: reject {
        /// The method.
        required method: HttpMethod,
        /// The URL: `https` only.
        required url: HttpUrlText,
        /// The caller's headers: the allowlist of `crate::wire::http`,
        /// lowercase, each name once.
        optional headers: RequestHeaders,
        /// The body, for `POST`, `PUT`, `PATCH` and `DELETE` only: lowercase
        /// hexadecimal, at most [`crate::limits::MAX_NET_REQUEST_BODY_BYTES`].
        optional body: HexContent,
        /// A credential the authority attaches at the request's own origin, if
        /// both gates allow `secret.use` of it there: its handle, never its
        /// value or its header.
        optional credential_handle: CredentialHandle,
        /// Whether redirects are followed — each one decided as a new hop, at
        /// most five.
        required follow_redirects: bool,
        /// A narrower response body bound than the authority's.
        optional max_response_bytes: ResponseLimit,
    }
}

wire_struct! {
    /// A tool call: **exactly one** of the twelve typed members. The payload of
    /// `direwolf.tool.invoke` and `direwolf.tool.preview` at version 4.
    ToolCallV4: reject {
        /// Read bytes from one regular file.
        optional fs_read: FsReadCall,
        /// List one directory.
        optional fs_list: FsListCall,
        /// Search one regular file for a literal byte string.
        optional fs_search: FsSearchCall,
        /// Report one object's metadata.
        optional fs_stat: FsStatCall,
        /// Replace or create one regular file.
        optional fs_write: FsWriteCall,
        /// Apply typed edits to one regular file.
        optional fs_patch: FsPatchCall,
        /// Rename one regular file to a vacant name.
        optional fs_move: FsMoveCall,
        /// Remove one regular file or empty directory.
        optional fs_delete: FsDeleteCall,
        /// Launch one checked native executable.
        optional process_exec: ProcessExecCall,
        /// Observe one process this run launched.
        optional process_status: ProcessStatusCall,
        /// End one process this run launched.
        optional process_kill: ProcessKillCall,
        /// Perform one HTTPS request.
        optional net_http: NetHttpCall,
    }
    exactly_one(
        fs_read, fs_list, fs_search, fs_stat, fs_write, fs_patch, fs_move, fs_delete,
        process_exec, process_status, process_kill, net_http
    )
}

// ---------------------------------------------------------------------------
// Plans.
// ---------------------------------------------------------------------------

wire_enum! {
    /// A tool of the canonical inventory that has a wire form at version 4:
    /// version 3's eleven and `net.http`.
    CoreToolV4 {
        /// Read bytes from one regular file.
        FsRead = "fs.read",
        /// List one directory, not recursively.
        FsList = "fs.list",
        /// Search one regular file for a literal byte string.
        FsSearch = "fs.search",
        /// Report one object's metadata.
        FsStat = "fs.stat",
        /// Replace or create one regular file, atomically.
        FsWrite = "fs.write",
        /// Apply typed edits to one regular file, atomically, against a base revision.
        FsPatch = "fs.patch",
        /// Rename one regular file to a vacant name.
        FsMove = "fs.move",
        /// Remove one regular file or empty directory.
        FsDelete = "fs.delete",
        /// Launch one checked native executable with typed arguments.
        ProcessExec = "process.exec",
        /// Report the state and retained output of a process this run launched.
        ProcessStatus = "process.status",
        /// Terminate a process this run launched.
        ProcessKill = "process.kill",
        /// Perform one HTTPS request, kernel-side.
        NetHttp = "net.http",
    }
}

wire_enum! {
    /// Why a network or injection action was decided as it was.
    NetDecisionReason {
        /// A held capability covers it, a rule allowed it, and every
        /// obligation is enforceable.
        AllowedByRule = "ALLOWED_BY_RULE",
        /// A rule denied it.
        DeniedByRule = "DENIED_BY_RULE",
        /// No rule matched.
        DefaultDeny = "DEFAULT_DENY",
        /// No held capability covers it — for a network action, also when the
        /// grant's `max_requests` is spent.
        NoCapability = "NO_CAPABILITY",
        /// A rule could not be evaluated for want of a canonical input: a
        /// destination address before resolution, among others.
        UnresolvedPolicyInput = "UNRESOLVED_POLICY_INPUT",
        /// A rule allowed it with an obligation this build cannot enforce.
        ObligationUnenforceable = "OBLIGATION_UNENFORCEABLE",
        /// A rule required an approval, and approvals arrive at M6.
        ApprovalRequired = "APPROVAL_REQUIRED",
    }
}

wire_struct! {
    /// How the gates decided one network or injection action.
    NetActionDecision: reject {
        /// What was decided.
        required effect: DecisionEffect,
        /// Why.
        required reason: NetDecisionReason,
        /// Whether a held capability covers the action.
        required capability_result: GateResult,
        /// Whether policy permits it.
        required policy_result: GateResult,
        /// The rule that produced the effect, or could not be evaluated.
        required rule_id: RuleId,
        /// Where that rule is written.
        required rule_source: RuleSource,
    }
}

wire_struct! {
    /// The network action of a `net.http` hop: `network.https:<host>:<port>`
    /// with `methods=<method>`, as the authority canonicalised it. Neither the
    /// path nor the query is stated: the URL is named by its digest, so the
    /// plan says which request it is without repeating what it carries.
    PlannedNetAction: reject {
        /// The origin's host.
        required host: NetHost,
        /// The origin's port.
        required port: NetPort,
        /// The method.
        required method: HttpMethod,
        /// The SHA-256 of the canonical URL (`https://host:port/path?query`).
        required url_sha256: ContentDigest,
        /// How many body bytes the request carries.
        required body_bytes: ByteCount,
        /// Both gates' decision.
        required decision: NetActionDecision,
    }
}

wire_struct! {
    /// The injection action of a `net.http` hop that asked for a credential:
    /// `secret.use:<handle>`, at exactly the hop's origin. The value is never
    /// stated, nor its header, nor its length.
    PlannedInjectionAction: reject {
        /// The handle.
        required handle: CredentialHandle,
        /// The origin's host it would be injected at.
        required host: NetHost,
        /// The origin's port.
        required port: NetPort,
        /// Both gates' decision.
        required decision: NetActionDecision,
    }
}

wire_struct! {
    /// One action of a version-4 plan: exactly one of a filesystem action, a
    /// process action, a network action and an injection action.
    PlannedActionV4: reject {
        /// A filesystem action.
        optional fs: PlannedAction,
        /// A process action.
        optional process: PlannedProcessAction,
        /// A network action.
        optional net: PlannedNetAction,
        /// A credential's injection.
        optional injection: PlannedInjectionAction,
    }
    exactly_one(fs, process, net, injection)
}

/// A version-4 plan's actions, in the order they were decided.
pub type PlannedActionsV4 = BoundedList<PlannedActionV4, MAX_PLAN_ACTIONS>;

wire_struct! {
    /// The canonical plan a version-4 call resolves to. `effect` is `ALLOW`
    /// only if **every** action is allowed. A `net.http` plan is its first
    /// hop's; each later hop is decided again, from the start, and reported in
    /// the result.
    ToolPlanV4: reject {
        /// The tool.
        required tool: CoreToolV4,
        /// Where it runs: `HOST` — the broker is the HTTPS client.
        required environment: ActionEnvironment,
        /// The decision for the whole call.
        required effect: DecisionEffect,
        /// Every action the call requires.
        required actions: PlannedActionsV4,
    }
}

// ---------------------------------------------------------------------------
// Results.
// ---------------------------------------------------------------------------

wire_struct! {
    /// One hop of a `net.http`: where it went and what came back. No path, no
    /// query, no header, no address.
    NetHop: reject {
        /// Which hop.
        required hop: HopNumber,
        /// The origin's host.
        required host: NetHost,
        /// The origin's port.
        required port: NetPort,
        /// The method sent.
        required method: HttpMethod,
        /// The status the response carried, if one arrived.
        optional status: HttpStatus,
        /// Whether a credential was injected into this hop.
        required injected: bool,
    }
}

/// A request's hops, in order.
pub type NetHops = BoundedList<NetHop, { http::MAX_HOPS }>;

wire_enum! {
    /// Why a redirect the last response asked for was not followed. The
    /// result is that response's; nothing was sent to the redirect's target.
    RedirectEnd {
        /// The request did not ask for redirects to be followed.
        NotFollowed = "NOT_FOLLOWED",
        /// The sixth hop: at most five redirects are followed.
        RedirectLimit = "REDIRECT_LIMIT",
        /// The target is a URL this request already visited.
        RedirectLoop = "REDIRECT_LOOP",
        /// The `Location` is not an `https` URL with one reading.
        RedirectTargetInvalid = "REDIRECT_TARGET_INVALID",
        /// Following would send the body again (`301`, `302`, `307`, `308`
        /// after a method with a body).
        RedirectWouldResendBody = "REDIRECT_WOULD_RESEND_BODY",
        /// A gate refused the next hop: no capability covers it, policy denied
        /// it, or an obligation is unenforceable.
        HopDenied = "HOP_DENIED",
        /// The next hop's host is a metadata name or resolved to a blocked
        /// address.
        AddressBlocked = "ADDRESS_BLOCKED",
        /// The next hop's host resolved to blocked and allowed addresses.
        AddressMixed = "ADDRESS_MIXED",
        /// The next hop's host did not resolve.
        ResolutionFailed = "RESOLUTION_FAILED",
        /// The next hop's resolution overran its deadline.
        ResolutionTimeout = "RESOLUTION_TIMEOUT",
        /// A request, byte or origin budget is spent.
        BudgetExhausted = "BUDGET_EXHAUSTED",
        /// The request as a whole overran its deadline.
        RequestTimeout = "REQUEST_TIMEOUT",
        /// The next hop was sent and produced no response; the audit record
        /// says why.
        HopFailed = "HOP_FAILED",
    }
}

wire_struct! {
    /// What a `net.http` brought back: the last response's status, its kept
    /// headers and its body — redacted of every configured secret value, and
    /// cut at the bound — and every hop.
    NetHttpResult: reject {
        /// The last response's status.
        required status: HttpStatus,
        /// Its headers on the keep-list (`crate::wire::http`), `location` as
        /// the authority canonicalised it. Never `set-cookie`.
        required headers: ResponseHeaders,
        /// Its body, as lowercase hexadecimal: at most the request's bound.
        required body: HexContent,
        /// Whether the body was longer than what came back.
        required truncated: bool,
        /// Every hop, in order.
        required hops: NetHops,
        /// Why a redirect the last response asked for was not followed.
        optional redirect_ended: RedirectEnd,
    }
}

wire_struct! {
    /// A version-4 tool's output: **exactly one** member, the call's own.
    ToolOutputV4: reject {
        /// An `fs.read`'s bytes.
        optional fs_read: FsReadResult,
        /// An `fs.list`'s entries.
        optional fs_list: FsListResult,
        /// An `fs.search`'s offsets.
        optional fs_search: FsSearchResult,
        /// An `fs.stat`'s metadata.
        optional fs_stat: FsStatResult,
        /// An `fs.write`'s acknowledgement.
        optional fs_write: FsWriteResult,
        /// An `fs.patch`'s acknowledgement.
        optional fs_patch: FsPatchResult,
        /// An `fs.move`'s acknowledgement.
        optional fs_move: FsMoveResult,
        /// An `fs.delete`'s acknowledgement.
        optional fs_delete: FsDeleteResult,
        /// A launch's handle.
        optional process_exec: ProcessExecResult,
        /// A process's state and output.
        optional process_status: ProcessStatusResult,
        /// A kill's acknowledgement.
        optional process_kill: ProcessKillResult,
        /// A request's response.
        optional net_http: NetHttpResult,
    }
    exactly_one(
        fs_read, fs_list, fs_search, fs_stat, fs_write, fs_patch, fs_move, fs_delete,
        process_exec, process_status, process_kill, net_http
    )
}

// ---------------------------------------------------------------------------
// Responses.
// ---------------------------------------------------------------------------

wire_struct! {
    /// A version-4 invocation every action of whose plan was allowed, which
    /// the broker performed, and which the authority recorded — in that order.
    ToolResultV4: reject {
        /// The authority's id for this invocation.
        required invocation_id: InvocationId,
        /// The plan that was decided and performed (for `net.http`, its first
        /// hop's).
        required plan: ToolPlanV4,
        /// The tool's output.
        required output: ToolOutputV4,
    }
}

wire_struct! {
    /// Every target resolved and at least one action of the plan was refused.
    /// Nothing was performed, no broker was asked to act and no invocation was
    /// recorded. For `net.http` the broker may have resolved a host a grant
    /// covers, under an id the audit names and this answer does not: a
    /// resolution sends nothing to the host.
    ToolDenialV4: reject {
        /// The plan, with every action's decision.
        required plan: ToolPlanV4,
    }
}

wire_struct! {
    /// What a version-4 invocation would mean. Nothing was performed and —
    /// for `net.http` — nothing was resolved: a preview decides without a
    /// destination address, so a rule that needs one is unevaluable.
    CanonicalPreviewResultV4: reject {
        /// The plan `ToolInvoke` would decide on, with every action's decision.
        required plan: ToolPlanV4,
    }
}

wire_enum! {
    /// Why a version-4 tool operation was refused before any effect was
    /// authorised. Version 3's classes, and the network classes.
    ToolRefusalReasonV4 {
        /// The epoch presented is not the session's current epoch.
        StaleEpoch = "STALE_EPOCH",
        /// The run named is not a live admission of this caller.
        UnknownRun = "UNKNOWN_RUN",
        /// The idempotency key is already bound to an invocation.
        IdempotencyKeyReused = "IDEMPOTENCY_KEY_REUSED",
        /// The run's workspace has no bound root.
        WorkspaceUnbound = "WORKSPACE_UNBOUND",
        /// The bound root's path now names another directory.
        RootReplaced = "ROOT_REPLACED",
        /// The bound root could not be opened.
        RootUnavailable = "ROOT_UNAVAILABLE",
        /// This platform has no resolver or no broker.
        UnsupportedPlatform = "UNSUPPORTED_PLATFORM",
        /// A workspace path is outside `/workspace`.
        PathOutsideWorkspace = "PATH_OUTSIDE_WORKSPACE",
        /// A workspace path traverses with `.` or `..`.
        PathTraversal = "PATH_TRAVERSAL",
        /// A workspace path is not in canonical form.
        PathNotCanonical = "PATH_NOT_CANONICAL",
        /// Nothing is at a workspace path.
        NotFound = "NOT_FOUND",
        /// A component that must be a directory is not.
        NotADirectory = "NOT_A_DIRECTORY",
        /// A workspace path crosses a symlink.
        Symlink = "SYMLINK",
        /// A path crosses a magic link.
        MagicLink = "MAGIC_LINK",
        /// A workspace path crosses a mount.
        MountCrossing = "MOUNT_CROSSING",
        /// A name is not spelled as its directory holds it.
        NameMismatch = "NAME_MISMATCH",
        /// A name is canonically equivalent to another in its directory.
        NormalizationAmbiguity = "NORMALIZATION_AMBIGUITY",
        /// The object is neither a regular file nor a directory.
        SpecialFile = "SPECIAL_FILE",
        /// The object is not the kind the tool needs.
        WrongKind = "WRONG_KIND",
        /// A file to modify has more than one name.
        MultiplyLinked = "MULTIPLY_LINKED",
        /// The workspace root itself was named where it cannot be acted on.
        WorkspaceRoot = "WORKSPACE_ROOT",
        /// A move's destination exists.
        DestinationExists = "DESTINATION_EXISTS",
        /// A patch's edits do not transform its base into its post revision.
        PatchInconsistent = "PATCH_INCONSISTENT",
        /// A patch inserts more than an inline patch may carry.
        PatchTooLarge = "PATCH_TOO_LARGE",
        /// Something changed while a path was being resolved.
        Race = "RACE",
        /// The authority's own identity may not look there.
        PermissionDenied = "PERMISSION_DENIED",
        /// A directory holds more entries than may be examined.
        DirectoryTooLarge = "DIRECTORY_TOO_LARGE",
        /// Another operating-system error.
        IoError = "IO_ERROR",
        /// The executable path is not an absolute canonical spelling.
        ExecutablePathInvalid = "EXECUTABLE_PATH_INVALID",
        /// Nothing is at the executable path.
        ExecutableNotFound = "EXECUTABLE_NOT_FOUND",
        /// The executable resolves to something other than a regular file.
        ExecutableNotRegular = "EXECUTABLE_NOT_REGULAR",
        /// The executable has no execute bit.
        ExecutableNotExecutable = "EXECUTABLE_NOT_EXECUTABLE",
        /// Resolving the executable met more symlinks than it follows.
        ExecutableSymlinkLimit = "EXECUTABLE_SYMLINK_LIMIT",
        /// The executable could change under the authority's feet.
        ExecutableUntrusted = "EXECUTABLE_UNTRUSTED",
        /// The executable is larger than the authority hashes.
        ExecutableTooLarge = "EXECUTABLE_TOO_LARGE",
        /// The executable is a `#!` script.
        ScriptUnsupported = "SCRIPT_UNSUPPORTED",
        /// The executable is not a native ELF executable.
        NotNativeExecutable = "NOT_NATIVE_EXECUTABLE",
        /// The executable changed while it was being resolved and hashed.
        ExecutableRace = "EXECUTABLE_RACE",
        /// The arguments are more, or longer, than one request may carry.
        ArgvTooLarge = "ARGV_TOO_LARGE",
        /// No process this run launched has that id.
        UnknownProcess = "UNKNOWN_PROCESS",
        /// The URL is not one `https` URL with one reading: userinfo, a
        /// fragment, an address literal, a host or port or path that is not
        /// canonical (`crate::wire::url`).
        UrlInvalid = "URL_INVALID",
        /// The URL's scheme is not `https`: no plain HTTP, WebSocket or other
        /// scheme exists (D6).
        PlaintextUnsupported = "PLAINTEXT_UNSUPPORTED",
        /// A header name or value is not in its one spelling, a name repeats,
        /// or the headers are past their bounds.
        HeaderInvalid = "HEADER_INVALID",
        /// A header the caller may not set: framing, routing, credentials, or
        /// an operator's credential header.
        HeaderForbidden = "HEADER_FORBIDDEN",
        /// A body on a method that carries none.
        BodyNotPermitted = "BODY_NOT_PERMITTED",
        /// The host is a cloud metadata name, or resolved only to addresses the
        /// guard blocks.
        AddressBlocked = "ADDRESS_BLOCKED",
        /// The host resolved to blocked and allowed addresses: a rebinding's
        /// shape, refused whole.
        AddressMixed = "ADDRESS_MIXED",
        /// The host did not resolve.
        ResolutionFailed = "RESOLUTION_FAILED",
        /// The resolution overran its deadline.
        ResolutionTimeout = "RESOLUTION_TIMEOUT",
        /// A configured secret's value is in the URL, a header or the body:
        /// sending it would be exfiltration.
        SecretInRequest = "SECRET_IN_REQUEST",
        /// The run's request, byte or origin budget is spent.
        BudgetExhausted = "BUDGET_EXHAUSTED",
        /// The credential cannot be used: not configured, revoked, replaced,
        /// not for egress, or not bound to this origin.
        CredentialUnavailable = "CREDENTIAL_UNAVAILABLE",
        /// No broker is configured or reachable to resolve the host.
        NetworkUnavailable = "NETWORK_UNAVAILABLE",
    }
}

wire_enum! {
    /// Why a version-4 invocation that was authorised and recorded produced no
    /// result. Version 3's classes, and the network classes.
    ToolFailureReasonV4 {
        /// The object is no longer the one checked.
        ObjectChanged = "OBJECT_CHANGED",
        /// The object could not be opened for the handoff.
        ObjectUnreadable = "OBJECT_UNREADABLE",
        /// A name to create is occupied.
        TargetOccupied = "TARGET_OCCUPIED",
        /// A patch's file holds neither revision.
        Conflict = "CONFLICT",
        /// A directory to delete is not empty.
        DirectoryNotEmpty = "DIRECTORY_NOT_EMPTY",
        /// The broker's identity may not change names there.
        WriteDenied = "WRITE_DENIED",
        /// A replacement could not keep the replaced file's group.
        AttributesNotPreserved = "ATTRIBUTES_NOT_PRESERVED",
        /// A directory every user may write.
        SharedDirectory = "SHARED_DIRECTORY",
        /// The broker could not be reached, or is not configured.
        BrokerUnavailable = "BROKER_UNAVAILABLE",
        /// The broker's answer broke the protocol.
        BrokerProtocolError = "BROKER_PROTOCOL_ERROR",
        /// The broker refused for a reason of its own.
        BrokerExecutionError = "BROKER_EXECUTION_ERROR",
        /// An effect may have happened, and nothing proves what.
        OutcomeUnknown = "OUTCOME_UNKNOWN",
        /// The executable is no longer the object that was hashed.
        ExecutableChanged = "EXECUTABLE_CHANGED",
        /// The launch was prepared and the executable could not be started.
        ExecFailed = "EXEC_FAILED",
        /// The broker supervises as many processes as it may.
        ProcessTableFull = "PROCESS_TABLE_FULL",
        /// The broker holds a descriptor it could not keep from a target.
        BrokerEnvironmentUnsafe = "BROKER_ENVIRONMENT_UNSAFE",
        /// The broker that launched the process no longer supervises it.
        ProcessUnobservable = "PROCESS_UNOBSERVABLE",
        /// No pinned address accepted a connection. Nothing was sent.
        ConnectFailed = "CONNECT_FAILED",
        /// The TLS handshake failed: the certificate did not verify for the
        /// host, or the server offered nothing acceptable. Nothing was sent.
        TlsFailed = "TLS_FAILED",
        /// The response broke HTTP/1.1 framing, or was past a bound DireWolf
        /// refuses rather than cuts (the head, the header count).
        ResponseMalformed = "RESPONSE_MALFORMED",
        /// The response is encoded (`Content-Encoding` other than identity),
        /// which DireWolf never decodes (D7).
        EncodingUnsupported = "ENCODING_UNSUPPORTED",
        /// A deadline passed: connect, handshake, response head, body idle, or
        /// the hop's whole.
        Timeout = "TIMEOUT",
        /// The broker's own guard refused a pinned address.
        AddressBlocked = "ADDRESS_BLOCKED",
        /// The credential could not be read from its backend, or cannot be
        /// carried in a header. Nothing was sent.
        CredentialFailed = "CREDENTIAL_FAILED",
    }
}

/// Which refusal reasons each version-4 tool operation can produce. A preview
/// carries no idempotency key, resolves nothing and reads no secret's
/// backend, so it cannot reuse a key, find an address blocked or a host
/// unresolvable, or need a broker.
pub const TOOL_REFUSALS_V4: &[(&str, &[&str])] = &[
    ("TOOL_INVOKE", INVOKE_REFUSALS_V4),
    ("CANONICAL_PREVIEW", PREVIEW_REFUSALS_V4),
];

/// The refusals a preview can produce.
const PREVIEW_REFUSALS_V4: &[&str] = &[
    "STALE_EPOCH",
    "UNKNOWN_RUN",
    "WORKSPACE_UNBOUND",
    "ROOT_REPLACED",
    "ROOT_UNAVAILABLE",
    "UNSUPPORTED_PLATFORM",
    "PATH_OUTSIDE_WORKSPACE",
    "PATH_TRAVERSAL",
    "PATH_NOT_CANONICAL",
    "NOT_FOUND",
    "NOT_A_DIRECTORY",
    "SYMLINK",
    "MAGIC_LINK",
    "MOUNT_CROSSING",
    "NAME_MISMATCH",
    "NORMALIZATION_AMBIGUITY",
    "SPECIAL_FILE",
    "WRONG_KIND",
    "MULTIPLY_LINKED",
    "WORKSPACE_ROOT",
    "DESTINATION_EXISTS",
    "PATCH_INCONSISTENT",
    "PATCH_TOO_LARGE",
    "RACE",
    "PERMISSION_DENIED",
    "DIRECTORY_TOO_LARGE",
    "IO_ERROR",
    "EXECUTABLE_PATH_INVALID",
    "EXECUTABLE_NOT_FOUND",
    "EXECUTABLE_NOT_REGULAR",
    "EXECUTABLE_NOT_EXECUTABLE",
    "EXECUTABLE_SYMLINK_LIMIT",
    "EXECUTABLE_UNTRUSTED",
    "EXECUTABLE_TOO_LARGE",
    "SCRIPT_UNSUPPORTED",
    "NOT_NATIVE_EXECUTABLE",
    "EXECUTABLE_RACE",
    "ARGV_TOO_LARGE",
    "UNKNOWN_PROCESS",
    "URL_INVALID",
    "PLAINTEXT_UNSUPPORTED",
    "HEADER_INVALID",
    "HEADER_FORBIDDEN",
    "BODY_NOT_PERMITTED",
    "ADDRESS_BLOCKED",
    "SECRET_IN_REQUEST",
    "BUDGET_EXHAUSTED",
    "CREDENTIAL_UNAVAILABLE",
];

/// The refusals an invocation can produce: every reason.
const INVOKE_REFUSALS_V4: &[&str] = &[
    "STALE_EPOCH",
    "UNKNOWN_RUN",
    "IDEMPOTENCY_KEY_REUSED",
    "WORKSPACE_UNBOUND",
    "ROOT_REPLACED",
    "ROOT_UNAVAILABLE",
    "UNSUPPORTED_PLATFORM",
    "PATH_OUTSIDE_WORKSPACE",
    "PATH_TRAVERSAL",
    "PATH_NOT_CANONICAL",
    "NOT_FOUND",
    "NOT_A_DIRECTORY",
    "SYMLINK",
    "MAGIC_LINK",
    "MOUNT_CROSSING",
    "NAME_MISMATCH",
    "NORMALIZATION_AMBIGUITY",
    "SPECIAL_FILE",
    "WRONG_KIND",
    "MULTIPLY_LINKED",
    "WORKSPACE_ROOT",
    "DESTINATION_EXISTS",
    "PATCH_INCONSISTENT",
    "PATCH_TOO_LARGE",
    "RACE",
    "PERMISSION_DENIED",
    "DIRECTORY_TOO_LARGE",
    "IO_ERROR",
    "EXECUTABLE_PATH_INVALID",
    "EXECUTABLE_NOT_FOUND",
    "EXECUTABLE_NOT_REGULAR",
    "EXECUTABLE_NOT_EXECUTABLE",
    "EXECUTABLE_SYMLINK_LIMIT",
    "EXECUTABLE_UNTRUSTED",
    "EXECUTABLE_TOO_LARGE",
    "SCRIPT_UNSUPPORTED",
    "NOT_NATIVE_EXECUTABLE",
    "EXECUTABLE_RACE",
    "ARGV_TOO_LARGE",
    "UNKNOWN_PROCESS",
    "URL_INVALID",
    "PLAINTEXT_UNSUPPORTED",
    "HEADER_INVALID",
    "HEADER_FORBIDDEN",
    "BODY_NOT_PERMITTED",
    "ADDRESS_BLOCKED",
    "ADDRESS_MIXED",
    "RESOLUTION_FAILED",
    "RESOLUTION_TIMEOUT",
    "SECRET_IN_REQUEST",
    "BUDGET_EXHAUSTED",
    "CREDENTIAL_UNAVAILABLE",
    "NETWORK_UNAVAILABLE",
];

wire_struct! {
    /// A version-4 tool operation the authority would not attempt. Nothing was
    /// performed and no broker was asked to act.
    ToolRefusalV4: reject {
        /// Which operation.
        required operation: ToolOperation,
        /// Why.
        required reason: ToolRefusalReasonV4,
    }
    paired(operation -> reason, TOOL_REFUSALS_V4)
}

wire_struct! {
    /// A version-4 invocation whose plan was allowed and whose intent was
    /// recorded, and which did not produce a result. The audit record holds
    /// the detail; the caller learns the class.
    ToolFailureV4: reject {
        /// The authority's id for the invocation.
        required invocation_id: InvocationId,
        /// Why.
        required reason: ToolFailureReasonV4,
    }
}

#[cfg(test)]
mod tests {
    use super::{TOOL_REFUSALS_V4, ToolCallV4, ToolRefusalReasonV4};
    use crate::json::{self, ParseOptions};
    use crate::wire::{Cx, WireType};

    fn decode_call(text: &str) -> Result<ToolCallV4, crate::ProtocolError> {
        let value = json::parse(text.as_bytes(), ParseOptions::dwkp()).unwrap_or_else(|e| {
            unreachable!("fixture parses: {e}");
        });
        ToolCallV4::decode(value, &mut Cx::new())
    }

    #[test]
    fn a_network_call_is_one_typed_member_and_carries_no_authority_input() {
        let ok = [
            r#"{"net_http":{"method":"GET","url":"https://api.example.com/v1","follow_redirects":false}}"#,
            r#"{"net_http":{"method":"POST","url":"https://a.b/x","headers":[{"name":"content-type","value":"application/json"}],"body":"7b7d","follow_redirects":true,"max_response_bytes":1024}}"#,
            r#"{"net_http":{"method":"GET","url":"https://a.b/","credential_handle":"github-token","follow_redirects":false}}"#,
        ];
        for text in ok {
            assert!(decode_call(text).is_ok(), "{text}");
        }
        // Nothing the authority decides may be stated by the runtime.
        for extra in [
            r#""address":"1.2.3.4""#,
            r#""resolve":{"a.b":"1.2.3.4"}"#,
            r#""proxy":"http://p""#,
            r#""timeout_ms":1"#,
            r#""tls":{"verify":false}"#,
            r#""trust_root":"-----BEGIN""#,
            r#""cookies":[]"#,
            r#""token":"s3cr3t""#,
            r#""credential_header":"authorization""#,
            r#""origin":"a.b:443""#,
            r#""mode":"egress""#,
            r#""raw":"GET / HTTP/1.1""#,
        ] {
            let text = format!(
                r#"{{"net_http":{{"method":"GET","url":"https://a.b/","follow_redirects":false,{extra}}}}}"#
            );
            assert!(decode_call(&text).is_err(), "{extra}");
        }
        for bad in [
            // A method outside the closed set, or in another spelling.
            r#"{"net_http":{"method":"CONNECT","url":"https://a.b/","follow_redirects":false}}"#,
            r#"{"net_http":{"method":"get","url":"https://a.b/","follow_redirects":false}}"#,
            // A URL with a control or a non-ASCII character.
            r#"{"net_http":{"method":"GET","url":"https://a.b/\r\nx","follow_redirects":false}}"#,
            r#"{"net_http":{"method":"GET","url":"https://a.b/ x","follow_redirects":false}}"#,
            r#"{"net_http":{"method":"GET","url":"https://ä.b/","follow_redirects":false}}"#,
            // A header in another spelling, or with a smuggled line.
            r#"{"net_http":{"method":"GET","url":"https://a.b/","headers":[{"name":"Accept","value":"x"}],"follow_redirects":false}}"#,
            r#"{"net_http":{"method":"GET","url":"https://a.b/","headers":[{"name":"x-a","value":"b\r\nhost: c"}],"follow_redirects":false}}"#,
            r#"{"net_http":{"method":"GET","url":"https://a.b/","headers":{"accept":"x"},"follow_redirects":false}}"#,
            // A credential named by something other than a handle.
            r#"{"net_http":{"method":"GET","url":"https://a.b/","credential_handle":"Bearer x","follow_redirects":false}}"#,
            // A body that is not lowercase hex; a bound past the frame.
            r#"{"net_http":{"method":"POST","url":"https://a.b/","body":"zz","follow_redirects":false}}"#,
            r#"{"net_http":{"method":"GET","url":"https://a.b/","follow_redirects":false,"max_response_bytes":262145}}"#,
            // follow_redirects is stated, always.
            r#"{"net_http":{"method":"GET","url":"https://a.b/"}}"#,
            // Two members.
            r#"{"net_http":{"method":"GET","url":"https://a.b/","follow_redirects":false},"fs_stat":{"path":"/workspace"}}"#,
        ] {
            assert!(decode_call(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn every_refusal_reason_is_reachable_from_an_invocation() {
        let reasons = |op: &str| {
            TOOL_REFUSALS_V4
                .iter()
                .find(|(o, _)| *o == op)
                .map(|(_, r)| *r)
                .unwrap_or_default()
        };
        let invoke = reasons("TOOL_INVOKE");
        let preview = reasons("CANONICAL_PREVIEW");
        for reason in ToolRefusalReasonV4::ALL {
            assert!(invoke.contains(&reason.as_str()), "{}", reason.as_str());
        }
        assert_eq!(invoke.len(), ToolRefusalReasonV4::ALL.len());
        for reason in preview {
            assert!(invoke.contains(reason), "{reason}");
        }
        for never in [
            "IDEMPOTENCY_KEY_REUSED",
            "ADDRESS_MIXED",
            "RESOLUTION_FAILED",
            "RESOLUTION_TIMEOUT",
            "NETWORK_UNAVAILABLE",
        ] {
            assert!(!preview.contains(&never), "{never}");
        }
    }
}
