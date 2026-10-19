//! Version 5 of the tool messages (M5d.2, ADR-0052 §2): the twelve tools of
//! version 4, with `process.exec` run **where the kernel decides** — in the
//! run's execution environment when the authority has one — and its answer
//! saying where it ran, at what level, as which executable, how it ended and
//! what it left.
//!
//! Versions 1 to 4 are kept exactly. Version 5 is a new version rather than
//! new members of version 4 because a sandboxed launch changes what a plan
//! and a result are: its action names an **image executable** (the image's
//! content digest, the path inside it, and the SHA-256 the operator's
//! manifest pins), the environment the authority chose and its measured
//! assurance level; its result is one bounded invocation — spawn, then
//! collect — with an ending and a residue, not a handle. A version-4 decoder
//! never sees one: to it, `process_exec_sandboxed` is an undeclared member.
//!
//! Like every earlier version, a request carries what the runtime proposes
//! and nothing the authority decides: `process_exec` names an executable
//! path, the arguments as exact bytes, an optional working directory, and —
//! new — at most a **narrowing** of the wall clock and of each stream's
//! bound. Never an environment, an image, a container, a user, a shell, a
//! mount, an environment variable, a privilege or a runtime option: each
//! would be the runtime choosing where or how something runs (ADR-0052 OD-1).

use crate::error::{ProtocolError, Violation};
use crate::json::{Number, Value};
use crate::limits::{MAX_PLAN_ACTIONS, MAX_SAFE_INTEGER};
use crate::schema::{Defs, int, obj, string};
use crate::wire::id::{EnvironmentId, InvocationId};
use crate::wire::list::BoundedList;
use crate::wire::macros::wire_struct;
use crate::wire::scalar::{
    ActionEnvironment, ActionRole, ArgCount, ArgvSafetyClass, ContentDigest, DecisionEffect,
    ExitCode, HostPath, ProcessVerb, SignalNumber, ToolOperation, WorkspacePath, wire_enum,
    wire_int, wire_text,
};
use crate::wire::{Cx, WireType, expect_integer, expect_string};

use super::fsops::{
    FsDeleteCall, FsDeleteResult, FsListCall, FsListResult, FsMoveCall, FsMoveResult, FsPatchCall,
    FsPatchResult, FsSearchCall, FsSearchResult, FsStatCall, FsStatResult, FsWriteCall,
    FsWriteResult, PlannedAction,
};
use super::messages::{FsReadCall, FsReadResult};
use super::netops::{
    CoreToolV4, NetHttpCall, NetHttpResult, PlannedInjectionAction, PlannedNetAction,
};
use super::procops::{
    PlannedProcessAction, ProcessActionDecision, ProcessArgs, ProcessExecResult, ProcessKillCall,
    ProcessKillResult, ProcessStatusCall, ProcessStatusResult, ProcessStreamSnapshot,
};

// ---------------------------------------------------------------------------
// Scalars.
// ---------------------------------------------------------------------------

/// The longest wall clock a sandboxed launch may have, in seconds.
pub const MAX_EXEC_SECONDS: u32 = 600;

/// The most bytes of each output stream a sandboxed launch returns.
pub const MAX_EXEC_STREAM_BYTES: u32 = 131_072;

wire_int! {
    /// A sandboxed launch's wall clock, in seconds: 1 to [`MAX_EXEC_SECONDS`].
    ExecSeconds(u32), min = 1, max = 600
}

wire_int! {
    /// How many bytes of each output stream a sandboxed launch keeps: 1 to
    /// [`MAX_EXEC_STREAM_BYTES`].
    ExecStreamLimit(u32), min = 1, max = 131_072
}

wire_int! {
    /// A duration, in milliseconds.
    ExecMilliseconds(u32), min = 0, max = 4_294_967_295
}

wire_int! {
    /// How many processes the environment's init ended after a launch.
    ReapedCount(u32), min = 0, max = 4096
}

const _: () = assert!(ExecSeconds::MAX == MAX_EXEC_SECONDS);
const _: () = assert!(ExecStreamLimit::MAX == MAX_EXEC_STREAM_BYTES);

fn lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

wire_text! {
    /// An image, by content: `sha256:` and 64 lowercase hexadecimal digits.
    /// Never a tag.
    ImageDigest,
    max_chars = 71,
    pattern = Some("^sha256:[0-9a-f]{64}$"),
    format = None,
    validate = |s| s.len() == 71 && s.strip_prefix("sha256:").is_some_and(lower_hex)
}

wire_enum! {
    /// How strongly an execution environment isolates what runs in it, as
    /// the authority measured it (SANDBOX.md §1) — never higher than the
    /// environment's kind declares.
    ExecutionAssurance {
        /// No isolation: the host.
        None = "NONE",
        /// A process on the host with its own restrictions.
        ProcessIsolation = "PROCESS_ISOLATION",
        /// An OCI container meeting every required invariant.
        ContainerIsolation = "CONTAINER_ISOLATION",
        /// A virtual machine.
        VmIsolation = "VM_ISOLATION",
    }
}

wire_enum! {
    /// How a sandboxed launch that completed ended. A lost environment, an
    /// unreachable runtime or an ending nothing observed is never one of
    /// these: it is a failure whose outcome is unknown.
    SandboxEnding {
        /// It exited; `exit_code` says how.
        Exited = "EXITED",
        /// A signal ended it; `signal` says which.
        Killed = "KILLED",
        /// It outran its wall clock and was ended.
        TimedOut = "TIMED_OUT",
    }
}

wire_enum! {
    /// How a sandboxed launch is started (ADR-0052 §5a).
    ExecLaunch {
        /// The runtime's `exec` runs the executable itself.
        Direct = "DIRECT",
        /// The trusted in-image launcher sets `workspace_exec_hygiene`'s
        /// fixed variables and executes the executable; the tool's own
        /// neutralising arguments come first in the argv.
        Hygiene = "HYGIENE",
    }
}

wire_enum! {
    /// What the environment's init found after a launch.
    ResidueVerdict {
        /// Every other process of the environment was proved gone.
        Pass = "PASS",
        /// Some could not be ended: the environment was destroyed.
        Fail = "FAIL",
        /// Nothing proved it either way: the environment was destroyed.
        Unobservable = "UNOBSERVABLE",
    }
}

// ---------------------------------------------------------------------------
// Calls.
// ---------------------------------------------------------------------------

wire_struct! {
    /// A `process.exec` at version 5: launch one executable with these
    /// arguments, where the kernel decides.
    ///
    /// With an execution environment, `executable` is a path **inside the
    /// image**, which the operator's manifest must name; the working
    /// directory, when given, must be the workspace root (the environment's
    /// `/workspace`). Without one, it is version 3's host launch, decided and
    /// refused by the host floor.
    ProcessExecCallV5: reject {
        /// The executable, as an absolute path.
        required executable: HostPath,
        /// The arguments after `argv[0]`, each passed as exactly its bytes.
        required args: ProcessArgs,
        /// The working directory, in the logical workspace namespace. The
        /// workspace root when absent.
        optional cwd: WorkspacePath,
        /// A shorter wall clock than the authority's.
        optional timeout_seconds: ExecSeconds,
        /// A smaller per-stream bound than the authority's.
        optional max_stream_bytes: ExecStreamLimit,
    }
}

wire_struct! {
    /// A tool call: **exactly one** of the twelve typed members. The payload
    /// of `direwolf.tool.invoke` and `direwolf.tool.preview` at version 5.
    ToolCallV5: reject {
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
        /// Launch one executable, where the kernel decides.
        optional process_exec: ProcessExecCallV5,
        /// Observe one host process this run launched.
        optional process_status: ProcessStatusCall,
        /// End one host process this run launched.
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

wire_struct! {
    /// An executable in an image: the identity a sandboxed launch is decided
    /// on. The image is content addressed and its root read-only, so the path
    /// names one file in every environment made from it; the broker proves
    /// that file's bytes against `sha256` before every launch.
    ImageExecutableRef: reject {
        /// The image, by content digest.
        required image: ImageDigest,
        /// The path inside the image.
        required path: HostPath,
        /// The SHA-256 the operator's manifest pins for it.
        required sha256: ContentDigest,
    }
}

wire_struct! {
    /// One sandboxed launch, as the authority decided it: every fact policy
    /// decided on (the environment is `SANDBOX`), the environment it chose,
    /// and the bounds it will hold the launch to. The capability it required
    /// is `process.exec:<path>@<sha256>` — with `?argv_allowlist=<first
    /// argument>` for a first argument an allowlist can name.
    PlannedWorkloadAction: reject {
        /// What part it plays: always `TARGET`.
        required role: ActionRole,
        /// The capability verb it requires: `process.exec`.
        required verb: ProcessVerb,
        /// The executable, in the image.
        required executable: ImageExecutableRef,
        /// The environment the authority chose: the run's `READY` one.
        /// Absent from a denial, which needs none, and from a preview of a
        /// run whose environment an invocation would prepare.
        optional environment_id: EnvironmentId,
        /// That environment's measured, effective level.
        optional assurance: ExecutionAssurance,
        /// How it is started.
        required launch: ExecLaunch,
        /// How many arguments follow `argv[0]`, as the broker is told them:
        /// the obligation's first, then the call's.
        required arg_count: ArgCount,
        /// The SHA-256 of that argv.
        required argv_sha256: ContentDigest,
        /// The kernel's classification of the call's arguments: what policy
        /// decided on.
        required argv_safety: ArgvSafetyClass,
        /// The wall clock it will be held to.
        required timeout_seconds: ExecSeconds,
        /// How many bytes of each stream come back.
        required max_stream_bytes: ExecStreamLimit,
        /// Both gates' decision for this action.
        required decision: ProcessActionDecision,
    }
}

wire_struct! {
    /// One action of a version-5 plan: exactly one of a filesystem action, a
    /// host process action, a sandboxed launch, a network action and an
    /// injection action.
    PlannedActionV5: reject {
        /// A filesystem action.
        optional fs: PlannedAction,
        /// A host process action.
        optional process: PlannedProcessAction,
        /// A sandboxed launch.
        optional workload: PlannedWorkloadAction,
        /// A network action.
        optional net: PlannedNetAction,
        /// A credential's injection.
        optional injection: PlannedInjectionAction,
    }
    exactly_one(fs, process, workload, net, injection)
}

/// A version-5 plan's actions, in the order they were decided.
pub type PlannedActionsV5 = BoundedList<PlannedActionV5, MAX_PLAN_ACTIONS>;

wire_struct! {
    /// The canonical plan a version-5 call resolves to. `effect` is `ALLOW`
    /// only if **every** action is allowed. A sandboxed launch's plan says
    /// `SANDBOX`; nothing else of version 5 runs anywhere but `HOST`.
    ToolPlanV5: reject {
        /// The tool.
        required tool: CoreToolV4,
        /// Where it runs.
        required environment: ActionEnvironment,
        /// The decision for the whole call.
        required effect: DecisionEffect,
        /// Every action the call requires.
        required actions: PlannedActionsV5,
    }
}

// ---------------------------------------------------------------------------
// Results.
// ---------------------------------------------------------------------------

wire_struct! {
    /// What a sandboxed `process.exec` did: where it ran, at what level, as
    /// which executable, how it ended, its bounded output, and what the
    /// environment's init found after it. Its output is content the
    /// environment produced: the run is `LOCAL_UNVERIFIED` before this is
    /// answered, and a configured secret's value in it is redacted.
    SandboxedExecResult: reject {
        /// The environment it ran in.
        required environment_id: EnvironmentId,
        /// That environment's measured, effective level.
        required assurance: ExecutionAssurance,
        /// The executable, in the image, whose bytes the broker proved.
        required executable: ImageExecutableRef,
        /// How it ended.
        required ending: SandboxEnding,
        /// For `EXITED`: the code.
        optional exit_code: ExitCode,
        /// For `KILLED`: the signal.
        optional signal: SignalNumber,
        /// Its standard output, redacted, to the bound.
        required stdout: ProcessStreamSnapshot,
        /// Its standard error, redacted, to the bound.
        required stderr: ProcessStreamSnapshot,
        /// How long it ran.
        required elapsed_ms: ExecMilliseconds,
        /// Whether every other process of the environment was then proved
        /// gone.
        required residue: ResidueVerdict,
        /// How many processes, besides init, were found and ended.
        required ended_processes: ReapedCount,
        /// Whether the environment was destroyed after it: its residue was
        /// not proved clean.
        required environment_destroyed: bool,
    }
}

wire_struct! {
    /// A version-5 tool's output: **exactly one** member, the call's own. A
    /// `process_exec` in an execution environment answers with
    /// `process_exec_sandboxed`; on the host, with `process_exec`.
    ToolOutputV5: reject {
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
        /// A host launch's handle.
        optional process_exec: ProcessExecResult,
        /// A sandboxed launch's ending.
        optional process_exec_sandboxed: SandboxedExecResult,
        /// A host process's state and output.
        optional process_status: ProcessStatusResult,
        /// A kill's acknowledgement.
        optional process_kill: ProcessKillResult,
        /// A request's response.
        optional net_http: NetHttpResult,
    }
    exactly_one(
        fs_read, fs_list, fs_search, fs_stat, fs_write, fs_patch, fs_move, fs_delete,
        process_exec, process_exec_sandboxed, process_status, process_kill, net_http
    )
}

// ---------------------------------------------------------------------------
// Responses.
// ---------------------------------------------------------------------------

wire_struct! {
    /// A version-5 invocation every action of whose plan was allowed, which
    /// the broker performed, and which the authority recorded — in that
    /// order.
    ToolResultV5: reject {
        /// The authority's id for this invocation.
        required invocation_id: InvocationId,
        /// The plan that was decided and performed.
        required plan: ToolPlanV5,
        /// The tool's output.
        required output: ToolOutputV5,
    }
}

wire_struct! {
    /// Every target resolved and at least one action of the plan was
    /// refused. Nothing was performed and no invocation was recorded.
    ToolDenialV5: reject {
        /// The plan, with every action's decision.
        required plan: ToolPlanV5,
    }
}

wire_struct! {
    /// What a version-5 invocation would mean. Nothing was performed: no
    /// broker, no launch, no environment touched.
    CanonicalPreviewResultV5: reject {
        /// The plan `ToolInvoke` would decide on, with every action's decision.
        required plan: ToolPlanV5,
    }
}

wire_enum! {
    /// Why a version-5 tool operation was refused before any effect was
    /// authorised. Version 4's classes, and the execution environment's.
    ToolRefusalReasonV5 {
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
        /// The URL is not one `https` URL with one reading.
        UrlInvalid = "URL_INVALID",
        /// The URL's scheme is not `https`.
        PlaintextUnsupported = "PLAINTEXT_UNSUPPORTED",
        /// A header name or value is not in its one spelling, a name repeats,
        /// or the headers are past their bounds.
        HeaderInvalid = "HEADER_INVALID",
        /// A header the caller may not set.
        HeaderForbidden = "HEADER_FORBIDDEN",
        /// A body on a method that carries none.
        BodyNotPermitted = "BODY_NOT_PERMITTED",
        /// The host is a cloud metadata name, or resolved only to addresses
        /// the guard blocks.
        AddressBlocked = "ADDRESS_BLOCKED",
        /// The host resolved to blocked and allowed addresses.
        AddressMixed = "ADDRESS_MIXED",
        /// The host did not resolve.
        ResolutionFailed = "RESOLUTION_FAILED",
        /// The resolution overran its deadline.
        ResolutionTimeout = "RESOLUTION_TIMEOUT",
        /// A configured secret's value is in the URL, a header or the body.
        SecretInRequest = "SECRET_IN_REQUEST",
        /// The run's budget is spent: for `net.http` its requests, bytes or
        /// origins; for a sandboxed launch its workloads, wall-clock seconds
        /// or environments.
        BudgetExhausted = "BUDGET_EXHAUSTED",
        /// The credential cannot be used.
        CredentialUnavailable = "CREDENTIAL_UNAVAILABLE",
        /// No broker is configured or reachable to resolve the host.
        NetworkUnavailable = "NETWORK_UNAVAILABLE",
        /// The image manifest names no executable at the path: nothing else
        /// runs in an environment.
        ExecutableNotInImage = "EXECUTABLE_NOT_IN_IMAGE",
        /// A sandboxed launch runs in the workspace root, and the call named
        /// another directory.
        WorkingDirectoryUnsupported = "WORKING_DIRECTORY_UNSUPPORTED",
        /// The run has no live execution environment. Nothing runs on the
        /// host instead.
        NoEnvironment = "NO_ENVIRONMENT",
        /// The run's environment is not `READY`: being prepared, destroyed,
        /// or of unknown state.
        EnvironmentNotReady = "ENVIRONMENT_NOT_READY",
        /// The run had no environment, and the one the authority prepared
        /// for it was refused, measured unusable or is of unknown state.
        /// Nothing ran, and nothing runs on the host instead.
        EnvironmentUnavailable = "ENVIRONMENT_UNAVAILABLE",
        /// The run's environment measured below `CONTAINER_ISOLATION`.
        AssuranceInsufficient = "ASSURANCE_INSUFFICIENT",
        /// The run's environment is running another launch: one at a time.
        EnvironmentBusy = "ENVIRONMENT_BUSY",
        /// The run was admitted against another image or manifest than the
        /// environment's or the authority's now (OD-9).
        ImageChanged = "IMAGE_CHANGED",
    }
}

/// Which refusal reasons each version-5 tool operation can produce. A
/// preview carries no idempotency key, resolves no host, prepares no
/// environment and runs nothing, so it cannot reuse a key, find an address
/// blocked or a host unresolvable, need a broker, find the environment busy,
/// or fail to prepare one.
pub const TOOL_REFUSALS_V5: &[(&str, &[&str])] = &[
    ("TOOL_INVOKE", INVOKE_REFUSALS_V5),
    ("CANONICAL_PREVIEW", PREVIEW_REFUSALS_V5),
];

/// The refusals a preview can produce.
const PREVIEW_REFUSALS_V5: &[&str] = &[
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
    "EXECUTABLE_NOT_IN_IMAGE",
    "WORKING_DIRECTORY_UNSUPPORTED",
    "NO_ENVIRONMENT",
    "ENVIRONMENT_NOT_READY",
    "ASSURANCE_INSUFFICIENT",
    "IMAGE_CHANGED",
];

/// The refusals an invocation can produce: every reason.
const INVOKE_REFUSALS_V5: &[&str] = &[
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
    "EXECUTABLE_NOT_IN_IMAGE",
    "WORKING_DIRECTORY_UNSUPPORTED",
    "NO_ENVIRONMENT",
    "ENVIRONMENT_NOT_READY",
    "ENVIRONMENT_UNAVAILABLE",
    "ASSURANCE_INSUFFICIENT",
    "ENVIRONMENT_BUSY",
    "IMAGE_CHANGED",
];

wire_struct! {
    /// A version-5 tool operation the authority would not attempt. Nothing
    /// was performed and no broker was asked to act.
    ToolRefusalV5: reject {
        /// Which operation.
        required operation: ToolOperation,
        /// Why.
        required reason: ToolRefusalReasonV5,
    }
    paired(operation -> reason, TOOL_REFUSALS_V5)
}

wire_enum! {
    /// Why a version-5 invocation that was authorised and recorded produced
    /// no result. Version 4's classes, and the execution environment's.
    ToolFailureReasonV5 {
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
        /// An effect may have happened, and nothing proves what. For a
        /// sandboxed launch: it may have run and nothing proves how it ended;
        /// it is never run again, and its environment is destroyed.
        OutcomeUnknown = "OUTCOME_UNKNOWN",
        /// The executable is no longer the object that was hashed — for a
        /// sandboxed launch, its bytes in the image are not the pinned ones.
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
        /// The TLS handshake failed. Nothing was sent.
        TlsFailed = "TLS_FAILED",
        /// The response broke HTTP/1.1 framing, or was past a bound.
        ResponseMalformed = "RESPONSE_MALFORMED",
        /// The response is encoded, which DireWolf never decodes.
        EncodingUnsupported = "ENCODING_UNSUPPORTED",
        /// A deadline passed.
        Timeout = "TIMEOUT",
        /// The broker's own guard refused a pinned address.
        AddressBlocked = "ADDRESS_BLOCKED",
        /// The credential could not be read from its backend, or cannot be
        /// carried in a header. Nothing was sent.
        CredentialFailed = "CREDENTIAL_FAILED",
        /// The environment, as its runtime record shows it now, is not the
        /// clean one recorded. Nothing ran, and it was destroyed.
        EnvironmentNotClean = "ENVIRONMENT_NOT_CLEAN",
        /// The environment recorded is gone, or not this run's. Nothing ran.
        EnvironmentUnavailable = "ENVIRONMENT_UNAVAILABLE",
        /// The container runtime, its client, the image or the network
        /// topology could not be used. Nothing ran.
        RuntimeUnavailable = "RUNTIME_UNAVAILABLE",
    }
}

wire_struct! {
    /// A version-5 invocation whose plan was allowed and whose intent was
    /// recorded, and which did not produce a result. The audit record holds
    /// the detail; the caller learns the class — and, for a sandboxed
    /// launch, its environment and whether that environment is gone.
    ToolFailureV5: reject {
        /// The authority's id for the invocation.
        required invocation_id: InvocationId,
        /// Why.
        required reason: ToolFailureReasonV5,
        /// For a sandboxed launch: the environment it was to run in.
        optional environment_id: EnvironmentId,
        /// For a sandboxed launch: whether that environment was destroyed
        /// (or its destruction begun) because of it.
        optional environment_destroyed: bool,
    }
}

#[cfg(test)]
mod tests {
    use super::{TOOL_REFUSALS_V5, ToolCallV5, ToolOutputV5, ToolRefusalReasonV5};
    use crate::json::{self, ParseOptions};
    use crate::wire::{Cx, WireType};

    fn decode_call(text: &str) -> Result<ToolCallV5, crate::ProtocolError> {
        let value = json::parse(text.as_bytes(), ParseOptions::dwkp()).unwrap_or_else(|e| {
            unreachable!("fixture parses: {e}");
        });
        ToolCallV5::decode(value, &mut Cx::new())
    }

    #[test]
    fn a_launch_names_an_executable_and_at_most_narrows_its_bounds() {
        for ok in [
            r#"{"process_exec":{"executable":"/usr/bin/git","args":["status"]}}"#,
            r#"{"process_exec":{"executable":"/usr/bin/git","args":[],"cwd":"/workspace"}}"#,
            r#"{"process_exec":{"executable":"/x","args":[],"timeout_seconds":30,"max_stream_bytes":4096}}"#,
            r#"{"process_exec":{"executable":"/x","args":[],"timeout_seconds":600,"max_stream_bytes":131072}}"#,
        ] {
            assert!(decode_call(ok).is_ok(), "{ok}");
        }
        // Past the authority's bounds, or not a bound at all.
        for bad in [
            r#"{"process_exec":{"executable":"/x","args":[],"timeout_seconds":0}}"#,
            r#"{"process_exec":{"executable":"/x","args":[],"timeout_seconds":601}}"#,
            r#"{"process_exec":{"executable":"/x","args":[],"max_stream_bytes":131073}}"#,
            r#"{"process_exec":{"executable":"/x","args":[],"max_stream_bytes":0}}"#,
            r#"{"process_exec":{"executable":"/x","args":"status"}}"#,
        ] {
            assert!(decode_call(bad).is_err(), "{bad}");
        }
        // Nothing that chooses where or how it runs.
        for extra in [
            r#""environment":"HOST""#,
            r#""environment_id":"env_01M24BB8G3E0A851TRWE3M8FZG""#,
            r#""image":"sha256:00""#,
            r#""container":"abc""#,
            r#""user":"0""#,
            r#""uid":0"#,
            r#""shell":true"#,
            r#""mounts":[]"#,
            r#""env":{"A":"B"}"#,
            r#""privileged":true"#,
            r#""network":"host""#,
            r#""runtime_options":[]"#,
            r#""fallback":"host""#,
            r#""argv0":"git""#,
            r#""sha256":"00""#,
        ] {
            let text = format!(r#"{{"process_exec":{{"executable":"/x","args":[],{extra}}}}}"#);
            assert!(decode_call(&text).is_err(), "{extra}");
        }
    }

    #[test]
    fn an_output_is_exactly_one_member() {
        let value = json::parse(b"{}", ParseOptions::dwkp()).unwrap_or_else(|e| {
            unreachable!("{e}");
        });
        assert!(ToolOutputV5::decode(value, &mut Cx::new()).is_err());
    }

    #[test]
    fn every_refusal_reason_is_reachable_from_an_invocation() {
        let reasons = |op: &str| {
            TOOL_REFUSALS_V5
                .iter()
                .find(|(o, _)| *o == op)
                .map(|(_, r)| *r)
                .unwrap_or_default()
        };
        let invoke = reasons("TOOL_INVOKE");
        let preview = reasons("CANONICAL_PREVIEW");
        for reason in ToolRefusalReasonV5::ALL {
            assert!(invoke.contains(&reason.as_str()), "{}", reason.as_str());
        }
        assert_eq!(invoke.len(), ToolRefusalReasonV5::ALL.len());
        for reason in preview {
            assert!(invoke.contains(reason), "{reason}");
        }
        for never in [
            "IDEMPOTENCY_KEY_REUSED",
            "ADDRESS_MIXED",
            "RESOLUTION_FAILED",
            "RESOLUTION_TIMEOUT",
            "NETWORK_UNAVAILABLE",
            "ENVIRONMENT_BUSY",
            "ENVIRONMENT_UNAVAILABLE",
        ] {
            assert!(!preview.contains(&never), "{never}");
        }
    }
}
