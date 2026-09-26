//! Version 3 of the tool messages (M4d, ADR-0045): the eight filesystem tools
//! of version 2 and the three process tools — `process.exec`,
//! `process.status`, `process.kill` — as one closed, typed sum.
//!
//! Versions 1 and 2 (`messages.rs`, `fsops.rs`) are kept exactly. Version 3
//! is a new version rather than new members of version 2 because a process
//! call changes what a plan is: its action names an **executable identity**
//! (a canonical host path and the SHA-256 of the file found there), not a
//! workspace path, and its decision has reasons a filesystem action cannot
//! have (`HOST_EXECUTION_DISABLED`, `APPROVAL_REQUIRED`). A version-2 decoder
//! never sees a process call: to it, `process_exec` is an undeclared member.
//!
//! Like the earlier versions, a request carries what the runtime proposes and
//! nothing the authority decides: no capability, no executable digest, no
//! `argv[0]` (the authority derives it), no environment, no argv
//! classification, no raw process id. A process is named by the opaque
//! [`ProcessId`] its launch returned, within the run that launched it.

use crate::limits::{MAX_PLAN_ACTIONS, MAX_PROCESS_ARGS};
use crate::wire::id::{InvocationId, ProcessId};
use crate::wire::list::BoundedList;
use crate::wire::macros::wire_struct;
use crate::wire::scalar::{
    ActionEnvironment, ActionRole, ArgCount, ArgvSafetyClass, ByteCount, ContentDigest, CoreTool,
    DecisionEffect, ExitCode, GateResult, HostPath, KillOutcome, ProcessArg, ProcessDecisionReason,
    ProcessState, ProcessVerb, RuleId, RuleSource, SignalNumber, StreamContent,
    ToolFailureReasonV3, ToolOperation, ToolRefusalReasonV3, WorkspacePath,
};

use super::fsops::{
    FsDeleteCall, FsDeleteResult, FsListCall, FsListResult, FsMoveCall, FsMoveResult, FsPatchCall,
    FsPatchResult, FsSearchCall, FsSearchResult, FsStatCall, FsStatResult, FsWriteCall,
    FsWriteResult, PlannedAction,
};
use super::messages::{FsReadCall, FsReadResult};

// ---------------------------------------------------------------------------
// Calls.
// ---------------------------------------------------------------------------

/// A launch's arguments, after `argv[0]`.
pub type ProcessArgs = BoundedList<ProcessArg, MAX_PROCESS_ARGS>;

wire_struct! {
    /// A `process.exec`: launch one native executable with these arguments.
    ///
    /// The request names the executable by an absolute host path. The
    /// authority resolves it — following a bounded chain of symlinks to the
    /// final object — hashes the file it opened, and decides on that identity;
    /// `argv[0]` is the canonical path it resolved to, never a runtime choice
    /// (ADR-0045 §§4, 7).
    ProcessExecCall: reject {
        /// The executable, as an absolute host path.
        required executable: HostPath,
        /// The arguments after `argv[0]`, each passed as exactly its bytes.
        required args: ProcessArgs,
        /// The working directory, in the logical workspace namespace. The
        /// workspace root when absent.
        optional cwd: WorkspacePath,
    }
}

wire_struct! {
    /// A `process.status`: the state and retained output of one process this
    /// run launched.
    ProcessStatusCall: reject {
        /// The handle its launch returned.
        required process_id: ProcessId,
    }
}

wire_struct! {
    /// A `process.kill`: end one process this run launched.
    ProcessKillCall: reject {
        /// The handle its launch returned.
        required process_id: ProcessId,
    }
}

wire_struct! {
    /// A tool call: **exactly one** of the eleven typed members. The payload
    /// of `direwolf.tool.invoke` and `direwolf.tool.preview` at version 3.
    ToolCallV3: reject {
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
    }
    exactly_one(
        fs_read, fs_list, fs_search, fs_stat, fs_write, fs_patch, fs_move, fs_delete,
        process_exec, process_status, process_kill
    )
}

// ---------------------------------------------------------------------------
// Plans.
// ---------------------------------------------------------------------------

wire_struct! {
    /// An executable's authority identity: where it resolved to, and what was
    /// there. Two builds of the same program at the same path are two
    /// identities.
    ExecutableRef: reject {
        /// The canonical host path of the final object: every symlink on the
        /// way resolved, no symlink left on it.
        required path: HostPath,
        /// The SHA-256 of the file's whole content, from the descriptor the
        /// authority opened and hashed.
        required sha256: ContentDigest,
    }
}

wire_struct! {
    /// How the gates decided one process action.
    ProcessActionDecision: reject {
        /// What was decided.
        required effect: DecisionEffect,
        /// Why.
        required reason: ProcessDecisionReason,
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
    /// One canonical process action: every fact policy decided on, stated by
    /// the authority. The capability it required is
    /// `<verb>:<executable path>@<sha256>` — with
    /// `?argv_allowlist=<first argument>` for a launch whose first argument is
    /// an allowlist token.
    PlannedProcessAction: reject {
        /// What part it plays: always `TARGET`.
        required role: ActionRole,
        /// The capability verb it requires.
        required verb: ProcessVerb,
        /// The executable identity it is about: for a launch, the one
        /// resolved and hashed now; for a status or a kill, the one the process
        /// was launched as.
        required executable: ExecutableRef,
        /// The process, for a status or a kill.
        optional process_id: ProcessId,
        /// The working directory's canonical path, for a launch.
        optional cwd: WorkspacePath,
        /// How many arguments follow `argv[0]`, for a launch.
        optional arg_count: ArgCount,
        /// The SHA-256 of the canonical argv — `argv[0]` and every argument —
        /// for a launch: what an approval will bind (ADR-0045 §7).
        optional argv_sha256: ContentDigest,
        /// The kernel's classification of the arguments, for a launch.
        optional argv_safety: ArgvSafetyClass,
        /// Both gates' decision for this action.
        required decision: ProcessActionDecision,
    }
}

wire_struct! {
    /// One action of a version-3 plan: exactly one of a filesystem action (as
    /// version 2 states it) and a process action.
    PlannedActionV3: reject {
        /// A filesystem action.
        optional fs: PlannedAction,
        /// A process action.
        optional process: PlannedProcessAction,
    }
    exactly_one(fs, process)
}

/// A version-3 plan's actions, in the order they were decided.
pub type PlannedActionsV3 = BoundedList<PlannedActionV3, MAX_PLAN_ACTIONS>;

wire_struct! {
    /// The canonical plan a version-3 call resolves to. `effect` is `ALLOW`
    /// only if **every** action is allowed. A process action's environment is
    /// `HOST`: until M5 there is no other place a process could run.
    ToolPlanV3: reject {
        /// The tool.
        required tool: CoreTool,
        /// Where it runs.
        required environment: ActionEnvironment,
        /// The decision for the whole call.
        required effect: DecisionEffect,
        /// Every action the call requires.
        required actions: PlannedActionsV3,
    }
}

// ---------------------------------------------------------------------------
// Results.
// ---------------------------------------------------------------------------

wire_struct! {
    /// What a `process.exec` did: the target executable replaced the broker's
    /// launch helper — `execve` succeeded — and the broker supervises it.
    ProcessExecResult: reject {
        /// The handle for `process.status` and `process.kill`.
        required process_id: ProcessId,
        /// What it was when the launch was confirmed.
        required state: ProcessState,
        /// Its exit code, if it had already exited.
        optional exit_code: ExitCode,
        /// The signal that ended it, if one already had.
        optional signal: SignalNumber,
    }
}

wire_struct! {
    /// One output stream, as the broker retained it: its **first** bytes, in
    /// order, and how many it saw.
    ProcessStreamSnapshot: reject {
        /// The retained bytes: at most the launch's per-stream bound, and never
        /// more than [`crate::limits::MAX_PROCESS_STREAM_BYTES`].
        required content: StreamContent,
        /// Every byte the process wrote to the stream so far, retained or not.
        required observed: ByteCount,
        /// Whether more was written than was retained.
        required truncated: bool,
    }
}

wire_struct! {
    /// What a `process.status` observed.
    ProcessStatusResult: reject {
        /// The process.
        required process_id: ProcessId,
        /// Its state.
        required state: ProcessState,
        /// Its exit code, when it exited.
        optional exit_code: ExitCode,
        /// The signal that ended it, when one did.
        optional signal: SignalNumber,
        /// Whether the broker ended it at its wall-clock bound.
        required timed_out: bool,
        /// Its standard output so far.
        required stdout: ProcessStreamSnapshot,
        /// Its standard error so far.
        required stderr: ProcessStreamSnapshot,
    }
}

wire_struct! {
    /// What a `process.kill` did.
    ProcessKillResult: reject {
        /// The process.
        required process_id: ProcessId,
        /// Whether a signal was sent.
        required outcome: KillOutcome,
    }
}

wire_struct! {
    /// A version-3 tool's output: **exactly one** member, the call's own.
    ToolOutputV3: reject {
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
    }
    exactly_one(
        fs_read, fs_list, fs_search, fs_stat, fs_write, fs_patch, fs_move, fs_delete,
        process_exec, process_status, process_kill
    )
}

// ---------------------------------------------------------------------------
// Responses.
// ---------------------------------------------------------------------------

wire_struct! {
    /// A version-3 invocation every action of whose plan was allowed, which
    /// the broker performed, and which the authority recorded — in that order.
    ToolResultV3: reject {
        /// The authority's id for this invocation.
        required invocation_id: InvocationId,
        /// The plan that was decided and performed.
        required plan: ToolPlanV3,
        /// The tool's output.
        required output: ToolOutputV3,
    }
}

wire_struct! {
    /// Every target resolved and at least one action of the plan was refused.
    /// Nothing was opened for an effect, no broker was contacted and no
    /// invocation id was minted.
    ToolDenialV3: reject {
        /// The plan, with every action's decision.
        required plan: ToolPlanV3,
    }
}

wire_struct! {
    /// What a version-3 invocation would mean. Nothing was performed: no
    /// broker, no launch, no handle.
    CanonicalPreviewResultV3: reject {
        /// The plan `ToolInvoke` would decide on, with every action's decision.
        required plan: ToolPlanV3,
    }
}

/// Which refusal reasons each version-3 tool operation can produce. A preview
/// carries no idempotency key, so it cannot reuse one.
pub const TOOL_REFUSALS_V3: &[(&str, &[&str])] = &[
    ("TOOL_INVOKE", INVOKE_REFUSALS),
    ("CANONICAL_PREVIEW", PREVIEW_REFUSALS),
];

const INVOKE_REFUSALS: &[&str] = &[
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
];

const PREVIEW_REFUSALS: &[&str] = &[
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
];

wire_struct! {
    /// A version-3 tool operation the authority would not attempt. Nothing was
    /// performed and no broker was contacted.
    ToolRefusalV3: reject {
        /// Which operation.
        required operation: ToolOperation,
        /// Why.
        required reason: ToolRefusalReasonV3,
    }
    paired(operation -> reason, TOOL_REFUSALS_V3)
}

wire_struct! {
    /// A version-3 invocation whose plan was allowed and whose intent was
    /// recorded, and which did not produce a result. The audit record holds
    /// the detail; the caller learns the class.
    ToolFailureV3: reject {
        /// The authority's id for the invocation.
        required invocation_id: InvocationId,
        /// Why.
        required reason: ToolFailureReasonV3,
    }
}

#[cfg(test)]
mod tests {
    use super::{TOOL_REFUSALS_V3, ToolCallV3, ToolOutputV3};
    use crate::json::{self, ParseOptions};
    use crate::wire::scalar::ToolRefusalReasonV3;
    use crate::wire::{Cx, WireType};

    fn decode_call(text: &str) -> Result<ToolCallV3, crate::ProtocolError> {
        let value = json::parse(text.as_bytes(), ParseOptions::dwkp()).unwrap_or_else(|e| {
            unreachable!("fixture parses: {e}");
        });
        ToolCallV3::decode(value, &mut Cx::new())
    }

    #[test]
    fn a_process_call_is_one_typed_member_and_argv_is_an_array() {
        assert!(
            decode_call(r#"{"process_exec":{"executable":"/usr/bin/git","args":["status"]}}"#)
                .is_ok()
        );
        assert!(
            decode_call(
                r#"{"process_exec":{"executable":"/usr/bin/git","args":[],"cwd":"/workspace/src"}}"#
            )
            .is_ok()
        );
        // A command string is not argv.
        assert!(
            decode_call(r#"{"process_exec":{"executable":"/usr/bin/git","args":"status"}}"#)
                .is_err()
        );
        // No shell member, no argv[0], no environment, no digest from the runtime.
        for extra in [
            r#""argv0":"git""#,
            r#""env":{"A":"B"}"#,
            r#""sha256":"00""#,
            r#""shell":true"#,
        ] {
            let text =
                format!(r#"{{"process_exec":{{"executable":"/usr/bin/git","args":[],{extra}}}}}"#);
            assert!(decode_call(&text).is_err(), "{extra}");
        }
        // A NUL inside an argument is not representable.
        assert!(
            decode_call(r#"{"process_exec":{"executable":"/usr/bin/git","args":["a\u0000b"]}}"#)
                .is_err()
        );
        // A raw pid is not a process id.
        assert!(decode_call(r#"{"process_kill":{"process_id":"1234"}}"#).is_err());
        assert!(decode_call(r#"{"process_status":{"pid":1234}}"#).is_err());
        // Two members, or a tool this build lacks.
        assert!(
            decode_call(r#"{"process_exec":{"executable":"/bin/x","args":[]},"fs_stat":{"path":"/workspace"}}"#)
                .is_err()
        );
        assert!(decode_call(r#"{"process_spawn":{"executable":"/bin/x"}}"#).is_err());
    }

    #[test]
    fn an_output_is_exactly_one_member() {
        let value = json::parse(b"{}", ParseOptions::dwkp()).unwrap_or_else(|e| {
            unreachable!("{e}");
        });
        assert!(ToolOutputV3::decode(value, &mut Cx::new()).is_err());
    }

    #[test]
    fn every_refusal_reason_is_reachable_from_an_invocation() {
        let invoke = TOOL_REFUSALS_V3
            .iter()
            .find(|(op, _)| *op == "TOOL_INVOKE")
            .map(|(_, reasons)| *reasons)
            .unwrap_or_default();
        for reason in ToolRefusalReasonV3::ALL {
            assert!(invoke.contains(&reason.as_str()), "{}", reason.as_str());
        }
        let preview = TOOL_REFUSALS_V3
            .iter()
            .find(|(op, _)| *op == "CANONICAL_PREVIEW")
            .map(|(_, reasons)| *reasons)
            .unwrap_or_default();
        assert!(!preview.contains(&"IDEMPOTENCY_KEY_REUSED"));
        assert_eq!(preview.len() + 1, invoke.len());
    }
}
