//! Version 6 of the tool messages (M5d.3, ADR-0052 §7): a sandboxed
//! `process.exec` may consume **one credential**, named by its handle.
//!
//! Versions 1 to 5 are kept exactly. Version 6 is version 5 with one optional
//! member added to `process_exec` -- `credential_handle`, the operator's name
//! for a secret the launched executable receives at spawn -- and a plan that
//! can say so. The kernel decides everything else: whether the handle may be
//! used at all (`secret.use:<handle>` through both gates, beside `process.exec`
//! on the image executable), by which consumer (the operator's metadata names
//! it, the image manifest pins its bytes), in which mode -- a descriptor
//! (`FD_AT_SPAWN`) before a variable (`ENV_AT_SPAWN`) -- and under which
//! variable. A call never names a mode, a variable, a descriptor, a value, a
//! length or an origin: each would be the runtime choosing how a secret is
//! exposed (ADR-0046 §15).
//!
//! A plan that consumes a credential states a second action, the
//! **spawn injection**: the handle, the mode the kernel chose, and both gates'
//! decision for `secret.use:<handle>` in the `SANDBOX` environment. Nothing
//! states the value, its length, its digest or the variable's name.
//!
//! A version-6 result, refusal and failure are version 5's: a
//! credential-bearing launch ends, fails and is refused as any other --
//! `CREDENTIAL_UNAVAILABLE` when the credential cannot be used here (not
//! configured, revoked, replaced, not allowed for this executable, no spawn
//! mode, a variable the environment reserves, or no execution environment to
//! deliver it in), `CREDENTIAL_FAILED` when it could not be read or delivered
//! before anything ran.

use crate::limits::MAX_PLAN_ACTIONS;
use crate::wire::id::InvocationId;
use crate::wire::list::BoundedList;
use crate::wire::macros::wire_struct;
use crate::wire::scalar::{ActionEnvironment, DecisionEffect, HostPath, WorkspacePath, wire_enum};

use super::fsops::{
    FsDeleteCall, FsListCall, FsMoveCall, FsPatchCall, FsSearchCall, FsStatCall, FsWriteCall,
    PlannedAction,
};
use super::messages::FsReadCall;
use super::netops::{
    CoreToolV4, CredentialHandle, NetHttpCall, PlannedInjectionAction, PlannedNetAction,
};
use super::procops::{
    PlannedProcessAction, ProcessActionDecision, ProcessArgs, ProcessKillCall, ProcessStatusCall,
};
use super::sandboxops::{ExecSeconds, ExecStreamLimit, PlannedWorkloadAction, ToolOutputV5};

wire_enum! {
    /// How a credential reaches a sandboxed launch, as the kernel chose it
    /// from the operator's metadata (ADR-0046 §15) -- never the call's.
    SpawnInjection {
        /// A one-shot pipe the launched process reads on descriptor 3. A
        /// process it starts may inherit that descriptor.
        FdAtSpawn = "FD_AT_SPAWN",
        /// A variable of the launched process's environment, named by the
        /// operator. A process it starts inherits it.
        EnvAtSpawn = "ENV_AT_SPAWN",
    }
}

// ---------------------------------------------------------------------------
// Calls.
// ---------------------------------------------------------------------------

wire_struct! {
    /// A `process.exec` at version 6: version 5's, and at most one
    /// credential the launched executable consumes.
    ProcessExecCallV6: reject {
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
        /// A credential the operator configured, by its handle: delivered
        /// to the executable at spawn, in a mode the kernel chooses, only in
        /// an execution environment and only if both gates allow
        /// `secret.use:<handle>`.
        optional credential_handle: CredentialHandle,
    }
}

wire_struct! {
    /// A tool call: **exactly one** of the twelve typed members. The payload
    /// of `direwolf.tool.invoke` and `direwolf.tool.preview` at version 6.
    ToolCallV6: reject {
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
        /// Launch one executable, where the kernel decides, with at most one
        /// credential.
        optional process_exec: ProcessExecCallV6,
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
    /// The injection action of a sandboxed launch that consumes a
    /// credential: `secret.use:<handle>`, environment `SANDBOX`, delivered to
    /// the plan's workload executable in the mode stated. The value is never
    /// stated, nor its length, nor the variable that would carry it.
    PlannedSpawnInjectionAction: reject {
        /// The handle.
        required handle: CredentialHandle,
        /// How it would reach the executable.
        required mode: SpawnInjection,
        /// Both gates' decision for `secret.use:<handle>`.
        required decision: ProcessActionDecision,
    }
}

wire_struct! {
    /// One action of a version-6 plan: exactly one of a filesystem action, a
    /// host process action, a sandboxed launch, a network action, a hop's
    /// injection and a launch's injection.
    PlannedActionV6: reject {
        /// A filesystem action.
        optional fs: PlannedAction,
        /// A host process action.
        optional process: PlannedProcessAction,
        /// A sandboxed launch.
        optional workload: PlannedWorkloadAction,
        /// A network action.
        optional net: PlannedNetAction,
        /// A credential's injection into a `net.http` hop.
        optional injection: PlannedInjectionAction,
        /// A credential's injection into a sandboxed launch.
        optional spawn_injection: PlannedSpawnInjectionAction,
    }
    exactly_one(fs, process, workload, net, injection, spawn_injection)
}

/// A version-6 plan's actions, in the order they were decided.
pub type PlannedActionsV6 = BoundedList<PlannedActionV6, MAX_PLAN_ACTIONS>;

wire_struct! {
    /// The canonical plan a version-6 call resolves to. `effect` is `ALLOW`
    /// only if **every** action is allowed: a launch that consumes a
    /// credential runs only if its workload action and its spawn injection
    /// are both allowed.
    ToolPlanV6: reject {
        /// The tool.
        required tool: CoreToolV4,
        /// Where it runs.
        required environment: ActionEnvironment,
        /// The decision for the whole call.
        required effect: DecisionEffect,
        /// Every action the call requires.
        required actions: PlannedActionsV6,
    }
}

// ---------------------------------------------------------------------------
// Responses.
// ---------------------------------------------------------------------------

wire_struct! {
    /// A version-6 invocation every action of whose plan was allowed, which
    /// the broker performed, and which the authority recorded. Its output is
    /// version 5's: a launch that consumed a credential has its output
    /// redacted of the value before this is answered.
    ToolResultV6: reject {
        /// The authority's id for this invocation.
        required invocation_id: InvocationId,
        /// The plan that was decided and performed.
        required plan: ToolPlanV6,
        /// The tool's output.
        required output: ToolOutputV5,
    }
}

wire_struct! {
    /// Every target resolved and at least one action of the plan was
    /// refused. Nothing was performed, no credential was read and no
    /// invocation was recorded.
    ToolDenialV6: reject {
        /// The plan, with every action's decision.
        required plan: ToolPlanV6,
    }
}

wire_struct! {
    /// What a version-6 invocation would mean. Nothing was performed: no
    /// broker, no launch, no environment touched, no credential read.
    CanonicalPreviewResultV6: reject {
        /// The plan `ToolInvoke` would decide on, with every action's decision.
        required plan: ToolPlanV6,
    }
}

#[cfg(test)]
mod tests {
    use super::{PlannedActionV6, ToolCallV6};
    use crate::json::{self, ParseOptions};
    use crate::wire::{Cx, WireType};

    fn decode_call(text: &str) -> Result<ToolCallV6, crate::ProtocolError> {
        let value = json::parse(text.as_bytes(), ParseOptions::dwkp()).unwrap_or_else(|e| {
            unreachable!("fixture parses: {e}");
        });
        ToolCallV6::decode(value, &mut Cx::new())
    }

    #[test]
    fn a_launch_names_at_most_a_credential_handle_and_never_how_it_is_delivered() {
        for ok in [
            r#"{"process_exec":{"executable":"/usr/bin/git","args":["status"]}}"#,
            r#"{"process_exec":{"executable":"/usr/bin/git","args":["fetch"],"credential_handle":"deploy-key"}}"#,
            r#"{"process_exec":{"executable":"/x","args":[],"timeout_seconds":30,"credential_handle":"a"}}"#,
        ] {
            assert!(decode_call(ok).is_ok(), "{ok}");
        }
        // A handle in its one grammar: never a value, a path or a list.
        for bad in [
            r#"{"process_exec":{"executable":"/x","args":[],"credential_handle":"Bearer x"}}"#,
            r#"{"process_exec":{"executable":"/x","args":[],"credential_handle":""}}"#,
            r#"{"process_exec":{"executable":"/x","args":[],"credential_handle":"Deploy"}}"#,
            r#"{"process_exec":{"executable":"/x","args":[],"credential_handle":["a","b"]}}"#,
            r#"{"process_exec":{"executable":"/x","args":[],"credential_handle":"/run/secret"}}"#,
        ] {
            assert!(decode_call(bad).is_err(), "{bad}");
        }
        // Nothing that chooses how a credential is exposed, or carries one.
        for extra in [
            r#""credential_mode":"ENV_AT_SPAWN""#,
            r#""injection":"FD_AT_SPAWN""#,
            r#""credential_env":"TOKEN""#,
            r#""env":{"TOKEN":"x"}"#,
            r#""credential_fd":3"#,
            r#""plaintext":"hunter2""#,
            r#""secret":"hunter2""#,
            r#""stdin":"hunter2""#,
            r#""credentials":["a"]"#,
            r#""environment":"HOST""#,
        ] {
            let text = format!(
                r#"{{"process_exec":{{"executable":"/x","args":[],"credential_handle":"a",{extra}}}}}"#
            );
            assert!(decode_call(&text).is_err(), "{extra}");
        }
        // A credential is a launch's: no other tool of version 6 gains one.
        assert!(
            decode_call(
                r#"{"fs_read":{"path":"/workspace/a","max_bytes":1,"credential_handle":"a"}}"#
            )
            .is_err()
        );
    }

    #[test]
    fn a_spawn_injection_states_a_handle_a_mode_and_a_decision_and_nothing_more() {
        let decision = r#""decision":{"effect":"DENY","reason":"NO_CAPABILITY","capability_result":"NOT_SATISFIED","policy_result":"SATISFIED","rule_id":"allow","rule_source":"policy/a.toml:12"}"#;
        let action = |extra: &str| {
            format!(
                r#"{{"spawn_injection":{{"handle":"deploy-key","mode":"FD_AT_SPAWN",{decision}{extra}}}}}"#
            )
        };
        let decode = |text: &str| {
            json::parse(text.as_bytes(), ParseOptions::dwkp())
                .map_err(|_| ())
                .and_then(|v| PlannedActionV6::decode(v, &mut Cx::new()).map_err(|_| ()))
        };
        assert!(decode(&action("")).is_ok());
        for extra in [
            r#","value":"hunter2""#,
            r#","length":7"#,
            r#","env_name":"TOKEN""#,
            r#","sha256":"00""#,
        ] {
            assert!(decode(&action(extra)).is_err(), "{extra}");
        }
        assert!(
            decode(&action("").replace("FD_AT_SPAWN", "EGRESS")).is_err(),
            "mode A is never a spawn's"
        );
        assert!(
            decode(&action("").replace("FD_AT_SPAWN", "PLAINTEXT_TO_MODEL")).is_err(),
            "mode D is never a mode"
        );
    }
}
