//! Version 2 of the tool messages (M4c, ADR-0044): the eight filesystem tools
//! of the canonical inventory as one closed, typed sum.
//!
//! Version 1 (`messages.rs`, ADR-0043) is kept exactly — one tool, `fs.read`,
//! one canonical action. Version 2 differs in four ways, each of which would
//! change what a version-1 message means, which is why they are a new version
//! rather than new members:
//!
//! 1. **A call is exactly one of eight typed members** ([`ToolCall`]). There is
//!    no tool name and no argument map; a ninth member is an undeclared member
//!    and a protocol error.
//! 2. **A decision is a plan** ([`ToolPlan`]): every canonical action the call
//!    requires — a creating `fs.write` needs `fs.write` *and* `fs.create`, an
//!    `fs.move` needs `fs.delete` on its source *and* `fs.create` on its
//!    destination — each with both gates' decision. The call proceeds only if
//!    every action is permitted, and a preview shows all of them.
//! 3. **An invocation carries an idempotency key** (the envelope's), because
//!    `fs.move` and `fs.delete` are not retry-safe: a key names one invocation,
//!    is never performed twice, and is what M9's status query will answer by.
//! 4. **The reason vocabularies are wider** — new refusal and failure classes,
//!    and `OBLIGATION_UNENFORCEABLE` — in new enumerations, so that version 1's
//!    closed enumerations still mean what they meant.
//!
//! Like version 1, a request carries what the runtime proposes and nothing the
//! authority decides: no capability, no `cap_id`, no environment, no taint, no
//! existence claim.

use crate::limits::{MAX_LIST_ENTRIES, MAX_PATCH_EDITS, MAX_PLAN_ACTIONS, MAX_SEARCH_MATCHES};
use crate::wire::id::InvocationId;
use crate::wire::list::BoundedList;
use crate::wire::macros::wire_struct;
use crate::wire::scalar::{
    ActionEnvironment, ActionRole, ByteCount, ContentDigest, DecisionEffect, EntryCount, EntryKind,
    EntryName, FsDecisionReason, FsFailureReason, FsRefusalReason, FsTool, FsVerb, GateResult,
    HexContent, LinkCount, ListLimit, MatchLimit, Needle, ObjectState, PatchLength, PatchOutcome,
    RuleId, RuleSource, ScanLimit, StatKind, ToolOperation, WorkspacePath,
};

use super::messages::{FsReadCall, FsReadResult};

// ---------------------------------------------------------------------------
// Calls.
// ---------------------------------------------------------------------------

wire_struct! {
    /// An `fs.list`: the names in one directory, not recursively.
    FsListCall: reject {
        /// The directory, in the logical namespace.
        required path: WorkspacePath,
        /// The most entries to examine, in byte order of their names.
        required max_entries: ListLimit,
    }
}

wire_struct! {
    /// An `fs.search`: the offsets at which a literal byte string occurs in
    /// the first `max_scan_bytes` of one regular file.
    FsSearchCall: reject {
        /// The file, in the logical namespace.
        required path: WorkspacePath,
        /// The bytes to find.
        required needle: Needle,
        /// The most bytes to scan from the start of the file: the `max_bytes`
        /// of the `fs.read` the search requires.
        required max_scan_bytes: ScanLimit,
        /// The most offsets to return.
        required max_matches: MatchLimit,
    }
}

wire_struct! {
    /// An `fs.stat`: one object's kind, size and link count.
    FsStatCall: reject {
        /// The object, in the logical namespace.
        required path: WorkspacePath,
    }
}

wire_struct! {
    /// An `fs.write`: replace one regular file's content, or create it, with
    /// exactly these bytes — atomically.
    FsWriteCall: reject {
        /// The file, in the logical namespace. If it does not exist, its parent
        /// must, and the plan requires `fs.create` too.
        required path: WorkspacePath,
        /// The complete new content. Lossless bytes; at most
        /// `MAX_FS_WRITE_BYTES`.
        required content: HexContent,
    }
}

wire_struct! {
    /// A file revision, stated exactly: the SHA-256 of its whole content and
    /// its length. Objectively checkable; no timestamp, no version-control
    /// system, no claim the file cannot confirm.
    ContentRevision: reject {
        /// SHA-256 of the whole content.
        required sha256: ContentDigest,
        /// Its length in bytes.
        required length: PatchLength,
    }
}

wire_struct! {
    /// One edit of an `fs.patch`, against the **base** revision's bytes:
    /// remove `delete` bytes at `offset` and put `insert` in their place.
    PatchEdit: reject {
        /// Where, in the base revision.
        required offset: PatchLength,
        /// How many base bytes to remove.
        required delete: PatchLength,
        /// The bytes that replace them.
        required insert: HexContent,
    }
}

/// An `fs.patch`'s edits: in ascending, non-overlapping order of offset.
pub type PatchEdits = BoundedList<PatchEdit, MAX_PATCH_EDITS>;

wire_struct! {
    /// An `fs.patch`: transform one regular file from its base revision to its
    /// post revision by typed edits, atomically. **One file**: a multi-file
    /// patch would need a transaction a sequence of renames is not
    /// (ADR-0044 §7).
    ///
    /// If the file holds the base revision, the edits are applied and the
    /// result must be the post revision. If it already holds the post
    /// revision, nothing is done and the answer says so — which is what makes
    /// a retry safe. Anything else is a conflict, never a merge.
    FsPatchCall: reject {
        /// The file, in the logical namespace.
        required path: WorkspacePath,
        /// What the file must hold for the edits to apply.
        required base: ContentRevision,
        /// What it holds afterwards.
        required post: ContentRevision,
        /// The edits.
        required edits: PatchEdits,
    }
}

wire_struct! {
    /// An `fs.move`: rename one regular file to a name that does not exist,
    /// within the run's workspace. Never replaces; never copies.
    FsMoveCall: reject {
        /// The file's current name.
        required source: WorkspacePath,
        /// Its new name. Its parent must exist; the name itself must not.
        required destination: WorkspacePath,
    }
}

wire_struct! {
    /// An `fs.delete`: remove one regular file, or one empty directory.
    /// Never recursive.
    FsDeleteCall: reject {
        /// The object, in the logical namespace.
        required path: WorkspacePath,
    }
}

wire_struct! {
    /// A tool call: **exactly one** of the eight typed members. The payload of
    /// `direwolf.tool.invoke` and `direwolf.tool.preview` at version 2.
    ToolCall: reject {
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
    }
    exactly_one(fs_read, fs_list, fs_search, fs_stat, fs_write, fs_patch, fs_move, fs_delete)
}

// ---------------------------------------------------------------------------
// Plans.
// ---------------------------------------------------------------------------

wire_struct! {
    /// How the two gates of ADR-0006 decided one action of a plan.
    ActionDecision: reject {
        /// What was decided for this action.
        required effect: DecisionEffect,
        /// Why.
        required reason: FsDecisionReason,
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
    /// One canonical action a call requires: every fact policy decided on,
    /// stated by the authority. The capability it required is
    /// `<verb>:<canonical_path>?max_bytes=<byte_count>&no_symlink_targets=true`
    /// for `fs.read` and `fs.write`, and
    /// `<verb>:<canonical_path>?no_symlink_targets=true` for the others.
    PlannedAction: reject {
        /// What part it plays.
        required role: ActionRole,
        /// The capability verb it requires.
        required verb: FsVerb,
        /// The object's canonical path: resolved beneath the pinned root, or —
        /// for a vacant name — the checked parent's path and the validated
        /// name.
        required canonical_path: WorkspacePath,
        /// Whether the object existed when it was resolved.
        required object: ObjectState,
        /// The file-content bytes the action reads or writes, which is what
        /// policy's `max_bytes` bounds: the request's bound for a read or a
        /// scan, the content's length for a write, zero for metadata and names.
        required byte_count: ByteCount,
        /// Both gates' decision for this action.
        required decision: ActionDecision,
    }
}

/// A plan's actions, in the order they were decided.
pub type PlannedActions = BoundedList<PlannedAction, MAX_PLAN_ACTIONS>;

wire_struct! {
    /// The canonical plan a call resolves to: the tool, where it runs, the
    /// decision, and every action it requires. `effect` is `ALLOW` only if
    /// **every** action is allowed; one denied action denies the call and
    /// nothing is performed.
    ToolPlan: reject {
        /// The tool.
        required tool: FsTool,
        /// Where it runs.
        required environment: ActionEnvironment,
        /// The decision for the whole call.
        required effect: DecisionEffect,
        /// Every action the call requires.
        required actions: PlannedActions,
    }
}

// ---------------------------------------------------------------------------
// Results.
// ---------------------------------------------------------------------------

wire_struct! {
    /// One entry of a directory listing.
    FsListEntry: reject {
        /// Its name: one canonical path component.
        required name: EntryName,
        /// What the directory says it is. Not followed or opened.
        required kind: EntryKind,
    }
}

/// A listing's entries, in ascending byte order of their names.
pub type FsListEntries = BoundedList<FsListEntry, MAX_LIST_ENTRIES>;

wire_struct! {
    /// What an `fs.list` returned. The broker examined the first `max_entries`
    /// names in byte order; the addressable ones are listed, and the ones no
    /// canonical path can name — not UTF-8, not NFC, or holding a control,
    /// bidi or invisible-format character — are counted and never emitted.
    FsListResult: reject {
        /// The addressable entries, in ascending byte order.
        required entries: FsListEntries,
        /// How many of the examined entries could not be named.
        required unaddressable: EntryCount,
        /// Whether every entry of the directory was examined.
        required complete: bool,
    }
}

/// Where a needle was found, in ascending order.
pub type MatchOffsets = BoundedList<ByteCount, MAX_SEARCH_MATCHES>;

wire_struct! {
    /// What an `fs.search` returned: offsets, never content.
    FsSearchResult: reject {
        /// Every offset at which the needle starts and ends within the scanned
        /// bytes, overlapping occurrences included, up to `max_matches`.
        required offsets: MatchOffsets,
        /// How many bytes were scanned: at most `max_scan_bytes`, never more.
        required scanned: ByteCount,
        /// Whether the end of the file was observed within the scan.
        required eof_observed: bool,
        /// Whether more matches were found than were returned.
        required matches_truncated: bool,
    }
}

wire_struct! {
    /// What an `fs.stat` returned, from the checked object's own descriptor.
    FsStatResult: reject {
        /// What the object is.
        required kind: StatKind,
        /// `st_size`: a regular file's length; for a directory, the
        /// filesystem's size of the directory object, not of its contents.
        required size: ByteCount,
        /// `st_nlink`.
        required link_count: LinkCount,
        /// Whether a regular file has any execute bit. Always false for a
        /// directory.
        required executable: bool,
    }
}

wire_struct! {
    /// What an `fs.write` did.
    FsWriteResult: reject {
        /// Whether the file did not exist and was created.
        required created: bool,
        /// The new content's length.
        required length: ByteCount,
        /// The new content's SHA-256.
        required sha256: ContentDigest,
    }
}

wire_struct! {
    /// What an `fs.patch` did.
    FsPatchResult: reject {
        /// Whether it changed the file.
        required outcome: PatchOutcome,
        /// The file's revision now: the patch's post revision.
        required post: ContentRevision,
    }
}

wire_struct! {
    /// An `fs.move` completed: the source name no longer exists and the
    /// destination name binds the object that was checked.
    FsMoveResult: reject {}
}

wire_struct! {
    /// An `fs.delete` completed: the name no longer exists.
    FsDeleteResult: reject {}
}

wire_struct! {
    /// A tool's output: **exactly one** member, the call's own.
    ToolOutput: reject {
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
    }
    exactly_one(fs_read, fs_list, fs_search, fs_stat, fs_write, fs_patch, fs_move, fs_delete)
}

// ---------------------------------------------------------------------------
// Responses.
// ---------------------------------------------------------------------------

wire_struct! {
    /// An invocation every action of whose plan was allowed, which the broker
    /// performed on the objects that were checked, and which the authority
    /// recorded — in that order.
    ToolResultV2: reject {
        /// The authority's id for this invocation.
        required invocation_id: InvocationId,
        /// The plan that was decided and performed.
        required plan: ToolPlan,
        /// The tool's output.
        required output: ToolOutput,
    }
}

wire_struct! {
    /// Every object resolved and at least one action of the plan was refused.
    /// Nothing was opened for an effect, no broker was contacted and no
    /// invocation id was minted.
    ToolDenialV2: reject {
        /// The plan, with every action's decision.
        required plan: ToolPlan,
    }
}

wire_struct! {
    /// What an invocation would mean. Every object was resolved (never opened
    /// for an effect) and the gates ran on every action. Nothing was performed.
    CanonicalPreviewResultV2: reject {
        /// The plan `ToolInvoke` would decide on, with every action's decision.
        required plan: ToolPlan,
    }
}

/// Which refusal reasons each version-2 tool operation can produce. A preview
/// carries no idempotency key, so it cannot reuse one.
pub const TOOL_REFUSALS_V2: &[(&str, &[&str])] = &[
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
];

wire_struct! {
    /// A version-2 tool operation the authority would not attempt: its own
    /// state refused it, a path did not resolve, or the call is not one the
    /// tool can perform. Nothing was performed and no broker was contacted.
    ToolRefusalV2: reject {
        /// Which operation.
        required operation: ToolOperation,
        /// Why.
        required reason: FsRefusalReason,
    }
    paired(operation -> reason, TOOL_REFUSALS_V2)
}

wire_struct! {
    /// A version-2 invocation whose plan was allowed and whose intent was
    /// recorded, and which did not produce a result. The audit record holds
    /// the detail; the caller learns the class.
    ToolFailureV2: reject {
        /// The authority's id for the invocation.
        required invocation_id: InvocationId,
        /// Why.
        required reason: FsFailureReason,
    }
}

#[cfg(test)]
mod tests {
    use super::{TOOL_REFUSALS_V2, ToolCall, ToolOutput};
    use crate::json::{self, ParseOptions};
    use crate::wire::scalar::FsRefusalReason;
    use crate::wire::{Cx, WireType};

    fn decode_call(text: &str) -> Result<ToolCall, crate::ProtocolError> {
        let value = json::parse(text.as_bytes(), ParseOptions::dwkp()).unwrap_or_else(|e| {
            unreachable!("fixture parses: {e}");
        });
        ToolCall::decode(value, &mut Cx::new())
    }

    #[test]
    fn a_call_is_exactly_one_typed_member() {
        assert!(decode_call(r#"{"fs_stat":{"path":"/workspace/a"}}"#).is_ok());
        // None.
        assert!(decode_call("{}").is_err());
        // Two.
        assert!(
            decode_call(
                r#"{"fs_stat":{"path":"/workspace/a"},"fs_delete":{"path":"/workspace/a"}}"#
            )
            .is_err()
        );
        // A tool this build lacks is an undeclared member.
        assert!(decode_call(r#"{"fs_chmod":{"path":"/workspace/a"}}"#).is_err());
        // No tool-and-arguments shape.
        assert!(decode_call(r#"{"tool":"fs.stat","args":{"path":"/workspace/a"}}"#).is_err());
    }

    #[test]
    fn an_output_is_exactly_one_member_too() {
        let value = json::parse(b"{}", ParseOptions::dwkp()).unwrap_or_else(|e| {
            unreachable!("{e}");
        });
        assert!(ToolOutput::decode(value, &mut Cx::new()).is_err());
    }

    #[test]
    fn every_refusal_reason_is_reachable_from_an_invocation() {
        let invoke = TOOL_REFUSALS_V2
            .iter()
            .find(|(op, _)| *op == "TOOL_INVOKE")
            .map(|(_, reasons)| *reasons)
            .unwrap_or_default();
        for reason in FsRefusalReason::ALL {
            assert!(invoke.contains(&reason.as_str()), "{}", reason.as_str());
        }
        let preview = TOOL_REFUSALS_V2
            .iter()
            .find(|(op, _)| *op == "CANONICAL_PREVIEW")
            .map(|(_, reasons)| *reasons)
            .unwrap_or_default();
        assert!(!preview.contains(&"IDEMPOTENCY_KEY_REUSED"));
        assert_eq!(preview.len() + 1, invoke.len());
    }
}
