//! The canonical plan of a tool call (M4c, [ADR-0044] §4): every canonical
//! action the call requires, each decided by both gates, built once and used
//! by `CanonicalPreview` and `ToolInvoke` alike.
//!
//! # A tool name is not a capability verb
//!
//! What a call needs is derived here, from the call's type and what the
//! resolver found — never read from the request:
//!
//! | call | actions (role, verb, `byte_count`) |
//! |---|---|
//! | `fs.read` | TARGET `fs.read` (`max_bytes`) |
//! | `fs.search` | TARGET `fs.read` (`max_scan_bytes`) |
//! | `fs.stat` | TARGET `fs.stat` (0) |
//! | `fs.list` | TARGET `fs.list` (0) |
//! | `fs.write`, existing target | TARGET `fs.write` (content length) |
//! | `fs.write`, vacant target | TARGET `fs.write`, TARGET `fs.create` (content length each) |
//! | `fs.patch` | TARGET `fs.read` (base length), TARGET `fs.write` (post length) |
//! | `fs.move` | SOURCE `fs.delete` (0), DESTINATION `fs.create` (0) |
//! | `fs.delete` | TARGET `fs.delete` (0) |
//!
//! `byte_count` is the content the action moves through the broker: what it
//! reads, scans or writes. A name or metadata moves none. Each action's
//! required capability is `<verb>:<canonical path>`, constrained by
//! `no_symlink_targets=true` (true of every object the resolver returns: it
//! follows none) and — for an action that moves content — by
//! `max_bytes=<byte_count>`.
//!
//! # Every gate of every action, and all of them must allow
//!
//! Both gates run for every action, in plan order, without short-circuit, so
//! a denial shows every reason at once. The call proceeds only if **every**
//! action is permitted: a creating write whose `fs.write` is allowed and whose
//! `fs.create` is not creates nothing.
//!
//! # An obligation this build cannot enforce is not a permission
//!
//! A rule may allow with obligations (`POLICY.md` §2). The authority enforces
//! two, and only where they are satisfied by construction:
//! `read_only_workspace` on an action that changes nothing (`fs.read`,
//! `fs.list`, `fs.stat`), and `max_output_bytes=N` on an `fs.read` whose bound
//! is at most `N`. Any other obligation — `require_artifact_capture` above all,
//! which needs M8's artifact store — makes the action **denied**,
//! `OBLIGATION_UNENFORCEABLE`, attributed to the rule that imposed it. This
//! holds for both protocol versions: version 1 reports it as that rule's
//! denial, the way it reports `REQUIRE_APPROVAL`, because a runtime choosing
//! the older version must not be a way round a condition.
//!
//! [ADR-0044]: ../../../../../docs/adr/0044-m4c-filesystem-operations-plans-and-atomic-mutation.md

use dwk_proto::brokerp::patch_insert_bytes;
use dwk_proto::dwkp::fsops::{ContentRevision, PatchEdits, ToolCall};
use dwk_proto::limits::MAX_PATCH_INSERT_BYTES_TOTAL;
use dwk_proto::wire::scalar::{
    ActionRole, FsDecisionReason, FsRefusalReason, FsTool, FsVerb, ListLimit, MatchLimit, Needle,
    ObjectState, ReadLimit, ScanLimit,
};

use crate::capability::{
    Action, Capability, ConstraintSet, DeclaredPath, Namespace, NoSymlinkTargets, Scope, Verb,
};
use crate::policy::{CanonicalAction, Effect, Environment, Obligation};
use crate::resource::CanonicalPath;

use super::admission::Admission;
use super::error::AuthorityError;
use super::policy_state::ActiveAuthority;
use super::query::{self, DecisionRecord};

/// The protocol version a tool request arrived in, which is the version its
/// answer is given in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ToolVersion {
    /// `direwolf.tool.*` version 1 (M4b): `fs.read` only.
    V1,
    /// Version 2 (M4c): the eight filesystem tools.
    V2,
    /// Version 3 (M4d): the same eight, beside the process tools, in version
    /// 3's shapes. The filesystem semantics are version 2's.
    V3,
}

/// Whether running an invocation twice is the same as running it once
/// (RELIABILITY.md §1). Fixed per tool; never chosen by a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetryClass {
    /// Running it again converges on the same state: the read family, a whole-
    /// content `fs.write`, and an `fs.patch` whose post revision is recognised.
    RetrySafe,
    /// Running it again is a second effect: `fs.move` and `fs.delete`.
    NonRetryable,
}

impl RetryClass {
    /// The stored spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RetrySafe => "RETRY_SAFE",
            Self::NonRetryable => "NON_RETRYABLE",
        }
    }
}

/// A tool call, typed: exactly one of eight, its paths still only declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Call {
    /// Read at most `max_bytes` from the start of a regular file.
    Read {
        /// The file.
        path: DeclaredPath,
        /// The bound.
        max_bytes: ReadLimit,
    },
    /// List a directory.
    List {
        /// The directory.
        path: DeclaredPath,
        /// How many entries to examine.
        max_entries: ListLimit,
    },
    /// Find a literal byte string in a regular file.
    Search {
        /// The file.
        path: DeclaredPath,
        /// The bytes.
        needle: Needle,
        /// How much to scan.
        max_scan_bytes: ScanLimit,
        /// How many offsets to report.
        max_matches: MatchLimit,
    },
    /// Report a file's or directory's metadata.
    Stat {
        /// The object.
        path: DeclaredPath,
    },
    /// Replace or create a regular file's whole content.
    Write {
        /// The file.
        path: DeclaredPath,
        /// The content.
        content: Vec<u8>,
    },
    /// Transform a regular file from one revision to another.
    Patch {
        /// The file.
        path: DeclaredPath,
        /// What it must hold.
        base: ContentRevision,
        /// What it will hold.
        post: ContentRevision,
        /// The edits, against the base.
        edits: PatchEdits,
    },
    /// Rename a regular file to a vacant name.
    Move {
        /// The file.
        source: DeclaredPath,
        /// The vacant name.
        destination: DeclaredPath,
    },
    /// Remove a regular file or an empty directory.
    Delete {
        /// The object.
        path: DeclaredPath,
    },
}

impl Call {
    /// Type a wire call, refusing what no resolution could make sense of: a
    /// path that is not even a path, and a patch whose edits do not describe
    /// a transformation of its base into its post revision.
    ///
    /// # Errors
    ///
    /// `PATH_NOT_CANONICAL`, `PATCH_TOO_LARGE`, `PATCH_INCONSISTENT`.
    pub(super) fn from_wire(call: &ToolCall) -> Result<Self, FsRefusalReason> {
        let path = |text: &str| DeclaredPath::new(text).ok_or(FsRefusalReason::PathNotCanonical);
        let typed = if let Some(read) = &call.fs_read {
            Self::Read {
                path: path(read.path.as_str())?,
                max_bytes: read.max_bytes,
            }
        } else if let Some(list) = &call.fs_list {
            Self::List {
                path: path(list.path.as_str())?,
                max_entries: list.max_entries,
            }
        } else if let Some(search) = &call.fs_search {
            Self::Search {
                path: path(search.path.as_str())?,
                needle: search.needle.clone(),
                max_scan_bytes: search.max_scan_bytes,
                max_matches: search.max_matches,
            }
        } else if let Some(stat) = &call.fs_stat {
            Self::Stat {
                path: path(stat.path.as_str())?,
            }
        } else if let Some(write) = &call.fs_write {
            Self::Write {
                path: path(write.path.as_str())?,
                content: write.content.to_bytes(),
            }
        } else if let Some(patch) = &call.fs_patch {
            // Inline content is bounded by the frame it travels in (limits.rs):
            // refused before anything is resolved, decided or recorded.
            if patch_insert_bytes(&patch.edits) > MAX_PATCH_INSERT_BYTES_TOTAL {
                return Err(FsRefusalReason::PatchTooLarge);
            }
            if !patch_consistent(&patch.base, &patch.post, &patch.edits) {
                return Err(FsRefusalReason::PatchInconsistent);
            }
            Self::Patch {
                path: path(patch.path.as_str())?,
                base: patch.base.clone(),
                post: patch.post.clone(),
                edits: patch.edits.clone(),
            }
        } else if let Some(moved) = &call.fs_move {
            Self::Move {
                source: path(moved.source.as_str())?,
                destination: path(moved.destination.as_str())?,
            }
        } else if let Some(delete) = &call.fs_delete {
            Self::Delete {
                path: path(delete.path.as_str())?,
            }
        } else {
            // The decoder admits exactly one member; a call with none never
            // reaches here.
            return Err(FsRefusalReason::PathNotCanonical);
        };
        Ok(typed)
    }

    /// Which tool.
    pub(super) const fn tool(&self) -> FsTool {
        match self {
            Self::Read { .. } => FsTool::FsRead,
            Self::List { .. } => FsTool::FsList,
            Self::Search { .. } => FsTool::FsSearch,
            Self::Stat { .. } => FsTool::FsStat,
            Self::Write { .. } => FsTool::FsWrite,
            Self::Patch { .. } => FsTool::FsPatch,
            Self::Move { .. } => FsTool::FsMove,
            Self::Delete { .. } => FsTool::FsDelete,
        }
    }
}

/// The retry class of each tool: `fs.move` and `fs.delete` are not safe to
/// repeat; everything else converges.
pub(super) const fn retry_class(tool: FsTool) -> RetryClass {
    match tool {
        FsTool::FsMove | FsTool::FsDelete => RetryClass::NonRetryable,
        FsTool::FsRead
        | FsTool::FsList
        | FsTool::FsSearch
        | FsTool::FsStat
        | FsTool::FsWrite
        | FsTool::FsPatch => RetryClass::RetrySafe,
    }
}

/// Whether a tool changes the workspace. A tool that does not can end
/// `INTERRUPTED` but never `UNKNOWN`; one that does, the reverse.
pub(super) const fn has_effect(tool: FsTool) -> bool {
    matches!(
        tool,
        FsTool::FsWrite | FsTool::FsPatch | FsTool::FsMove | FsTool::FsDelete
    )
}

/// Whether a result of `tool` carries workspace content — bytes, names,
/// offsets, metadata — and so raises the run's taint. An acknowledgement of
/// a change does not (ADR-0044 §11).
pub(super) const fn taints(tool: FsTool) -> bool {
    !has_effect(tool)
}

/// Whether `edits` describe a transformation of `base` into `post`: at least
/// one edit; each edit changes something; offsets strictly ascending with no
/// edit overlapping the next; every edit within the base; and the lengths
/// adding up. A patch whose base and post revisions are the same revision
/// would make `APPLIED` and `ALREADY_APPLIED` indistinguishable, so it is
/// refused too. The broker still proves the result's digest; this proves only
/// what can be proved without the file.
pub(super) fn patch_consistent(
    base: &ContentRevision,
    post: &ContentRevision,
    edits: &PatchEdits,
) -> bool {
    if edits.is_empty() || base == post {
        return false;
    }
    let base_length = u64::from(base.length.get());
    let mut next_free: u64 = 0;
    let mut previous_offset: Option<u64> = None;
    let mut deleted: u64 = 0;
    let mut inserted: u64 = 0;
    for edit in edits {
        let offset = u64::from(edit.offset.get());
        let delete = u64::from(edit.delete.get());
        let insert = u64::try_from(edit.insert.to_bytes().len()).unwrap_or(u64::MAX);
        if delete == 0 && insert == 0 {
            return false;
        }
        if previous_offset.is_some_and(|previous| offset <= previous) || offset < next_free {
            return false;
        }
        let Some(end) = offset.checked_add(delete) else {
            return false;
        };
        if end > base_length {
            return false;
        }
        previous_offset = Some(offset);
        next_free = end;
        deleted = deleted.saturating_add(delete);
        inserted = inserted.saturating_add(insert);
    }
    base_length
        .checked_sub(deleted)
        .and_then(|kept| kept.checked_add(inserted))
        == Some(u64::from(post.length.get()))
}

/// One action of a plan, before the gates: what it does, to what.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ActionSpec {
    /// Its role in the call.
    pub(super) role: ActionRole,
    /// Its verb.
    pub(super) verb: FsVerb,
    /// The canonical path it acts on.
    pub(super) canonical: CanonicalPath,
    /// Whether that path names an object.
    pub(super) object: ObjectState,
    /// The content it moves.
    pub(super) byte_count: u64,
}

/// The canonical paths a call's targets resolved to, as the plan needs them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Resolved {
    /// One target, existing or vacant.
    One {
        /// Its canonical path.
        canonical: CanonicalPath,
        /// Whether an object is there.
        object: ObjectState,
    },
    /// A move's source (existing) and destination (vacant).
    Pair {
        /// The source.
        source: CanonicalPath,
        /// The destination.
        destination: CanonicalPath,
    },
}

/// The actions `call` requires, given what its targets resolved to. The one
/// derivation (the table in this module's documentation).
///
/// # Errors
///
/// [`AuthorityError::Invariant`] when the resolution does not fit the call —
/// a bug, never a request's doing.
pub(super) fn actions(call: &Call, resolved: &Resolved) -> Result<Vec<ActionSpec>, AuthorityError> {
    let mismatch = AuthorityError::Invariant("a resolution does not fit its call");
    match resolved {
        Resolved::Pair {
            source,
            destination,
        } => match call {
            Call::Move { .. } => Ok(vec![
                ActionSpec {
                    role: ActionRole::Source,
                    verb: FsVerb::FsDelete,
                    canonical: source.clone(),
                    object: ObjectState::Existing,
                    byte_count: 0,
                },
                ActionSpec {
                    role: ActionRole::Destination,
                    verb: FsVerb::FsCreate,
                    canonical: destination.clone(),
                    object: ObjectState::Vacant,
                    byte_count: 0,
                },
            ]),
            _ => Err(mismatch),
        },
        Resolved::One { canonical, object } => Ok(target_verbs(call, *object)
            .ok_or(mismatch)?
            .into_iter()
            .map(|(verb, byte_count)| ActionSpec {
                role: ActionRole::Target,
                verb,
                canonical: canonical.clone(),
                object: *object,
                byte_count,
            })
            .collect()),
    }
}

/// The verbs a call needs on its one target, each with the content it moves,
/// given whether an object is there — `None` for a combination resolution
/// never produces.
fn target_verbs(call: &Call, object: ObjectState) -> Option<Vec<(FsVerb, u64)>> {
    let length = |bytes: usize| u64::try_from(bytes).unwrap_or(u64::MAX);
    Some(match (call, object) {
        (Call::Read { max_bytes, .. }, ObjectState::Existing) => {
            vec![(FsVerb::FsRead, u64::from(max_bytes.get()))]
        }
        (Call::Search { max_scan_bytes, .. }, ObjectState::Existing) => {
            vec![(FsVerb::FsRead, u64::from(max_scan_bytes.get()))]
        }
        (Call::Stat { .. }, ObjectState::Existing) => vec![(FsVerb::FsStat, 0)],
        (Call::List { .. }, ObjectState::Existing) => vec![(FsVerb::FsList, 0)],
        (Call::Write { content, .. }, ObjectState::Existing) => {
            vec![(FsVerb::FsWrite, length(content.len()))]
        }
        (Call::Write { content, .. }, ObjectState::Vacant) => vec![
            (FsVerb::FsWrite, length(content.len())),
            (FsVerb::FsCreate, length(content.len())),
        ],
        (Call::Patch { base, post, .. }, ObjectState::Existing) => vec![
            (FsVerb::FsRead, u64::from(base.length.get())),
            (FsVerb::FsWrite, u64::from(post.length.get())),
        ],
        (Call::Delete { .. }, ObjectState::Existing) => vec![(FsVerb::FsDelete, 0)],
        _ => return None,
    })
}

/// The capability verb an action's verb is.
const fn verb_action(verb: FsVerb) -> Action {
    match verb {
        FsVerb::FsRead => Action::Read,
        FsVerb::FsList => Action::List,
        FsVerb::FsStat => Action::Stat,
        FsVerb::FsWrite => Action::Write,
        FsVerb::FsCreate => Action::Create,
        FsVerb::FsDelete => Action::Delete,
    }
}

/// Whether an action's verb moves content, and so carries `max_bytes`.
const fn moves_content(verb: FsVerb) -> bool {
    matches!(verb, FsVerb::FsRead | FsVerb::FsWrite | FsVerb::FsCreate)
}

/// The capability an action requires. The single derivation; nothing on the
/// wire states one.
///
/// # Errors
///
/// [`AuthorityError::Invariant`] if it does not assemble — a bug.
pub(super) fn required_capability(spec: &ActionSpec) -> Result<Capability, AuthorityError> {
    let verb = Verb::new(Namespace::Fs, verb_action(spec.verb))
        .ok_or(AuthorityError::Invariant("an fs action is not a verb"))?;
    let constraints = ConstraintSet {
        max_bytes: moves_content(spec.verb).then_some(spec.byte_count),
        no_symlink_targets: Some(NoSymlinkTargets),
        ..ConstraintSet::unconstrained()
    };
    Capability::new(verb, Scope::Path(spec.canonical.clone()), constraints)
        .map_err(|_| AuthorityError::Invariant("an fs capability does not assemble"))
}

/// Whether the authority enforces every obligation `record`'s decision
/// carries, for this action. Only meaningful for a decision that allows.
pub(super) fn obligations_enforced(spec: &ActionSpec, record: &DecisionRecord) -> bool {
    record
        .policy()
        .obligations()
        .as_slice()
        .iter()
        .all(|obligation| match obligation {
            Obligation::ReadOnlyWorkspace => {
                matches!(spec.verb, FsVerb::FsRead | FsVerb::FsList | FsVerb::FsStat)
            }
            Obligation::MaxOutputBytes(limit) => {
                spec.verb == FsVerb::FsRead && spec.byte_count <= *limit
            }
            Obligation::ForceEnvironment(_)
            | Obligation::RequireArtifactCapture
            | Obligation::RedactProfile(_)
            | Obligation::NetworkDeny
            | Obligation::AuditLevel(_)
            | Obligation::SingleUseOnly
            | Obligation::ForceQuarantinedRead
            | Obligation::WorkspaceExecHygiene => false,
        })
}

/// One action of a plan, decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedAction {
    spec: ActionSpec,
    action: CanonicalAction,
    record: DecisionRecord,
    obligations_enforced: bool,
}

impl PlannedAction {
    /// Its role in the call.
    #[must_use]
    pub const fn role(&self) -> ActionRole {
        self.spec.role
    }

    /// Its verb.
    #[must_use]
    pub const fn verb(&self) -> FsVerb {
        self.spec.verb
    }

    /// The canonical path it acts on.
    #[must_use]
    pub const fn canonical_path(&self) -> &CanonicalPath {
        &self.spec.canonical
    }

    /// Whether that path names an object.
    #[must_use]
    pub const fn object(&self) -> ObjectState {
        self.spec.object
    }

    /// The content it moves.
    #[must_use]
    pub const fn byte_count(&self) -> u64 {
        self.spec.byte_count
    }

    /// The canonical action policy decided on.
    #[must_use]
    pub const fn action(&self) -> &CanonicalAction {
        &self.action
    }

    /// Both gates' results.
    #[must_use]
    pub const fn record(&self) -> &DecisionRecord {
        &self.record
    }

    /// Whether the policy gate is satisfied: the rule allows, and every
    /// obligation it imposes is one this authority enforces.
    #[must_use]
    pub fn policy_satisfied(&self) -> bool {
        self.record.policy_satisfied() && self.obligations_enforced
    }

    /// Both gates.
    #[must_use]
    pub fn permits(&self) -> bool {
        self.record.capability_satisfied() && self.policy_satisfied()
    }

    /// Why it was decided as it was.
    #[must_use]
    pub fn reason(&self) -> FsDecisionReason {
        let policy = self.record.policy();
        if self.permits() {
            FsDecisionReason::AllowedByRule
        } else if policy.unevaluable().is_some() {
            FsDecisionReason::UnresolvedPolicyInput
        } else if policy.effect() == Effect::Allow && !self.obligations_enforced {
            FsDecisionReason::ObligationUnenforceable
        } else if policy.effect() == Effect::Allow {
            FsDecisionReason::NoCapability
        } else if policy.rule_id().is_default() {
            FsDecisionReason::DefaultDeny
        } else {
            FsDecisionReason::DeniedByRule
        }
    }
}

/// A call's complete canonical plan: every action, each decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolPlan {
    tool: FsTool,
    actions: Vec<PlannedAction>,
}

impl ToolPlan {
    /// The tool.
    #[must_use]
    pub const fn tool(&self) -> FsTool {
        self.tool
    }

    /// Its retry class.
    #[must_use]
    pub const fn retry_class(&self) -> RetryClass {
        retry_class(self.tool)
    }

    /// Every action, in plan order.
    #[must_use]
    pub fn actions(&self) -> &[PlannedAction] {
        &self.actions
    }

    /// Whether every action of the plan is permitted by both gates — the only
    /// condition under which anything is performed.
    #[must_use]
    pub fn permits(&self) -> bool {
        !self.actions.is_empty() && self.actions.iter().all(PlannedAction::permits)
    }

    /// The first action: the target, or a move's source.
    #[must_use]
    pub fn primary(&self) -> Option<&PlannedAction> {
        self.actions.first()
    }
}

/// Decide every action `call` requires, given what its targets resolved to.
/// Pure: reads the run's admission and policy context the caller loaded, and
/// changes nothing.
///
/// # Errors
///
/// [`AuthorityError::Invariant`] for a resolution that does not fit the call.
pub(super) fn decide(
    call: &Call,
    resolved: &Resolved,
    admission: &Admission,
    context: &crate::policy::PolicyContext,
    active: &ActiveAuthority,
) -> Result<ToolPlan, AuthorityError> {
    let mut actions = Vec::new();
    for spec in actions_for(call, resolved)? {
        let capability = required_capability(&spec)?;
        let action =
            CanonicalAction::new(capability, Environment::Host).with_byte_count(spec.byte_count);
        let record = query::decide(&action, admission, context, active);
        let obligations_enforced = obligations_enforced(&spec, &record);
        actions.push(PlannedAction {
            spec,
            action,
            record,
            obligations_enforced,
        });
    }
    Ok(ToolPlan {
        tool: call.tool(),
        actions,
    })
}

fn actions_for(call: &Call, resolved: &Resolved) -> Result<Vec<ActionSpec>, AuthorityError> {
    let specs = actions(call, resolved)?;
    if specs.is_empty() || specs.len() > dwk_proto::limits::MAX_PLAN_ACTIONS {
        return Err(AuthorityError::Invariant("a plan of no action or too many"));
    }
    Ok(specs)
}

#[cfg(test)]
mod tests {
    use dwk_proto::dwkp::fsops::{ContentRevision, PatchEdit, PatchEdits};
    use dwk_proto::wire::scalar::{ContentDigest, FsTool, HexContent, PatchLength};

    use super::{RetryClass, has_effect, patch_consistent, retry_class, taints};

    fn revision(fill: char, length: u32) -> ContentRevision {
        let (Some(sha256), Some(length)) = (
            ContentDigest::new(fill.to_string().repeat(64)),
            PatchLength::new(length),
        ) else {
            unreachable!("a revision")
        };
        ContentRevision { sha256, length }
    }

    fn edits(list: &[(u32, u32, &str)]) -> PatchEdits {
        let edits: Vec<PatchEdit> = list
            .iter()
            .filter_map(|(offset, delete, insert)| {
                Some(PatchEdit {
                    offset: PatchLength::new(*offset)?,
                    delete: PatchLength::new(*delete)?,
                    insert: HexContent::new(*insert)?,
                })
            })
            .collect();
        assert_eq!(edits.len(), list.len(), "every edit builds");
        let Some(edits) = PatchEdits::new(edits) else {
            unreachable!("within the bound")
        };
        edits
    }

    #[test]
    fn a_patch_must_describe_a_transformation_of_its_base_into_its_post_revision() {
        let base = revision('a', 10);
        // Replace 2 bytes at 1 with 3; delete 1 at 5; insert 1 at 10.
        let good = edits(&[(1, 2, "aabbcc"), (5, 1, ""), (10, 0, "dd")]);
        assert!(patch_consistent(&base, &revision('b', 11), &good));
        // The lengths do not add up.
        assert!(!patch_consistent(&base, &revision('b', 12), &good));
        // No edit, or an edit that changes nothing.
        assert!(!patch_consistent(&base, &revision('b', 10), &edits(&[])));
        assert!(!patch_consistent(
            &base,
            &revision('b', 10),
            &edits(&[(3, 0, "")])
        ));
        // Out of order, overlapping, two inserts at one offset.
        assert!(!patch_consistent(
            &base,
            &revision('b', 10),
            &edits(&[(5, 1, "aa"), (1, 1, "")])
        ));
        assert!(!patch_consistent(
            &base,
            &revision('b', 8),
            &edits(&[(1, 3, ""), (3, 1, "")])
        ));
        assert!(!patch_consistent(
            &base,
            &revision('b', 12),
            &edits(&[(4, 0, "aa"), (4, 0, "bb")])
        ));
        // Beyond the base.
        assert!(!patch_consistent(
            &base,
            &revision('b', 9),
            &edits(&[(10, 1, "")])
        ));
        // Adjacent edits are fine.
        assert!(patch_consistent(
            &base,
            &revision('b', 8),
            &edits(&[(1, 1, ""), (2, 1, "")])
        ));
        // Base and post the same revision: APPLIED and ALREADY_APPLIED could
        // not be told apart.
        assert!(!patch_consistent(
            &base,
            &revision('a', 10),
            &edits(&[(1, 1, "aa"), (2, 1, "")])
        ));
    }

    /// A consistent patch of a one-byte base that inserts `first` bytes at 0
    /// and `second` at 1.
    fn inserting(first: usize, second: usize) -> dwk_proto::dwkp::fsops::ToolCall {
        use dwk_proto::dwkp::fsops::{FsPatchCall, ToolCall};
        use dwk_proto::wire::scalar::WorkspacePath;
        let post = u32::try_from(1 + first + second).unwrap_or(0);
        let (Some(path), Some(a), Some(b)) = (
            WorkspacePath::new("/workspace/f"),
            HexContent::from_bytes(&vec![0x61; first]),
            HexContent::from_bytes(&vec![0x62; second]),
        ) else {
            unreachable!("the parts")
        };
        let (Some(zero), Some(one)) = (PatchLength::new(0), PatchLength::new(1)) else {
            unreachable!("lengths")
        };
        let Some(edits) = PatchEdits::new(vec![
            PatchEdit {
                offset: zero,
                delete: zero,
                insert: a,
            },
            PatchEdit {
                offset: one,
                delete: zero,
                insert: b,
            },
        ]) else {
            unreachable!("two edits")
        };
        ToolCall {
            fs_read: None,
            fs_list: None,
            fs_search: None,
            fs_stat: None,
            fs_write: None,
            fs_patch: Some(FsPatchCall {
                path,
                base: revision('a', 1),
                post: revision('b', post),
                edits,
            }),
            fs_move: None,
            fs_delete: None,
        }
    }

    #[test]
    fn a_patch_inserting_more_than_the_inline_bound_is_refused_before_anything_else() {
        use dwk_proto::limits::MAX_PATCH_INSERT_BYTES_TOTAL as MAX;
        use dwk_proto::wire::scalar::FsRefusalReason;
        // Exactly the bound: a patch.
        assert!(super::Call::from_wire(&inserting(MAX - 1, 1)).is_ok());
        // One byte more, split so that no single edit is over its own bound:
        // refused, whatever else is right or wrong with it.
        assert_eq!(
            super::Call::from_wire(&inserting(MAX, 1)).err(),
            Some(FsRefusalReason::PatchTooLarge)
        );
        let mut inconsistent = inserting(MAX, 1);
        if let Some(patch) = inconsistent.fs_patch.as_mut() {
            patch.post = revision('b', 3);
        }
        assert_eq!(
            super::Call::from_wire(&inconsistent).err(),
            Some(FsRefusalReason::PatchTooLarge),
            "the bound is checked first"
        );
    }

    #[test]
    fn the_retry_class_and_the_effect_are_fixed_per_tool() {
        for tool in FsTool::ALL {
            let effect = has_effect(*tool);
            assert_eq!(taints(*tool), !effect, "{tool:?}");
            let expected = if matches!(tool, FsTool::FsMove | FsTool::FsDelete) {
                RetryClass::NonRetryable
            } else {
                RetryClass::RetrySafe
            };
            assert_eq!(retry_class(*tool), expected, "{tool:?}");
        }
    }
}
