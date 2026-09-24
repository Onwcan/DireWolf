//! `AdmitRun` and `ReleaseRun`: minting a run's authority, durably, exactly
//! once per admission attempt.
//!
//! # The contract ([ADR-0036] §8 as amended by [ADR-0040]), in the order it is decided
//!
//! 1. **The fence.** Lease, holder, epoch and expiry are checked first. A
//!    stale caller gets `STALE_EPOCH` whatever idempotency key it presents: a
//!    zombie holding a valid old key is precisely the caller fencing stops,
//!    and a key is never a way past the fence.
//! 2. **The record**, scoped by `(authenticated subject, session_id,
//!    idempotency_key)` — a primary key, so SQLite enforces the scope. None:
//!    admit, mint, persist everything in one transaction, commit, flush the
//!    audit record, and only then answer.
//! 3. **The digest.** Different: `IDEMPOTENCY_CONFLICT`, whatever state the
//!    recorded run is in, and the original admission is untouched.
//! 4. **The run.** Same digest, and the recorded run is `ACTIVE` under the
//!    epoch the caller holds now: **same-response replay** — the recorded
//!    grant, with the same run id, epoch, policy revision, profile, cap ids,
//!    capabilities and withheld list. No policy is re-read, nothing is
//!    re-minted, no row is written except the audit record of the replay.
//! 5. **Otherwise the run has ended** — released, or reaped because the lease
//!    it was admitted under was rotated, expired or invalidated by a restart:
//!    `ADMISSION_ENDED`. The key is spent for ever, and the run is never
//!    active again. A `RunGrant` is never returned for a run the caller cannot
//!    use now.
//!
//! A different subject is a different scope, so another subject's key finds
//! nothing and collides with nothing.
//!
//! Three properties are kept apart. **Duplicate suppression** — one key, at
//! most one admission — holds permanently. **Same-response replay** holds
//! within the tenure that admitted the run, while it is active. **Run
//! resumption** is not provided: a run's authority ends with its lease, and
//! resuming means a new admission under a new key (M9 owns checkpoints).
//!
//! The bound request is the RFC 8785 encoding of the **decoded** `AdmitRun`
//! with exactly `id`, `ts`, `correlation_id`, `causation_id` and `epoch`
//! removed, so `schema_version`, `session_id`, `idempotency_key` and the whole
//! payload are bound. The epoch is not a property of *what* was asked but of
//! the tenure asking, and the tenure is enforced by steps 1 and 4 instead. Its
//! digest is domain-separated SHA-256 (`direwolf.dwkp.admit_run.request.v2`).
//!
//! # Retention
//!
//! **Idempotency records are never garbage-collected in M3d.** ADR-0036 left
//! the dedupe window to evidence, and there is none yet. A finite window
//! reopens duplicate admission for any retry slower than it; keeping records
//! costs storage, which is recoverable, while a duplicate admission mints
//! authority, which is not. A retention policy is future work that needs
//! measurement, and it must never delete the record of an admission that is
//! still live.
//!
//! # Minting
//!
//! Every requested capability is either granted **exactly as requested** —
//! canonicalised, never widened, never narrowed into something the runtime did
//! not ask for — or withheld with the first term of the minting expression
//! that does not cover it ([`CAPABILITIES.md`] §4):
//!
//! ```text
//! granted(r)  iff  r is resolvable            -- else UNRESOLVED_RESOURCE
//!             ∧   profile.declared  covers r   -- else NOT_IN_AGENT_PROFILE
//!             ∧   ∀ active skill s: s covers r -- else NOT_IN_SKILL_SET
//!             ∧   mode ceiling      covers r   -- else ABOVE_PROFILE_CEILING
//! ```
//!
//! **A concrete `fs.read` path means what the filesystem says it means**
//! (M4b, [ADR-0043] §8). Every one any term names — the request, the profile,
//! every active skill, the ceiling — is resolved by the production M4a
//! resolver beneath the session's pinned workspace root, **outside any
//! transaction**, and becomes comparable only through the resolver's answer.
//! So an admission that names one runs in passes: the first decides everything
//! up to minting, writes nothing, and returns the paths; they are resolved;
//! the second decides again from the start — the fence, the record, the
//! profile, the skills — and mints from those answers, provided they were
//! resolved beneath the binding in force and cover every path it now names.
//! A path that did not resolve (missing, a symlink, a magic link, a mount, a
//! normalisation ambiguity, a replaced root, no workspace) covers nothing and
//! is granted to no one; a request for it is withheld `UNRESOLVED_RESOURCE`.
//! `fs.read:*` names no object and needs no resolution. A replay is answered
//! from the record before any path is looked at, so it never resolves or
//! mints again.
//!
//! "Covers" is M3b's `CapabilitySet::covers`: **one** member of the term must
//! contain `r` whole, so no grant is ever assembled from fragments of two
//! declarations. The parent term is absent: `AdmitRun` has no parent field,
//! every M3 admission is a root, and subagent spawning is M14's.
//!
//! **Policy is not consulted.** A capability is authority to *attempt* a class
//! of action; policy decides a specific action, and `AdmitRun` carries no
//! action to decide. There is therefore no policy preflight, and
//! `DENIED_BY_POLICY` is never produced: fabricating an action to make policy
//! evaluate would be a decision about something nobody asked to do.
//!
//! # Active skills cannot be used to widen
//!
//! [ADR-0028]'s finding: a runtime that names *no* skills maximises an
//! intersection over skills. So the active set is **the profile's baseline
//! skills, always, plus** whatever the runtime names. Omitting a skill cannot
//! remove a baseline one; naming one can only add a term, and a term only
//! narrows. A named skill the kernel does not hold — or holds as
//! `QUARANTINED` — contributes the **empty** set, so everything is withheld
//! `NOT_IN_SKILL_SET`: an unknown constraint is never read as no constraint.
//!
//! [ADR-0028]: ../../../../../docs/adr/0028-policy-input-ownership.md
//! [ADR-0036]: ../../../../../docs/adr/0036-m3-authority-operations-and-the-capability-wire-form.md
//! [ADR-0043]: ../../../../../docs/adr/0043-m4b-private-broker-channel-and-brokered-fs-read.md
//! [ADR-0040]: ../../../../../docs/adr/0040-m3d-reconciliation-admission-across-tenures-and-undecidable-proposals.md
//! [`CAPABILITIES.md`]: ../../../../../docs/CAPABILITIES.md

use core::fmt;

use dwk_proto::dwkp::messages::AdmitRun;
use dwk_proto::dwkp::{DwkpBody, DwkpMessage};
use dwk_proto::json::{self, Value};
use dwk_proto::wire::id::{CapId, RunId, SessionId};
use dwk_proto::wire::scalar::{
    CapabilityText, Epoch, RefusalReason, RefusedOperation, WithheldReason,
};
use rusqlite::OptionalExtension as _;

use std::collections::BTreeMap;

use crate::capability::{
    self, Capability, CapabilitySet, CapabilitySpec, DeclaredPath, PrivacyClass, UnresolvedScope,
};
use crate::policy::{Origin, TaintLevel};

use super::Mode;
use super::audit::{AuditEvent, Field, Fields};
use super::config::{self, RootBinding, SkillRecord};
use super::digest::{self, DomainHash, Sha256Hash};
use super::error::AuthorityError;
use super::identity::CallerContext;
use super::lease::{self, to_sql};
use super::policy_state::ActiveAuthority;
use super::scopes::{self, Resolutions, Unresolved, VacantScope};
use super::{Reply, Work};

/// Why a requested capability was not granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WithheldCause {
    /// No member of the agent profile's declared set covers it — including a
    /// capability outside the kernel's vocabulary, which no profile can
    /// declare.
    NotInAgentProfile,
    /// An active skill's declared set does not cover it.
    NotInSkillSet,
    /// The parent run's effective set does not cover it. Never produced in
    /// M3d: every admission is a root.
    NotInParentGrant,
    /// The mode ceiling does not cover it.
    AboveProfileCeiling,
    /// It names an `fs` or `process` resource with no authority identity: an
    /// `fs.read` path the M4a resolver did not resolve beneath the session's
    /// root, or a verb M4b does not resolve at all. On the wire:
    /// `UNRESOLVED_RESOURCE` (ADR-0040). Stored with the scope that could not
    /// be resolved.
    NeedsCanonicalization(UnresolvedScope),
}

impl WithheldCause {
    /// The stored code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotInAgentProfile => "NOT_IN_AGENT_PROFILE",
            Self::NotInSkillSet => "NOT_IN_SKILL_SET",
            Self::NotInParentGrant => "NOT_IN_PARENT_GRANT",
            Self::AboveProfileCeiling => "ABOVE_PROFILE_CEILING",
            Self::NeedsCanonicalization(UnresolvedScope::CanonicalPath) => "NEEDS_CANONICAL_PATH",
            Self::NeedsCanonicalization(UnresolvedScope::ExecutableIdentity) => {
                "NEEDS_EXECUTABLE_IDENTITY"
            }
        }
    }

    fn from_code(code: &str) -> Option<Self> {
        [
            Self::NotInAgentProfile,
            Self::NotInSkillSet,
            Self::NotInParentGrant,
            Self::AboveProfileCeiling,
            Self::NeedsCanonicalization(UnresolvedScope::CanonicalPath),
            Self::NeedsCanonicalization(UnresolvedScope::ExecutableIdentity),
        ]
        .into_iter()
        .find(|cause| cause.code() == code)
    }

    /// The wire reason. Total: every cause has a truthful one (ADR-0040).
    #[must_use]
    pub const fn to_wire(self) -> WithheldReason {
        match self {
            Self::NotInAgentProfile => WithheldReason::NotInAgentProfile,
            Self::NotInSkillSet => WithheldReason::NotInSkillSet,
            Self::NotInParentGrant => WithheldReason::NotInParentGrant,
            Self::AboveProfileCeiling => WithheldReason::AboveProfileCeiling,
            Self::NeedsCanonicalization(_) => WithheldReason::UnresolvedResource,
        }
    }
}

impl fmt::Display for WithheldCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// One capability the kernel granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    cap_id: CapId,
    capability: Capability,
}

impl Grant {
    /// The kernel's id for this grant.
    #[must_use]
    pub const fn cap_id(&self) -> &CapId {
        &self.cap_id
    }

    /// What was granted.
    #[must_use]
    pub const fn capability(&self) -> &Capability {
        &self.capability
    }
}

/// One capability that was requested and withheld.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Withheld {
    requested: CapabilityText,
    cause: WithheldCause,
}

impl Withheld {
    /// The capability, as requested.
    #[must_use]
    pub const fn requested(&self) -> &CapabilityText {
        &self.requested
    }

    /// Why it was withheld.
    #[must_use]
    pub const fn cause(&self) -> WithheldCause {
        self.cause
    }
}

/// The logical `RunGrant`: what one admission minted.
///
/// A record of the past, not a live token. Whether its grants are *effective*
/// is a question for the run's current state — a released run's admission
/// still reads back identically, and authorises nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission {
    run_id: RunId,
    session_id: SessionId,
    epoch: Epoch,
    policy_revision: Sha256Hash,
    mode: Mode,
    granted: Vec<Grant>,
    withheld: Vec<Withheld>,
}

impl Admission {
    /// The run.
    #[must_use]
    pub const fn run_id(&self) -> &RunId {
        &self.run_id
    }

    /// The session it was admitted in.
    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// The epoch it is fenced to.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// The policy revision in force when it was minted.
    #[must_use]
    pub const fn policy_revision(&self) -> &Sha256Hash {
        &self.policy_revision
    }

    /// The mode ceiling it was admitted under.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.mode
    }

    /// What it holds.
    #[must_use]
    pub fn granted(&self) -> &[Grant] {
        &self.granted
    }

    /// What it asked for and did not get.
    #[must_use]
    pub fn withheld(&self) -> &[Withheld] {
        &self.withheld
    }

    /// The granted capabilities as a set, for coverage.
    #[must_use]
    pub fn capabilities(&self) -> CapabilitySet {
        self.granted.iter().map(|g| g.capability.clone()).collect()
    }
}

/// The digest an `AdmitRun`'s idempotency key is bound to.
///
/// # Errors
///
/// [`AuthorityError::Invariant`] if the message does not re-encode, which a
/// decoded message always does.
pub fn request_digest(message: &DwkpMessage) -> Result<Sha256Hash, AuthorityError> {
    let Ok(Value::Object(mut bound)) = message.to_value() else {
        return Err(AuthorityError::Invariant(
            "a decoded request did not re-encode as an object",
        ));
    };
    // `epoch` is the caller's tenure, not what it asked for: the fence and the
    // replay rule enforce it (ADR-0040 part 1).
    for unbound in ["id", "ts", "correlation_id", "causation_id", "epoch"] {
        bound.remove(unbound);
    }
    let canonical = json::to_canonical_bytes(&Value::Object(bound));
    Ok(DomainHash::new(digest::ADMIT_REQUEST)
        .bytes(&canonical)
        .finish())
}

fn grant_digest(admission: &Admission) -> Sha256Hash {
    let mut hash = DomainHash::new(digest::RUN_GRANT)
        .text(admission.run_id.as_str())
        .text(admission.session_id.as_str())
        .int(admission.epoch.get())
        .text(&admission.policy_revision.to_hex())
        .text(admission.mode.as_str())
        .int(u64::try_from(admission.granted.len()).unwrap_or(u64::MAX));
    for grant in &admission.granted {
        hash = hash
            .text(grant.cap_id.as_str())
            .text(&grant.capability.to_canonical_string());
    }
    hash = hash.int(u64::try_from(admission.withheld.len()).unwrap_or(u64::MAX));
    for withheld in &admission.withheld {
        hash = hash
            .text(withheld.requested.as_str())
            .text(withheld.cause.code());
    }
    hash.finish()
}

/// The members of a declaration that are comparable for this admission: a
/// concrete `fs.read` member only through the resolver's answer for its path;
/// other `fs` verbs and `process` not at all. A member that is not comparable
/// covers nothing — which never widens anything, because a request that is
/// not comparable is withheld before any term is consulted.
fn resolvable(specs: &[CapabilitySpec], resolutions: &Resolutions) -> CapabilitySet {
    specs
        .iter()
        .filter_map(|spec| scopes::declared(spec, resolutions).ok())
        .collect()
}

/// One active skill, and where it came from.
struct ActiveSkill {
    name: String,
    origin: &'static str,
    record: Option<SkillRecord>,
}

impl ActiveSkill {
    /// The declaration this skill contributes, if it contributes one.
    fn declaration(&self) -> Option<&[CapabilitySpec]> {
        match &self.record {
            Some(record) if record.trust.contributes_declaration() => Some(&record.declared),
            _ => None,
        }
    }

    /// What this skill contributes to the intersection. An unknown or
    /// quarantined skill contributes nothing, which withholds everything.
    fn term(&self, resolutions: &Resolutions) -> CapabilitySet {
        self.declaration()
            .map_or_else(CapabilitySet::empty, |declared| {
                resolvable(declared, resolutions)
            })
    }
}

/// The minting decision for one requested capability.
fn mint_one(
    requested: &CapabilityText,
    resolutions: &Resolutions,
    profile: &CapabilitySet,
    skills: &[CapabilitySet],
    ceiling: &CapabilitySet,
) -> Result<Capability, WithheldCause> {
    let Ok(spec) = capability::parse(requested.as_str()) else {
        return Err(WithheldCause::NotInAgentProfile);
    };
    let wanted =
        scopes::declared(&spec, resolutions).map_err(WithheldCause::NeedsCanonicalization)?;
    if !profile.covers(&wanted) {
        return Err(WithheldCause::NotInAgentProfile);
    }
    if skills.iter().any(|skill| !skill.covers(&wanted)) {
        return Err(WithheldCause::NotInSkillSet);
    }
    if !ceiling.covers(&wanted) {
        return Err(WithheldCause::AboveProfileCeiling);
    }
    Ok(wanted)
}

fn refuse(
    work: &mut Work<'_>,
    attempt: &Attempt<'_>,
    reason: RefusalReason,
    extra: Fields,
) -> Result<Reply<Admission>, AuthorityError> {
    let mut fields = lease::refusal_fields(
        attempt.caller,
        RefusedOperation::AdmitRun,
        reason,
        attempt.session,
        Some(attempt.epoch),
    );
    fields.extend(extra);
    work.audit(AuditEvent::RunAdmitRefused, fields)?;
    Ok(Reply::Refused(reason))
}

/// The envelope facts one `AdmitRun` is decided on.
struct Attempt<'m> {
    caller: &'m CallerContext,
    session: &'m SessionId,
    epoch: Epoch,
    key: &'m str,
    digest: Sha256Hash,
    agent_profile: &'m str,
}

/// The run's kernel-derived policy inputs.
struct Inputs {
    origin: Origin,
    taint: TaintLevel,
    privacy: PrivacyClass,
    workspace: Option<(String, super::config::WorkspaceSensitivity)>,
}

/// The most passes one admission makes: the first finds the paths, the second
/// normally mints, and a third absorbs a configuration change between them.
/// The last pass never asks to resolve: a path it has no current answer for
/// covers nothing.
pub(super) const PASSES: usize = 3;

/// What one pass of `AdmitRun` produced.
#[derive(Debug)]
pub(super) enum Pass {
    /// The answer: refused, replayed or admitted — recorded.
    Answered(Reply<Admission>),
    /// Nothing was written: these concrete filesystem paths must first be
    /// resolved beneath `binding`, with no transaction open.
    Resolve {
        /// The session's workspace root binding.
        binding: RootBinding,
        /// Every concrete filesystem path the admission's terms name, and
        /// whether any declaration naming it may name a vacant one.
        paths: Vec<(DeclaredPath, VacantScope)>,
    },
}

/// The concrete filesystem paths an admission names, and what the resolver
/// said about each: the input to minting, and to its audit record.
struct FsTerms {
    paths: Vec<DeclaredPath>,
    resolutions: Resolutions,
}

/// `AdmitRun`: one pass. `resolved` is what the previous pass's paths
/// resolved to; `last` is whether this pass must answer.
pub(super) fn admit(
    work: &mut Work<'_>,
    caller: &CallerContext,
    message: &DwkpMessage,
    active: &ActiveAuthority,
    resolved: Option<&Resolutions>,
    last: bool,
) -> Result<Pass, AuthorityError> {
    let DwkpBody::AdmitRun(request) = &message.body else {
        return Err(AuthorityError::NotAnAuthorityRequest);
    };
    let header = &message.header;
    let (Some(session), Some(epoch), Some(key)) =
        (&header.session_id, header.epoch, &header.idempotency_key)
    else {
        return Err(AuthorityError::Invariant(
            "an AdmitRun decoded without its required envelope fields",
        ));
    };
    let attempt = Attempt {
        caller,
        session,
        epoch,
        key: key.as_str(),
        digest: request_digest(message)?,
        agent_profile: request.agent_profile.as_str(),
    };

    // 1. The fence. Nothing else is looked at first -- not even the key.
    if !lease::fence(work, caller, session, epoch)? {
        return refuse(work, &attempt, RefusalReason::StaleEpoch, Fields::new())
            .map(Pass::Answered);
    }

    // 2. Only now, the idempotency record, under this subject's scope. A
    //    replay is answered here: nothing below runs, nothing is resolved.
    if let Some(reply) = recorded(work, &attempt)? {
        return Ok(Pass::Answered(reply));
    }

    // 3. The profile, from the kernel's own record.
    let Some(profile) = config::current_profile(work.tx, attempt.agent_profile)? else {
        return refuse(
            work,
            &attempt,
            RefusalReason::UnknownAgentProfile,
            Fields::new().text("agent_profile", attempt.agent_profile),
        )
        .map(Pass::Answered);
    };

    // 4. The active skills: the baseline, always; then what was named.
    let skills = active_skills(work, &profile, request)?;

    // 5. Every concrete fs.read path any term names, with the M4a resolver's
    //    answer for it -- or, first, a pass that asks for them.
    let probes = concrete_paths(request, &profile, &skills, active);
    let paths: Vec<DeclaredPath> = probes.iter().map(|(path, _)| path.clone()).collect();
    let Some(resolutions) = fs_resolutions(work, session, &paths, resolved, last)? else {
        let Some(binding) = session_root(work, session)? else {
            return Err(AuthorityError::Invariant(
                "a pass asked to resolve with no root to resolve beneath",
            ));
        };
        return Ok(Pass::Resolve {
            binding,
            paths: probes,
        });
    };
    let fs = FsTerms { paths, resolutions };

    // 6. Mint.
    let (granted, withheld) = mint_all(request, &profile, &skills, active, &fs.resolutions);

    // 7. The run's policy inputs, derived here and nowhere else.
    let inputs = derive_inputs(work, &profile, session)?;

    // 8. Identities, rows, the record, and the audit.
    let admission = persist(
        work, &attempt, &profile, &skills, granted, withheld, &inputs, active, &fs,
    )?;
    Ok(Pass::Answered(Reply::Done(admission)))
}

/// Every concrete filesystem path the request, the profile, the contributing
/// skills and the mode ceiling name, once each, in order — each with whether
/// any declaration naming it is for a verb that may name a vacant path
/// (`fs.write`, `fs.create`). Only such a path is probed for vacancy; one
/// named only by verbs that act on what exists is resolved as M4b resolved
/// it, and a missing object is `NOT_FOUND`.
fn concrete_paths(
    request: &AdmitRun,
    profile: &config::ProfileRecord,
    skills: &[ActiveSkill],
    active: &ActiveAuthority,
) -> Vec<(DeclaredPath, VacantScope)> {
    let requested: Vec<CapabilitySpec> = request
        .requested_capabilities
        .iter()
        .filter_map(|text| capability::parse(text.as_str()).ok())
        .collect();
    let declared = skills.iter().filter_map(ActiveSkill::declaration).flatten();
    let mut paths: BTreeMap<DeclaredPath, VacantScope> = BTreeMap::new();
    for spec in requested
        .iter()
        .chain(&profile.declared)
        .chain(declared)
        .chain(&active.ceiling)
    {
        if let (Some(path), Some(vacant)) =
            (scopes::concrete_path(spec), scopes::scope_rule(spec.verb()))
        {
            let entry = paths.entry(path.clone()).or_insert(vacant);
            if vacant == VacantScope::Accepted {
                *entry = VacantScope::Accepted;
            }
        }
    }
    paths.into_iter().collect()
}

/// The session's workspace root binding, if it has one.
fn session_root(
    work: &Work<'_>,
    session: &SessionId,
) -> Result<Option<RootBinding>, AuthorityError> {
    match config::session_workspace(work.tx, session.as_str())? {
        Some((workspace, _)) => config::workspace_root(work.tx, &workspace),
        None => Ok(None),
    }
}

/// The resolver's answers for `paths`, or `None` when they must first be
/// resolved (never on the last pass). Answers are used only if they were
/// resolved beneath the binding in force now and cover every path named now.
fn fs_resolutions(
    work: &Work<'_>,
    session: &SessionId,
    paths: &[DeclaredPath],
    resolved: Option<&Resolutions>,
    last: bool,
) -> Result<Option<Resolutions>, AuthorityError> {
    if paths.is_empty() {
        return Ok(Some(Resolutions::empty()));
    }
    let Some((workspace, _)) = config::session_workspace(work.tx, session.as_str())? else {
        return Ok(Some(Resolutions::unavailable(
            paths,
            &Unresolved::NoWorkspace,
        )));
    };
    let Some(binding) = config::workspace_root(work.tx, &workspace)? else {
        return Ok(Some(Resolutions::unavailable(
            paths,
            &Unresolved::NoWorkspaceRoot,
        )));
    };
    Ok(match resolved {
        Some(answers) if answers.binding() == Some(&binding) && (last || answers.covers(paths)) => {
            // On the last pass a path without an answer is `NOT_ATTEMPTED`.
            Some(answers.clone())
        }
        _ if last => Some(Resolutions::unavailable(paths, &Unresolved::NotAttempted)),
        _ => None,
    })
}

/// Steps 3–5 of the contract, or `None` for a first admission.
fn recorded(
    work: &mut Work<'_>,
    attempt: &Attempt<'_>,
) -> Result<Option<Reply<Admission>>, AuthorityError> {
    let subject = attempt.caller.subject().storage_key();
    let recorded: Option<(String, String, String)> = work.db(work
        .tx
        .query_row(
            "SELECT request_digest, run_id, grant_digest FROM admission_idempotency \
                 WHERE subject = ?1 AND session_id = ?2 AND idempotency_key = ?3",
            rusqlite::params![subject, attempt.session.as_str(), attempt.key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional())?;
    let Some((stored_digest, run, stored_grant)) = recorded else {
        return Ok(None);
    };
    if stored_digest != attempt.digest.to_hex() {
        return refuse(
            work,
            attempt,
            RefusalReason::IdempotencyConflict,
            Fields::new().text("original_run_id", run),
        )
        .map(Some);
    }
    let (state, run_epoch): (String, i64) = work
        .db(work
            .tx
            .query_row(
                "SELECT state, epoch FROM run WHERE run_id = ?1",
                [&run],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional())?
        .ok_or(AuthorityError::Invariant(
            "an idempotency record names a run that does not exist",
        ))?;
    let current = run_epoch == to_sql(attempt.epoch.get())?;
    if state != "ACTIVE" {
        // Released, or reaped when its lease ended. The key is spent; the run
        // is never replayed as if it were usable (ADR-0040 part 1).
        return refuse(
            work,
            attempt,
            RefusalReason::AdmissionEnded,
            Fields::new()
                .text("original_run_id", run)
                .text("original_run_state", state),
        )
        .map(Some);
    }
    if !current {
        // A lease change reaps every run admitted under the old epoch in the
        // same transaction, so an active run under another epoch is a store
        // that contradicts itself.
        return Err(AuthorityError::Invariant(
            "an active run is recorded under an epoch that is not current",
        ));
    }
    let admission = load(work, &run)?;
    if grant_digest(&admission).to_hex() != stored_grant {
        return Err(AuthorityError::Invariant(
            "a recorded admission no longer matches the grant recorded for it",
        ));
    }
    work.audit(
        AuditEvent::RunAdmitReplayed,
        Fields::new()
            .text("subject", subject)
            .text("holder", attempt.caller.holder().to_string())
            .text("session_id", attempt.session.as_str())
            .int("epoch", attempt.epoch.get())
            .text("run_id", run)
            .text("request_digest", attempt.digest.to_hex()),
    )?;
    Ok(Some(Reply::Done(admission)))
}

fn active_skills(
    work: &Work<'_>,
    profile: &config::ProfileRecord,
    request: &AdmitRun,
) -> Result<Vec<ActiveSkill>, AuthorityError> {
    let mut skills: Vec<ActiveSkill> = Vec::new();
    let named = request
        .skills
        .iter()
        .map(|s| (s.as_str().to_owned(), "REQUESTED"));
    for (name, origin) in profile
        .baseline
        .iter()
        .map(|s| (s.clone(), "BASELINE"))
        .chain(named)
    {
        if skills.iter().any(|skill| skill.name == name) {
            continue;
        }
        let record = config::current_skill(work.tx, &name)?;
        skills.push(ActiveSkill {
            name,
            origin,
            record,
        });
    }
    Ok(skills)
}

fn mint_all(
    request: &AdmitRun,
    profile: &config::ProfileRecord,
    skills: &[ActiveSkill],
    active: &ActiveAuthority,
    resolutions: &Resolutions,
) -> (Vec<Capability>, Vec<Withheld>) {
    let skill_terms: Vec<CapabilitySet> =
        skills.iter().map(|skill| skill.term(resolutions)).collect();
    let profile_term = resolvable(&profile.declared, resolutions);
    let ceiling = resolvable(&active.ceiling, resolutions);
    let mut granted: Vec<Capability> = Vec::new();
    let mut withheld: Vec<Withheld> = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    for requested in &request.requested_capabilities {
        if seen.contains(&requested.as_str()) {
            continue;
        }
        seen.push(requested.as_str());
        match mint_one(
            requested,
            resolutions,
            &profile_term,
            &skill_terms,
            &ceiling,
        ) {
            Ok(capability) => {
                if !granted.contains(&capability) {
                    granted.push(capability);
                }
            }
            Err(cause) => withheld.push(Withheld {
                requested: requested.clone(),
                cause,
            }),
        }
    }
    (granted, withheld)
}

fn derive_inputs(
    work: &Work<'_>,
    profile: &config::ProfileRecord,
    session: &SessionId,
) -> Result<Inputs, AuthorityError> {
    let workspace = config::session_workspace(work.tx, session.as_str())?;
    // A session with no kernel-recorded workspace has an unknown sensitivity,
    // and unknown is read as the strictest.
    let ceiling = workspace
        .as_ref()
        .map_or(PrivacyClass::LocalOnly, |(_, sensitivity)| {
            sensitivity.privacy_ceiling()
        });
    Ok(Inputs {
        // The only admission path is DWKP from a programmatic peer, and no
        // approval channel exists: every M3d run is `api`, which every
        // shipped pack treats as unattended.
        origin: Origin::Api,
        // The kernel has delivered nothing to a run it is only now admitting.
        taint: TaintLevel::None,
        privacy: core::cmp::min(profile.privacy_default, ceiling),
        workspace,
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "each argument is a separate, already-derived part of the admission"
)]
fn persist(
    work: &mut Work<'_>,
    attempt: &Attempt<'_>,
    profile: &config::ProfileRecord,
    skills: &[ActiveSkill],
    granted: Vec<Capability>,
    withheld: Vec<Withheld>,
    inputs: &Inputs,
    active: &ActiveAuthority,
    fs: &FsTerms,
) -> Result<Admission, AuthorityError> {
    let subject = attempt.caller.subject().storage_key();
    let run_id = work.run_id()?;
    work.db(work.tx.execute(
        "INSERT INTO run (run_id, session_id, subject, epoch, agent_profile, \
         agent_profile_revision, activation_id, state, admitted_ms, ended_ms) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'ACTIVE', ?8, NULL)",
        rusqlite::params![
            run_id.as_str(),
            attempt.session.as_str(),
            subject,
            to_sql(attempt.epoch.get())?,
            attempt.agent_profile,
            profile.revision,
            active.activation_id,
            to_sql(work.now)?,
        ],
    ))?;
    insert_skills(work, &run_id, skills)?;
    let mut grants = Vec::with_capacity(granted.len());
    for (ordinal, capability) in granted.into_iter().enumerate() {
        let cap_id = work.cap_id()?;
        work.db(work.tx.execute(
            "INSERT INTO run_grant (cap_id, run_id, ordinal, capability) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                cap_id.as_str(),
                run_id.as_str(),
                ordinal_sql(ordinal),
                capability.to_canonical_string()
            ],
        ))?;
        grants.push(Grant { cap_id, capability });
    }
    insert_side_rows(work, &run_id, &withheld, inputs)?;

    let admission = Admission {
        run_id,
        session_id: attempt.session.clone(),
        epoch: attempt.epoch,
        policy_revision: active.revision,
        mode: active.mode,
        granted: grants,
        withheld,
    };
    let recorded_grant = grant_digest(&admission);
    work.db(work.tx.execute(
        "INSERT INTO admission_idempotency (subject, session_id, idempotency_key, request_digest, \
         run_id, grant_digest, recorded_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            subject,
            attempt.session.as_str(),
            attempt.key,
            attempt.digest.to_hex(),
            admission.run_id.as_str(),
            recorded_grant.to_hex(),
            to_sql(work.now)?,
        ],
    ))?;
    let mut fields = admitted_fields(
        attempt,
        profile,
        skills,
        inputs,
        active,
        &admission,
        &recorded_grant,
    );
    fields.extend(fs_path_fields(fs));
    work.audit(AuditEvent::RunAdmitted, fields)?;
    Ok(admission)
}

/// The run's active-skill rows.
fn insert_skills(
    work: &Work<'_>,
    run_id: &RunId,
    skills: &[ActiveSkill],
) -> Result<(), AuthorityError> {
    for (ordinal, skill) in skills.iter().enumerate() {
        work.db(work.tx.execute(
            "INSERT INTO run_skill (run_id, ordinal, skill, origin, skill_revision, trust) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                run_id.as_str(),
                ordinal_sql(ordinal),
                skill.name,
                skill.origin,
                skill.record.as_ref().map(|r| r.revision),
                skill.record.as_ref().map(|r| r.trust.as_str()),
            ],
        ))?;
    }
    Ok(())
}

/// The run's withheld requests and its policy inputs.
fn insert_side_rows(
    work: &Work<'_>,
    run_id: &RunId,
    withheld: &[Withheld],
    inputs: &Inputs,
) -> Result<(), AuthorityError> {
    for (ordinal, entry) in withheld.iter().enumerate() {
        work.db(work.tx.execute(
            "INSERT INTO run_withheld (run_id, ordinal, capability, reason) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                run_id.as_str(),
                ordinal_sql(ordinal),
                entry.requested.as_str(),
                entry.cause.code()
            ],
        ))?;
    }
    work.db(work.tx.execute(
        "INSERT INTO run_policy_input (run_id, origin, taint, privacy, workspace_id, \
         workspace_sensitivity) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            run_id.as_str(),
            inputs.origin.as_str(),
            taint_rank(inputs.taint),
            inputs.privacy.as_str(),
            inputs.workspace.as_ref().map(|(id, _)| id.clone()),
            inputs.workspace.as_ref().map(|(_, s)| s.rank()),
        ],
    ))?;

    Ok(())
}

fn admitted_fields(
    attempt: &Attempt<'_>,
    profile: &config::ProfileRecord,
    skills: &[ActiveSkill],
    inputs: &Inputs,
    active: &ActiveAuthority,
    admission: &Admission,
    recorded_grant: &Sha256Hash,
) -> Fields {
    let skill = |skill: &ActiveSkill| {
        Field::Object(vec![
            ("name", Field::Text(skill.name.clone())),
            ("origin", Field::Text(skill.origin.to_owned())),
            (
                "trust",
                Field::Text(
                    skill
                        .record
                        .as_ref()
                        .map_or_else(|| "UNKNOWN".to_owned(), |r| r.trust.as_str().to_owned()),
                ),
            ),
        ])
    };
    let grant = |grant: &Grant| {
        Field::Object(vec![
            ("cap_id", Field::Text(grant.cap_id.as_str().to_owned())),
            (
                "capability",
                Field::Text(grant.capability.to_canonical_string()),
            ),
        ])
    };
    let withheld = |entry: &Withheld| {
        Field::Object(vec![
            (
                "capability",
                Field::Text(entry.requested.as_str().to_owned()),
            ),
            ("reason", Field::Text(entry.cause.code().to_owned())),
        ])
    };
    Fields::new()
        .text("subject", attempt.caller.subject().storage_key())
        .text("holder", attempt.caller.holder().to_string())
        .text("session_id", attempt.session.as_str())
        .int("epoch", attempt.epoch.get())
        .text("run_id", admission.run_id.as_str())
        .text("agent_profile", attempt.agent_profile)
        .int(
            "agent_profile_revision",
            u64::try_from(profile.revision).unwrap_or(0),
        )
        .int(
            "activation_id",
            u64::try_from(active.activation_id).unwrap_or(0),
        )
        .text("policy_revision", active.revision.to_hex())
        .text("mode", active.mode.as_str())
        .text("request_digest", attempt.digest.to_hex())
        .text("grant_digest", recorded_grant.to_hex())
        .list("skills", skills.iter().map(skill).collect())
        .list("granted", admission.granted.iter().map(grant).collect())
        .list(
            "withheld",
            admission.withheld.iter().map(withheld).collect(),
        )
        .text("origin", inputs.origin.as_str())
        .text("taint", inputs.taint.as_str())
        .text("privacy", inputs.privacy.as_str())
        .maybe_text(
            "workspace_id",
            inputs.workspace.as_ref().map(|(id, _)| id.clone()),
        )
}

/// The most resolved paths one admission's audit record lists; the totals
/// count them all.
const MAX_AUDITED_PATHS: usize = 32;

/// What the resolver said about each concrete `fs.read` path, for the audit:
/// the class of every refusal, and the identity of every object resolved.
fn fs_path_fields(fs: &FsTerms) -> Fields {
    let mut unresolved: u64 = 0;
    let mut listed = Vec::new();
    for path in &fs.paths {
        let answer = fs.resolutions.answer(path);
        if answer.is_err() {
            unresolved += 1;
        }
        if listed.len() == MAX_AUDITED_PATHS {
            continue;
        }
        let mut entry = vec![("path", Field::Text(path.as_str().to_owned()))];
        match answer {
            Ok((_, scopes::Found::Existing(identity))) => {
                entry.push(("outcome", Field::Text("RESOLVED".to_owned())));
                entry.push(("device", Field::Text(identity.device().to_string())));
                entry.push(("inode", Field::Text(identity.inode().to_string())));
            }
            Ok((_, scopes::Found::Vacant(parent))) => {
                entry.push(("outcome", Field::Text("VACANT".to_owned())));
                entry.push(("parent_device", Field::Text(parent.device().to_string())));
                entry.push(("parent_inode", Field::Text(parent.inode().to_string())));
            }
            Err(why) => entry.push(("outcome", Field::Text(why.class().to_owned()))),
        }
        listed.push(Field::Object(entry));
    }
    Fields::new()
        .list("fs_paths", listed)
        .int(
            "fs_paths_total",
            u64::try_from(fs.paths.len()).unwrap_or(u64::MAX),
        )
        .int("fs_paths_unresolved", unresolved)
}

/// Reconstruct an admission from its immutable rows.
pub(super) fn load(work: &Work<'_>, run: &str) -> Result<Admission, AuthorityError> {
    let invariant = AuthorityError::Invariant;
    let (session, epoch, revision, mode): (String, i64, String, String) = work
        .db(work
            .tx
            .query_row(
                "SELECT r.session_id, r.epoch, a.policy_revision, a.mode FROM run r \
                     JOIN activation a ON a.id = r.activation_id WHERE r.run_id = ?1",
                [run],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional())?
        .ok_or(invariant("an admission names a run that does not exist"))?;

    let grants: Vec<(String, String)> = {
        let mut statement = work.db(work.tx.prepare(
            "SELECT cap_id, capability FROM run_grant WHERE run_id = ?1 ORDER BY ordinal",
        ))?;
        let rows = work.db(statement.query_map([run], |row| Ok((row.get(0)?, row.get(1)?))))?;
        work.db(rows.collect::<rusqlite::Result<_>>())?
    };
    let withheld: Vec<(String, String)> = {
        let mut statement = work.db(work.tx.prepare(
            "SELECT capability, reason FROM run_withheld WHERE run_id = ?1 ORDER BY ordinal",
        ))?;
        let rows = work.db(statement.query_map([run], |row| Ok((row.get(0)?, row.get(1)?))))?;
        work.db(rows.collect::<rusqlite::Result<_>>())?
    };

    let granted = grants
        .into_iter()
        .map(|(cap_id, text)| {
            let cap_id = CapId::parse(&cap_id).ok_or(invariant("a stored cap_id is malformed"))?;
            // Stored text is the authority's own canonical rendering of what it
            // resolved and minted -- a trusted stored grant, not a declaration
            // -- and the grammar that reads it back is exact: it must
            // reproduce itself, or the store and this build disagree about
            // what was granted.
            let capability = capability::parse(&text)
                .ok()
                .and_then(|spec| scopes::rehydrate(&spec).ok())
                .filter(|capability| capability.to_canonical_string() == text)
                .ok_or(invariant("a stored grant no longer resolves to itself"))?;
            Ok(Grant { cap_id, capability })
        })
        .collect::<Result<Vec<_>, AuthorityError>>()?;
    let withheld = withheld
        .into_iter()
        .map(|(text, code)| {
            Ok(Withheld {
                requested: CapabilityText::new(text)
                    .ok_or(invariant("a stored withheld capability is malformed"))?,
                cause: WithheldCause::from_code(&code)
                    .ok_or(invariant("a stored withheld reason is malformed"))?,
            })
        })
        .collect::<Result<Vec<_>, AuthorityError>>()?;

    Ok(Admission {
        run_id: RunId::parse(run).ok_or(invariant("a stored run_id is malformed"))?,
        session_id: SessionId::parse(&session)
            .ok_or(invariant("a stored session_id is malformed"))?,
        epoch: u64::try_from(epoch)
            .ok()
            .and_then(Epoch::new)
            .ok_or(invariant("a stored epoch is malformed"))?,
        policy_revision: Sha256Hash::from_hex(&revision)
            .ok_or(invariant("a stored policy revision is malformed"))?,
        mode: Mode::ALL
            .iter()
            .copied()
            .find(|m| m.as_str() == mode)
            .ok_or(invariant("a stored mode is malformed"))?,
        granted,
        withheld,
    })
}

/// `ReleaseRun`. The fence first; then an active run belonging to this caller,
/// session and epoch is released, and anything else — already released,
/// reaped, unknown, someone else's — is acknowledged without effect. Release
/// only ever removes authority, and a trigger guarantees a released run is
/// never active again.
pub(super) fn release(
    work: &mut Work<'_>,
    caller: &CallerContext,
    session: &SessionId,
    run: &RunId,
    epoch: Epoch,
) -> Result<Reply<()>, AuthorityError> {
    if !lease::fence(work, caller, session, epoch)? {
        work.audit(
            AuditEvent::RunReleaseRefused,
            lease::refusal_fields(
                caller,
                RefusedOperation::ReleaseRun,
                RefusalReason::StaleEpoch,
                session,
                Some(epoch),
            ),
        )?;
        return Ok(Reply::Refused(RefusalReason::StaleEpoch));
    }
    let subject = caller.subject().storage_key();
    let changed = work.db(work.tx.execute(
        "UPDATE run SET state = 'RELEASED', ended_ms = ?5 WHERE run_id = ?1 AND session_id = ?2 \
         AND subject = ?3 AND epoch = ?4 AND state = 'ACTIVE'",
        rusqlite::params![
            run.as_str(),
            session.as_str(),
            subject,
            to_sql(epoch.get())?,
            to_sql(work.now)?
        ],
    ))?;
    if changed == 1 {
        work.audit(
            AuditEvent::RunReleased,
            Fields::new()
                .text("subject", subject)
                .text("holder", caller.holder().to_string())
                .text("session_id", session.as_str())
                .int("epoch", epoch.get())
                .text("run_id", run.as_str()),
        )?;
    }
    Ok(Reply::Done(()))
}

pub(super) const fn taint_rank(taint: TaintLevel) -> i64 {
    match taint {
        TaintLevel::None => 0,
        TaintLevel::LocalUnverified => 1,
        TaintLevel::ExternalUntrusted => 2,
    }
}

pub(super) fn taint_from_rank(rank: i64) -> Option<TaintLevel> {
    TaintLevel::ALL.into_iter().find(|t| taint_rank(*t) == rank)
}

fn ordinal_sql(ordinal: usize) -> i64 {
    i64::try_from(ordinal).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{
        Resolutions, WithheldCause, mint_one as mint_with, resolvable, taint_from_rank, taint_rank,
    };
    use crate::capability::{Capability, CapabilitySet, UnresolvedScope, parse};
    use crate::policy::TaintLevel;
    use dwk_proto::wire::scalar::{CapabilityText, WithheldReason};

    fn set(texts: &[&str]) -> CapabilitySet {
        let specs: Vec<_> = texts.iter().filter_map(|t| parse(t).ok()).collect();
        assert_eq!(specs.len(), texts.len(), "fixtures parse");
        resolvable(&specs, &Resolutions::empty())
    }

    /// Minting with no filesystem answers: what every non-`fs` request sees.
    fn mint_one(
        requested: &CapabilityText,
        profile: &CapabilitySet,
        skills: &[CapabilitySet],
        ceiling: &CapabilitySet,
    ) -> Result<Capability, WithheldCause> {
        mint_with(requested, &Resolutions::empty(), profile, skills, ceiling)
    }

    fn text(t: &str) -> CapabilityText {
        let Some(text) = CapabilityText::new(t) else {
            unreachable!("lexically valid")
        };
        text
    }

    #[test]
    fn each_term_withholds_in_order_and_names_itself() {
        let everything = set(&["network.https:*", "model.call:*"]);
        let profile = set(&["network.https:*.example.com"]);
        let ceiling = set(&["network.https:api.example.com"]);
        let wanted = text("network.https:api.example.com");

        assert!(
            mint_one(
                &wanted,
                &profile,
                core::slice::from_ref(&everything),
                &ceiling
            )
            .is_ok()
        );
        assert_eq!(
            mint_one(
                &text("model.call:*"),
                &profile,
                core::slice::from_ref(&everything),
                &everything
            ),
            Err(WithheldCause::NotInAgentProfile)
        );
        assert_eq!(
            mint_one(
                &wanted,
                &profile,
                &[everything.clone(), set(&["model.call:*"])],
                &ceiling
            ),
            Err(WithheldCause::NotInSkillSet),
            "one skill that does not cover it is enough"
        );
        assert_eq!(
            mint_one(
                &text("network.https:www.example.com"),
                &profile,
                &[],
                &ceiling
            ),
            Err(WithheldCause::AboveProfileCeiling)
        );
    }

    #[test]
    fn an_empty_skill_term_withholds_everything_and_no_term_adds_anything() {
        let all = set(&["network.https:*"]);
        let wanted = text("network.https:api.example.com");
        assert_eq!(
            mint_one(&wanted, &all, &[CapabilitySet::empty()], &all),
            Err(WithheldCause::NotInSkillSet),
            "an unknown skill is the empty set, not the absence of a constraint"
        );
    }

    #[test]
    fn a_resource_the_kernel_cannot_yet_identify_is_withheld_honestly() {
        let all = set(&["model.call:*"]);
        // M4b canonicalises fs.read and no other fs verb (ADR-0043).
        assert_eq!(
            mint_one(&text("fs.write:/workspace"), &all, &[], &all),
            Err(WithheldCause::NeedsCanonicalization(
                UnresolvedScope::CanonicalPath
            ))
        );
        // A concrete fs.read path with no resolver answer names no resource,
        // however canonical its spelling: the grammar alone is no authority.
        for path in [
            "fs.read:/etc",
            "fs.read:/workspace",
            "fs.read:/workspace/src",
        ] {
            assert_eq!(
                mint_one(&text(path), &set(&["fs.read:*"]), &[], &set(&["fs.read:*"])),
                Err(WithheldCause::NeedsCanonicalization(
                    UnresolvedScope::CanonicalPath
                )),
                "{path}"
            );
        }
        assert_eq!(
            mint_one(&text("process.exec:/usr/bin/git"), &all, &[], &all),
            Err(WithheldCause::NeedsCanonicalization(
                UnresolvedScope::ExecutableIdentity
            ))
        );
        // On the wire, one truthful reason for both scopes (ADR-0040): it
        // claims nothing about any declaration.
        for scope in [
            UnresolvedScope::CanonicalPath,
            UnresolvedScope::ExecutableIdentity,
        ] {
            assert_eq!(
                WithheldCause::NeedsCanonicalization(scope).to_wire(),
                WithheldReason::UnresolvedResource
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fs_read_is_minted_through_every_term_in_one_canonical_meaning() {
        // M4b: the request and every declaration mean what the M4a resolver
        // found beneath the root (ADR-0043 §8), so containment compares like
        // with like -- and a path that does not resolve covers nothing.
        use super::scopes::resolve_paths;
        use crate::capability::DeclaredPath;
        use crate::resource::fs::PinnedRoot;

        let scratch = crate::scratch::Scratch::new("mint");
        let dir = scratch.path().join("ws");
        let made = std::fs::create_dir_all(dir.join("src"))
            .and_then(|()| std::fs::write(dir.join("src/lib.rs"), b"x"))
            .and_then(|()| std::fs::create_dir_all(dir.join("srcX")));
        assert!(made.is_ok(), "the fixture tree");
        let Some(host) = dir.to_str().map(str::to_owned) else {
            unreachable!("a UTF-8 temporary directory")
        };
        let Ok((_, fingerprint)) = PinnedRoot::install(&host) else {
            unreachable!("the fixture root pins")
        };
        let binding = super::RootBinding {
            host_path: host,
            fingerprint,
        };
        let paths: Vec<DeclaredPath> = [
            "/workspace",
            "/workspace/src",
            "/workspace/src/lib.rs",
            "/workspace/srcX",
            "/workspace/missing",
        ]
        .into_iter()
        .filter_map(DeclaredPath::new)
        .collect();
        let probes: Vec<_> = paths
            .iter()
            .map(|p| (p.clone(), super::scopes::VacantScope::Refused))
            .collect();
        let answers = resolve_paths(&binding, &probes);
        let term = |texts: &[&str]| {
            let specs: Vec<_> = texts.iter().filter_map(|t| parse(t).ok()).collect();
            resolvable(&specs, &answers)
        };
        let profile = term(&["fs.read:/workspace"]);
        let skill = term(&["fs.read:/workspace/src"]);
        let ceiling = term(&["fs.read:/workspace?max_bytes=1048576"]);
        let wanted = text("fs.read:/workspace/src/lib.rs?max_bytes=4096");
        assert_eq!(
            mint_with(
                &wanted,
                &answers,
                &profile,
                core::slice::from_ref(&skill),
                &ceiling
            )
            .map(|c| c.to_canonical_string()),
            Ok("fs.read:/workspace/src/lib.rs?max_bytes=4096".to_owned())
        );
        // A request the ceiling's byte bound does not cover.
        assert_eq!(
            mint_with(
                &text("fs.read:/workspace/src"),
                &answers,
                &profile,
                core::slice::from_ref(&skill),
                &ceiling
            ),
            Err(WithheldCause::AboveProfileCeiling)
        );
        // A sibling of the skill's prefix, not below it.
        assert_eq!(
            mint_with(
                &text("fs.read:/workspace/srcX?max_bytes=1"),
                &answers,
                &profile,
                core::slice::from_ref(&skill),
                &ceiling
            ),
            Err(WithheldCause::NotInSkillSet)
        );
        // A path that does not exist resolves to nothing: withheld, however
        // well every term would have covered its spelling.
        assert_eq!(
            mint_with(
                &text("fs.read:/workspace/missing?max_bytes=1"),
                &answers,
                &profile,
                &[],
                &ceiling
            ),
            Err(WithheldCause::NeedsCanonicalization(
                UnresolvedScope::CanonicalPath
            ))
        );
        // A profile member that did not resolve covers nothing.
        assert_eq!(
            mint_with(
                &wanted,
                &answers,
                &term(&["fs.read:/workspace/missing"]),
                &[],
                &ceiling
            ),
            Err(WithheldCause::NotInAgentProfile)
        );
    }

    #[test]
    fn a_capability_outside_the_vocabulary_is_withheld_by_the_first_term() {
        let all = set(&["model.call:*"]);
        assert_eq!(
            mint_one(&text("teleport.now:*"), &all, &[], &all),
            Err(WithheldCause::NotInAgentProfile)
        );
    }

    #[test]
    fn no_grant_is_assembled_from_two_declarations() {
        // The profile covers the host; a different member carries a
        // constraint. Neither alone covers a request needing both parts
        // narrowed from different members -- and the request is granted only
        // as asked, never as a synthesis.
        let profile = set(&[
            "network.https:api.example.com?max_requests=10",
            "network.https:*.example.com",
        ]);
        let all = set(&["network.https:*"]);
        let wanted = text("network.https:api.example.com");
        let Ok(granted) = mint_one(&wanted, &profile, &[], &all) else {
            unreachable!("the wildcard member covers it whole")
        };
        assert_eq!(
            granted.to_canonical_string(),
            "network.https:api.example.com"
        );
    }

    #[test]
    fn taint_ranks_round_trip_in_order() {
        for taint in TaintLevel::ALL {
            assert_eq!(taint_from_rank(taint_rank(taint)), Some(taint));
        }
        assert!(taint_rank(TaintLevel::None) < taint_rank(TaintLevel::LocalUnverified));
        assert!(
            taint_rank(TaintLevel::LocalUnverified) < taint_rank(TaintLevel::ExternalUntrusted)
        );
        assert_eq!(taint_from_rank(3), None);
    }

    #[test]
    fn every_stored_code_round_trips() {
        for cause in [
            WithheldCause::NotInAgentProfile,
            WithheldCause::NotInSkillSet,
            WithheldCause::NotInParentGrant,
            WithheldCause::AboveProfileCeiling,
            WithheldCause::NeedsCanonicalization(UnresolvedScope::CanonicalPath),
            WithheldCause::NeedsCanonicalization(UnresolvedScope::ExecutableIdentity),
        ] {
            assert_eq!(WithheldCause::from_code(cause.code()), Some(cause));
        }
    }
}
