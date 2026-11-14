# ADR-0063: Sessions, workspaces and agent profiles belong to principals -- the kernel-reported uid holds only what the operator declared, or a new session it created

**Status:** Proposed · **Date:** 2026-11-14 (designed, reviewed and built 2026-11-14 for finding F-18; its hosted evidence is pending and nothing here is accepted) · **Would amend (on acceptance):** [ADR-0011](0011-session-concurrency.md) point 2 (an expired, released or invalidated lease goes to the next acquirer **that may hold the session**), [ADR-0039](0039-durable-authority-state.md) (schema version 14, its migration and its records), [ADR-0041](0041-m3e-authenticated-dwkp-transport.md) (the peer policy lets a uid speak; ownership decides what it may act on) · **Refines:** [ADR-0036](0036-m3-authority-operations-and-the-capability-wire-form.md) §8 (idempotency stays scoped by subject), [ADR-0028](0028-policy-input-ownership.md) (nothing on the wire names a subject or a principal), [APPROVALS.md](../APPROVALS.md) §7 (the terminal passed over the runtime's socket is not built; M6 uses an approver endpoint of its own)

> **The uid the kernel reports for a socket holds a session only as its
> owner or the operator's delegate, uses a workspace only as one of its
> principals, and names an agent profile only under the operator's grant.**
> A new session is its first acquirer's; a session the store held before, or
> one bound to a workspace, is the operator's to declare. A migration grants
> nothing from history. A revocation ends the subject's leases and runs in
> one transaction, and its environments after it, and says which of the two
> it has reached.

Proposed. The change is built so that its evidence can run; the accepted
records' bodies are unchanged (README.md, rule 1), and their sections stay the
accepted design until this record is accepted.

## Context

**What decided who may act.** The DWKP server lets a uid speak if the
operator's closed `--allow-uid` list names it (ADR-0041), and makes the
kernel-reported uid the subject of every request. Runs, grants and
idempotency records are scoped to that subject. Sessions, workspaces and
profiles were not:

- **V1 -- session takeover.** `AcquireLease` refused only a *live* lease held
  by another connection. Once a lease expired, was released or a restart
  invalidated it, any allowed uid took the session at a new epoch, inherited
  its workspace binding, and reaped the previous subject's runs -- ending
  their environments.
- **V2 -- profile escalation.** `AdmitRun` resolved any operator profile by
  name; no record said which subject might run under it.
- **V3 -- implicit sharing.** Every allowed uid could bind to every
  workspace through any session bound to it, and two workspaces bound to one
  directory shared a root no one had said was shared.

**What M6 depends on.** [APPROVALS.md](../APPROVALS.md) §7 had the CLI pass
its controlling terminal to the kernel over the DWKP socket (`SCM_RIGHTS`).
The runtime connects to that socket as the same uid; a runtime that passes a
pseudo-terminal it controls could answer its own approval prompt. The server
reads with `read()`, so no descriptor is received today -- but nothing kept it
that way.

## Decision

### 1. The principal is the kernel's uid

A principal is an `AuthenticatedSubject` (`uid:N`), made once per accepted
connection from `SO_PEERCRED` -- in the server, only as `unix_uid(peer.uid)`
(TX063). No envelope or payload field names a subject, a principal, an owner
or a delegate; a message that tries is not decodable. A larger principal
registry (named users, groups, external identities) is deferred (OD-1).

### 2. The records (store schema 14)

| record | made by | means |
|---|---|---|
| `session_owner` | the operator (`OPERATOR`), the single-principal adoption (`ADOPTED`), or a **new** session's first acquirer (`FIRST_ACQUIRER`) | the session's one owner, fixed for its life; revoking it retires the session, delegates included |
| `session_delegate` | the operator | another subject that may hold the session |
| `workspace_principal` | the operator | a subject whose sessions may be bound to the workspace, and held while bound |
| `profile_principal` | the operator | a subject that may name the profile in `AdmitRun` |
| `workspace_root_share` | the operator | a workspace whose root more than one principal reaches |
| `ownership_revocation` (+ `_run`) | a revocation | what was revoked, what it ended, and the runs it reaped |
| `legacy_session` | the migration, once | every session the store held before schema 14 |
| `ownership_observation` | the migration, once | what the store's history showed -- never authority (§6) |

A grant is revoked once and never deleted; a re-grant is a new row (a
partial unique index keeps one active grant per subject). Triggers state the
rules a second time: an owner is fixed; `FIRST_ACQUIRER` only for a session
with no lease row, no binding and no legacy record; `ADOPTED` only for a
legacy session; a bound session's owner and delegates are principals of its
workspace; a session is bound only with such an owner; a workspace has a
second principal only once acknowledged; a revocation names only runs it
reaped.

### 3. Who may hold a session

`AcquireLease` decides first, before anything of the session is looked at
(`ownership::standing`):

| found | outcome |
|---|---|
| no owner, and the session is new (no lease row, no binding, not legacy) | granted; the acquirer is recorded its owner (`FIRST_ACQUIRER`) |
| no owner, and the session is legacy, bound or already has a lease row | `LEASE_HELD` (audited `SESSION_UNOWNED`) |
| an owner, revoked | `LEASE_HELD` (`SESSION_RETIRED`) |
| an owner; the subject is neither it nor an active delegate | `LEASE_HELD` (`SESSION_NOT_PERMITTED`) |
| bound, and the subject is not an active principal of the workspace | `LEASE_HELD` (`WORKSPACE_NOT_PERMITTED`) |
| otherwise | ADR-0011's lease rules, unchanged |

A refused subject takes over nothing and reaps nothing. The public answer is
the existing `LEASE_HELD`: it does not say whether the session exists or who
holds it; the audit record says why. The fence (ADR-0011 point 3) adds a
fifth condition: the holder's subject may still hold the session -- the
second, independent statement of what a revocation ensures by invalidating
the lease. A new connection by the same uid is still a new holder.

### 4. Who may run under a profile

After the fence and the idempotency record, an `AdmitRun` naming a profile the
subject has no active grant for is refused `UNKNOWN_AGENT_PROFILE` -- the same
answer as a profile the kernel does not hold -- audited
`PROFILE_NOT_PERMITTED`. A grant is by profile name, so it holds across the
profile's revisions.

### 5. Revocation is two-phase

**Phase A, in one transaction.** The grant is revoked; every live lease the
affected subjects hold on the affected sessions is invalidated (holder
cleared, epoch kept; `lease.revoked`); their active runs are reaped (cause
`principal_revoked`); each run's live environment is recorded `DESTROYING`
(reason `REVOKED`); the revocation and its runs are recorded and audited
(`ownership.revoked`). From that commit nothing the subject sends passes the
fence or the ownership check -- a stale epoch, a replayed admission key, a
re-acquisition, a restart -- and nothing new can run in those environments.

| revoked | ends |
|---|---|
| a session's delegate | its lease and runs on that session |
| a session's owner | the session: every lease and run on it; its delegates are revoked with it |
| a workspace principal | its leases and runs on every session bound to the workspace |
| a profile principal | its active runs under the profile |

**Phase B, after the commit.** The broker removes each environment by its
labels, which ends its workload and its tunnels. One it cannot remove --
the broker unreachable, an indeterminate answer, no sandbox attached -- stays
`DESTROYING`, is audited where the broker answered (`environment.destroy_failed`),
and is removed by the next destruction, reclamation or start. A parked
workload's next collection settles it as for any run -- its egress, its
root's exposure (ADR-0061), its run's taint (ADR-0062) -- and the revoked
run's parked request is answered `OUTCOME_UNKNOWN`, never with what the
workload produced.

**Its report.** `revocation_status` is `REVOKED` from the commit and
`COMPLETE` only when every environment of every reaped run is no longer live
and none of their workloads is `LAUNCHING` and none of their host processes is
launching or running.

The production server holds the store's exclusive lock (`authority.lock`), so
an operator changes ownership with the server stopped: the access ends at
once, and the next start's invalidation and reconciliation perform Phase B.
The in-process API revokes online. An online operator endpoint is later work
under the same disjoint-identity rule as §8's approver endpoint.

### 6. The migration grants nothing

Schema 14 creates every ownership record **empty**. A lease holder, the
subject of a run and a profile's past use are not evidence of authority: any
of them may be the takeover this record exists to stop. What the history
showed is copied once into `ownership_observation` -- per session, profile and
workspace, every subject seen, its source (`LEASE_HOLDER`, `RUN_SUBJECT`),
occurrences, first and last seen, and `ambiguous` where two subjects met --
and the table is closed by its own trigger. Only `adoption.rs` reads it, and
only to refuse (TX064). Every session the store held is `legacy_session`.

The operator's bootstrap, offline, in order: grant workspace principals;
grant profile principals; declare session owners and bind (an owner must be a
principal of the workspace first); add delegates. A deployment with one
runtime identity may instead **adopt** it -- one audited operator act that
declares it the owner of every legacy session and a principal of every
workspace and profile -- refused, with nothing written, when the observation
shows any other subject or any conflict, or when an ownership record names
another subject. It never runs by itself.

The authority starts with ownership incomplete (OD-11): what is missing is
reported (`StartReport::ownership`) and audited once (`ownership.incomplete`),
and each request it touches refuses. A failed migration rolls back whole.

### 7. Workspaces and shared roots

A workspace has a second active principal only once the operator has
acknowledged that its root is shared. Two workspaces bound to one directory
are one root (ADR-0061): when the principals of every workspace bound to a
root are more than one subject, every one of those workspaces must be
acknowledged -- checked when a principal is granted and when a root is bound.
Ownership never narrows what exposure and taint follow: they are the root's,
whichever principal reaches it.

### 8. The runtime is never its own approver

Built now:

- the runtime's DWKP endpoint receives no descriptor: a descriptor a runtime
  attaches -- a pipe it holds, a terminal it controls -- is discarded by the
  kernel with the bytes, and none is installed (tested on the real server;
  TX061 keeps `recvmsg`, ancillary buffers and `SCM_RIGHTS` out of the server);
- no runtime path selects an attended origin or records an approval (every
  admitted run is `api`; TX062);
- the server makes a subject only from the kernel's report (TX063).

Required of M6, not built here:

- approvals are decided only on an **approver endpoint** of their own, whose
  identities the operator keeps disjoint from the runtime's, the authority's
  and the broker's uids;
- what the human approves is rendered by the kernel from canonical data;
- every approval and standing grant is bound to a principal, records who
  granted it, and the store refuses one whose approver is its requester;
- a terminal, if one is used, is accepted only on the approver endpoint and
  proved to be the approver's -- never a descriptor a runtime could
  substitute; [APPROVALS.md](../APPROVALS.md) §7's terminal passed over the
  runtime's socket is withdrawn.

### 9. Wire and store

Store schema 13 -> 14. Public DWKP and the private broker protocol (12) are
unchanged: every refusal reuses `LEASE_HELD` or `UNKNOWN_AGENT_PROFILE`. No
`serve` flag is added; ownership is configured in process by the operator's
tooling (OD-8).

## Consequences

- A runtime uid allowed to speak can no longer take another principal's
  session, run under another principal's profile, or reach a workspace the
  operator did not grant it.
- Every operator who installs a profile, a workspace or a binding now states
  who holds it; an upgraded store refuses until the operator declares, or
  adopts, ownership.
- A delegated subject is an explicit operator act; tests that used a second
  subject on one session now delegate it.

## Residuals and what is assigned elsewhere

- **A running workload keeps its egress until its environment is removed.**
  Phase A grants nothing new, but a workload already running keeps the
  egress and workspace its launch was granted for the destroy's latency, and
  longer if the broker or the runtime fails. An immediate broker-side stop
  would change the private protocol (13) and is a separate decision (OD-12).
- **A host process of a reaped run is not stopped.** None runs in production
  before M6; the report stays `REVOKED` while one runs.
- **Production ownership changes are offline.** The store's lock allows one
  process; an online operator endpoint is later work (§5).
- **The principal is a uid.** Two people sharing a uid are one principal;
  a registry of principals is deferred (OD-1).
- **Concurrency.** The authority's single worker means no fs or `net.http`
  effect overlaps Phase A today; F-02 must keep a revocation serialised with
  intents already recorded.
- **Content another subject wrote** to a shared root stays `LOCAL_UNVERIFIED`
  unless an origin's bytes reached it (ADR-0062's R19); a foreign-writer taint
  policy is deferred (OD-7).

## Alternatives considered

- **A: keep the uid list as the boundary** -- every allowed uid one trust
  domain. Rejected: it is V1-V3, and M6's approver must be another identity.
- **B: ownership derived from history at migration** -- the last holder or
  the run subjects become owners. Rejected: the history may be the takeover.
- **C: explicit principal records, first-acquirer for new sessions only,
  operator declaration for everything else** -- chosen.
- **D: a principal registry with named identities now.** Deferred: it needs
  the operator surface M6 and later milestones define.

## Owner decisions

OD-1 durable records now, registry deferred; OD-2 the kernel-reported uid is
the principal; OD-3 first-acquirer ownership only for sessions new after
schema 14; OD-4 the migration grants nothing, history is observation, the
adoption refuses on conflict; OD-5 two-phase revocation with `REVOKED` and
`COMPLETE`; OD-6 delegation is the operator's; OD-7 a foreign-writer taint
policy is deferred to Phase 3.4; OD-8 configuration stays in process, no new
`serve` flag; OD-9 the approver-endpoint constraints of §8 bind M6; OD-11 the
authority starts with ownership incomplete and refuses per request; OD-12 an
immediate broker-side stop (private protocol 13) is deferred.

## Evidence

- `crates/dwkd-authority/tests/state_ownership.rs`: takeover after expiry,
  release and restart; same-uid reconnect; first acquirer; binding,
  delegation and sharing rules; profiles; revocation of delegates, owners,
  workspace and profile principals; stale epochs and replayed keys; the
  fence's own check; a migrated store with conflicting history; adoption
  with consistent and conflicting history and with another subject's
  declaration; an adoption interrupted before its commit; forged subject
  fields.
- `state/ownership_route_tests.rs` (fake broker): revocation during a parked
  workload, a broker that cannot confirm, a crash before the broker and one
  after it; `taint_route_tests.rs`: exposure and taint across principals.
- `state/schema.rs`: version 13 -> 14 with conflicting history.
- `transport_hostile.rs`: a pipe end and a terminal master passed over the
  real socket are never installed.
- Hosted only (a second and third OS identity): `transport_foreign.rs`'s
  cross-uid ownership test (`authority-transport-evidence`), and the agent's
  three-identity `i09` case (`sandbox-agent-evidence`).
- `make authority-ownership-mutations`: each guard weakened in turn.
- Boundary rules TX061-TX064.

## Revisit if

M6 designs its approver endpoint; a principal registry is introduced; F-02
adds concurrency to the authority; the private protocol gains a broker-side
stop; or an operator surface makes ownership changes online.
