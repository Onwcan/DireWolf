# ADR-0067: The approver is reached at an endpoint of its own, by operator-declared uids disjoint from every runtime's, the broker's and the authority's -- authenticated by the kernel, and holding no approval operation until M6's registry exists

**Status:** Proposed · **Date:** 2026-11-16 (designed, built and reviewed locally 2026-11-16 for F-18 Phase 3.4; its three-identity evidence observed on CI #201 (run 44818094052, `3998de2`), recorded in [PRE_M6_REMEDIATION.md](../PRE_M6_REMEDIATION.md); nothing here is accepted) · **Would amend (on acceptance):** [ADR-0041](0041-m3e-authenticated-dwkp-transport.md) (the authority listens at a second socket, the approver endpoint, beside the DWKP socket; two audit kinds) · **Refines:** [ADR-0063](0063-principal-ownership-of-sessions-workspaces-and-profiles.md) §8 (the approver endpoint's identity boundary is built; what an approval is stays M6's), [APPROVALS.md](../APPROVALS.md) §7 (the approver's channel), [ADR-0021](0021-approval-binding-v2.md) (proposes, for M6, that the requester's principal join the binding) · **Leaves open:** the approval registry, its request vocabulary, kernel-rendered prompts, standing grants and any terminal -- all M6's, under the contract in §7

> **An approver is a uid the operator names with `--approver-uid`, and is
> reached only at `--approver-socket`, a socket of its own.** No approver is
> a runtime (`--allow-uid`), the broker or the authority, and nothing
> overrides that. The kernel's report decides who a peer is before a byte is
> read. Until M6's approval registry exists the endpoint holds no approval
> operation: it records who the kernel reported and closes the connection,
> and every `REQUIRE_APPROVAL` still denies.

Proposed. The change is built so that its evidence can run; the accepted
records' bodies are unchanged (README.md, rule 1).

## Context

F-18 (ADR-0063, Proposed) made sessions, workspaces and profiles belong to
principals, kept the runtime's DWKP endpoint free of descriptors (TX061),
kept every runtime admission unattended (TX062) and took every subject from
the kernel (TX063). It left one thing to M6 (§8): *a human approver must be
an independently authenticated principal, acting through an approval
boundary the runtime cannot control.*

Without that boundary, any approval M6 adds would be decided by someone the
system cannot tell from the requester:

- **The DWKP socket is the runtime's.** Every uid it admits is a runtime's,
  and the same uid may run the CLI. An approval taken there could come from
  the runtime itself.
- **A uid is not a person.** The only identity the kernel reports is a uid
  (ADR-0063 OD-1); "the human" and "the runtime" are distinguishable only if
  they are different uids.
- **The withdrawn terminal design** passed a terminal over the runtime's
  socket; a runtime that passes a pseudo-terminal it controls answers its own
  prompt (APPROVALS.md §7, withdrawn by ADR-0063).

The approval registry -- binding, scopes, expiry, single-use burn,
rendering, standing grants -- is M6's deliverable and does not exist. An
endpoint that accepted a decision before it does could only approve by
fiat.

## Decision

### 1. A door of its own

`dwkd-authority serve --approver-socket <PATH> --approver-uid <UID>...`
binds a second Unix-domain socket. Its place is checked as the DWKP
socket's is (`server/socket.rs`, ADR-0041): absolute; the final name never
followed; in a directory the authority owns that no one else can write;
every ancestor root's or the authority's, or sticky; a stale socket removed
only if it is the authority's own dead one; one lock per name. It is never
the DWKP socket, as written or by another spelling: the parser refuses the
first, the start resolves the second and refuses it. Without both flags
there is no approver endpoint.

An operator who wants a runtime unable even to connect gives it a directory
of its own, `0710` with the approvers' group. That narrows who can reach the
socket. It proves nobody's identity: the kernel's report does.

### 2. Who is an approver

A closed set of at most 16 uids the operator names: no wildcard, no group,
no user name, no exception for root. The set is **disjoint**, with no
override flag, from:

| identity | refused by | why |
|---|---|---|
| every `--allow-uid` (a runtime's) | the parser | a runtime that is an approver approves its own requests |
| `--broker-uid` | the parser, even with `--allow-shared-broker-uid` | the broker performs effects; it never decides them |
| the authority's own uid | the start, before an incarnation begins | the authority decides what an approval permits; it is not the human who grants it |

This is stricter than the DWKP peer policy, which admits the authority's uid
or a shared broker uid on an acknowledgement for development. There is no
such acknowledgement for approvers, so the approver endpoint cannot be
configured on a one-user machine.

A uid is an operating-system identity, not a person. Two people who share
one are one approver; an approver uid's own processes are trusted as that
approver, so a connected socket an approver's process hands to another
process carries the approver's identity with it.

### 3. What the endpoint does now

```text
accept ──▶ SO_PEERCRED (server/peer.rs)          nothing is read
       ──▶ an operator-declared approver?
             no  → approver.peer_refused         {uid, pid, reason: uid_not_an_approver}
             yes → approver.peer_authenticated   {uid, pid, outcome: closed,
                                                  reason: no_approval_operation}
       ──▶ the connection is closed
```

It reads no byte, writes no byte, makes no subject, mints no lease holder,
decodes no frame and reaches no dispatch (TX065, and the module's own test).
A descriptor a peer attaches is never received -- nothing here receives
(TX061 covers the whole server directory) -- and the kernel closes it with
the connection. Both records carry only what the kernel reported and the
authority's own words. Each is rate-limited in a class of its own, as the
DWKP transport's records are (ADR-0041). `approver.peer_authenticated` is not
an approval and nothing reads it as one.

### 4. What the runtime path keeps

Unchanged, and now restated against approvals:

- The runtime's endpoint receives no descriptor (TX061) and makes its subject
  only from the kernel (TX063).
- Every run a runtime admits is `api`, unattended (TX062). Nothing a runtime
  sends reaches the origin, and the approver endpoint's existence changes
  nothing on the DWKP wire.
- **No claim of a human is decodable.** An `origin`, `attended`, `approved`,
  `approval`, `approval_id`, `approval_token`, `approver`, `approver_uid`,
  `granted_by`, `request_nonce`, `binding_hash`, `remembered_approval`,
  `auto_approve`, `yolo`, `dangerously_skip_permissions` or `tty` member, in
  the envelope or the payload, is an unknown field: the message is refused,
  the connection closed, nothing reaches the authority. A coding agent's own
  approval state, a remembered approval, model text and a terminal path are
  each such a claim.
- `StandingGrantState` keeps its single variant, `Unavailable`; no caller can
  state that a grant exists.
- `REQUIRE_APPROVAL` still denies, as `deny-approval-needed-when-unattended`
  in the shipped packs and `APPROVAL_REQUIRED` in the process, `net.http` and
  workload routes. SAFE, BALANCED and POWER decide exactly as before.

### 5. No terminal

No terminal descriptor is accepted anywhere: not on the runtime's endpoint
(ADR-0063), and not on this one. A descriptor proves less than it seems:

- `isatty()` says a descriptor is a terminal, not whose. A pseudo-terminal's
  owner and session are whatever the process that opened it made them; a
  runtime that opens a pty, or is given the approver's, can read and write
  it.
- A matching session id says the descriptor and the peer share a session --
  not that the runtime is outside it. A runtime started from the approver's
  shell shares that session.
- The kernel-side checks that would prove the opposite -- the terminal's
  owning uid is the approver's and no runtime uid holds a descriptor to it --
  need a scan of other processes' descriptors the authority is not
  permitted, and should not be permitted, to make.

The recommended M6 shape is a **trusted approver client**: a separate
program, run as an approver uid, that connects to this endpoint, receives
the authority-rendered request as data and renders it on its own terminal.
The runtime is a different uid: it cannot write to that terminal or ptrace
that client. The prompt's integrity is then the client's and its terminal's,
under the approver's uid, not a property the authority guesses from a
descriptor. If a future design accepts a terminal descriptor, it does so only
on this endpoint, from a peer this endpoint authenticated, refusing a pipe,
a socket or a terminal whose owner is not the peer's uid -- and that is a
decision of its own, with its own ADR.

### 6. What is not built

The approval registry, the request vocabulary, kernel-rendered prompts,
approval consumption, standing grants and approval audit events. Nothing
here records an approval (TX062 still forbids an insert into an approval
table on the runtime path), no grant can be held, no prompt is rendered,
and no approval token exists, in production or in a temporary in-memory
form.

### 7. What M6 builds on this endpoint

The constraints below are this record's contract for M6; M6's own ADR
decides the rest and, on acceptance, replaces TX065.

- **Vocabulary, closed and minimal**, on this endpoint only: list the
  pending requests the authority rendered; show one; decide one -- approve
  or deny -- naming its request id and echoing its request nonce. No
  operation writes anything else: not a policy, a grant, an ownership
  record, a session or a run.
- **Authentication before acceptance.** A decision is accepted only on a
  connection this endpoint authenticated, from a uid in the approver set at
  the moment of the decision; a revoked or removed approver decides nothing.
- **The record.** An approval names its approver (the uid the kernel
  reported, and the endpoint), its requester (the run's subject) and its
  agent, run, session and workspace; the store refuses one whose approver is
  its requester -- the second statement of §2's disjointness -- and one for
  another run, agent or principal is never spent.
- **The binding.** ADR-0021's eleven fields, re-canonicalised before the
  effect; this record proposes that M6 add the requester's principal, so an
  approval for one principal's request is never another's. That changes the
  accepted binding, so M6 records it in a new ADR; nothing here changes it.
  An approval is not a capability grant: it never overrides a capability
  denial, a policy denial, resolution, ownership, a network constraint, a
  sandbox requirement or an obligation.
- **Single use, expiry, nonce, replay.** `not_after` always set; `max_uses`
  default 1; the use burned in the same transaction that records the
  effect's intent, inside F-02's gate (ADR-0064), so a revocation or an end
  of authority is ordered with it and two concurrent spends yield one
  effect; the request nonce single-use; a consumed approval durable across a
  restart.
- **Rendering.** The authoritative region from canonical, authority-owned
  data -- requester, agent, session, run, operation, resource identity,
  security-relevant arguments, rule, capability, environment and assurance,
  taint, privacy, obligations, scope, expiry, uses, credential handles
  without values; every field stripped of control characters, ANSI and
  bidirectional controls, bounded, with truncation shown; agent prose only in
  a separate region labelled untrusted.
- **Audit.** `approval.requested`, `approval.granted`, `approval.denied`,
  `approval.expired`, `approval.used`, `approval.drift_detected`,
  `approval.revoked`, and refusals of a self-approval or an unauthorised
  approver -- written by the authority, carrying both identities, the
  binding hash, the canonical operation, the policy revision and the
  endpoint, never a secret.
- **Standing grants** are a separate operator act, never created by
  approving once: the 90-day cap, `require_untainted_run`, revocation,
  listed, atomically consumed, owned by a principal.

### 8. Wire and store

DWKP, the private broker protocol (12) and the store schema (14) are
unchanged. The audit log gains two kinds, `approver.peer_refused` and
`approver.peer_authenticated`, in the record format every kind uses; a log
holding them is verified by this build's `verify-audit`, as every added kind
has been. Two `serve` flags are added.

## Consequences

- An approver is a configured, kernel-authenticated identity that no runtime,
  broker or authority uid can be, by construction and with no override.
- M6 has an endpoint to attach its vocabulary to, and an audited record of
  who connected to it before it does.
- A deployment that configures the endpoint today gains nothing it can
  approve with; the start-up line says so.
- An operator on a one-user machine cannot configure it at all.

## Residuals

- **The approver set is configuration, not a registry.** It is not in the
  audit chain at start; each authentication is. A changed set takes a
  restart. A named principal registry stays deferred (ADR-0063 OD-1).
- **A uid is the approver.** Every process of that uid is trusted as the
  approver; a compromised approver session is a compromised approver.
- **Reachability is the operator's.** Mode `0666` lets any local uid connect
  and be refused; each refusal is a rate-limited record, as at the DWKP
  socket. A directory of the approvers' own narrows it.
- **No terminal proof** exists; none is relied on (§5).
- **Hosted evidence.** The three-identity property is exercised only by the
  hosted `authority-transport` job (`DW_PEER_AS`, `DW_APPROVER_AS`). On CI
  #201 it ran with three identities (uid 1001, `DW_PEER_AS`, `DW_APPROVER_AS`
  uid 999), and the six `cross-uid-*` cases were contained.

## Alternatives considered

- **A: a separate authenticated socket and an operator-declared approver uid
  set** -- chosen for the identity boundary: the kernel authenticates, the
  operator configures, the runtime's endpoint is untouched, and it is
  testable with real identities now.
- **B: an operator-only control process with its own channel** (a separate
  daemon, or the authority's in-process operator API reached over IPC).
  Rejected for now: a second trusted daemon to build, harden and audit, and
  its channel to the authority would itself be a door needing A's checks.
- **C: a design-only contract, nothing live until the registry.** Taken for
  everything that needs the registry -- the vocabulary, the binding,
  consumption, rendering, the terminal, grants. Not taken for the identity
  boundary, which grants nothing and can be proved now with real uids.

## Owner decisions

- OD-1 the endpoint is a second socket with its own uid set (A), live now,
  holding no operation (C) until M6;
- OD-2 approvers disjoint from runtime, broker and authority uids, with no
  override;
- OD-3 no terminal descriptor; a trusted approver client is M6's recommended
  shape;
- OD-4 the requester's principal proposed for the binding, decided by M6's
  ADR;
- OD-5 the three-identity hosted evidence before acceptance;
- OD-6 the approver set's place in the audit record and a principal registry
  deferred to M6.

## Evidence

- `crates/dwkd-authority/src/server/approver.rs`: the decision from the
  kernel's report, and the module's scan of its own code
  (`the_endpoint_reads_answers_and_dispatches_nothing`).
- `crates/dwkd-authority/src/server/config.rs`: no approver is a runtime or
  the broker, never the DWKP socket, no override flag.
- `crates/dwkd-authority/src/state/transport.rs`: the two records.
- `crates/dwkd-authority/tests/transport_approver.rs`, the released binary:
  the runtime's uid refused unread and its own door unchanged; the
  authority's uid refused at start with no incarnation; the DWKP socket by
  another spelling refused; the approver socket's name protected; every
  claim of a human undecodable on the DWKP wire and the admission still
  `api`; and, hosted only, three identities --
  `an_approver_is_its_own_identity_and_a_runtime_is_never_one`, run by
  `make authority-transport-evidence` with `DW_PEER_AS` and `DW_APPROVER_AS`.
- `make approver-identity-mutations`: each guard weakened in turn.
- Boundary rule TX065; TX061-TX063 unchanged.
- [F18_APPROVER_IDENTITY.md](../F18_APPROVER_IDENTITY.md): the inventory, the
  adversarial matrix and what is pending.

## Revisit if

M6 designs its approval registry or request vocabulary; a principal
registry is introduced; a terminal-based approval is proposed; the
authority gains an online operator endpoint (ADR-0063 §5); or the approver
set needs to change without a restart.
