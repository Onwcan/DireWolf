# ADR-0077: Every local approval arrives on the approver endpoint, and an approver uid is a principal, not a person

**Status:** Proposed · **Date:** 2026-11-23 (found by the second security review of 2026-11-22 as ISR2-05 and ISR2-06; a decision record only -- nothing is built, and no approval operation exists before M6; nothing here is accepted) · **Would amend (on acceptance):** [ADR-0022](0022-approval-response-authentication.md) ("CLI-local (default)" and "Detached-local": both withdrawn) · **Refines:** [ADR-0063](0063-principal-ownership-of-sessions-workspaces-and-profiles.md) §8, [ADR-0067](0067-f18-approver-endpoint-identity-boundary.md) §§5 and 7, [APPROVALS.md](../APPROVALS.md) §7 · **Leaves unchanged:** ADR-0022's remote channel (a response MAC keyed by a paired device, over the binding hash), [ADR-0021](0021-approval-binding-v2.md)'s binding, DWKP, the private protocol, the store and every decision

> **There is one door for a local approval: the approver endpoint.** A
> terminal passed over the runtime's socket and a `direwolf approve` that
> speaks DWKP as the runtime's uid are withdrawn. The endpoint authenticates
> a **principal** -- a kernel-reported uid the operator declared, disjoint
> from every runtime's, the broker's and the authority's. It does not prove
> a person decided: that is the deployment's (assurance A1) or a presence
> factor's (A2), and this record says which is which.

## Context

[ADR-0022](0022-approval-response-authentication.md) is Accepted and names
three delivery paths. Two of them put the approval on the runtime's side of
the boundary:

- **CLI-local** passes the CLI's controlling terminal to the authority over
  the DWKP socket and has the authority draw the prompt and read the key on
  it, after checking the descriptor is a terminal of the peer's session.
- **Detached-local** is `direwolf approve`, "a local DWKP client
  authenticated by socket peer credentials".

F-18 ([ADR-0063](0063-principal-ownership-of-sessions-workspaces-and-profiles.md)
§8) found that the DWKP socket is the runtime's endpoint, reached as the same
uid as the CLI: a runtime that passes a pseudo-terminal it controls answers
its own prompt, and a DWKP client as that uid is the runtime as far as the
kernel can tell. ADR-0063 withdrew the first and stopped the runtime's
endpoint receiving any descriptor (TX061);
[ADR-0067](0067-f18-approver-endpoint-identity-boundary.md) built a separate
approver endpoint, identity boundary only, and recommended a trusted approver
client (§5). Both are Proposed, and neither says it amends ADR-0022, so the
Accepted record still prescribes both paths (ISR2-05). What is built is
safe -- no descriptor is received, no approval operation exists, every
`REQUIRE_APPROVAL` denies -- but M6 must not build ADR-0022's paths as
written, and the records should say so before it starts.

The second review also observed (ISR2-06) that an approver uid is not a
person: an agent, a script or a scheduled job run as that uid passes the
endpoint's check exactly as a human does. ADR-0063 OD-1 already says two
people who share a uid are one approver; nothing yet says what a decision
under that uid proves.

## Decision

### 1. One door

A local approval, a denial and a standing grant's creation are accepted
only on the approver endpoint ([ADR-0067](0067-f18-approver-endpoint-identity-boundary.md)),
from a peer whose kernel-reported uid is one the operator declared with
`--approver-uid` -- never a runtime's, the broker's or the authority's, with
no override. ADR-0022's **CLI-local** and **Detached-local** paths are
withdrawn:

- no descriptor carries an approval, a prompt or a keystroke: neither
  endpoint receives one (TX061 covers both);
- nothing on the DWKP endpoint is an approval, whatever its fields say
  (ADR-0067 §4: every approval-shaped member is an unknown field);
- `direwolf approve`, when M6 builds it, is the **trusted approver client**
  below, run as an approver uid against the approver endpoint -- not a DWKP
  peer.

ADR-0022's **remote** channel is untouched: a device paired out of band
MACs the binding hash, and the relay stays outside the approval TCB. Where it
enters the authority is M6's (or later) to place; it is not the runtime's
endpoint either.

### 2. The trusted approver client

A separate program, run as an approver uid, that:

1. connects to the approver endpoint and is admitted by its uid alone;
2. receives the authority's rendered request **as data** -- the canonical
   action, the binding fields and the binding hash ([APPROVALS.md](../APPROVALS.md)
   §§1-2, §6), agent-authored text quarantined and labelled -- and renders
   it itself, on a terminal its own uid owns;
3. returns a decision bound to that request's identifier and binding hash,
   which the authority re-verifies, burns once, and records with the
   approver's uid and the channel.

The runtime is another uid: it cannot write to that terminal, `ptrace` the
client, or reach the endpoint as an approver. The prompt's integrity is the
client's and its terminal's, under the approver's uid.

### 3. A principal, not a person: assurance levels

The endpoint authenticates a uid. What a decision under it proves depends on
what else runs as that uid, which the authority cannot see:

| Level | What the operator provides | What a decision proves | What it does not |
|---|---|---|---|
| **A0** | an approver uid that is also a user's everyday account, where agents, editors' assistants or automation run | that a process of that uid answered | that a person did; an agent run as the user is indistinguishable |
| **A1** | a **dedicated approver account**: used for approving and nothing else, no coding agent, assistant, scheduled job or runtime runs as it, its login reached only by the person who approves | that the approver principal answered, and -- on the deployment's word -- that it was the person | presence: unattended automation the operator later starts as that account would pass |
| **A2** | A1, plus a **presence factor** the authority verifies over the binding hash (for example a FIDO2/WebAuthn assertion with user presence, or an equivalent the kernel checks) | that a person holding the factor was present for this action | that the person read the prompt; consent is presence plus a correct rendering |

- The authority records the level a decision was made at. It never reports
  A1 as A2, nor any level as more than the configuration provides.
- An operator who names an approver uid declares at least A1 for it; the
  documentation says so ([OPERATIONS.md](../OPERATIONS.md) §4). The
  authority checks what it can (the uid is disjoint from every runtime's,
  the broker's and the authority's) and cannot check the rest.
- Which classes need A2 is an owner decision (OD-2); the recommended set is
  the high-risk classes ADR-0022 already names -- `DESTRUCTIVE`,
  `secret.use`, host execution -- and the creation of a standing grant. Until
  a presence factor exists, a class that needs A2 is not approvable: its
  `REQUIRE_APPROVAL` stays `DENY`.

### 4. What no channel accepts

- **A coding agent's own approval.** An external agent's permission prompt,
  its "auto-approve" or "skip permissions" mode, a remembered approval, and
  any approval token it holds are the agent's state, not the kernel's: on
  DWKP they are unknown fields (ADR-0067 §4), and an agent is a contained
  workload or a client, never an authority
  ([ADR-0051](0051-external-agent-interoperability.md), Proposed).
- **Unattended consent.** No approver connected, no decision before the
  approval's expiry, or no approver endpoint at all: `REQUIRE_APPROVAL`
  degrades to `DENY` ([APPROVALS.md](../APPROVALS.md) §8), and expiry is not
  denial.
- **Self-approval.** An approval whose approver is its requester is refused,
  whatever the uids: ADR-0063 §8 requires it of M6's store.

### 5. Before M6

Nothing changes in the build. The approver endpoint keeps holding no
approval operation (ADR-0067 §6, TX065), every run a runtime admits is
`api` (TX062), and every `REQUIRE_APPROVAL` denies.

## Consequences

- M6 has one approval channel to build and test, not three; the
  terminal-over-DWKP design cannot be implemented by reading ADR-0022 alone.
- An operator who wants approvals provisions a dedicated approver account
  (A1) at least; one who wants high-risk actions approvable also needs the
  presence factor M6 or a later milestone builds (A2).
- An audit record of an approval says which level it was made at.

## Alternatives considered

- **Keep ADR-0022's terminal path and verify the descriptor harder.**
  Rejected (ADR-0067 §5): a descriptor proves it is a terminal, not whose,
  and the checks that would prove the runtime holds none of it need the
  authority to scan other processes' descriptors.
- **Treat the approver uid as proof of a person.** Rejected: any process of
  that uid passes the same check, and the record would claim what nothing
  measured.
- **Require a presence factor for every approval now.** Not decided here: it
  makes M6 depend on an authenticator before any approval works. OD-2 is the
  owner's.
- **Amend ADR-0022 inside ADR-0063 or ADR-0067.** Rejected: both are
  Proposed records about ownership and the endpoint's identity; the
  withdrawal of an Accepted record's paths, and the meaning of an approver
  uid, are a decision of their own.

## Residuals

- At A1, a decision proves the approver principal, and a person only on the
  deployment's word.
- At A2, presence is proven, reading is not: the rendering's correctness and
  fatigue limits ([APPROVALS.md](../APPROVALS.md) §8) carry that.
- Root on the host can be any uid; the approval boundary, like every
  boundary here, assumes root is the operator.

## Owner decisions

- **OD-1** accept the withdrawal of ADR-0022's CLI-local and detached-local
  paths: one approval channel, the approver endpoint. Recommended; M6.0's
  prerequisite, with ADR-0063 and ADR-0067.
- **OD-2** which classes need A2 before they are approvable, and whether M6
  builds a presence factor or leaves those classes `DENY` until one exists.
  Recommended: the high-risk classes and standing grants need A2; M6 ships
  A1 for the rest and leaves the A2 classes denied until the factor exists.

## Evidence

A decision record; nothing is built. The boundary it builds on is evidenced
in ADR-0067: the approver endpoint's three-identity suite ("approver
evidence: 1 test, 6 cases contained, three identities") in CI #213's
`authority boundary` job (run 45250010413, `8b771a7`), and
`transport_approver` with `make approver-identity-mutations` 13 of 13 killed
(re-run by the second security review).

## Revisit if

A presence factor is built; the approver endpoint gains an operation; a
remote channel is placed; or a platform offers a way to prove a terminal's
owner and every holder of it.
