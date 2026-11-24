# ADR-0078: Approval assurance -- which classes need A2, and the presence factor

**Status:** Proposed · **Date:** 2026-11-24 (ADR-0077's OD-2, moved here so that ADR-0077 could be accepted without deciding it; a decision record only -- nothing is built, and no approval operation exists; nothing here is accepted) · **Builds on:** [ADR-0077](0077-the-approval-channel-is-the-approver-endpoint-and-an-approver-uid-is-a-principal-not-a-person.md) §3 (assurance levels A0, A1, A2), [ADR-0067](0067-f18-approver-endpoint-identity-boundary.md) §7 (what M6 builds on the endpoint), [ADR-0045](0045-m4d-process-execution-broker.md) (the host floor) · **Leaves unchanged:** DWKP, the private protocol, the store, the shipped packs and every decision made today

> **High-risk classes need a person, not only a principal.** Host execution,
> `secret.use`, `fs.delete` and a standing grant's creation are approvable
> only at A2 -- a presence factor the authority verifies over the binding
> hash. Until such a factor is built and verified, they stay `DENY`. Every
> other class is approvable at A1, a dedicated approver account. A0 is never
> enough, and A1 is never recorded as A2.

## Context

ADR-0077 makes the approver endpoint the one door for a local approval and
says what a decision through it proves: at **A1** -- a dedicated approver
account no agent or automation runs as -- that the approver principal
answered, and a person only on the deployment's word; at **A2** -- A1 plus a
presence factor the authority verifies -- that a person holding the factor
was present for that action. It left two questions open (its OD-2): which
classes need A2, and whether M6 builds a presence factor.

The classes have to be ones the authority can recognise mechanically from
the canonical action, not prose. "DESTRUCTIVE" in
[CAPABILITIES.md](../CAPABILITIES.md) §1 and the reason
`DESTRUCTIVE_IN_WORKSPACE` are policy metadata, not a class the code knows;
the canonical verb and the environment are.

M6's roadmap deliverables -- the binding hash, the registry, standing grants,
kernel-rendered prompts, the budget ledger, unattended `DENY`
([ROADMAP.md](../ROADMAP.md), M6) -- do not include enabling host execution.
[ADR-0045](0045-m4d-process-execution-broker.md)'s host floor needs a
per-invocation approval "so that no production build launches anything
before M6": M6 makes such an approval possible, and whether a host launch is
then allowed is this record's question.

## Decision

### 1. The A2 classes

An action needs A2 when its canonical form is any of:

| Class | Recognised by | Why |
|---|---|---|
| host execution | `Environment::Host` (any verb) | the broker's own privileges, outside every environment's containment |
| credential use | the verb `secret.use` (including a `net.http` hop's own `secret.use` action) | a credential's value leaves the authority |
| deletion | the verb `fs.delete` | the one file verb whose effect no later action undoes |
| a standing grant | its creation on the approver endpoint (an operator act, not a DWKP action) | it outlives the prompt and spends without one |

Everything else that a rule sends to `REQUIRE_APPROVAL` is approvable at A1.
The set is a floor: a policy may ask A2 for more, never for less; the
authority takes the stricter of the policy's and this table's.

### 2. Until a presence factor exists

An A2 class is not approvable: its `REQUIRE_APPROVAL` stays `DENY` (reason
`APPROVAL_ASSURANCE_UNAVAILABLE`, or the existing denial until M6 names it),
whatever an approver answers. No configuration flag lowers it to A1. An A1
decision for an A2 class is refused and audited, never spent.

### 3. M6 does not enable host execution

M6 builds the approval path for A1 classes and the gate for A2 classes, and
proves that gate denies; it does **not** make a host launch possible. M6.6 is
therefore "host execution under approval: wired, and shown to `DENY` without
A2", not "host execution enabled". Enabling it needs a presence factor (§4),
its own hosted evidence and a decision of its own; no milestone report calls
host execution complete before then.

### 4. The presence factor is a decision of its own

Building A2 adds an authenticator to the trusted computing base. The
candidates, as architecture options -- none is selected here:

| Option | What it proves | TCB in the authority | Platform | Offline | Replay | Recovery |
|---|---|---|---|---|---|---|
| **FIDO2 / WebAuthn user presence** (CTAP2 authenticator; assertion over the binding hash and the request nonce) | a person touched a registered authenticator for this action | ECDSA P-256 (or Ed25519) verification and COSE/CBOR parsing -- new dependencies, an amendment of ADR-0019's set | the trusted client needs the authenticator (USB HID, `hidraw` on Linux; NFC/BLE elsewhere) | yes | signature counter and the single-use nonce | register two or more; loss is an offline operator re-enrolment |
| **A paired device's MAC** (ADR-0022's remote channel, used locally) | the paired device answered; presence is the device's own unlock | HMAC-SHA-256 only (already linked) | a phone app and a pairing ceremony | needs a path from device to client | the device nonce and `not_after`, as ADR-0022 | re-pair |
| **TOTP entered in the trusted client** | someone with the seed's device read a code within its window | HMAC-SHA-1 | none | yes | burned per window; not bound to the action | re-seed |
| **OS re-authentication** (PAM or polkit in the client) | someone knew the approver's password at that moment -- verified by the client, not the authority | none | Linux PAM | yes | none the authority sees | password reset |

Only the first two bind the factor to the action, and only the first proves
a person without a second device's own security. OS re-authentication is
verified outside the authority and is not A2 under ADR-0077's definition.
The recommendation, for that later decision: FIDO2 user presence, verified by
the authority, with the dependency review ADR-0019's rule requires.

## Consequences

- An operator can approve sandboxed, non-credential, non-deleting actions at
  A1 once M6.3 is built.
- `secret.use`, `fs.delete`, host execution and standing grants are denied
  through all of M6 unless the presence-factor decision is taken and built
  inside it; the shipped packs' `deny-approval-needed-when-unattended` and
  the host floor keep deciding them.
- Every approval's record names its level.

## Alternatives considered

- **A1 for everything, A2 later.** Rejected: a credential's use, a deletion
  and a host launch approved by whatever runs as the approver account is the
  failure ADR-0077 names.
- **A2 for everything.** Rejected for now: no approval works until an
  authenticator is built, and the A1 classes are bounded by the sandbox,
  the egress ceiling and their obligations already.
- **Build FIDO2 inside M6.** Possible, as a separately verifiable M6.3b
  checkpoint before any A2 class is enabled; not chosen here, because it
  grows the authority's dependency set and that needs its own review. The
  owner may choose it (OD-3).

## Residuals

- At A1, a decision proves the principal; the person is the deployment's
  word.
- The A2 classes stay unavailable for as long as no factor exists, and a
  deployment that needs them waits.

## Owner decisions

- **OD-1** the A2 classes of §1 (recommended as written).
- **OD-2** A2 classes `DENY` until a verified factor exists, with no
  override (recommended).
- **OD-3** whether M6 builds the presence factor (recommended: no -- a
  decision of its own after M6, with FIDO2 user presence the candidate) and,
  if it does, as M6.3b before M6.4's high-risk grants and M6.6's enablement.

## Evidence

A decision record; nothing is built. M6.3's evidence must show an A1
approval spent for an A1 class, and refused for each A2 class; M6.6's that a
host launch is denied with and without an A1 approval.

## Revisit if

A presence factor is built; a policy needs a class this table does not
recognise; or the roadmap places host execution in a milestone.
