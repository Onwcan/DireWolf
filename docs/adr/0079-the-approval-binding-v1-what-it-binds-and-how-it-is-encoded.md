# ADR-0079: The approval binding v1 -- what it binds, and how it is encoded

**Status:** Proposed · **Date:** 2026-11-24 (M6.1; built and tested locally, hosted evidence pending; nothing stores, asks for or spends a binding) · **Amends, on acceptance:** [ADR-0021](0021-approval-binding-v2.md) (its field set: `requester` and `schema` join it, and `environment_profile` and `agent` are defined as the code can produce them) · **Builds on:** [ADR-0032](0032-wire-contract-framing-strict-json-and-jcs.md) (RFC 8785), [ADR-0063](0063-principal-ownership-of-sessions-workspaces-and-profiles.md) (the requester is a principal), [ADR-0067](0067-f18-approver-endpoint-identity-boundary.md) §7 (the requester's principal proposed for the binding), [ADR-0062](0062-taint-follows-delivered-content.md) (taint), [ADR-0076](0076-isr2-01-audit-level-full-is-not-kept-on-a-net-http-hop.md) (an obligation a route cannot keep), [ADR-0078](0078-approval-assurance-which-classes-need-a2-and-the-presence-factor.md) (assurance) · **Leaves unchanged:** DWKP, the private protocol, the store (schema 14), the audit log, the shipped packs, every route's decision and every accepted decision

> **A binding names exactly what an approval would cover, and grants
> nothing.** Thirteen members, each from a value the authority decided,
> resolved or recorded -- never from what a runtime says -- encoded with RFC
> 8785, every integer a decimal string, every set sorted and duplicate-free;
> `binding_hash = SHA256(JCS(binding))`. A binding that cannot name every
> member is refused, never defaulted. It is built in the state layer, stored
> nowhere, crosses no protocol and is consulted by nothing until M6.2's
> registry.

## Context

[ADR-0021](0021-approval-binding-v2.md) and [APPROVALS.md](../APPROVALS.md)
§2 name the binding's fields; ADR-0032 fixed its encoding as `SHA256(jcs(...))`
and records that "nothing is hashed or MACed yet". M6.1 encodes the first
version. [M6_IMPLEMENTATION_PLAN.md](../M6_IMPLEMENTATION_PLAN.md) §4 mapped
every field to a producer in the code and found two fields with nothing
behind them: `environment_profile_id` (`policy::Environment` is `Sandbox` or
`Host` and carries no profile id) and `agent_id` (no agent id exists; a run
is admitted under an agent profile). It also proposed the requesting
principal (ADR-0067 §7) and a schema member. This record decides all of it,
as built in `crates/dwkd-authority/src/state/binding.rs`.

## Decision

### 1. The object

Thirteen members, every one always present:

| Member | Trusted producer | Canonical form |
|---|---|---|
| `schema` | constant | `"direwolf.approval.binding.v1"` |
| `verb` | the decision's required capability's verb (`policy::Decision`, `capability::Verb`) | `"fs.write"` |
| `resource_identity` | §3 | a tagged object |
| `canonical_args` | §4 | a tagged object |
| `workspace` | the run's session's workspace (`session_workspace`) and its root as recorded (`workspace_root`) | `{"id", "root": {"device", "inode", "birth"}}` |
| `environment_profile` | §5 | a tagged object |
| `credential_handles` | each secret's current revision (`state/secrets.rs`) | a set of `{"handle", "revision", "metadata_sha256"}` |
| `agent` | the run record's `agent_profile` and `agent_profile_revision` | `{"profile", "revision"}` |
| `requester` | the run record's `subject`: the uid the kernel reported at admission (ADR-0063) | `"uid:N"` |
| `scope` | §6 | a tagged object |
| `taint_level` | the run's stored taint, read by `taint::run_taint` (ADR-0062) | `"NONE"`, `"LOCAL_UNVERIFIED"`, `"EXTERNAL_UNTRUSTED"` |
| `privacy_class` | the required capability's `privacy_class` constraint | its spelling, or `null` |
| `obligations` | the decision's obligations, only where the route keeps every one (§7) | a set of tagged objects |

The requester is the principal that asked. It is not, and is never confused
with, an approver: the approver's identity is the registry's (§8).

### 2. Encoding

- **RFC 8785** through `dwk_proto::json::to_canonical_bytes`, the one
  canonicaliser (ADR-0032); **SHA-256** of those bytes through the state
  layer's digest; the hash is 64 lowercase hex digits. No second encoder, no
  domain-separated prefix: the `schema` member is the domain. JCS sorts it
  among the other members (it is not first); its presence is what separates
  a binding from every other hashed object.
- **Every integer is a decimal string** -- a device, an inode, a byte count,
  a revision, a port, a birth time -- with no sign but a negative value's `-`
  and no leading zero. A binding holds no JSON number and no boolean, so no
  value is ever an IEEE-754 double and none rounds into another; one field
  has one representation, whatever its value.
- **Every set** is an array sorted by its members' canonical bytes, compared
  unsigned byte by byte; a member twice is refused; an empty set is `[]`
  where a set may be empty and refused where it may not. An ordered value
  (argv) keeps its order.
- **Every variant** is an object carrying `kind`. A `null` means the decided
  value is absent (a root with no recorded birth time, a sandbox with no
  relay, a capability with no privacy constraint) -- never a value nobody
  could produce.
- **No Unicode normalisation.** A string is bound as it was decided or
  resolved; JCS escapes only what JSON must.

### 3. Resource identity, by route

| Kind | Members | Producer |
|---|---|---|
| `file` | `device`, `inode` | the filesystem resolver's `FileIdentity` of the opened object |
| `vacant` | `parent` (`device`, `inode`), `name` | the resolver's checked parent directory and validated absent name (`fs.write` or `fs.create` only) |
| `executable` | `path`, `sha256` | the executable resolver's `ExecutableIdentity`, or the image manifest's (ADR-0052) |
| `host` | `host`, `port`, `addresses` | the decided name, the port and every address the guard pinned (at most 64, ADR-0074) |
| `credential` | `handle` | `secret.use`'s handle; its revision is `credential_handles`' |

A file is its identity, never its name: two hard links to one inode are one
resource (APPROVALS.md §2), and a file replaced at the same path is another.
A verb with no canonical identity producer -- `model.*`, `browser.*`,
`mcp.*`, `agent.*` and the rest -- has no binding (§9).

### 4. Canonical arguments, by route

| Kind | Members | For |
|---|---|---|
| `fs` | `byte_count` | an fs verb that moves no content, or reads a bound of it |
| `fs_content` | `byte_count`, `content_sha256` | `fs.write` (required: a count alone lets one body stand for another) and a creating `fs.create` |
| `argv` | `argv` (ordered) | `process.exec`: the checked arguments, within DWKP's argv bounds |
| `http` | `method`, `url_sha256`, `body_bytes`, `body_sha256` | `network.https`: the URL as the hop's own digest and the body as a digest and a length -- never the URL's path or query, a header value or the body (ADR-0050 §13) |
| `none` | -- | `secret.use` |

### 5. The environment profile

The plan's mismatch is resolved here: the binding does not invent a profile
id. It binds what the authority actually has.

- `{"kind": "host"}` for an action decided in `Environment::Host`.
- For an action decided in `Environment::Sandbox`: `runtime`, `socket`,
  `image` (`sha256:` digest), `probe_sha256`, `topology`, `relay_sha256`
  (`null` without a proxy) from the operator's `SandboxConfig`, and
  `assurance` -- the **effective** level the environment's measurement
  earned (`sandbox::Judgement`). Only a measurement that makes the
  environment usable binds; a name is never taken for a posture.

The environment kind must be the one the action was decided in: a sandbox
binding is never a host binding, and neither is built for the other.

### 6. Scopes

The `scope` member is the matched rule's `ApprovalSpec` kind with its
resolved payload; the kind must equal the rule's.

| Kind | Payload |
|---|---|
| `exact_action` | -- |
| `path_set` | `verb`, `files` (a set of `{device, inode}`, 1 to 64) |
| `path_subtree` | `root` (`{device, inode}`), `verbs` (a set) |
| `executable_and_argv` | `executable` (`{path, sha256}`), `argv_allowlist` (a set of tokens: `capability::ArgvAllowlist`) |
| `host_and_methods` | `host`, `port`, `addresses`, `methods` (a set) |
| `credential_use` | `handle`, `host`, `port` |

A scope is a descriptor, never a membership proof. At grant time the action
that asks must be within the scope it asks for, on what the binding can see
(a path set holds its file and its verb; a subtree holds its verb; a host
scope is its host with its method; an executable scope is its executable; a
credential scope names a credential the action carries) -- or the binding is
refused. At spend time each action is canonicalised on its own and its
membership checked by the registry (M6.2); two actions within one scope are
two uses, never one action. A subtree's containment of a file needs the
resolver and is the spend's.

### 7. Taint, privacy class and obligations

- `taint_level` is the run's taint as the store holds it when the binding is
  built: clean and tainted are two bindings, so approve-clean-spend-tainted
  cannot match. Whether the current taint is above it at spend is the
  registry's check.
- `privacy_class` is the required capability's constraint. Only `model.call`
  carries one, and it has no binding yet, so for every verb a binding is
  built for today the member is `null`; it is bound so that it cannot later
  change unnoticed.
- `obligations` are the decision's, each an explicit tagged object with its
  parameter as a named member (`{"bytes": "262144", "kind":
  "max_output_bytes"}`) -- never a rendering of the type. They are bound
  **only** where the route keeps every one, by the route's own test (the
  same answer it gives for an `ALLOW`); otherwise no binding is built
  (`OBLIGATION_UNENFORCEABLE`), so a binding never shows an obligation as
  kept that is not, `audit_level=full` on a hop among them (ADR-0076).

### 8. What is not hashed

The hash names what is approved. The registry checks the rest independently,
in the spending transaction:

| Field | Checked by | When | Status |
|---|---|---|---|
| run id (run-scoped approvals) | registry | spend: equal | M6.2 |
| policy revision | registry | spend: equal, or void | M6.2 |
| lease tenure, epoch, incarnation | registry under ADR-0064's gate | spend: still live | M6.2 |
| request id, nonce | registry | grant and spend: single use | M6.2, M6.3 |
| `not_after`, `max_uses`, `uses` | registry | spend: in time, under the count, atomically | M6.2 |
| revocation, ownership | registry | spend: not revoked, still the run's subject | M6.2 |
| approver, channel, assurance | approver endpoint and registry | grant: an approver, not the requester, at the level the class needs (ADR-0078) | M6.3 |
| current taint not above the bound one | registry | spend | M6.2 |

The TTL and `max_uses` a rule states are not hashed: they are spend guards,
and one hash serves a standing grant with its own life and count. Nothing in
this table is silently dropped: each is a named M6.2 or M6.3 obligation.

### 9. Construction fails closed

A binding is built only from a `REQUIRE_APPROVAL` decision naming an approval
shape, for the canonical action that decision was made on, and only when
every member exists and fits. Otherwise it is refused, by name:
`NOT_APPROVABLE`, `ACTION_MISMATCH`, `SCOPE_MISMATCH`, `RESOURCE_MISMATCH`,
`ARGUMENTS_MISMATCH`, `ENVIRONMENT_MISMATCH`, `ENVIRONMENT_UNUSABLE`,
`OBLIGATION_UNENFORCEABLE`, `CREDENTIAL_UNAVAILABLE` (a revoked, removed or
unconfigured revision), `RUN_UNAVAILABLE` (an unknown or ended run),
`DUPLICATE_MEMBER`, `EMPTY_SET`, `TOO_MANY_MEMBERS`, `TOO_LARGE`,
`MALFORMED`. No member is ever an empty string, a zero digest or a wildcard
in place of a value the authority does not have.

### 10. Bounds

Every set holds at most 64 members; argv is held to DWKP's own bounds; the
canonical bytes are refused past 1 MiB, above the worst case bounded inputs
can reach (a maximal argv of control characters, each escaped as six bytes).
A host name is at most 253 characters, a leaf name at most 255 bytes.

### 11. Where it lives, and what it cannot do

`crate::state::binding`: every constructor is visible only inside the state
layer, and each takes the producer's own type (a resolver's `FileIdentity`,
an `ExecutableIdentity`, a `Decision`, a `SandboxConfig` and its
`Judgement`, a secret's current revision) or the run's record. Nothing reads
a binding to allow anything; no route calls the module; the store, the audit
log and DWKP are unchanged. Until M6.2 the production build carries the
module with no caller, said in its code (`expect(dead_code)`) rather than
hidden behind a call that does nothing. TX066 keeps the module from writing,
permitting, reaching the broker or a dispatcher, or reading a clock; TX067
keeps every other module, the runtime included, from naming it.

## Consequences

- M6.2's request record has one canonical, tested name for what it asks.
- The two field mismatches the plan found are closed by binding what exists
  (an environment's configuration and measurement; a profile and its
  revision), not by inventing identifiers.
- ADR-0021's field list, once this is accepted, reads with `requester` and
  `schema` added and with `environment_profile` and `agent` as defined here.

## Alternatives considered

- **The file's path beside its identity.** Rejected: APPROVALS.md §2 binds
  identity, not name; a path the policy decided on is re-decided at spend.
- **JSON numbers for integers that fit a double.** Rejected: one field, one
  representation, whatever its value.
- **TTL and `max_uses` in the hash.** Rejected: spend guards, and a standing
  grant's hash must not depend on one prompt's TTL.
- **The run id in the hash.** Rejected, as the plan's §4.2: one hash serves a
  standing grant; a run-scoped approval's run is a spend guard.
- **A domain-separated digest (`DomainHash`).** Rejected: ADR-0021 and
  ADR-0032 fix `SHA256(jcs(...))`; the schema member separates.
- **Computing a binding on every `REQUIRE_APPROVAL` now.** Rejected: with no
  registry it would be computed and discarded -- a store read per decision
  that proves nothing. M6.2 wires it where a request is recorded.

## Residuals

- `privacy_class` is `null` for every verb a binding is built for.
- `executable_and_argv`'s allowlist has no source yet: no policy field offers
  one (M6.4 decides it, with standing grants).
- A subtree's containment is checked at spend, not at grant.
- Hard links alias by design.
- A digest of a low-entropy URL or body can be guessed by someone who sees
  the binding; no secret value or credential is ever bound, and a binding is
  shown only to an approver.
- **For the owner, observed while building this:** the fs route, the
  kernel-performed `net.http` hop and host process execution are all decided
  in `Environment::Host` in the code. ADR-0078 §1 recognises "host
  execution" as `Environment::Host` (any verb), so as written every fs and
  `net.http` approval is an A2 class and stays `DENY` through M6, and only
  sandboxed workload actions are approvable at A1. Nothing here changes
  that; M6.3 implements it as written unless a decision narrows it.

## Owner decisions

- **OD-1** The field set, encoding and producers of §§1-7 (recommended as
  written).
- **OD-2** A file bound by identity alone (hard links alias) (recommended).
- **OD-3** TTL, `max_uses` and the run id outside the hash, as §8's registry
  obligations (recommended).
- **OD-4** `executable_and_argv`'s payload as the executable identity and an
  argv allowlist, its policy source left to M6.4 (recommended).
- **OD-5** A `net.http` request's body bound by digest and length
  (recommended).

## Evidence

Local, 2026-11-24 (WSL2, Linux): the golden vectors agree with an
independent, test-only oracle (`tests/protocol/test_approval_binding_vectors.py`);
the property, adversarial and refusal tests and the Linux real-authority
tests pass; the mutation campaign is recorded in
[M6_1_IMPLEMENTATION.md](../M6_1_IMPLEMENTATION.md). Hosted: pending -- `make
test` on Linux, Windows and macOS after the change is committed.

## Revisit if

M6.2's registry needs a member this record does not bind; a route gains a
canonical identity producer (a verb joins §3); the agent loop introduces an
agent identity; a presence factor changes what an approval records; or the
encoding has to change -- which is a new schema string, never this one
reread.
