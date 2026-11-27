# M6 implementation plan: Approvals and budgets

**As of 2026-11-24 (M6.0).** The bounded plan for M6
([ROADMAP.md](ROADMAP.md): binding hash; approval registry with scopes,
expiry and single-use burn; standing grants with the 90-day cap and
`require_untainted_run`; kernel-rendered prompts; hierarchical subtractive
budgets; unattended `DENY`). **Nothing of M6.1 to M6.7 is built**, no
approval operation exists, and no approval, grant or budget authority is
active. The decisions it rests on are
[M6_0_DECISION_PACKAGE.md](M6_0_DECISION_PACKAGE.md); what came before is
[M6_PREPARATION_HANDOFF.md](M6_PREPARATION_HANDOFF.md). The milestone order
stays M6 → M3.5 → M7 → M8 → M9.

The phase labels M6.1 to M6.7 are this plan's, not roadmap milestones.

## 1. Baseline

| | |
|---|---|
| Revision | `0bd727d` on `main` (`0bd727ded1ce8aea25764efcae67c8b7ef5ef99b`), equal to `origin/main` |
| CI | #216, [run 45276662436](https://github.com/Onwcan/DireWolf/actions/runs/45276662436): attempt 2 succeeded, 33 of 33 job records; attempt 1's only non-success was `tests (make test) (macos-latest)`, cancelled, which made its aggregate `CI` job fail |
| Push workflow (CodeQL) | #34, [run 45276662285](https://github.com/Onwcan/DireWolf/actions/runs/45276662285): 4 of 4 |
| Namespace evidence | `sandbox egress`: `namespace evidence: 5 tests, 10 markers, each exercised` -- F-16's six cases, F-05's two, the hidden-pid peer reader, and the bind mount inside a workspace refused `MOUNT_CROSSING` |
| Approver boundary | `authority boundary`: "approver evidence: 1 test, 6 cases contained, three identities" |
| Ownership | `authority boundary`: the cross-uid ownership tests; `sandbox agent`: `i09-runtime-holds-only-what-the-operator-declared` at `hosted-three-identity` |
| `net.http` | 193 cases, `obligation-unenforceable` among them |
| Not exercised hosted | a casefold filesystem (`canonical filesystem` lists it NOT EXERCISED, with the cross-device link; the bind mount is NOT EXERCISED in that job by design and exercised in `sandbox egress`) |
| Store schema | 14 (`state/schema.rs` `CURRENT_VERSION`) |
| Records | ADR-0075 Accepted; ADR-0063, ADR-0067, ADR-0077 (OD-1) accepted 2026-11-24, recorded in `5520ab8`; ADR-0078 (OD-2) accepted 2026-11-24; ADR-0062, ADR-0076 and ADR-0079 accepted 2026-11-25; ADR-0064 and ADR-0080 accepted 2026-11-27 |

## 2. The M6.0 gate

| Gate | Needs | State |
|---|---|---|
| **M6.0a** the channel and the principal | ADR-0063, ADR-0067, ADR-0077 OD-1 | **met**: recorded in `5520ab8`; CI #218 at `6475172`, 33 of 33 |
| **M6.0b** the assurance policy | ADR-0078 (OD-1 to OD-3) | **met**: accepted 2026-11-24, as recommended |
| M6.1's own record | [ADR-0079](adr/0079-the-approval-binding-v1-what-it-binds-and-how-it-is-encoded.md), amending ADR-0021 (§4 below) | **Accepted** 2026-11-25, OD-1 to OD-5, on CI #225's evidence |

Both are met: M6.1 may start, and M6.3 starts with its assurance policy
decided.

## 3. Security invariants for M6.1 to M6.7

Each is a property a phase's tests must hold, not an aspiration. Changing one
is a new ADR.

1. **The runtime is never an approver.** Approval-shaped input on DWKP is an
   unknown field; no descriptor is received on either endpoint (TX061); a
   coding agent's permission mode, remembered approval or token is never
   authority (ADR-0067 §4, ADR-0077 §4).
2. **The approved action is immutable.** An approval covers the canonical
   action and context it was granted for; an action changed after approval
   is denied (`approval.drift_detected`) or needs a new approval.
3. **An approval is not transferable** between principals, agents, runs,
   resources, environments or security states; a parent and a child never
   spend each other's.
4. **Single use is transactional.** With `max_uses = 1`, of two concurrent
   spenders exactly one succeeds; the burn commits with the effect's intent,
   inside ADR-0064's gate; no crash or restart resurrects a spent use.
5. **Revocation is authoritative.** A revoked approval, a changed policy
   revision, a risen taint, a new tenure or epoch, a reaped run and a revoked
   ownership each leave no spendable approval.
6. **Obligations are enforceable.** An approval binds the decision's
   obligations, and only obligations the route keeps (ADR-0076); a spend
   never reports one kept that was not.
7. **Displayed content cannot make authority.** The trusted client renders
   the kernel's canonical data; agent prose is a separate, labelled region,
   and nothing in it changes what is bound.
8. **Unattended stays `DENY`.** No decision within the window means no
   execution; `approval.expired` and `approval.denied` stay distinct, and only
   denials count toward fatigue (APPROVALS.md §8).
9. **Standing grants never widen.** Never created from a prompt; a hard
   90-day cap; bound to a principal and an agent; `require_untainted_run` by
   default; listed and revocable.
10. **Budgets subtract.** A child's allowance is reserved from its parent's;
    fan-out mints nothing; overflow, underflow and races refuse; settlement
    returns at most what was reserved.
11. **Host-local execution stays disabled** without the operator's opt-in, a
    per-invocation approval, the assurance ADR-0078 requires, executable and
    environment identity at use, and the confinement ADR-0070 OD-D decides.
    Nothing in M6.0 changes it.
12. **Assurance is never overstated.** A0 never suffices; an approval records
    the level actually provided; A1 is never A2; an A2 class without a
    verified factor is `DENY`.

## 4. The binding contract (M6.1's input)

[APPROVALS.md](APPROVALS.md) §2 and [ADR-0021](adr/0021-approval-binding-v2.md)
(as amended by [ADR-0032](adr/0032-wire-contract-framing-strict-json-and-jcs.md):
`SHA256(jcs({...}))`) name eleven fields; APPROVALS.md adds a schema member.
Nothing has ever been encoded (ADR-0032: "Nothing is hashed or MACed yet"),
so M6.1 encodes the first version. Its record amends ADR-0021 for two
additions ADR-0067 §7 proposes or this plan finds necessary: the requesting
principal, and the schema member.

### 4.1 Encoding

- **JCS** through `dwk_proto::json::to_canonical_bytes` (`dwk-proto/src/json/jcs.rs`),
  the one canonical encoding (ADR-0032, key rule per ADR-0034); **SHA-256**
  through the authority's own `Sha256Hash` (`state/digest.rs`). No new
  dependency.
- **Domain separation:** the object's member
  `"schema": "direwolf.approval.binding.v1"` (JCS sorts it among the
  others; ADR-0079 §2); a later field set is a new schema string, never a
  reinterpretation.
- **Integers past 2^53 - 1** -- a device or inode number, a byte count --
  are decimal strings: DWKP's integers stop there (`wire::scalar`), and a
  JCS number is an IEEE-754 double.
- **Sets** (inodes, handles, addresses, obligations) are sorted arrays of
  their canonical strings, duplicates refused.
- The binding is computed in `dwkd-authority`. The runtime never computes
  one; the trusted client receives it as data. Golden vectors under
  `tests/protocol/vectors` only if a second implementation (Python) ever
  computes it -- none is planned.

### 4.2 Fields

"Hash" means inside `binding_hash`; "spend" means re-derived or checked in
the spending transaction. The producer is where the value comes from today.

| Field | Trusted producer (today) | Canonical form | Mutable | Hash | Spend | Negative tests |
|---|---|---|---|---|---|---|
| `schema` | constant | `direwolf.approval.binding.v1` | no | yes | -- | a different schema string never matches |
| `verb` | the decided `CanonicalAction`'s capability (`policy/action.rs`) | the verb's spelling (`fs.delete`) | no | yes | re-derived, equal | another verb on the same resource |
| `resource_identity` | files: `FileIdentity` (dev, ino) from the resolver (`resource/fs`); executables: `ExecutableIdentity` (canonical path, SHA-256) from `resource/exec`; hosts: the pinned address set and the decided name (`state/net_http` plan); a credential: the handle | a tagged object; dev and ino as strings; addresses sorted | **yes** (the world changes) | yes | re-resolved, equal; else drift | a swapped inode at the same path; a rewritten binary; a changed DNS answer |
| `canonical_args` | process: the checked argv (`resource/exec/argv.rs`); `net.http`: method and the URL's SHA-256 -- never the path or query (ADR-0050 §13); file writes: the content's SHA-256 | an object per route | no | yes | recomputed from the actual request, equal | one changed argument; another body |
| `workspace_id` | the run's bound workspace (`state/config.rs` `WorkspaceId`) and its root's identity | the id; the root's dev and ino | root can be replaced | yes | root re-pinned (`RootError::Replaced` denies) | a replaced root |
| `environment_profile` | **mismatch:** `policy::Environment` is `Sandbox` or `Host` only; it carries no profile id, though its comment says one travels. M6.1 defines it: `host`, or for a sandbox the operator file's runtime client, image and probe digests (`sandbox::operator`) and the measured assurance level | a tagged object of digests | the environment is re-measured | yes | the broker's re-judged environment, equal | sandbox-granted spent on host; another image digest |
| `credential_handles` | `secret::metadata::SecretHandle` and its revision (`secret_revision`) | sorted `handle@revision` | revoked or replaced | yes | each revision current, not revoked | a replaced credential; one added |
| `agent` | **mismatch:** no `AgentId` exists. A run is admitted under an agent profile (`ProfileName`, `profile_principal`); sub-agents arrive with the agent loop (M8+). M6.1 binds the profile's name and revision | `profile@revision` | revision can change | yes | equal | another profile; a profile revision changed |
| `requester` (new) | the run's subject (`state/identity.rs` `AuthenticatedSubject`), held under ADR-0063's ownership | `uid:N` | ownership can be revoked | yes | still the run's subject, still permitted | another principal's run; a revoked delegate |
| `scope` | the matched rule's `ApprovalSpec` (`policy/approval.rs`: `ApprovalScopeKind`, TTL, `max_uses`) plus its resolved payload | the scope's tag and payload: `path_set` sorted identities, `path_subtree` root identity and verbs, `executable_and_argv` identity and argv shape, `host_and_methods` name, addresses and methods, `credential_use` handle and origin | no | yes (the scope, not each action) | the actual action is **within** the scope | an action outside the scope; a fourth inode for a three-file `path_set` |
| `taint_level` | the run's taint (`policy::TaintLevel`; `state/taint.rs`, ADR-0062) | `NONE`, `LOCAL_UNVERIFIED`, `EXTERNAL_UNTRUSTED` | **rises** | yes (at grant) | current taint not above it | the patient attack: approve clean, spend tainted |
| `privacy_class` | the decision's capability constraints (`capability/constraint.rs` `PrivacyClass`) | its spelling | no | yes | equal | a wider class |
| `obligations` | the decision record's obligations (`policy/obligation.rs`), each one the route keeps | sorted canonical spellings | no | yes | the re-decided rule carries the same set | a later match without `network_deny` |
| `run_id` | the request's run (`wire::id::RunId`) | the id | no | **no** (one hash serves a standing grant) | equal for a run-scoped approval; absent for a grant | spent in another run; after the run is reaped |
| `policy_revision` | the active policy's `Sha256Hash` (`state/policy_state.rs`) | hex | changes at a start | no | equal, or the approval is void | a policy changed between grant and use |
| tenure | the lease epoch (`wire::scalar::Epoch`) and the holder's incarnation (`state/identity.rs`) | -- | yes | no | the run's tenure still live (the fence) | a restart; a takeover |
| `not_after`, `max_uses`, `uses` | the authority's clock; the rule's `ApprovalSpec` | -- | `uses` | no | `now < not_after`, `uses < max_uses`, atomically | expired; the second concurrent spender |
| request id, nonce | the registry | -- | burned | no | single use | replayed decision; replayed nonce |
| approver, channel, assurance | the approver endpoint's kernel report; the factor if any | -- | no | no | the approver still in the set, not the requester | self-approval; a removed approver; A1 for an A2 class |

**Broad scopes without aliasing.** A broad scope's hash covers the scope's
descriptor, not one action; every spend computes the actual action's own
canonical form and requires it inside the scope, and `approval.used` records
that action's fingerprint. Two distinct actions are two uses of one approval,
never one action.

## 5. The phases

Each phase ends with a green hosted run and its evidence lines read, and is
its own commit group or groups. Nothing in a later phase starts until the
earlier one's exit holds.

### M6.1 -- canonical approval binding

| | |
|---|---|
| Scope | the binding type and its hash; nothing stores, asks or spends one |
| Depends on | M6.0a; its own ADR (amends ADR-0021); ADR-0062, ADR-0076 accepted by its closeout |
| Reuses | `CanonicalAction`, `ApprovalSpec`, `FileIdentity`, `ExecutableIdentity`, the `net_http` plan's pinned addresses, `SecretHandle`, `TaintLevel`, `PrivacyClass`, `Obligations`, `dwk_proto::json::to_canonical_bytes`, `Sha256Hash` |
| New | an authority-internal `ApprovalBinding` built only from decided, resolved values; `binding_hash()`; the environment-profile and agent identities §4.2 defines |
| Store / protocol | none |
| Tests | property: every field's change changes the hash; equal actions equal hashes; distinct inodes, binaries, address sets never alias; JCS vectors; integers past 2^53 as strings; no constructor takes a runtime-supplied field |
| Adversarial | the §4.2 negative column, one test each |
| Mutation | each field dropped from the hash, in turn: a named test must fail |
| Hosted | `make test` on three platforms |
| Exit | the above; no registry, endpoint operation or spend |
| Forbidden | any persistence, any DWKP or approver operation, any spend |

**State (2026-11-25): hosted-verified and accepted.** Committed as
`b87f2d4`; CI #225 ([run 45492684496](https://github.com/Onwcan/DireWolf/actions/runs/45492684496)) passed 33 of 33 jobs --
the binding's 33 tests on Linux, Windows and macOS, its five Linux
real-authority tests, the oracle's five tests on each platform, TX066 and
TX067 -- and the Push workflow ([run 45492684058](https://github.com/Onwcan/DireWolf/actions/runs/45492684058)) 4 of 4.
[ADR-0079](adr/0079-the-approval-binding-v1-what-it-binds-and-how-it-is-encoded.md) is the record, accepted 2026-11-25 with ADR-0062
and ADR-0076; [M6_1_IMPLEMENTATION.md](M6_1_IMPLEMENTATION.md) is the
report. `make approval-binding-mutations` (43 of 43) is local evidence.
M6.2 starts once these acceptance records are committed and their own CI
is green.

### M6.2 -- the kernel-owned registry

| | |
|---|---|
| Scope | durable requests and approvals; atomic burn; revocation; restart |
| Depends on | M6.1; ADR-0064 accepted by its closeout; its own ADR (the schema) |
| Reuses | `state/schema.rs` migrations, `state/gate.rs` (ADR-0064), `state/audit.rs`, `state/crash.rs`, `state/interleave.rs`, ownership (`state/ownership.rs`) |
| New | the next store schema (15 today): request, approval and use records; `approval.*` audit kinds (ADR-0067 §7) |
| Store / protocol | store migration; DWKP and the private protocol unchanged |
| Tests | burn atomic with intent; `uses` never past `max_uses`; expired, revoked, stale-revision, wrong-run, wrong-principal each deny; self-approval refused by a trigger |
| Concurrency and crash | N concurrent spenders, one effect; crash windows before, during and after the burn (`state/crash.rs`'s child); restart finds the use burned; revocation racing a spend under the gate |
| Mutation | the burn outside the intent's transaction; the `uses` check removed; the gate skipped |
| Hosted | `make test`; `authority-state-evidence` hosted if it is made a job |
| Exit | the above; no approver operation yet, so nothing grants |
| Forbidden | any operation that creates an approval from outside the authority |

**State (2026-11-26): built locally, not committed; hosted evidence pending.**
[ADR-0080](adr/0080-the-approval-registry-durable-requests-and-atomic-consumption.md) is the record
(Proposed); [M6_2_IMPLEMENTATION.md](M6_2_IMPLEMENTATION.md) is the report.
Store schema 15 holds requests, approvals and uses; a sandboxed launch
denied `REQUIRE_APPROVAL` at A1 records a request, and an approved one spends
its use after its intent, in its intent's transaction. The decision seam has
no production caller and the shipped build attaches no approver: nothing is
approvable before M6.3. Its hosted evidence is `make test` and
`make approval-registry-evidence`, a step of the `authority-transport` job;
its crash windows are in-process hooks on a reopened store, real process
termination not exercised (the report's §12). ADR-0064's acceptance package
is the report's §20.

**State (2026-11-27): committed; M6.2.1 evidence built locally.** M6.2 was
committed as `b8414fd`; CI #227 ([run 45859307449](https://github.com/Onwcan/DireWolf/actions/runs/45859307449)) passed 33 of 33,
its 27 registry cases each once. M6.2.1 --
[M6_2_1_SECURITY_EVIDENCE.md](M6_2_1_SECURITY_EVIDENCE.md) -- closes the three
evidence lines M6.2 left open, locally: 34 crash windows with real process
termination (an external supervisor kills the unit-test executable's child
with SIGKILL at each and another process recovers its files), the
thirteen binding members' drift, every unsupported scope and every A2 class
on its real route, the release build's separation from every test seam, and
54 of 54 mutants killed. It adds no authority; ADR-0080 and ADR-0064 stay
Proposed. Its hosted run is pending.

**State (2026-11-27): hosted-verified and accepted -- M6.2 is complete.**
M6.2.1 was committed as `f81b898`; CI #228 ([run 45985130343](https://github.com/Onwcan/DireWolf/actions/runs/45985130343))
passed 33 of 33 and the Push workflow 4 of 4: 34 registry cases, each
once, and 34 real-process crash cases in `authority boundary`, the
release build's separation, `make test` on three platforms.
[ADR-0080](adr/0080-the-approval-registry-durable-requests-and-atomic-consumption.md) is accepted, OD-1 to OD-6 as written, and
[ADR-0064](adr/0064-f02-authority-endings-serialised-with-decided-effects.md) as written, on 2026-11-27, each its own change. Crash
recovery, real-process crash evidence and scope and binding drift each
pass within M6.2's supported scope; positive broad-scope consumption is
not enabled, and nothing is approvable before M6.3. The closeout is
[M6_2_IMPLEMENTATION.md](M6_2_IMPLEMENTATION.md) §22; the mutation reviews are local.

### M6.3 -- the approver endpoint's operations and the trusted client

| | |
|---|---|
| Scope | list, show, decide on the approver endpoint (ADR-0067 §7); `direwolf approve` as the trusted client; rendering |
| Depends on | M6.2; **M6.0b (ADR-0078)**; its own ADR replacing TX065 |
| Reuses | `server/approver.rs`, `server/config.rs`, `server/peer.rs`, `crates/direwolf-cli` |
| New | the approver protocol's frames on that socket only; request ids and nonces; the client's renderer (control, ANSI and bidi characters stripped, bounded, truncation shown, agent prose labelled) |
| Store / protocol | approver frames; DWKP unchanged |
| Tests | a decision only from an authenticated approver; nonce single use; binding echoed and re-verified; level recorded |
| Real-process and adversarial | three identities: the runtime uid cannot list, show, decide or replay; no descriptor received; prompt-injection and terminal-control strings in agent text stay in the labelled region; an A1 decision for each ADR-0078 class refused |
| Mutation | TX065's successor rule; the approver check; the nonce burn; the level |
| Hosted | `authority boundary` three-identity suite extended |
| Exit | an A1 class approvable and spent once; every A2 class still `DENY` |
| Forbidden | any A2 class approvable without a verified factor; a remote channel; a terminal descriptor |

ADR-0078 OD-3 keeps the presence factor out of M6. If a later decision brings
it in, **M6.3b** is its own checkpoint here: the factor's ADR and dependency
review, its verification in the authority over the binding hash and nonce,
enrolment and recovery, and hosted evidence -- before any A2 class is enabled
anywhere.

### M6.4 -- standing grants

| | |
|---|---|
| Scope | create, list, revoke on the approver endpoint; matching at spend |
| Depends on | M6.3; its ADR (revalidation across a policy change) |
| New | grant records (principal, agent profile, scope, `not_after` ≤ 90 days, uses); `grant.*` audit kinds; `StandingGrantState` gains its first real variant (`policy/context.rs`) |
| Tests | no grant from a prompt; the cap enforced at creation and use; `require_untainted_run` default; revoked or expired never used; a scope never widened |
| Adversarial | creating a grant through DWKP; a grant spent by another principal or profile; a grant surviving a policy change it should not |
| Exit | the above; creating a grant for an A2 class needs A2, so stays refused (ADR-0078) |
| Forbidden | an implicit grant; a grant with no expiry |

### M6.5 -- hierarchical budgets

| | |
|---|---|
| Scope | a subtractive ledger: reservations from a parent, spends, settlement |
| Depends on | M6.2 (transactions, crash discipline); its ADR (units) |
| Reuses | the existing per-route bounds -- `NetBudget` (`state/net_http`), the process stream limits, `PROXY_ONLY`'s byte budgets -- as consumers, not as the ledger |
| New | budget units and a reservation ledger in the store |
| Tests | property: no amplification through children; checked arithmetic refuses overflow and underflow; settlement returns at most the reservation |
| Concurrency and crash | concurrent children on one parent; a crash mid-reservation and mid-settlement |
| Exit | the above; fan-out mints nothing |
| Forbidden | a budget that grows on release |

### M6.6 -- host execution under approval

| | |
|---|---|
| Scope | the host floor (ADR-0045) wired to approvals; executable and environment identity at use |
| Depends on | M6.3; ADR-0078; ADR-0070 OD-D (Landlock) |
| Tests | without `--allow-host-execution`: `DENY`; without an approval: `DENY`; with an A1 approval: `DENY` (host execution is an A2 class); binary or environment drift: `DENY`; no sandbox-to-host escalation |
| Hosted | `process-broker` evidence |
| Exit (ADR-0078 §3) | **wired and shown to deny**; host execution is not enabled and M6 does not call it complete |
| Exit if M6.3b exists | the same, plus a launch with a verified A2 approval, its own evidence, and the Landlock decision applied |

### M6.7 -- adversarial verification and closeout

Replay and substitution; file, DNS, executable and environment drift;
revocation and crash recovery; parent and child laundering (as far as M6
has children: profiles and runs); standing-grant widening; budget
amplification; fatigue; an agent's self-approval. Every ROADMAP M6
acceptance item mapped to a hosted evidence line; no NOT EXERCISED case
reported as passing; a final review; M6's records accepted; the closeout
the owner's.

## 6. Where the code meets M6

| Concern | Module today | M6's use |
|---|---|---|
| canonical action, environment | `policy/action.rs` | the binding's verb, environment |
| `REQUIRE_APPROVAL`, the rule's approval shape | `policy/effect.rs`, `policy/eval.rs`, `policy/approval.rs` | when a request is made; scope, TTL, uses |
| taint, standing grants | `policy/context.rs`, `state/taint.rs` | the binding's taint; `StandingGrantState` |
| obligations | `policy/obligation.rs`; each route's keeper (`state/net_http/plan.rs`, `state/process.rs`, `state/workload.rs`, `state/plan.rs`, `state/secret_use.rs`, `state/workload_egress.rs`) | only kept obligations are bound |
| resources | `resource/fs` (`FileIdentity`, the resolver), `resource/exec` (`ExecutableIdentity`, argv) | resource identity and args |
| principals, ownership | `state/identity.rs`, `state/ownership.rs`, `state/adoption.rs` | requester; self-approval refusal |
| the gate, crash windows | `state/gate.rs`, `state/crash.rs`, `state/interleave.rs` | the burn's transaction |
| store, audit | `state/schema.rs` (schema 15 since M6.2), `state/audit.rs` | the registry; `approval.*`, `grant.*` |
| approver endpoint | `server/approver.rs`, `server/config.rs`, `server/peer.rs` | M6.3's operations |
| secrets | `secret/metadata.rs` (`SecretHandle`), `secret_revision` | credential handles in the binding |
| existing bounds | `state/net_http` (`NetBudget`), process stream limits, the sandbox's byte budgets | budget consumers |
| canonical JSON | `dwk-proto/src/json/jcs.rs` | the binding's encoding |
| the client | `crates/direwolf-cli` (`doctor`, `models` today) | `direwolf approve` |

## 7. A1, A2, and what M6 delivers

Under ADR-0078, accepted 2026-11-24, M6 delivers approvals at A1 for
sandboxed, non-credential, non-deleting actions; `secret.use`, `fs.delete`,
host execution and standing grants for them stay `DENY` until a verified
presence factor exists, and M6 builds none (OD-3). That is a smaller M6 than
"everything approvable", stated so; it is not a deferral hidden behind a
completed phase. If a later decision brings the factor into M6, M6.3b adds it
and M6.4 and M6.6 gain their A2 exits.

## 8. Evidence plan

| Phase | Required hosted evidence |
|---|---|
| M6.1 | `make test` on three platforms with the binding's property and vector tests |
| M6.2 | the registry's concurrency and crash tests in `make test`; the burn's mutation review recorded; M6.2.1: `make approval-registry-crash-evidence` (real process termination) and `make approval-registry-separation` |
| M6.3 | the three-identity approver suite in `authority boundary`, extended to every operation and refusal |
| M6.4 | grant creation, use, expiry and revocation in `make test`; the DWKP refusal in `authority boundary` |
| M6.5 | the ledger's property and concurrency tests in `make test` |
| M6.6 | `process-broker` evidence: every deny case; with M6.3b, one approved launch |
| M6.7 | every M6 acceptance item named in a hosted log line; NOT EXERCISED cases listed, never counted |

## 9. Remaining risks

| Risk | Owner of the decision | Closed when |
|---|---|---|
| standing grants across a policy change | M6.4's ADR | decided |
| no presence factor: the four A2 classes `DENY` through M6 | ADR-0078 OD-3 (accepted) | a factor's ADR, after M6 |
| casefold filesystem evidence | engineering | the hosted plan in the handoff §G runs |
| ISR2-07 branch protection | the owner | a ruleset, or a recorded decision |
| F-05 per-environment user namespace | upstream runtimes | partially completed, unchanged |
| F-12 artifact capture | M8 | its storage exists; until then `require_artifact_capture` refuses |
| M5e.2 | -- | partially completed, tracked by its existing issue |
| domain fronting, the shared kernel | accepted residuals | not closed |

## 10. Next engineering task

**M6.3 -- the trusted approver endpoint and client. Not started.** M6.2 is
complete ([M6_2_IMPLEMENTATION.md](M6_2_IMPLEMENTATION.md) §22). M6.3 starts once the two
acceptance changes of 2026-11-27 -- ADR-0064, and ADR-0080's OD-1 to OD-6
-- are committed and their hosted CI is green. Its first step is its own
record replacing TX065 under an explicitly justified contract; then the
phase in §5: the approver endpoint's list, show and decide operations, the
trusted `direwolf approve` client, the decision and revocation seams'
first production callers, the approver set from the operator's
configuration, the request rendered from canonical data with its request
id and nonce verified, agent prose kept apart from it and labelled,
terminal control, ANSI and bidi characters stripped, rendering bounded and
truncation shown, three-identity adversarial evidence, A1 approval
evidence, and every A2 class still refused. Nothing of it exists today:
no approver frame, client command, production approver set or decision
path.
