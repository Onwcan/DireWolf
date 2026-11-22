# F-12: shipped policy pack usability, trusted home anchors and artifact capture

This document covers why the three shipped policy packs refused every
ordinary filesystem operation, what was built to fix that without weakening a
hard denial, and why `require_artifact_capture` still cannot be enforced. The
decision is
[ADR-0066](adr/0066-f12-host-path-anchors-are-placed-by-identity.md)
(**Proposed**).

| Part | Status |
|---|---|
| Home and DireWolf anchors, absolute protections (§§5-7) | implementation complete; hosted evidence observed on CI #201 ([PRE_M6_REMEDIATION.md](PRE_M6_REMEDIATION.md)) |
| `require_artifact_capture` (§8) | **ARTIFACT CAPTURE DEFERRED TO M8**: still unenforceable, and BALANCED's writes are still refused |

## 1. Source and scope

The remediation program's audit of 2026-11-11/12 recorded F-12 in one line:

> shipped policy packs deny every read (no home anchor) and `balanced`
> cannot write (`require_artifact_capture`)

The audit's full text is not in this repository. The scope below is derived
from that line, the code at `ddf9601`, and the accepted records:

- POLICY.md §3;
- ADR-0028, ADR-0037, ADR-0038, ADR-0042 and ADR-0044.

**In scope:**

- the shipped packs' filesystem behaviour;
- the path anchors their hard denials name;
- the obligation BALANCED attaches to writes.

**Out of scope:**

| Item | Where it belongs |
|---|---|
| the approver | M6 |
| the artifact store and its consumers | M8 and later |
| the connected `doctor` | M17 |
| egress, the resolver, the proxy peer, user namespaces | F-04, F-05, F-06, F-16 |

## 2. Baseline

`main` at `ddf9601`; CI #183 (run 43761920437): 33/33 jobs successful.

## 3. Reproduction

All three packs were run through the authority's own decision path, using
`tests/policy_packs.rs`:

- an in-process authority;
- the shipped pack, installed as the operator's policy;
- a real workspace tree, bound and pinned;
- the real resolver;
- a run admitted with every filesystem grant;
- a broker that records whether it was asked.

Each case is previewed (the decision) and then invoked (the outcome). The
baseline was taken with the same cases at `ddf9601`, unmodified.

**At `ddf9601`, in every pack:**

| Case | Decision | Rule | Broker asked |
|---|---|---|---|
| `fs.read /workspace/a.txt` | `UNRESOLVED_POLICY_INPUT` | `deny-credential-paths` (`~` unresolved) | no |
| `fs.list`, `fs.stat` | allowed | `allow-workspace-read` | yes |
| `fs.write` (existing) | `UNRESOLVED_POLICY_INPUT` | `deny-direwolf-self-modification` (`${DIREWOLF_HOME}` unresolved) | no |
| `fs.write` (creating) | `UNRESOLVED_POLICY_INPUT` ×2 | the same | no |
| `fs.delete` | `UNRESOLVED_POLICY_INPUT` | the same | no |
| a symlink out, `/etc/shadow`, `/workspace/../x` | refused by the resolver (`SYMLINK`, `PATH_OUTSIDE_WORKSPACE`, `PATH_TRAVERSAL`) | none | no |

Reads, writes, creations and deletions were refused in every pack, and the
packs' intended differences never appeared. List and stat passed only because
neither verb is in either deny rule.

## 4. Before and after

**After**, with `--path-anchor home=` naming a home beside the workspace.
Each cell gives the decision and then whether the broker was asked; `—` means
unchanged from before.

| Case | SAFE before | SAFE after | BALANCED before | BALANCED after | POWER before | POWER after |
|---|---|---|---|---|---|---|
| read | unresolved, no | **allowed, yes** | unresolved, no | **allowed, yes** | unresolved, no | **allowed, yes** |
| list, stat | allowed, yes | — | allowed, yes | — | allowed, yes | — |
| write (existing) | unresolved | **`PROFILE_CEILING`** (`deny-workspace-mutation`) | unresolved | **`OBLIGATION_UNENFORCEABLE`** (`allow-workspace-write`) | unresolved | **allowed, yes** |
| write (creating) | unresolved ×2 | **`PROFILE_CEILING`** ×2 | unresolved ×2 | **`OBLIGATION_UNENFORCEABLE`** ×2 | unresolved ×2 | **allowed ×2, yes** |
| delete | unresolved | **`PROFILE_CEILING`** | unresolved | **`NO_HUMAN_AVAILABLE`** (approval, unattended run) | unresolved | **allowed, yes** |
| symlink out, host path, traversal | resolver refusal | — | resolver refusal | — | resolver refusal | — |

**Variants**, each through the same path:

| Variant | Result |
|---|---|
| no `--path-anchor home=` (any pack) | read refused, `UNRESOLVED_POLICY_INPUT` at `deny-credential-paths`: unchanged |
| the home *is* the workspace root | read refused, `UNRESOLVED_POLICY_INPUT`: `~/.ssh` would be inside the workspace |
| `~/.ssh` is a symlink to the workspace root | read refused, `DENIED_BY_RULE` `SENSITIVE_PATH` at `deny-credential-paths` |
| `${DIREWOLF_CONFIG}` is the workspace (POWER) | write refused, `SELF_MODIFICATION`; the read is still allowed |
| a run with read grants only (POWER) | write refused, `NO_CAPABILITY`: POWER's `ALLOW` does not reach past the capability gate |
| a home that is absent, or a file | the authority does not start |
| workspace root at `/` | every absolute protection is placed inside the workspace, so its rule is unevaluated and denies (`state/anchors.rs`) |

**Paths no placement touches.** Sandbox execution, host execution and
network access are decided on executable and endpoint scopes. `path_under` is
false for them before any anchor is consulted, so F-12 does not change them.
The workspace suites, `process_production.rs` and `net_http_evidence.rs` run
them with the shipped packs, and they pass unchanged. Required but
unavailable approval is the unattended postcondition (BALANCED delete,
above), and `REQUIRE_APPROVAL` never becomes permission.

## 5. Confirmed defects

| | Defect | Evidence | Fixed |
|---|---|---|---|
| D1 | Only `${WORKSPACE}` has a value: the first filesystem rule of every pack is unevaluable for reads (`~`) and for writes, creations and deletions (`${DIREWOLF_HOME}`). Every pack refuses all four | §3 | yes, for an operator-named home (§6) |
| D2 | An absolute rule path is compared by spelling with a logical `/workspace/...` path and never matches. A workspace root bound at `/etc` or `/` exposed `/workspace/shadow` (that is, `/etc/shadow`) to `allow-workspace-read`. It was hidden by D1, and **resolving `~` alone would have opened it** | `policy/fixtures.rs` (`an_absolute_protected_path_is_placed_on_the_host_not_compared_with_the_workspace`), `state/anchors.rs` (root at `/`) | yes (§6) |
| D3 | An `ALLOW` or `REQUIRE_APPROVAL` rule naming a host path loaded, and silently never matched | `policy/fixtures.rs` (`a_host_path_may_be_named_only_by_a_denial`) | yes: refused at load (§6) |
| D4 | `require_artifact_capture` is unenforceable, so BALANCED never writes | §4 | no: deferred to M8 (§8) |

D4 is the intended fail-closed behaviour of ADR-0044, not a fault; it is what
makes BALANCED's writes unusable.

## 6. Trusted anchors

### Identities kept apart

| Identity | What it is | Its role here |
|---|---|---|
| the run's workspace root | a host directory the operator bound, pinned by `(device, inode)` | every candidate path is `/workspace/...` beneath it |
| the logical `/workspace` namespace | the path the agent sees and rules and capabilities are written in | `${WORKSPACE}` and `/workspace/...` rules compare in it, by components |
| the authenticated DWKP subject | the kernel-reported uid of the runtime | **not** a source of `~`: in a real deployment it is the runtime's own user, not the human whose credentials the packs protect |
| the authority's own uid | the owner of the state directory | **not** a source of `~`; its state and executable directories are DireWolf's own anchors |
| the operator's home(s) | where the protected credentials live | `~`, by `--path-anchor home=<dir>` only |
| DireWolf's state, configuration, binaries | what the authority knows plus what the operator declares | `${DIREWOLF_HOME}`, `${DIREWOLF_CONFIG}`, `${DIREWOLF_INSTALL}` |

### How a host path is decided

ADR-0066 §1 has the full rule. Before each filesystem decision, with no
transaction open, the root's recorded path and each host path are walked from
`/` the way the kernel resolves them, and related by identity. The four
possible answers:

- **disjoint:** false;
- **the root inside it:** true;
- **inside the root:** unevaluated, which denies;
- **unexaminable:** unevaluated, which denies.

The policy engine receives the answers as values.

### Anchor sources and checks

The source of each anchor is ADR-0066 §2. Every directory is checked at
start: absolute, a directory, not a symlink, searchable. `serve` logs what
each anchor stands for:

```text
dwkd-authority: path anchor ~ = /home/alice
dwkd-authority: path anchor ${DIREWOLF_HOME} = /var/lib/direwolf/authority
dwkd-authority: path anchor ${DIREWOLF_CONFIG} = /var/lib/direwolf/authority, /etc/direwolf
dwkd-authority: path anchor ${DIREWOLF_INSTALL} = /usr/local/bin
```

Without a home, the first line reads:

```text
path anchor ~ stands for nothing: every rule naming it is unresolved and denies (--path-anchor)
```

**Deployment:**

```bash
dwkd-authority serve ... --path-anchor home=/home/alice
```

Name the home of every person whose credentials could lie under a workspace
root. The authority needs search permission on each home, and on `~/.config`
for `~/.config/gh`, but no read permission.

### What each protection holds against

| Threat | How it is handled |
|---|---|
| missing anchor value | unresolved, so denied (`PathAnchor`); an unconfigured `~` never disables a deny |
| malicious home redefinition | no runtime, environment or subject input reaches an anchor; only `serve`'s command line |
| a forged subject | the subject is not an anchor source |
| symlink substitution | the protected place is walked with links followed (`~/.ssh` → the workspace: `Encloses`, denied); the resolver never follows a link inside the workspace (`SYMLINK`) |
| path traversal, equivalent spellings | candidates are the resolver's (no `..`, NFC only, exact names verified); places are compared by identity, never by text |
| relative or absolute confusion | `/workspace/...` is logical; every other absolute rule path is a host place (D2) |
| prefix matching (`/workspaceX`, `~/.sshconfig`) | logical rules compare by components; host places by identity |
| aliases of a protected directory | a bind mount shows the same `(device, inode)` and is caught, except as a residual below |
| different identities, one home | one home, any number of identities: the home is a place, not a user |
| a workspace overlapping a protected place | denied, either by name (`Encloses`) or unevaluated (`InsideWorkspace`) |
| TOCTOU | placed per decision, against the root the targets were resolved beneath; the effect uses the resolver's descriptors |
| a home outside the workspace | `Disjoint`: the normal case |
| a DireWolf anchor missing | each includes what the authority knows (its state directory, its executable's directory, its configuration files), and is never empty |

## 7. Changes to the packs, and the boundary

**The pack files are unchanged, byte for byte.** What changed is what their
paths mean for a live decision:

- the host paths are placed (ADR-0066 §1);
- the loader refuses a host path outside a `DENY` rule (ADR-0066 §3).

**What is preserved:**

- first-match order;
- narrowing-only postconditions;
- the mandatory final `DENY`;
- the three effects;
- the closed grammar;
- revisions;
- rule provenance;
- composition's refusal of a widening child: a child permitting the
  parent's `~/.ssh` is now refused even earlier, at load.

**What the gates still do:**

- The capability gate is independent: POWER without a write grant is refused
  (§4).
- `ALLOW` with an obligation this build cannot enforce is still not
  permission.

## 8. Artifact capture

### What exists

| Piece | State |
|---|---|
| durable staging for writes (ADR-0044 §10) | an effect mechanism: what a crash leaves, not evidence of content |
| the audit chain | records digests and sizes, by design not content (ADR-0027) |
| the policy verbs `artifact.read`, `artifact.create` | exist; no store behind them |
| F-10's CI evidence archive | a different system, for hosted run logs; not a runtime store |
| ARTIFACTS.md's store | specified, not built |

ARTIFACTS.md specifies the store:

- kernel-owned and content-addressed (`artifacts/<sha256>`);
- metadata giving provenance, trust and sensitivity;
- retention and reference-counted garbage collection;
- quotas;
- redaction on creation;
- quarantine for downloads.

STORAGE.md places the store under `$DIREWOLF_HOME`, and ADR-0044 assigns
`require_artifact_capture` to M8.

### What a minimal capture would need

The authority already holds every byte an `fs.write` would write: the
content arrives in the request. A capture subset is therefore conceivable:

- the authority writes the content to a kernel-owned content-addressed
  directory, then fsyncs it;
- it records the digest, length, invocation, run and principal with the
  intent;
- only then does it hand the effect to the broker.

A crash between the two leaves a captured artifact and an intent
reconciled `UNKNOWN`, which is truthful. A retry with the same key names the
same invocation, and content addressing stores identical bytes once.

### Why it is not built

**Material parts of the contract have no owner yet:**

- **Retention and quota.** Without collection, every captured write grows the
  state directory without bound, a denial of service through writes. The
  retention classes and garbage collection are M8's, and they are tied to the
  event log and provenance reachability.
- **Redaction.** ARTIFACTS.md redacts on creation. Capturing verbatim keeps a
  second copy of any secret an agent writes, in a more protected place but
  without the redaction contract; capturing redacted is not "full output
  preserved".
- **A consumer.** `artifact.read`, export and provenance chains do not exist,
  so nothing could read or verify what was captured. ARTIFACTS.md's
  identifiers (`art_<uuidv7>`) and metadata rows are M8's schema.
- **Before-state.** For a replaced file, the forensics ADR-0027 motivates
  need what was overwritten. Reading it is another brokered read, with its
  own policy decision and bound.
- **A new persistent store** and a store schema change (the artifact
  metadata) that M8 would then have to migrate or redo.

The decision is therefore unchanged: `RequireArtifactCapture` stays
unenforceable, and BALANCED's writes stay refused, `OBLIGATION_UNENFORCEABLE`,
attributed to `allow-workspace-write`. Removing the obligation or treating it
as enforced is not done; a mutant does the latter, and it is killed.

### Owner decision needed

The choice is between:

- **(a)** M8 builds the store, and `require_artifact_capture` becomes
  enforceable there;
- **(b)** a narrow F-12 subset, specified as follows:
  - **Scope:** `fs.write` content only, captured verbatim into
    `<state>/artifacts/<sha256>` (0600, owned by the authority).
  - **Limits:** a per-run and a global byte quota, beyond which the write is
    refused before its intent.
  - **Record:** digest and length in the intent record.
  - **Consumer:** none until M8.
  - **What it does not do:** no redaction, no before-state, no
    `fs.patch`, `fs.move` or `fs.delete`.
  - **Contract:** a new Proposed ADR, store schema 15.

Until one is chosen, BALANCED's writes need an operator policy, as ADR-0044
already says.

## 9. What an operator can tell apart

None of the following needed a DWKP change:

| Why it was refused | Where it shows |
|---|---|
| the capability ceiling, or no grant | `NO_CAPABILITY`; the capability gate `NOT_SATISFIED` |
| a policy rule | `DENIED_BY_RULE`, with the rule id, source line and reason |
| an unresolved anchor | `UNRESOLVED_POLICY_INPUT`; the audit record's `unevaluable`, "the path anchor ~ is unresolved"; `serve`'s start-up line |
| a protected place inside the workspace | `UNRESOLVED_POLICY_INPUT`; `unevaluable`, "a host location under the path anchor ~ lies inside the workspace root" |
| a place that could not be examined | the same, "… could not be placed (unexamined)" |
| an unenforceable obligation | `OBLIGATION_UNENFORCEABLE`, with the rule id and its obligations in the audit record |
| no human available | `DENIED_BY_RULE` at `deny-approval-needed-when-unattended`, `NO_HUMAN_AVAILABLE` |
| a sensitive path | `DENIED_BY_RULE`, `SENSITIVE_PATH` |
| outside the workspace | refused by the resolver: `PATH_OUTSIDE_WORKSPACE`, `SYMLINK`, `PATH_TRAVERSAL` |
| an artifact that could not be captured | not applicable: nothing is captured (§8) |

## 10. Evidence

Local, WSL Ubuntu 26.04. Hosted, CI #201 (run 44818094052, `3998de2`): `broker-fs-read`'s
shipped-pack cases and `make test` on three platforms
([PRE_M6_REMEDIATION.md](PRE_M6_REMEDIATION.md)).

| Claim | Evidence |
|---|---|
| the policy engine answers host paths by placement, and denies when unplaced or overlapping | `policy/fixtures.rs` (the F-12 section) |
| a host path is placed by identity on the real filesystem | `resource/fs/linux/tests.rs` (`host_placement`) |
| a root at `/` holds every absolute protection; several homes, the strictest | `state/anchors.rs` |
| the shipped packs' matrix (§4) | `tests/policy_packs.rs` (`F12-MATRIX` lines) |
| the released daemons read with a named home and refuse an overlapping or missing one | `tests/broker_fs_read.rs`; required cases `shipped-pack-reads-with-a-trusted-home`, `shipped-pack-refuses-an-overlapping-home`, `serve-refuses-an-unexaminable-home`, plus the unchanged `shipped-pack-denies-unevaluable` |
| no widening through a child profile | `tests/policy_composition.rs` |
| the orderings and sources (no `~` default, placement outside any transaction, no live one-namespace context) | `tests/architecture/test_f12_policy_anchors.py` |
| each guard is detected | `make policy-anchor-mutations` (19 mutants) |

## 11. Hosted requirements

The pushed commit's CI must show:

- `make test` on Linux, macOS and Windows: the policy suites and the
  architecture tests run everywhere; the placements are Linux's;
- `broker-fs-read`, with its four shipped-pack cases;
- `filesystem-canonicalization`, `filesystem-operations` and
  `authority-transport`;
- the M5e gate;
- the F-02 and F-03 suites, unchanged;
- `dependencies`.

`make policy-anchor-mutations` is local, like F-02's and F-03's reviews. No
workflow changes.

## 12. Residual risks

ADR-0066 lists them, under *Residuals*:

- a root that is a bind mount of a directory inside a protected place;
- a link inside an unsearchable directory;
- path rules protect places, not moved or hard-linked objects;
- placement is a fact at decision time;
- `InsideWorkspace` is coarse;
- `${DIREWOLF_*}` cover what is known and declared;
- off Linux nothing is placed;
- `require_artifact_capture` is deferred.
