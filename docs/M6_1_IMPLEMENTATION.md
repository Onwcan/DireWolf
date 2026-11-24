# M6.1 implementation report: the canonical approval binding

**As of 2026-11-24.** M6.1 of [M6_IMPLEMENTATION_PLAN.md](M6_IMPLEMENTATION_PLAN.md):
the binding type and its hash, built and tested locally. Its record is
[ADR-0079](adr/0079-the-approval-binding-v1-what-it-binds-and-how-it-is-encoded.md)
(Proposed). **Nothing stores, asks for or spends a binding; no approval
operation exists; every `REQUIRE_APPROVAL` still denies.** M6.1 closes on a
green hosted `make test` on three platforms and the acceptance of ADR-0062,
ADR-0076 and ADR-0079; M6.2 does not start before.

## 1. Baseline

| | |
|---|---|
| Revision | `20ca1a7` on `main` (`20ca1a78b7f1f72e559b938b2a1687bc859ca585`), equal to `origin/main`; the working tree clean before this change |
| CI | #224, [run 45414543923](https://github.com/Onwcan/DireWolf/actions/runs/45414543923): 33 of 33 jobs |
| Push workflow (CodeQL) | #39, [run 45414544375](https://github.com/Onwcan/DireWolf/actions/runs/45414544375): success |
| Since M6.0 | `5520ab8` and `6475172` (M6.0), `740505f` (ADR-0078 accepted), two Python dependency merges (`3f65e88`, `20ca1a7`) that touch no Rust |
| Decisions in force | ADR-0063, ADR-0067, ADR-0077 OD-1 and ADR-0078 accepted; ADR-0062, ADR-0064 and ADR-0076 Proposed |
| Rust dependencies | unchanged: Dependabot's grouped Rust update (PR #33, failing) is not part of this change |

## 2. The decision

[ADR-0079](adr/0079-the-approval-binding-v1-what-it-binds-and-how-it-is-encoded.md)
fixes the field set, the encoding, each member's producer, the scope
payloads, what is left to the registry, and every refusal. It resolves the
plan's two mismatches by binding what exists: the host, or the operator's
sandbox configuration with its measured assurance, for the environment; the
run's agent profile and its revision for the agent. It amends ADR-0021 on
acceptance.

## 3. What was added

| File | What |
|---|---|
| `crates/dwkd-authority/src/state/binding.rs` | `ApprovalBinding`, `BindingInput`, `BindingError`; the members `BoundResource`, `BoundHost`, `BoundArguments`, `BoundWorkspace`, `BoundEnvironment`, `BoundCredentials`, `BoundAgent`, `BoundScope`, `RunContext` (with `RunContext::load`, reading a run's record) |
| `crates/dwkd-authority/src/state/binding_tests.rs` | vectors, properties, adversarial cases, refusals (every platform) |
| `crates/dwkd-authority/src/state/binding_route_tests.rs` | the binding from a real admission, store and resolver (Linux) |
| `crates/dwkd-authority/src/state/taint_route_tests.rs` | one case: the binding's taint from the real producer, before and after a rise (Linux) |
| `tests/protocol/test_approval_binding_vectors.py`, `tests/protocol/vectors/approval_binding_v1.json` | the independent, test-only oracle and its vectors |
| `scripts/dw.py`, `Makefile` | `make approval-binding-mutations` |
| `architecture.toml`, `tests/architecture/test_boundaries.py`, fixtures | TX066, TX067 and their violation fixtures |
| `tests/architecture/test_m6_1_approval_binding.py` | the mutation table, the record and the code agree |
| `state/mod.rs`, `state/secrets.rs`, `resource/mod.rs`, `resource/fs/mod.rs` | the module's declaration; a current revision's metadata digest; a test-only synthetic file identity |

Reused, unchanged: `dwk_proto::json::to_canonical_bytes` (RFC 8785),
`state::digest::plain` (SHA-256), `policy::{CanonicalAction, Decision,
ApprovalScopeKind, Obligations, TaintLevel}`, `capability::{Verb,
ExecutableIdentity, ArgvAllowlist, MethodSet, PrivacyClass}`,
`resource::fs::{FileIdentity, RootFingerprint}`, `sandbox::{SandboxConfig,
Judgement}`, `secret::metadata::SecretHandle`, `state::secrets::Current`,
`state::taint::run_taint`, `AuthenticatedSubject`, `WorkspaceId`,
`AgentProfileName`.

## 4. The field contract

| Member | Trusted source | Form |
|---|---|---|
| `schema` | constant | `direwolf.approval.binding.v1` |
| `verb` | `Decision::required_capability().verb()` | `fs.write` |
| `resource_identity` | the resolvers' `FileIdentity` / `ExecutableIdentity`; the net plan's decided host and pinned addresses; a `SecretHandle` | tagged |
| `canonical_args` | the route's byte count; the content's, URL's and body's SHA-256; the checked argv | tagged |
| `workspace` | `session_workspace`, `workspace_root` (the run's record) | id, root device, inode, birth |
| `environment_profile` | `Environment`; `SandboxConfig` and `Judgement` (effective assurance, usable only) | tagged |
| `credential_handles` | `secret_revision`'s current `CONFIGURED` row | handle, revision, metadata digest |
| `agent` | `run.agent_profile`, `run.agent_profile_revision` | profile, revision |
| `requester` | `run.subject` (the kernel's report at admission) | `uid:N` |
| `scope` | `Decision::approval()`'s kind, with resolved identities | tagged |
| `taint_level` | `run_policy_input.taint` through `taint::run_taint` | spelling |
| `privacy_class` | the capability's `privacy_class` constraint | spelling or `null` |
| `obligations` | `Decision::obligations()`, only where the route keeps all | tagged objects |

No constructor is visible outside the state layer; each takes the producer's
own type or reads the run's record. A runtime can name none of them (TX067).

## 5. Hashed, and checked elsewhere

| Responsibility | Hashed | Grant | Spend | Phase | State |
|---|---|---|---|---|---|
| the thirteen members | yes | built from the decision | re-derived and compared | M6.1 / M6.2 | built (M6.1) |
| scope membership of each action | no (the scope is) | the asking action within it | every action within it | M6.1 / M6.2 | grant check built; spend M6.2 |
| run id | no | recorded | equal (run-scoped) | M6.2 | not built |
| policy revision | no | recorded | equal, or void | M6.2 | not built |
| tenure, epoch, incarnation | no | recorded | live, under ADR-0064's gate | M6.2 | not built |
| request id, nonce | no | issued | single use | M6.2 / M6.3 | not built |
| `not_after`, `max_uses`, `uses` | no | from the rule | atomically | M6.2 | not built |
| revocation, ownership | no | -- | not revoked; still the run's subject | M6.2 | not built |
| current taint not above bound | no | bound taint recorded | compared | M6.2 | not built |
| approver, channel, assurance | no | an approver, not the requester, at the class's level | recorded | M6.3 | not built |

## 6. Encoding and digest

RFC 8785 through `dwk-proto`; `binding_hash = SHA256(canonical bytes)`, 64
lowercase hex digits. Every integer a decimal string; every set sorted by its
members' canonical bytes, a duplicate refused; argv in its order; every
variant tagged with `kind`; `null` only for an absent decided value; no
Unicode normalisation; at most 64 members a set and 1 MiB a binding.

## 7. Scopes

The scope's kind must be the rule's; its payload is resolved identities
(ADR-0079 §6). A scope describes; it proves no membership. At grant the
action that asks must lie within it (a path set holds its file and verb; a
subtree its verb; a host scope its host and method; an executable scope its
executable; a credential scope a credential the action carries). At spend
each action is canonicalised on its own and checked (M6.2). Two decisions
are left: `executable_and_argv`'s allowlist has no policy source yet (M6.4),
and a subtree's containment is the spend's.

## 8. Golden vectors

Written by hand from ADR-0079 in a test-only oracle, encoded and hashed
there, and reproduced by the Rust code from typed values.

| Vector | Property | SHA-256 |
|---|---|---|
| `fs-write-exact-action` | a file by identity, a write by content | `34dbee4a9782fa53cf70512f3570c646f665a3b1ce2ac2b73014c0e97cfe95a7` |
| `process-exec-credentials-tainted` | argv order; a credential set; taint | `1ead57fe22c453eebde65d3cb8f917f7a63260b144b5862e445193a226938545` |
| `net-https-host-and-methods` | pinned addresses; digests, never the URL | `c12baf23e2d13da4c4f4e9b48c4f0713f336caf8e74e606c7ebb7660a68be2dc` |
| `sandbox-exec` | the sandbox's configuration and assurance | `4a65e50f2dadae530e31dd676387312620c45fad5e72cb7063836ad828adec17` |
| `fs-delete-path-set-past-2-53` | integers past 2^53 exact; a sorted path set | `373ee6c8bad23da3ff0773c33b0d3eb460f7d1f69d250531adf3fb022da5a04e` |
| `secret-use-credential-use` | a credential's use and its upstream | `bb050387f48c31b0824bc57f0a47038c5c7856e1209b968c373d54ab737cb838` |

## 9. Property and adversarial tests

Every platform (`binding_tests.rs`): 28 tests and 5 properties at 256 cases
each. Linux (`binding_route_tests.rs` and one in `taint_route_tests.rs`): 5
tests on a real admission, store and resolver. The oracle: 5 tests.

| Plan negative case | Shown by |
|---|---|
| file replaced at the same path | `m6_1_a_file_replaced_at_the_same_path_is_another_binding` (real resolver: a new file renamed over the old); `changing_any_one_member...` (device, inode) |
| workspace root replaced | `a_replaced_workspace_root_is_another_workspace`; root device, inode and birth in `changing_any_one_member...` |
| executable identity changed | `nested_members_of_every_route_are_load_bearing` (digest, path) |
| executable arguments changed | the same (changed, dropped, reordered, joined); `prop_a_permuted_argv_is_another_binding` |
| pinned address set changed | `nested_members...` (addresses, port) |
| HTTP method or request changed | `nested_members...` (method, URL, body) |
| file-write content changed | `changing_any_one_member...` (content, length) |
| credential added or revised | `changing_any_one_member...`, `nested_members...` (added, revised, metadata, removed), `prop_credentials_are_a_set_of_revisions` |
| requester substituted | `principals_profiles_and_revisions_never_transfer` |
| agent profile substituted, revision changed | the same |
| sandbox / host substituted | `a_sandbox_binding_is_never_a_host_binding` (and each refused for the other's action) |
| sandbox image changed | `every_sandbox_attribute_is_bound` (runtime, socket, image, probe, topology, relay, assurance) |
| taint changed | `every_taint_level_is_its_own_binding`; `m6_1_a_binding_takes_the_runs_taint_as_the_store_holds_it` (real producer: approve clean, spend tainted) |
| privacy class changed | `privacy_class_is_bound_and_each_class_is_its_own` (the member's encoding; `null` for every verb bound today) |
| obligation removed, parameter altered | `changing_any_one_member...`, `obligations_are_explicit_sorted_and_only_bound_where_kept` |
| path-set member inserted or removed | `nested_members...` (a fourth, two, replaced) |
| integer precision collision | `integers_past_the_doubles_exact_range_are_exact_strings`, `identities_that_share_digits_never_alias`, `prop_distinct_file_identities_never_alias` |
| unsupported or incomplete identity | `a_verb_with_no_canonical_identity_producer_has_no_binding`, `only_a_require_approval_decision_has_a_binding`, `malformed_and_unbounded_inputs_are_refused`, `a_measurement_that_does_not_make_the_sandbox_usable_binds_nothing`, `only_a_configured_current_revision_is_bound`, `m6_1_a_run_that_is_not_active_has_no_binding_context` |

Also: determinism (`the_same_inputs_give_the_same_bytes_every_time`,
`prop_a_binding_is_a_function_of_its_inputs`), set order
(`prop_set_order_is_not_meaning_and_argv_order_is`), the thirteen members
and no number (`a_binding_names_exactly_the_thirteen_members_and_holds_no_number`),
untrusted text (`text_a_rule_or_an_agent_writes_never_reaches_the_binding_or_moves_it`),
and that building a binding writes no audit record and no approval table
exists (`m6_1_a_binding_is_built_from_the_runs_own_record_and_the_resolvers_identity`).

These show that a binding **changes** when what it covers changes. That a
registry refuses to spend a changed binding is M6.2's to show.

## 10. Mutation review

`make approval-binding-mutations` (Linux), in the repository's method: the
baseline first, then each mutant applied, judged by a named failing test (a
compile error never counts), and the file restored byte-identically. Run in
a filesystem copy, never in the checkout.

| Mutants | Outcome |
|---|---|
| B01-B13: each of the thirteen members dropped | 13 KILLED |
| B14-B23: nested members dropped (a file's and the root's inode, a host's addresses, the content, body and metadata digests, a credential's and the profile's revision, the sandbox's assurance, a path set's files) | 10 KILLED |
| B24-B30: encoding (an integer through a double, a set unsorted, a duplicate accepted, an obligation's parameter lost, argv as a set, the requester or the taint as a constant) | 7 KILLED |
| B31-B43: refusals (action, environment, fit, write content, scope kind, scope admission, obligations kept, sandbox usable, credential state, duplicate handle, stored subject, host name, leaf name) | 13 KILLED |
| E1: the `REQUIRE_APPROVAL` check removed | SURVIVED, EQUIVALENT: a decision names an approval shape only when its effect is `REQUIRE_APPROVAL`, and the next line refuses one with none |
| E2: the 1 MiB bound removed | SURVIVED, EQUIVALENT: no bounded input reaches it (`the_largest_argv_dwkp_admits_stays_within_the_binding_bound`) |

43 of 43 table mutants KILLED. A first run found two mutants (B16, B23) that
did not compile -- dropping their member left an unannotated collection --
which the judge refused to count; the collections were annotated and the
whole table re-run.

## 11. TCB and dependencies

No new dependency, crate, feature or lock entry; `Cargo.lock` unchanged.
The authority already links `dwk-proto` (the encoder) and `sha2` (the
digest), used only from the state layer (TX005). The module adds no I/O but
one read-only query of the run's record. The production build carries it with
no caller until M6.2 (`expect(dead_code)`, said in the code).

## 12. The integration boundary

Built: the binding from a real `REQUIRE_APPROVAL` decision of the policy
engine, the fs route's own capability derivation, the real resolver's
identities, a real admission's record (subject, profile, revision,
workspace, root) and the real taint producer -- in tests. Not built, by
decision: no route computes a binding when it denies a `REQUIRE_APPROVAL`
(with no registry it would be computed and discarded); no DWKP field, no
store table, no audit record, no approver operation, no spend. M6.2 wires
the binding where its request record is written.

## 13. Known limitations

- `privacy_class` is `null` for every verb a binding is built for.
- Verbs with no canonical identity producer (`model.*`, `browser.*`,
  `mcp.*`, `agent.*`, ...) have no binding.
- `executable_and_argv`'s allowlist has no policy source (M6.4).
- Route-level obligation keeping is passed in as the route's own answer; the
  routes' answers are tested where the routes are (fs, process, `net.http`,
  secret use).
- A subtree's containment and every action's membership are the spend's.
- Hard links alias by design; low-entropy URL and body digests are guessable
  by whoever sees a binding.
- **For the owner:** the fs route, `net.http` and host process execution are
  decided in `Environment::Host`, so ADR-0078 §1's "`Environment::Host` (any
  verb)" makes every fs and `net.http` approval an A2 class -- `DENY` through
  M6. Recorded in ADR-0079's residuals; nothing changed.

## 14. Pending acceptances

**ADR-0062 (F-01, taint follows delivered content) -- recommendation: accept.**

- *Verified:* a run's taint is the store's (`run_policy_input.taint`), it only
  rises (`run_policy_input_taint_only_rises`), and its producers are the
  authority's own (`state/taint.rs`: delivered workload output, reached
  origins, exposed roots, a workspace root marked by an external run); no
  DWKP operation carries or lowers it, and the binding reads it through the
  same `taint::run_taint`.
- *Hosted evidence:* CI #224 (run 45414543923, `20ca1a7`): 15 `f01_` tests
  in `make test` (ubuntu), and seven real-OCI taint cases in `sandbox egress`
  (download with no output, partial transfer, a file read by another run, a
  tainted writer marking the root, a refusal and a failed dial not taken for
  content, an interrupted workload on restart); first observed on CI #201.
- *Records on acceptance:* the Status line to Accepted with the date and
  evidence, its "would amend" list made definite; its index row bold and the
  rows of 0039, 0043, 0044, 0045 and 0052 naming what 0062 amends;
  `dwcheck adr --record`; the README count; **its acceptance tripwires
  together** -- `docs/c3-evidence-matrix.json` (`"0062": "Accepted"`, F-01's
  `adr_acceptance`), `docs/C3_HOSTED_EVIDENCE.md`'s sentence and
  `tests/architecture/test_c3_evidence.py`'s pins; the ledger's F-01 row and
  sentence.

**ADR-0076 (ISR2-01, `audit_level=full` not kept on a hop) -- recommendation: accept, OD-1 as written.**

- *Verified:* a hop keeps `max_output_bytes` only; `audit_level=full` denies
  `OBLIGATION_UNENFORCEABLE` before any exchange
  (`a_tainted_run_reaches_no_new_origin_and_obligations_narrow_or_deny`: the
  exchange count is unchanged), `max_output_bytes` still narrows the
  response (64, then 16), and the hop's record keeps the URL only as a digest
  (ADR-0050 §13). A binding never shows the obligation as kept: it is built
  only when the route keeps every obligation (B37 killed).
- *Hosted evidence:* the `obligation-unenforceable` case of `make
  net-http-evidence` on CI #212, #213, #216 and #224 (193 cases on CI #224).
- *Records on acceptance:* the Status line to Accepted with the date and
  evidence, "amends ADR-0050 §5 step 6"; OD-1 marked accepted; its index row
  bold and ADR-0050's row "§5 step 6 amended by 0076"; `dwcheck adr
  --record`; the README count; the ledger's sentence.

**ADR-0079 (this change) -- acceptance prerequisites:** the change committed;
a green hosted `make test` on Linux, Windows and macOS running the binding's
tests (`state::binding::`); its OD-1 to OD-5 decided. Its Status line, index
row, `accepted.sha256` and the README count change then.

Accepting all three after the hosted run: 63 accepted, 13 Proposed.

## 15. Hosted verification

Required for M6.1's closeout: `make test` on ubuntu, windows and macos with
`state::binding::` passing (the vectors and properties, every platform) and,
on ubuntu, `state::workload_route::tests::binding::` and
`taint::m6_1_a_binding_takes_the_runs_taint_as_the_store_holds_it`; `make
arch` with TX066 and TX067; the oracle in `make test`'s pytest. **Pending:**
nothing here is hosted until the change is committed and its CI run read.

## 16. M6.2 prerequisites

1. M6.1's commit, its hosted run green and read.
2. ADR-0062, ADR-0076 and ADR-0079 accepted; ADR-0064 accepted by M6.2's
   closeout.
3. M6.2's own ADR: the registry's schema (store version 15), the request and
   approval records, the burn inside ADR-0064's gate, and where a route
   records a request with its binding.
4. The §5 table's registry obligations, each built and tested; TX062 and
   TX066 amended under that decision, not before.
