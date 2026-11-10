# M5e.5 — the npm and pip profiles: implementation handoff

**Project:** [DireWolf](https://github.com/Onwcan/DireWolf)\
**Prepared:** 2026-11-07, on `main` at `cb76b671581ac572922e966e09b44d79c9099c49` plus M5e.4's
second repair (unstaged at the time of writing)\
**Reviewed:** 2026-11-07, on `main` at `6a702d710a1750be656c698722825c3f89ad5304`, before the
evidence's first hosted run (§8)\
**Revised:** 2026-11-10, on `main` at `8c2bd8acf860e9669dbfdbd8c1b2e3abb6469733` (hosted [run 42820123829](https://github.com/Onwcan/DireWolf/actions/runs/42820123829), 32 of 32 jobs): ADR-0055's trust, F-PIP-TRUST (§12), before the evidence's first hosted run\
**Revised:** 2026-11-10, after the evidence's first hosted run, [42846068083](https://github.com/Onwcan/DireWolf/actions/runs/42846068083) on `7f0f01c`: five corrections to the evidence and its mutation review (§13)\
**Revised:** 2026-11-10, after the second hosted run, [42858621579](https://github.com/Onwcan/DireWolf/actions/runs/42858621579) on `2a1bbe9`: ADR-0054's npm configuration (F-NPM-CONFIG) and five corrections to the evidence (§14)\
**Status:** **COMPLETE (2026-11-11).** The third hosted run passed, ADR-0054 and ADR-0055
are accepted, and the acceptance change §10 designed is built (§15). Before that:
**IMPLEMENTATION COMPLETE / HOSTED EVIDENCE PENDING.** The profiles, the
evidence-only option, the launcher's profiles, the evidence suite, its task, its manual job
and its mutation review were committed as `bbe3561`, `7df0840` and `6a702d7`; required CI passed
on each, 30 of 30 jobs ([run 42397671369](https://github.com/Onwcan/DireWolf/actions/runs/42397671369)
on `6a702d7`). Required CI does not run this evidence. The review in §8 corrected the
evidence and one fail-closed defect before its first run. That first run (2026-11-10, §13)
stopped in the evidence's own harness in four of its five tests; the second (§14) passed
three of five and found that ADR-0054's profile kept npm from starting at all
(F-NPM-CONFIG). Both are corrected, ADR-0054 is revised, and the third run is pending;
no run has yet passed.\
**Authority of this document:** a technical handoff, not an ADR. It approves nothing.
[ADR-0054](adr/0054-m5e-npm-hygiene-profile.md) and
[ADR-0055](adr/0055-m5e-pip-hygiene-profile.md) stay **Proposed**. In every production
configuration npm stays `HYGIENE_NOT_EVIDENCED` and pip keeps today's treatment.

## 1. What was authorised

The owner authorised M5e.5's implementation on 2026-11-07
([the plan's §10](M5E_ASSURANCE_PLAN.md), "M5e.5's sequencing"). That is not acceptance. Its
evidence joins no job `ci` requires before M5e.4's repair passes hosted, and M5e.6 is not
authorised. The preparation is [M5E5_PREPARATION_HANDOFF.md](M5E5_PREPARATION_HANDOFF.md);
this document records what was built from it.

## 2. What was built, by commit

| Commit | What | Where |
|---|---|---|
| `bbe3561` | The sequencing record; the evidence-only option, inert | `server/config.rs`, `server/sandbox.rs`, `sandbox.rs`, `sandbox/profiles.rs`, TX060 and its fixture, the plan, the ROADMAP, the guard |
| `7df0840` | The profiles: the authority's decisions, the private launch values, the launcher's variables | `resource/exec/hygiene.rs`, `state/workload.rs`, `state/workload_route.rs`, `brokerp/workload.rs`, the broker's plan, `dwk-sandbox-profile`, `dwk-sandbox-probe`'s launcher |
| `6a702d7` | The evidence: suite, task, manual job, mutation review, guards | `tests/sandbox_hygiene.rs`, `scripts/dw.py`, `Makefile`, `.github/workflows/m5e5-evidence.yml`, the architecture tests, this document |
| §8 | The review's corrections, unstaged | `dwk-sandbox-probe`'s launcher, `tests/sandbox_hygiene.rs`, `scripts/dw.py`, `test_ci_sandbox_hygiene.py`, this document |

## 3. The evidence-only option and why it fails closed

`dwkd-authority serve --allow-unaccepted-hygiene-profile npm|pip`, repeatable.

- **Parsed** in `server/config.rs` with an exact name or a usage error. A repeated name is an
  error, and so is the option without `--sandbox-config`.
- **Attached** in `server/sandbox.rs` only through `SandboxConfig::with_hygiene_profiles`. That
  call refuses (`UNACCEPTED_PROFILE_OUTSIDE_EVIDENCE`) unless the operator's file says
  `[workspace] unverified_evidence`, the evidence harness's own workspace, which every broker
  refuses unless its operator acknowledged it.
- **Logged** at start: `REDUCED ASSURANCE: --allow-unaccepted-hygiene-profile npm pip`.
- **Carried** as a typed value from the attached configuration to each workload's check. The
  state layer gives the obligation's pure decision its own copy (`hygiene::Profiles`). It is
  never a global, and never read from a variable, a request or a file.
- **Fenced** by `architecture.toml` TX060: the option's spelling, the setter's call and the
  profile name's parse appear only in the server's command line, its attachment and the
  type's own module.
- **Without it** (`Profiles::NONE`) every decision is today's. `hygiene_with` with no profile
  equals `hygiene` over every input the obligation's tests use, and a profile changes no tool
  but its own. Both are unit tests.

## 4. The owner's acceptance items

The preparation's D1–D4 are implemented as it recommended. Each is the implementation's
choice, listed here for the owner's acceptance; none was decided by the owner. §9 gives a
recommendation for each.

| # | As built | What the owner is asked |
|---|---|---|
| D1 | Two launch values, `HYGIENE_NPM` and `HYGIENE_PIP`, are added to the **private** broker protocol (`brokerp::workload::WorkloadLaunch`). The launcher's `hygiene-npm` and `hygiene-pip` profiles set the hygiene variables plus each ADR's own (`HYGIENE_NPM_ENVIRONMENT`, `HYGIENE_PIP_ENVIRONMENT`). `HYGIENE_ENVIRONMENT` is byte-identical, so every other launch is unchanged. DWKP and its schemas are unchanged: the plan says `HYGIENE`, and the audited intent records `launch` and `hygiene_args`. A secret is never combined with a profiled launch: the authority does not keep it and the broker refuses it | Both ADRs say no schema is added. Confirm that a private broker enum value is acceptable, or say otherwise |
| D2 | One workspace per run: the suite's lab installs 48 workspaces and binds each session to its own. `npm ci` reads its project at that workspace's root | Nothing beyond the evidence |
| D3 | `make sandbox-hygiene-evidence` makes the PKI first, then builds two images from the registry tools image's checked rootfs: one with the run's anchor at both trust paths, one without | Nothing beyond the evidence |
| D4 | Under pip's profile, `python -m pip`, `-m ensurepip` and their submodules are refused (`HYGIENE_NOT_EVIDENCED`). Without the profile the interpreter is unchanged | Accept P3 as built. One extra case, `pip-interpreter-module-refused`, evidences it |

Five more implementation choices, each stricter than the ADRs' text and each with unit tests:

- **Abbreviations.** npm (nopt) and pip (optparse) expand an unambiguous abbreviation of a
  long option. Any prefix of a refused option is refused too (`--userc`, `--isol`, `--no-bin`).
  pip's exact `--pre` is kept as itself.
- **pip's `--cache-dir`** is refused beside ADR-0055 §3's list, since it would undo the
  profile's `--no-cache-dir` as `--no-binary` would undo `--only-binary`.
- **pip's `--index-url` and `--extra-index-url`** must name an `https` URL (ADR-0055 §3).
- **The `--` separator** is refused for pip as for npm.
- **pip's prefix goes after its subcommand.** `--only-binary` is `install`'s option, which pip
  refuses before the subcommand. The plan records where (`prefix_at`), and the argv digest
  covers it.

The review added a sixth, to keep what the owner already decided (§8, F-NPM-TRUST): **the
launcher starts npm's profile only when npm's trust file is there.**

## 5. The evidence: 44 cases

`make sandbox-hygiene-evidence` (`sandbox-hygiene`, `dwkp-end-to-end`). It covers ADR-0054
§8's 22 cases and ADR-0055 §9's 21, each by its exact name (an architecture test reads both
ADRs' tables), plus D4's one. Every case's outcome prefix and attribution is in `dw.py`
(`HYGIENE_OUTCOMES`, `ATTRIBUTION["sandbox-hygiene"]`). The suite's five tests are:

- **npm under its proposed profile:** npm's cases except the trust file's, the option's and
  the shipped packs'.
- **pip under its proposed profile:** pip's likewise, and D4's.
- **Without a trust file:** both `*-missing-trust-file-fails-closed` cases, in the image
  without the trust files, after a workload that reads both trust paths from inside it.
- **Without the option:** both `*-refused-without-the-evidence-option` cases, on a server
  started without it.
- **The shipped packs:** both `*-shipped-packs-behaviour` cases, under `balanced` and `power`,
  with the option.

Locally the task refuses: NOT EXERCISED, exit 2. **Every case is NOT EXERCISED until the
manual job runs it.** None has run anywhere.

**Where a case may fail on its first run**, in order of likelihood. Each runs last in its
test, so that its failure leaves every other case reported (§8, F-ORDER):

1. **`pip-os-trust-store-not-used`.** As built on 2026-11-07 it was expected to fail
   (§8, F-PIP-TRUST). ADR-0055 §5 is revised for it before the first run (§12): the
   prefix's `--use-deprecated=legacy-certs` keeps pip's `truststore` context out, so
   the case is expected to pass, and the hosted mutant that drops the value must make
   it fail. If it still fails, ADR-0055 is revised again; the profile is not weakened
   and the case is not dropped.
2. **`*-writes-only-workspace-and-tmp`** read `docker container diff`. The images now carry
   the mount points (§8, F-MOUNTS); anything the runtime still lists fails the case.
3. **`npm-direct-route-refused`** uses npm's own `--noproxy`, which the profile does not
   refuse, to make npm try a direct route. The topology must answer `ENETUNREACH`.
4. **The shipped packs** are measured, not assumed. pip must be denied (R3). npm's decision is
   recorded as it comes.

## 6. The mutation review

`make sandbox-registry-mutations` follows ADR-0054 §9, ADR-0055 §10 and the owner's OD-E7.
It applies each mutant and runs the obligation's and the launcher's unit tests (`unit`) or the
hosted evidence (`hosted`). It restores each file byte-identical and says so. **A mutant is
killed only when a test it names failed** (`mutant_verdict`). A mutant that does not build is
`not-compiled`, and one that fails some other test is `failed-elsewhere`; both fail the task,
and neither counts. A `hosted` mutant off a disposable GitHub-hosted runner is NOT EXERCISED,
which fails the task; it is never counted as killed. The manual workflow runs it with
`what: mutations` or `both`.

| Kind | Mutants | Where | As of this review |
|---|---|---|---|
| `unit` | 31: the default, the fence, npm's and pip's subcommands, specs, refusals, prefixes, pip's trust value (§12), `npx`, D4, the launcher's trust check | locally and hosted | run locally on the review's tree; the result is in the owner's report, from that run's own output |
| `hosted` | 6: the launcher's trust check removed; `npm_config_cafile`, `npm_config_userconfig`, `npm_config_globalconfig` and `PIP_CONFIG_FILE` dropped; `--use-deprecated=legacy-certs` dropped from pip's prefix (§12) | the manual job only | NOT EXERCISED |
| equivalent | 1: `PIP_ONLY_BINARY` dropped — the authority's prefix outranks it on every profiled invocation, and the prefix's own removal is a `unit` mutant | run by nothing | listed with its reason |

## 7. What acceptance still needs

1. **M5e.4 first — done.** Its repaired hosted run passed (runs 42390237238 to 42397671369), and
   it was accepted on 2026-11-09 ([M5E4_IMPLEMENTATION_HANDOFF.md](M5E4_IMPLEMENTATION_HANDOFF.md) §13;
   the plan's §10, "M5e.4's acceptance").
2. **This evidence, hosted.** Its first run stopped in the harness (§13); its second found
   F-NPM-CONFIG (§14). Commit §14's corrections, then run the manual workflow with `both`
   again (§11) and read every case and its attribution.
3. **ADR-0055's trust — revised and implemented (2026-11-10, §12)**, behind the same
   option, before the first run; the first run is its evidence.
4. **The owner's acceptance** of D1–D4 and the six choices (§4, §9), and of each ADR, or a
   revision of the ADR for any case that did not hold.
5. **The change that implements acceptance** (§10). It is separate, and it is not part of
   this work.

M5e.2 is COMPLETE (2026-11-09; the plan's §10, "M5e.2's closure"), and
[issue #19](https://github.com/Onwcan/DireWolf/issues/19) is closed. None of the above bears on it.

## 8. The review before the first hosted run (2026-11-07)

No manual run existed to read, so the review read the sources: the suite against both ADRs,
the images, the workflow, the mutation review, and the pinned tools' own code where a case
depends on what the tool does (npm 11.19.1, pip 26.2.2). It ran nothing on a package manager.

| # | Finding | Kind | What changed |
|---|---|---|---|
| F-NPM-TRUST | npm ignores a `cafile` it cannot find: npm 11.19.1's `definitions.js` reads it through `maybeReadFile`, which answers `null` on `ENOENT`, and the `cafile` flattener then sets no `ca`, so Node.js's bundled public roots apply. A missing `/etc/direwolf/npm-ca.pem` therefore did not fail closed, which ADR-0054 §4 states and the owner decided (OD-E6). `npm-missing-trust-file-fails-closed` would still have passed hosted, because the fixture's CA is not a public root | a fail-closed defect, and an evidence case that could not have shown it | The launcher executes nothing for `hygiene-npm` unless the trust file is a regular, readable, non-empty file. It exits `LAUNCH_FAILED`, which the broker never believes as npm's own status (ADR-0052 §5), so the authority answers `OUTCOME_UNKNOWN` and destroys the environment. The case now requires that answer, the destruction, **no tunnel the proxy carried**, no request at the registry and no `node_modules`. Two unit tests, two `unit` mutants and one `hosted` mutant. Production is unchanged: only `hygiene-npm` launches check, and only the evidence-only option reaches them |
| F-PIP-MISSING | pip refuses a `--cert` it cannot find itself, before it connects: its vendored `requests` raises "Could not find a suitable TLS CA certificate bundle" | none in pip; the case showed only that pip failed | `pip-missing-trust-file-fails-closed` now requires that message and no tunnel the proxy carried |
| F-MOUNTS | The images had no `/workspace`, `/tmp` or `/var/tmp`. The runtime makes a missing mount point in the container's own layer (the working directory at create, the mounts' targets at start), so `docker container diff` would have listed them. Both `*-writes-only-workspace-and-tmp` cases would have failed in their tests' first case, leaving every later case of the npm and the pip test unreported | an evidence defect | The images carry each as an empty directory (`HYGIENE_MOUNT_POINTS`), held to `dwk-sandbox-profile`'s own constants by `test_ci_sandbox_hygiene.py`, which also builds both images' roots without a runtime |
| F-ORDER | A test stops at its first failed assertion, so one surprise left every later case of its test unreported | evidence yield | The cases measured rather than assumed run last in their tests: `npm-direct-route-refused`, both `*-writes-only-workspace-and-tmp` (measured where they were, judged last) and `pip-os-trust-store-not-used`. Nothing is softened: each still fails its test |
| F-USERCONFIG | `npm_config_userconfig` and `npm_config_globalconfig` had no observable effect in the evidence, so their hosted mutants could only survive | a gap in the mutation review | The hostile `.npmrc` already names a user and a global configuration in the workspace. The suite now writes both, each sending npm to a proxy at an unrouted address. `npm-project-npmrc-cannot-reenable-scripts`'s `npm ci` succeeds only if neither is read. npm 11.19.1 resolves both locations through its precedence (`#get`), so a project's choice takes effect without the variables. New `hosted` mutant: `npm_config_globalconfig` dropped |
| F-VERDICT | The mutation review counted a mutant as killed when any step failed: a mutant that did not build, or failed an unrelated test, counted as a kill | a defect of the review | Each mutant names the tests that must catch it, and the review counts a kill only when one of those failed (`mutant_verdict`, tested with negative controls). The equivalent mutant is listed apart |
| F-PIP-TRUST | pip 26.2.2 builds its TLS context with `truststore`: `_create_truststore_ssl_context` loads `certifi`'s public roots into it, and truststore's Linux `_configure_context` adds OpenSSL's default paths or the first existing candidate (`/etc/ssl/cert.pem`, `/etc/ssl/certs/ca-certificates.crt`, …). A `--cert` file is loaded **beside** those. Under ADR-0055 as written, pip therefore trusts the pinned file, `certifi`'s roots and the image's system store | a predicted failure of ADR-0055 §5, **not changed** | Left as built: ADR-0055 §5 says this is measured, not assumed, and §9 says a case that does not hold revises the ADR. `pip-os-trust-store-not-used` is expected to fail on the first run, which also shows the case can fail. `certifi`'s roots cannot be shown by a hermetic fixture at all, so §5's "whole trust store" would be false even if the case passed. The revision this suggests, for the owner: `--use-deprecated=legacy-certs` in the authority's prefix and `PIP_USE_DEPRECATED=legacy-certs` in the launcher. pip 26.2.2 still accepts that value. pip then makes no `truststore` context, and `requests` hands urllib3 the `--cert` file alone. The value is deprecated, so its removal in a later pip becomes a revisit trigger |

## 9. Decisions for the owner, with recommendations

No item here is approved by this document.

| Item | Recommendation | Grounds, and what is still unproven |
|---|---|---|
| D1 private launch values | **Approve** | DWKP, its schemas and `HYGIENE_ENVIRONMENT` are unchanged (`make schema-check`, unit tests); a secret with a profiled launch is refused on both sides; required CI passed on `7df0840` and `6a702d7`. End to end it is unproven until the manual run |
| D2 one workspace per run | **Approve** | The evidence's own arrangement, with no production effect |
| D3 per-run trust files baked into the evidence's images | **Approve** | The evidence's own images; one without trust files; since §8, the mount points too |
| D4 `python -m pip` and `-m ensurepip` refused under pip's profile | **Approve** | Stricter; unit-tested and mutant-killed; its hosted case is pending |
| The five stricter choices (§4) | **Approve** | Each is stricter than the ADRs' text and unit-tested |
| The launcher's npm trust check (F-NPM-TRUST) | **Approve** | It keeps OD-E6 as decided. ADR-0054 §4's reason ("as npm documents it") was wrong for npm 11; reworded 2026-11-10 (§14) |
| ADR-0055's trust (F-PIP-TRUST) | **Revised before the first run (2026-11-10, §12)** | `--use-deprecated=legacy-certs` in pip's prefix; the hosted mutant that drops it records that the case can fail, in place of a first run that would only have recorded the predicted failure. Its evidence is the first manual run |
| ADR-0054 acceptance | **Not ready** | No hosted evidence; §2 revised for F-NPM-CONFIG (§14), its first npm install still to run |
| ADR-0055 acceptance | **Not ready** | No hosted evidence; F-PIP-TRUST |

## 10. The acceptance change, designed (not built)

Only after both ADRs are accepted on hosted evidence, as its own reviewable commit. Nothing
below is built, and production stays as it is until then.

1. **Remove the option.** `server/config.rs` (the flag, `hygiene_profile`,
   `hygiene_profiles_fit`, the usage line and their tests), `server/sandbox.rs` (the
   parameter and the `REDUCED ASSURANCE` line), `server/mod.rs`, `sandbox.rs`
   (`with_hygiene_profiles`, the field, its getter, `UNACCEPTED_PROFILE_OUTSIDE_EVIDENCE` and
   its test), and `sandbox/profiles.rs` (deleted). In `architecture.toml`, TX060 becomes a
   rule that the option's spelling appears nowhere; its violation fixture is replaced, and its
   test in `test_boundaries.py` with it.
2. **Make the profiles the obligation.** In `resource/exec/hygiene.rs`, `hygiene` applies npm's
   and pip's profiles itself; `hygiene_with`, `Profiles` and `state/workload.rs`'s
   `profiles_of` go; `UNEVIDENCED` drops `npm` and keeps `npx`, `pnpm`, `yarn`, `bun` and
   `cargo`, each still unit-tested as refused.
3. **Keep the launch values as accepted for D1.** The broker, the launcher, the variables and
   the npm trust check stay as they are.
4. **Evidence for production.** The suite's `Setup.profiles` goes. The two
   `*-refused-without-the-evidence-option` cases have no option left to be absent: the ADRs'
   acceptance revision names what replaces them (for example, the profile kept with no
   option), so no case is dropped silently. `make sandbox-hygiene-evidence` joins a new job
   `ci` requires, with the `test_ci_*` treatment. The manual workflow keeps the mutation
   review (OD-E7), and `test_ci_sandbox_hygiene.py`'s "required by nothing" check becomes its
   inverse.
5. **Records.** Both ADRs read Accepted with the date, and `docs/adr/accepted.sha256` takes
   their digests by the established procedure (`dwcheck adr`). `test_m5e_plan.py`'s "still
   Proposed" test and `test_m5e_r3_closure.py`'s M5e.5 record follow. `SANDBOX.md`,
   `SECURITY.md`, the plan and the ROADMAP say npm is kept under its profile.
6. **Unchanged.** The shipped packs (ADR-0055 P1: `pip install` stays R3), `npx`, the other
   package managers and the runners stay refused.

## 11. Running the evidence

Only the owner starts it. On GitHub: **Actions → M5e.5 evidence (manual) → Run workflow**, branch
`main`, **what: `both`**. Two jobs run on separate runners:

- **`sandbox hygiene evidence (make sandbox-hygiene-evidence)`.** It passes only if it ends
  with `attributed evidence: 44 cases reported`, after the cleanup line.
- **`profile mutation review (make sandbox-registry-mutations)`.** It passes only with
  `37/37 mutants killed; 1 equivalent, not run`. It first runs the evidence unmutated
  (`baseline: the unmutated hygiene evidence passed`); after a failed baseline every
  hosted mutant is `baseline-failed` and the review fails (§13, F-BASELINE). Each hosted
  mutant reruns the whole evidence, so this job takes the longer of the two.

A failed case prints its workload, exit, bounded output, the origins' request counts and the
broker's last events, then `GROUP FAILED: <group>`; the test still runs its later groups and
lists every failed one at its end. Read the job log, then this document's §5, §8 and §13.

## 12. ADR-0055's trust revision (2026-11-10)

F-PIP-TRUST (§8) is resolved in the profile before the evidence's first hosted run, as
§8's suggestion described, rather than after a run that would only have recorded the
predicted failure. The hosted mutant below records instead that the case can fail.

| Where | Change |
|---|---|
| [ADR-0055](adr/0055-m5e-pip-hygiene-profile.md) §§2, 5, 10, *Revisit if* | The authority's prefix gains `--use-deprecated=legacy-certs`; §5 says why the pinned `--cert` is then pip's whole trust store, and why a workload cannot take it back; the mutation review covers it; a pip that removes the value is a revisit. Still **Proposed** |
| `resource/exec/hygiene.rs` | `PIP_PREFIX` gains the value, before `--cert`, and its unit test the same |
| `tests/sandbox_hygiene.rs` | The suite's copy of the prefix; `pip-os-trust-store-not-used` is unchanged and now expected to pass |
| `scripts/dw.py` | Two mutants: `unit`, the prefix naming `legacy-resolver` instead (killed by the prefix's unit test); `hosted`, the value dropped (killed only by `pip_under_its_proposed_profile`, at its last case) |

pip's source (26.2.1, the same paths as the pinned 26.2.2): `_build_session` makes the
`truststore` context only when `"legacy-certs" not in options.deprecated_features_enabled`;
`--use-deprecated` is an `append` option whose choices include `legacy-certs`; and
`--use-feature=truststore` is listed as always on, a no-op. Without that context,
`session.verify` is the `--cert` path alone. No launcher variable repeats the value: the
prefix covers every profiled invocation, and `python -m pip` is refused (D4).

Nothing else changes: no production behaviour, no case, no outcome, no attribution. The
first manual run (§11) is this revision's evidence as well as M5e.5's.

## 13. The first hosted run (2026-11-10)

[Run 42846068083](https://github.com/Onwcan/DireWolf/actions/runs/42846068083): the manual workflow with `both`, on `main` at
`7f0f01c` (§12's revision, `a2399dd`, and a dependency update; required CI passed on both,
runs 42824684742 and 42829125085, 32 of 32 jobs each). The evidence job failed: one test of
five passed, `without_the_option_nothing_changes`, with both its cases. The other four
stopped in the suite's own harness, never at a profile's guard. The mutation review passed,
and that pass showed nothing about its hosted mutants.

| # | Finding | Where it stopped | What changed |
|---|---|---|---|
| F-PLAN-NPM | `registry_inspect.py plan` named pip's projects and the markers but no npm package, so the suite's `npm_package` panicked (`npm is not an object: None`) before any workload ran | `npm_under_its_proposed_profile` and `without_a_trust_file_both_fail_closed`, at their first line | `plan` names every npm package's name and version; a test reads each role the suite asks for |
| F-PYC | pip byte-compiles what it installs, by default. M5e.4's install check admits no `__pycache__` because that evidence passes `--no-compile`, which no invocation here does. pip's first install from the granted index exited 0 under the revised prefix, and the check then refused `dwfx_…_base/__pycache__/__init__.cpython-312.pyc` | `pip_under_its_proposed_profile`, its first case | `check --compiled` admits exactly pip's cache file beside each of the wheels' own modules (`D/__pycache__/M.cpython-NNN.pyc` for `D/M.py`) and nothing else: another stem, an optimisation level, another tag and a missing module are each tested to fail. M5e.4's check is unchanged |
| F-DENIED-ENV | `balanced` ran `npm ci` in the run, then denied `pip install` (`deny-approval-needed-when-unattended`, R3 as expected), its plan naming the environment `npm ci` had made. The suite's helper required every denial to name none | `the_shipped_packs_decide`, `balanced` | A denial may name the run's live environment and never another (`denied_in`); the test proves the denial made no environment by counting the run's environments before and after. Fresh runs still require none |
| F-ONE-FAILURE | Each test stopped at its first failure, so the run showed one failure per test; §8's F-ORDER only moved the measured cases last | every test | Each test's cases run in groups (`Groups`): a group that fails is reported and the next still runs, and the test fails at its end with every failed group listed. The task judges no evidence line of a run whose tests did not all pass, so nothing is weakened |
| F-BASELINE | The mutation review passed 37 of 37, but all four tests its six hosted mutants name had failed unmutated in the evidence job, and a test that fails anyway "kills" every mutant naming it | the review | Before any hosted mutant, the review runs the evidence unmutated once; after a failed baseline each hosted mutant is reported `baseline-failed`, never killed, and the review fails (`hosted_mutant_skip`, tested) |

Nothing in the profiles, the launcher, the authority or the broker changed, and no case, outcome or attribution changed. The run's two passing cases are not counted: the task judges a run's cases only when all five tests pass, and then requires all 44. The next manual run, with `both`, is the evidence (§11); the review now takes one evidence run longer.

## 14. The second hosted run (2026-11-10)

Run [42858621579](https://github.com/Onwcan/DireWolf/actions/runs/42858621579): the manual workflow with `both`, on `main` at `2a1bbe9` (§13's corrections;
required CI passed on it, [run 42854803010](https://github.com/Onwcan/DireWolf/actions/runs/42854803010), 32 of 32 jobs). With each
test's groups now run on their own, the evidence job reported every group that failed.
Three tests of five passed: `the_shipped_packs_decide`, `without_a_trust_file_both_fail_closed`
and `without_the_option_nothing_changes`, six cases between them. The pip test failed three
groups of fifteen: two in the harness, and the census those two left behind. The npm test
failed twelve of fifteen, nearly all for one defect of ADR-0054's profile. The mutation review
did what F-BASELINE now requires: the baseline
failed, so each hosted mutant was reported `baseline-failed`, and the review failed with 31 of
37 killed (every unit mutant).

| # | Finding | Kind | What changed |
|---|---|---|---|
| F-NPM-CONFIG | npm 11.19.1 refuses to load one file at two levels: with `npm_config_userconfig` and `npm_config_globalconfig` both `/dev/null`, every npm invocation ended at once, `double-loading config "/dev/null" as "global"`, before reading anything. And npm keeps a `globalconfig` from the environment on its lowest, default layer (its loader installs an accessor there), so a workspace `.npmrc` naming `globalconfig` wins over the variable: the hostile case's npm read the workspace file it named and followed that file's unroutable proxy (`ENETUNREACH 192.0.2.1:9`) | a defect of ADR-0054's profile, and a claim of its case that npm does not support | ADR-0054 §§2, 8 and *Revisit if* revised (still Proposed): the global variable names `/dev/null/npmrc`, a path no file can have, which npm reads as a missing file (`NPM_GLOBALCONFIG`, a launcher unit test that the two paths differ). The project's choice of the global file is recorded as what it is: a workspace file read below the project file and every pin, so nothing new. The hostile case now writes `offline=true` into the user file (read, every install would fail) and scripts and TLS off into the global one (read, without effect). The images carry a global `npmrc` of their own at npm's default path, `offline=true`, so every install shows it unread and the hosted mutant that drops the variable is seen |
| F-NPM-TRUST, worded | ADR-0054 §4 still said a missing trust file makes npm's TLS fail, as npm documents it; npm 11 does not, and the launcher's check (§8) is what fails closed | wording | §4 says so |
| F-FALSE-PASS | `npm-git-dependency-not-prepared` and `npm-untrusted-issuer-refused` printed their lines although npm never ran: each required only that npm fail, and npm failed at its configuration | an evidence defect | The git case requires that npm asked the granted registry for the parent; both TLS cases (the untrusted issuer, and TLS off in a workspace `.npmrc`) require Node.js's own certificate error and a tunnel the proxy carried. Two pip cases that also required only a failure now require pip's reason: `No matching distribution found` for the source distribution, and a refusal by the proxy of pip's own default index for the image's `pip.conf` |
| F-LEASE | The hostile case's `npm ci` retried its unroutable proxy for 72 s with no heartbeat possible, past the 60 s lease; the next group's first heartbeat, 76 s after its admission, was refused `STALE_EPOCH`. Why that admission waited is not established | an evidence defect | The lab's authority runs with the longest lease it allows (`--lease-ttl-ms 600000`) |
| F-PLAN-RECORD | `pip-plan-records-prefix-and-profile` read the run's last intent, which was the interpreter measuring pip's target (`HYGIENE`), not pip's | an evidence defect | The plan is read by executable |
| F-ARG-JSON | `pip-direct-route-refused` sent a multi-line program as an argument through a hand-made quote that left its newlines raw; the request was refused as invalid JSON | an evidence defect | Each string goes through the protocol's own encoder |

What the run showed, not counted (the task judges a run's cases only when all five tests pass): every pip case but those two, `pip-os-trust-store-not-used` among them, held as ADR-0055 states it, with its §12 trust revision; both missing-trust-file cases held; the shipped packs permit `npm ci` with the evidence option on and deny `pip install` (`deny-approval-needed-when-unattended`); every refusal before an intent held for npm and pip. No npm install has run yet: the next manual run is the first.

## 15. The third hosted run and the acceptance (2026-11-11)

Run [42879630675](https://github.com/Onwcan/DireWolf/actions/runs/42879630675): the manual workflow with `both`, on `main` at `05cdb51` (§14's corrections;
required CI passed on it, [42875288820](https://github.com/Onwcan/DireWolf/actions/runs/42875288820), 32 of 32 jobs). Both jobs passed. The evidence job's
five tests passed and reported all 44 cases at `dwkp-end-to-end`, each attributed with its
outcome, and a clean census. The mutation review's baseline passed, and then all 37
mutants were killed (31 unit, 6 hosted), the equivalent one listed apart. The shipped packs
permitted `npm ci` and denied `pip install` (`deny-approval-needed-when-unattended`).

Asked, the answers were "Accept both" (ADR-0054, ADR-0055), "Accept all as built" (§9's
items), "Accept M5", and "One change" for how the closing change lands (the plan's §10,
"M5e.5's acceptance" and "M5's acceptance"). The change, as §10 designed it:

| §10 step | As built |
|---|---|
| 1. Remove the option | Its parse, usage line and tests in `server/config.rs` (one test now proves it unknown), the attachment's parameter and `REDUCED ASSURANCE` line in `server/sandbox.rs`, `with_hygiene_profiles` and its error in `sandbox.rs`, and `sandbox/profiles.rs`, deleted. TX060 is now "the hygiene profiles have no switch": its three spellings appear nowhere but the test that proves the option unknown |
| 2. The profiles are the obligation | `hygiene()` applies npm's and pip's profiles over the decision it made before them (`base`); `hygiene_with`, `Profiles` and `profiles_of` are gone; `UNEVIDENCED` drops `npm`. Added: a runner or `uv` naming `npm` or pip is refused (ADR-0055 §3), with its unit test and a unit mutant |
| 3. Launch values kept (D1) | Unchanged |
| 4. Evidence for production | The suite starts the authority as production does; `with_no_option_both_are_kept` reports `npm-kept-with-no-option` and `pip-kept-with-no-option`, which replace the two `*-refused-without-the-evidence-option` cases. `sandbox-hygiene` is a job `ci` requires and the M5 gate needs; the manual workflow keeps the mutation review (OD-E7); `test_ci_sandbox_hygiene.py`'s workflow guard is inverted. The review lost its two mutants of the removed switch and gained one of the runner refusal: 36 mutants |
| 5. Records | Both ADRs Accepted (2026-11-11) with their digests; the plan's §10 records; `test_m5e_plan.py` and `test_m5e_r3_closure.py` follow; SANDBOX.md, the plan, the ROADMAP and README say npm and pip are kept under their profiles |
| 6. Unchanged | The shipped packs, `npx`, the other package managers and the runners naming them |

With it, the M5 gate requires `sandbox-hygiene-evidence` and nothing is left "not yet
required", so its acceptance verdict is READY; `M5e` and `M5` are available, and the
change's own CI run is where that verdict is enforced (the M5E6 handoff's §16).
