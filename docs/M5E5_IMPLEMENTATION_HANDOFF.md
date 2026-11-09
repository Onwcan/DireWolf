# M5e.5 — the npm and pip profiles: implementation handoff

**Project:** [DireWolf](https://github.com/Onwcan/DireWolf)\
**Prepared:** 2026-11-07, on `main` at `cb76b671581ac572922e966e09b44d79c9099c49` plus M5e.4's
second repair (unstaged at the time of writing)\
**Reviewed:** 2026-11-07, on `main` at `6a702d710a1750be656c698722825c3f89ad5304`, before the
evidence's first hosted run (§8)\
**Status:** **IMPLEMENTATION COMPLETE / HOSTED EVIDENCE PENDING.** The profiles, the
evidence-only option, the launcher's profiles, the evidence suite, its task, its manual job
and its mutation review were committed as `bbe3561`, `7df0840` and `6a702d7`; required CI passed
on each, 30 of 30 jobs ([run 42397671369](https://github.com/Onwcan/DireWolf/actions/runs/42397671369)
on `6a702d7`). Required CI does not run this evidence. The manual workflow has never run (the
Actions API listed no run of it on 2026-11-07), so no M5e.5 case has run anywhere. The review
in §8 corrected the evidence and one fail-closed defect before that first run.\
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

1. **`pip-os-trust-store-not-used` — expected to fail.** pip 26.2.2's own source says so
   (§8, F-PIP-TRUST). If it fails, ADR-0055 is revised, as its §9 requires; the profile is
   not weakened and the case is not dropped.
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
| `unit` | 30: the default, the fence, npm's and pip's subcommands, specs, refusals, prefixes, `npx`, D4, the launcher's trust check | locally and hosted | run locally on the review's tree; the result is in the owner's report, from that run's own output |
| `hosted` | 5: the launcher's trust check removed; `npm_config_cafile`, `npm_config_userconfig`, `npm_config_globalconfig` and `PIP_CONFIG_FILE` dropped | the manual job only | NOT EXERCISED |
| equivalent | 1: `PIP_ONLY_BINARY` dropped — the authority's prefix outranks it on every profiled invocation, and the prefix's own removal is a `unit` mutant | run by nothing | listed with its reason |

## 7. What acceptance still needs

1. **M5e.4 first — done.** Its repaired hosted run passed (runs 42390237238 to 42397671369), and
   it was accepted on 2026-11-09 ([M5E4_IMPLEMENTATION_HANDOFF.md](M5E4_IMPLEMENTATION_HANDOFF.md) §13;
   the plan's §10, "M5e.4's acceptance").
2. **This evidence, hosted.** Commit §8's corrections, then run the manual workflow with
   `both` (§11) and read every case and its attribution.
3. **ADR-0055's trust.** On F-PIP-TRUST, the owner's revision of ADR-0055 §2 and §5, its
   implementation behind the same option, and the evidence again.
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
| The launcher's npm trust check (F-NPM-TRUST) | **Approve** | It keeps OD-E6 as decided. ADR-0054 §4's reason ("as npm documents it") is wrong for npm 11 and needs rewording at acceptance |
| ADR-0055's trust (F-PIP-TRUST) | **Revise ADR-0055 §2 and §5 after the first run** | Run the evidence as built first, so the case's failure is on record. Then revise, implement behind the option and rerun |
| ADR-0054 acceptance | **Not ready** | No hosted evidence; §4's wording |
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
  `35/35 mutants killed; 1 equivalent, not run`. Each hosted mutant reruns the whole
  evidence, so this job takes the longer of the two.

A failed case prints its workload, exit, bounded output, the origins' request counts and the
broker's last events. Read the job log, then this document's §5 and §8.
