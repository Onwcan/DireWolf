# M5e.5 — the npm and pip profiles: implementation handoff

**Project:** [DireWolf](https://github.com/Onwcan/DireWolf)\
**Prepared:** 2026-11-07, on `main` at `cb76b671581ac572922e966e09b44d79c9099c49` plus M5e.4's
second repair (unstaged at the time of writing)\
**Status:** **IMPLEMENTATION COMPLETE — HOSTED EVIDENCE PENDING.** The profiles, the
evidence-only option, the launcher's profiles, the evidence suite, its task, its manual job
and its mutation review are built and checked locally. No M5e.5 case has run hosted, and none
is required by `ci`.\
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
| B | The sequencing record; the evidence-only option, inert | `server/config.rs`, `server/sandbox.rs`, `sandbox.rs`, `sandbox/profiles.rs`, TX060 and its fixture, the plan, the ROADMAP, the guard |
| C | The profiles: the authority's decisions, the private launch values, the launcher's variables | `resource/exec/hygiene.rs`, `state/workload.rs`, `state/workload_route.rs`, `brokerp/workload.rs`, the broker's plan, `dwk-sandbox-profile`, `dwk-sandbox-probe`'s launcher |
| D | The evidence: suite, task, manual job, mutation review, guards | `tests/sandbox_hygiene.rs`, `scripts/dw.py`, `Makefile`, `.github/workflows/m5e5-evidence.yml`, the architecture tests, this document |

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
choice, listed here for the owner's acceptance; none was decided by the owner.

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

## 5. The evidence: 44 cases

`make sandbox-hygiene-evidence` (`sandbox-hygiene`, `dwkp-end-to-end`). It covers ADR-0054
§8's 22 cases and ADR-0055 §9's 21, each by its exact name (an architecture test reads both
ADRs' tables), plus D4's one. Every case's outcome prefix and attribution is in `dw.py`
(`HYGIENE_OUTCOMES`, `ATTRIBUTION["sandbox-hygiene"]`). The suite's five tests are:

- **npm under its proposed profile:** npm's cases except the trust file's, the option's and
  the shipped packs'.
- **pip under its proposed profile:** pip's likewise, and D4's.
- **Without a trust file:** both `*-missing-trust-file-fails-closed` cases, in the image
  without the trust files.
- **Without the option:** both `*-refused-without-the-evidence-option` cases, on a server
  started without it.
- **The shipped packs:** both `*-shipped-packs-behaviour` cases, under `balanced` and `power`,
  with the option.

Locally the task refuses: NOT EXERCISED, exit 2. **Every case is NOT EXERCISED until the
manual job runs it.** None has run anywhere.

**Where a case may fail on its first run**, in order of likelihood:

1. **`pip-os-trust-store-not-used`.** pip may verify through `truststore`, which can consult
   the system store as well as `--cert`. ADR-0055 §5 says this is measured, not assumed. If it
   fails, the ADR is revised, as §9 requires; the profile is not weakened.
2. **`*-writes-only-workspace-and-tmp`** read `docker container diff`. A runtime that lists a
   mount point there would fail the case without any write having happened.
3. **`npm-direct-route-refused`** uses npm's own `--noproxy`, which the profile does not
   refuse, to make npm try a direct route. The topology must answer `ENETUNREACH`.
4. **The shipped packs** are measured, not assumed. pip must be denied (R3). npm's decision is
   recorded as it comes.

## 6. The mutation review

`make sandbox-registry-mutations` follows ADR-0054 §9, ADR-0055 §10 and the owner's OD-E7.
It applies each mutant, runs the obligation's and the launcher's unit tests (`unit`) or the
hosted evidence (`hosted`), and restores the file byte-identical. A `hosted` mutant off a
disposable GitHub-hosted runner is NOT EXERCISED, which fails the task; it is never counted as
killed. The manual workflow runs it with `what: mutations`.

The local run's result is recorded in the commit's description and the owner's report, from
that run's own output; nothing is claimed for a mutant that did not run.

## 7. What acceptance still needs

1. **M5e.4 first.** Its repaired hosted run must pass, and the owner must accept it.
2. **This evidence, hosted.** Run the manual workflow with `both`, then read every case and its
   attribution.
3. **The owner's acceptance** of D1–D4 (§4) and of each ADR, or a revision of the ADR for any
   case that did not hold.
4. **The change that implements acceptance.** It removes the option and TX060's patterns,
   moves `npm` out of `UNEVIDENCED`, makes the profiles unconditional and adds the evidence to
   a required job. It is not part of this work.

M5e.2 is unchanged by any of it: PARTIALLY IMPLEMENTED / ASSURANCE BLOCKED, tracked by
[issue #19](https://github.com/Onwcan/DireWolf/issues/19). M5's acceptance still waits for it.
