# M5e.5 — the npm and pip profiles: preparation handoff

**Project:** [DireWolf](https://github.com/Onwcan/DireWolf)\
**Prepared:** 2026-11-06, against `main` at `3e322ad8db41420c8109545a60e068de7b74815c` plus the
M5e.4 repair (unstaged at the time of writing)\
**Status:** **PREPARATION ONLY.** No M5e.5 code, image, task, case or job exists, and none has
run. This document changes no behaviour.\
**Status (2026-11-07):** **IMPLEMENTATION AUTHORISED, NOT ACCEPTED.** The owner authorised
implementing M5e.5 ([the plan's §10](M5E_ASSURANCE_PLAN.md), "M5e.5's sequencing"). §6's D1–D4 are
implemented as recommended and listed for the owner's review; §10's steps are under way behind
the evidence-only option; nothing joins a required job before M5e.4's repair passes hosted. This
document stays the record of the preparation.\
**Authority of this document:** a technical handoff, not an ADR. It approves nothing.
[ADR-0054](adr/0054-m5e-npm-hygiene-profile.md) and
[ADR-0055](adr/0055-m5e-pip-hygiene-profile.md) stay **Proposed**, and npm stays
`HYGIENE_NOT_EVIDENCED`.

## 1. What is authorised, and what is not

The owner authorised on 2026-11-06 **preparing** M5e.5 ahead of the deferred assurance work. That
is narrower than the sequencing exceptions in [the plan's §10](M5E_ASSURANCE_PLAN.md), and it
does not replace their record that M5e.5 and M5e.6 are not authorised for implementation.

| | |
|---|---|
| Authorised | This matrix and design; isolated unit-level groundwork, if it cannot affect M5e.4's repair |
| Not authorised | Enabling any profile in production; accepting ADR-0054 or ADR-0055; marking M5e.5 complete; weakening a `HYGIENE_NOT_EVIDENCED` refusal; adding M5e.5 cases to required CI ahead of M5e.4's hosted verification |
| Unchanged | M5e.2 is PARTIALLY IMPLEMENTED / ASSURANCE BLOCKED and tracked by [issue #19](https://github.com/Onwcan/DireWolf/issues/19). M5e.5 changes nothing there, and M5's acceptance still waits for it |

**This preparation stops at this document, on purpose.** The groundwork would touch
`scripts/dw.py`, `hygiene.rs` and the tests M5e.4's repair also touches, and that repair has not
yet passed hosted. Decisions D1–D4 (§6) also change what the code should be. So no M5e.5 code is
mixed into the repair.

## 2. Implementation and assurance matrix

Each row is one ADR clause, what the source does today, and what closes it. Paths are from the
repository root.

### npm (ADR-0054)

| Clause | Today, in source | Change needed | Shown by |
|---|---|---|---|
| §1 scope: only `npm`, by identity | `UNEVIDENCED` includes `npm` (`crates/dwkd-authority/src/resource/exec/hygiene.rs:67`); `hygiene()` refuses it first (`:199`) | a profile branch before the refusal, taken only when the switch is on | `npm-refused-without-the-evidence-option` |
| §1 subcommands: `ci`, `install` only | none: every npm invocation is refused | a pure allowlist over the first non-option argument | `npm-other-subcommands-refused` |
| §1 specs: registry names only | none | a pure spec filter, `--` refused | `npm-non-registry-specs-refused` |
| §2 launcher variables | only `npm_config_ignore_scripts=true` (`crates/dwk-sandbox-profile/src/lib.rs:165`) | eight more, delivered as D1 decides | `npm-lifecycle-scripts-not-run`, `npm-project-npmrc-*` |
| §2 authority prefix | `Hygiene::Kept { prefix }` already carries one (`hygiene.rs`) and `obligations()` records it (`crates/dwkd-authority/src/state/workload.rs:466`) | npm's five flags as the prefix | `npm-plan-records-prefix-and-profile` |
| §3 undoing arguments | none | a pure refusal list, `HYGIENE_OVERRIDDEN_BY_ARGV` | `npm-undoing-arguments-refused` |
| §4 destinations | proxy grants already enforce it; M5e.4 shows it for pip | nothing in the product | `npm-ungranted-registry-refused`, `npm-tarball-on-ungranted-host-refused`, `npm-redirect-to-ungranted-host-refused`, `npm-direct-route-refused` |
| §4 trust file (OD-E6) | the image has none; M5e.4 bakes no trust store | the per-run CA at `/etc/direwolf/npm-ca.pem`, as D3 decides | `npm-untrusted-issuer-refused`, `npm-missing-trust-file-fails-closed`, `npm-project-npmrc-cannot-replace-ca` |
| §5 integrity | npm's own | nothing in the product | `npm-tampered-tarball-refused` |
| §7 evidence-only option | none | §5 below | `npm-refused-without-the-evidence-option`, the fence rule |
| §9 mutation review | not built | §9 below | the hosted campaign |

### pip (ADR-0055)

| Clause | Today, in source | Change needed | Shown by |
|---|---|---|---|
| §1 scope: `pip`, `pip3`, `pip3.N` | falls to "anything else", kept with nothing pip-specific (`hygiene.rs`) | a profile branch, taken only when the switch is on | `pip-refused-without-the-evidence-option` |
| §1 subcommand and specs | none | a pure allowlist and spec filter | `pip-other-subcommands-refused`, `pip-non-name-specs-refused` |
| §2 launcher variables | none is pip's | six more, as D1 decides | `pip-only-binary-cannot-be-undone-by-variable-or-file`, `pip-image-configuration-not-read` |
| §2 authority prefix | the same mechanism as npm's | pip's five flags | `pip-plan-records-prefix-and-profile` |
| §3 undoing arguments | none | a pure refusal list | `pip-undoing-arguments-refused` |
| §5 trust file | M5e.4 passes `--cert` from the workspace, which §3 would refuse | the per-run CA at `/etc/direwolf/pip-ca.pem`, as D3 decides | `pip-os-trust-store-not-used`, `pip-missing-trust-file-fails-closed` |
| §6 shipped packs | `pip install` is R3 (`crates/dwkd-authority/src/resource/exec/argv.rs:412`), so `argv_safe` denies it | none: stays denied unless P1 decides otherwise | `pip-shipped-packs-behaviour` |
| §8 evidence-only option | none | §5 below | `pip-refused-without-the-evidence-option` |

## 3. npm today against ADR-0054

| Behaviour | Today | With the profile |
|---|---|---|
| `npm ci`, `npm install` | denied `OBLIGATION_UNENFORCEABLE`, no environment prepared. Three cases passed hosted in run [42112947252](https://github.com/Onwcan/DireWolf/actions/runs/42112947252) | run, scripts off, under the shipped packs too |
| Shipped packs | `npm`'s R3 words are `exec`, `x`, `run`, `run-script`, `dlx`, `test`, `start`, `stop`, `restart`, `rebuild`, `explore` (`argv.rs:355`). `install` and `ci` are not among them, so policy allows them and the obligation is what denies | policy unchanged; the obligation keeps them. **Enabling the profile therefore enables npm under the shipped packs**, which is why the fence is the whole control |
| `npx`, `pnpm`, `yarn`, `bun`, `cargo` | denied | denied, unchanged |
| A runner or `uv` naming npm | denied, `names_unevidenced` | **must stay denied**: nothing kept for `npm` itself may reach through a runner |
| `npm_config_ignore_scripts` | set for every hygiene launch, shown by nothing | measured |

## 4. pip today against ADR-0055

| Behaviour | Today (M5e.4) | With the profile |
|---|---|---|
| How it is reached | `python -m pip`, the interpreter family, under the evidence's own policy without `argv_safe` | the `pip` executable. `python -m pip` is P3. **The image's `bin/pip` cannot start today**, see §7 |
| Build backend | **runs at install**: `registry-pip-sdist-built-today` | never: `pip-sdist-never-built` |
| `.pth` | installed, not run by install; runs at a later start | the same, and stated: §7 of the ADR never claims otherwise |
| Trust | the workload names it (`--cert`) | the image's file only; `--cert` refused |
| Configuration | pip reads it all; the image carries none | `PIP_CONFIG_FILE=/dev/null`, measured against a hostile image `pip.conf` (already in M5e.3's fixtures) |
| Proxy, ungranted hosts, redirects | refused by the grant: M5e.4's cases | unchanged |

## 5. The evidence-only switch

**Shape.** `dwkd-authority serve --allow-unaccepted-hygiene-profile npm|pip`, repeatable, as
ADR-0054 §7 and ADR-0055 §8 propose.

- **Parsing:** in `crates/dwkd-authority/src/server/config.rs`, on the pattern of the `switch`
  flags there. It yields one value, default none.
- **Refused alone:** `serve` refuses the flag unless the sandbox configuration is the evidence's
  own (`[workspace] unverified_evidence = true`), which no production configuration may set.
- **Logged:** `REDUCED ASSURANCE` at start, beside the workspace waiver's line in
  `crates/dwkd-authority/src/server/sandbox.rs:41`.
- **Carried:** as a typed value, `HygieneProfiles`, into the attached environment and from there
  to `obligations()`. Never a global, never read from the environment or a file.
- **Decided:** `hygiene()` takes the value as an argument and stays pure. With none, every path
  through it is today's.

**Fail-closed when it is absent.** These are required properties, each with a test:

1. With no flag, `hygiene()` gives the same answer as today for every input. A table test covers
   every tool and argument form the current tests use.
2. An unknown profile name is a start-up error, never ignored.
3. The flag does not appear in `policy/`, any shipped configuration, `.github/workflows/ci.yml`
   outside the evidence task, or any document that tells an operator to set it.
4. No code path turns a profile on but the parsed flag.
5. Removing `npm` from `UNEVIDENCED` is not part of this work: that happens only in the change
   that implements acceptance, which also removes the flag.

**The fence.** A new `architecture.toml` rule, on TX059's pattern, with a violation fixture under
`tests/architecture/fixtures/violations/`: the flag's string appears only in the server's
configuration and its tests, and the evidence suite.

## 6. Decisions the owner must make first

| # | Question | Recommendation |
|---|---|---|
| D1 | **How the launcher's variables are delivered.** ADR-0054 §2 and ADR-0055 §2 add them to "every hygiene launch", that is to `HYGIENE_ENVIRONMENT`. That changes production before acceptance: `python -m pip` under an operator's policy would change behaviour, against ADR-0055 §8, and `hygiene-launcher-adds-exactly-its-variables` would change | New launch profiles, `hygiene-npm` and `hygiene-pip`, selected only under the switch, leaving `HYGIENE_ENVIRONMENT` byte-identical until acceptance. This adds values to the private broker enum `WorkloadLaunch` (`crates/dwk-proto/src/brokerp/workload.rs:153`) and to `profile_of` (`crates/dwk-sandbox-probe/src/launch.rs:71`). Both ADRs' "no schema is added" would need revising, so this is the owner's call |
| D2 | **Where a project sits.** A sandbox workload's working directory must be `/workspace` (`WORKING_DIRECTORY_UNSUPPORTED`, `crates/dwkd-authority/src/state/workload_route.rs:277`) and ADR-0054 §3 refuses `--prefix`, so `npm ci` can only use a project at the workspace's root. Runs in one lab share one workspace | One lab, or one workspace root, per npm case. This makes the suite slower, not weaker |
| D3 | **Where the trust file comes from.** OD-E6 bakes the per-run CA into the image, but the PKI is made per lab and the image once per task | `dw.py` makes the PKI first and the suite reads it, one CA per task run. "No trust file" needs a second image, or a variant of the same one |
| D4 | **`python -m pip`** (ADR-0055 P3). While it stays the interpreter's family, the profile can be bypassed by the interpreter | Refuse `-m pip` and `-m ensurepip` under the obligation when the profile is accepted, as P3 recommends, and evidence it |

## 7. Required hosted evidence: npm

ADR-0054 §8 requires each of these by name, in `sandbox-registry`-style evidence, `dwkp-end-to-end`
and attributed. They replace none of M5e.4's cases: `registry-npm-*` shows the refusal without
the option, and stays.

| # | Case | Expected |
|---|---|---|
| 1 | `npm-ci-granted-registry-installs` | the lockfile's packages installed |
| 2 | `npm-install-granted-registry-installs` | a named registry package installed |
| 3 | `npm-ungranted-registry-refused` | nothing installed, `CONNECT` refused |
| 4 | `npm-tarball-on-ungranted-host-refused` | nothing installed |
| 5 | `npm-redirect-to-ungranted-host-refused` | nothing installed |
| 6 | `npm-direct-route-refused` | no route but the proxy |
| 7 | `npm-lifecycle-scripts-not-run` | no marker from any of the four scripts, root's or dependency's |
| 8 | `npm-project-npmrc-cannot-reenable-scripts` | no marker, with a hostile `.npmrc` |
| 9 | `npm-project-npmrc-cannot-disable-tls` | the untrusted issuer still refused |
| 10 | `npm-project-npmrc-cannot-replace-ca` | the image's trust file stays in force |
| 11 | `npm-missing-trust-file-fails-closed` | nothing installed |
| 12 | `npm-git-dependency-not-prepared` | no git fetch, no `prepare` marker |
| 13 | `npm-untrusted-issuer-refused` | nothing installed |
| 14 | `npm-tampered-tarball-refused` | `EINTEGRITY`, nothing installed |
| 15 | `npm-writes-only-workspace-and-tmp` | nothing changed elsewhere |
| 16 | `npm-undoing-arguments-refused` | each §3 argument refused before an intent |
| 17 | `npm-other-subcommands-refused` | `run`, `test`, `exec`, an alias refused |
| 18 | `npm-non-registry-specs-refused` | each spec form refused |
| 19 | `npx-still-refused` | `HYGIENE_NOT_EVIDENCED` |
| 20 | `npm-refused-without-the-evidence-option` | `HYGIENE_NOT_EVIDENCED` with the option absent |
| 21 | `npm-shipped-packs-behaviour` | what `balanced` and `power` decide for `npm ci` |
| 22 | `npm-plan-records-prefix-and-profile` | the recorded, hashed plan names the prefix |

ADR-0055 §9's 21 pip cases are required the same way. M5e.3's fixtures already carry the content
most of these need: the four-script packages, the hostile `.npmrc`, the git dependency, the
tampered tarball, the lockfile and the image `pip.conf`.

Three facts from M5e.4 bear on the image:

- **The executable pinned must fit the broker's bound.** The official `node` binary is
  126 879 696 bytes, past the 64 MiB the broker hashes (run 42112947252's failure was this bound).
  ADR-0054 §1 already pins `npm`, a script, and leaves `node` to the image digest, which works.
  Pinning `node` itself would not.
- **`npm` needs a launcher.** The tarball's `bin/npm` is a symlink, and its `#!/usr/bin/env node`
  has no `env` in a `FROM scratch` image. M5e.4's `REGISTRY_NPM_LAUNCHER` already solves both.
- **So does `pip`.** The CPython build's `bin/pip` starts through `/bin/sh`, `dirname` and
  `realpath`, and a `FROM scratch` image has none of them. The image needs its own launcher,
  started by the pinned interpreter by absolute path, as npm's is.

## 8. Architecture and negative-control requirements

Each new job, task and case gets the treatment `tests/architecture/test_ci_sandbox_registry.py`
gives M5e.4, and:

- **The default:** a table test that `hygiene()` with no profile equals today's answer, and a
  negative control where a profile defaults on.
- **The fence:** the TX rule and its violation fixture; a test that the flag is in no workflow
  but through the evidence task.
- **Each refusal list:** one parametrised negative per entry of ADR-0054 §3 and ADR-0055 §3,
  each spelling included (`--x=y` and `--x y`).
- **The contract:** a dropped case, a wrong level, a wrong attribution and a hidden outcome each
  fail, and an installed case's outcome must show what it installed.
- **The reach:** `npx`, the runners and the wrappers stay refused with a profile on.
- **The status guard:** `tests/architecture/test_m5e_r3_closure.py` keeps holding that neither
  ADR is accepted by this work, and needs its M5e.5 wording changed only when implementation is
  authorised.

## 9. Proposed hosted mutation campaign

`make sandbox-registry-mutations`, run by a manual workflow the owner triggers (OD-E7), never
required by `ci`. Each mutant must compile, must fail a unit suite or the hosted evidence, and is
restored and proved byte-identical. A hosted-only kill is reported from the hosted run, never as
a local one.

| Guard | Mutant | Expected to fail |
|---|---|---|
| Default | a profile on with no flag | unit |
| Fence | the flag accepted without the evidence configuration | unit |
| npm subcommands | `run` allowed | unit, then hosted |
| npm specs | a git URL allowed | unit, then hosted |
| npm refusals | each §3 entry removed, one at a time | unit |
| npm variables | each added variable dropped, one at a time | hosted only |
| npm prefix | `--ignore-scripts` dropped | hosted only |
| `npx` | moved out of `UNEVIDENCED` | unit |
| pip subcommands | `download` allowed | unit, then hosted |
| pip specs | a URL allowed | unit, then hosted |
| pip refusals | each §3 entry removed, one at a time | unit |
| pip binary-only | `--only-binary` dropped from prefix and variable | hosted only |
| pip variables | `PIP_CONFIG_FILE` dropped | hosted only |
| Proxy | a grant check bypassed in `crates/dwkd-broker/src/egress/tunnel.rs` | hosted only |
| Executable pin | the copy bound lifted | unit, real runtime |

## 10. Work breakdown

Each is one reviewable commit, after M5e.4 closes and the owner authorises M5e.5 and decides §6.
Nothing here is required by `ci` until step 6.

1. **The switch, inert.** `--allow-unaccepted-hygiene-profile`, `HygieneProfiles`, `REDUCED
   ASSURANCE`, the TX rule. `hygiene()` ignores the value. All tests unchanged.
2. **npm's pure decisions.** Subcommands, specs, refusals and prefix, behind the value, with unit
   tests and the default-equals-today table.
3. **pip's pure decisions.** The same, with D4 applied.
4. **The launcher.** As D1 decides, its variable-set evidence updated in the same commit.
5. **The image and fixtures.** The trust files, the `pip` launcher, per-case workspaces (D2, D3).
6. **The evidence.** The npm and pip cases, a new required job or the existing one, its guards.
7. **The mutation campaign.** The task and the manual workflow, hosted.
8. **Acceptance, the owner's.** Hosted-green evidence, the ADRs decided, then a separate change
   that removes the flag and moves `npm` out of `UNEVIDENCED`. Not part of M5e.5's preparation.

## 11. Dependencies and risks

- **M5e.4 must close first.** The pip path through a real proxy is unverified until its hosted
  run passes, and every case above builds on it.
- **npm's documented precedence** is relied on only as far as cases 8–10 measure it, on the
  pinned version. A later npm needs the evidence again.
- **`HOME=/` is read-only**, and `/tmp` is a bounded tmpfs. `npm_config_cache=/tmp/.npm` must fit
  it, on real packages as well as the fixtures.
- **M5's acceptance** still waits for R3's evidence ([issue #19](https://github.com/Onwcan/DireWolf/issues/19)),
  whatever M5e.5 does.
