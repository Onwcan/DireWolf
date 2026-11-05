# M5e.4 — pip, and npm refused: implementation handoff

**Project:** [DireWolf](https://github.com/Onwcan/DireWolf)\
**Prepared:** 2026-11-04, on `main` at `6be8c414e42d09d90c817d217a6c22a01e4cb68e` plus M5e.3's
completion (unstaged at the time of writing)\
**Status (as prepared, 2026-11-04):** **NOT STARTED.** This was preparation only.\
**Status (2026-11-05):** **IN PROGRESS — implementation complete, hosted verification
pending.** The owner authorised M5e.4 ahead of M5e.2's close
([M5E_ASSURANCE_PLAN.md](M5E_ASSURANCE_PLAN.md) §10, "M5e.4's sequencing"); M5e.5 and M5e.6
are not authorised. What was built, and how §4's decisions were made, is §10 below. Nothing
has run hosted yet, and locally the evidence is NOT EXERCISED by design.\
**Authority of this document:** a technical handoff, not an ADR. It approves nothing.
[ADR-0054](adr/0054-m5e-npm-hygiene-profile.md) and
[ADR-0055](adr/0055-m5e-pip-hygiene-profile.md) stay **Proposed**, and npm stays
`HYGIENE_NOT_EVIDENCED`.

## 1. Before anything starts

- **An owner decision.** The owner's sequencing exception
  ([M5E_ASSURANCE_PLAN.md](M5E_ASSURANCE_PLAN.md) §10, "M5e.3's sequencing") covers M5e.3
  alone. M5e.4 follows M5e.2's close unless the owner decides otherwise, separately and
  explicitly. M5e.2 is partially implemented and assurance-blocked: R3's E6 is required and
  BLOCKED, 0 of 15, and [issue #19](https://github.com/Onwcan/DireWolf/issues/19) stays open.
  `tests/architecture/test_m5e_r3_closure.py` fails while ADR-0057 is Proposed if the
  ROADMAP's M5e heading stops saying "M5e.4–M5e.6 not started". Starting M5e.4 therefore
  needs that decision recorded and that guard updated in the same reviewed change.
- **M5e.3 hosted-green.** The fixtures, the per-run CA and the origins (plan §7a) pass the
  owner's hosted `make test`.
- **Nothing here touches E6.** M5e.4 uses only conforming `PROXY_ONLY` environments. It never
  weakens a hard rule or a topology, and no line of it counts toward R3.

## 2. What M5e.4 delivers (plan §6)

| | |
|---|---|
| Delivers | A registry tools image built **on the hosted runner**; pip, as it is today, against the granted fixture registry and against the ungranted one; npm **refused** `HYGIENE_NOT_EVIDENCED` before anything is prepared — today's fail-closed behaviour, evidenced |
| Product change | None. pip runs as it is today, and what it does not neutralise is stated. ADR-0055's profile is M5e.5's, behind the same evidence-only fence as npm's (OD-E2) |
| Exit | `make sandbox-registry-evidence` hosted-green; locally NOT EXERCISED, never a pass |

## 3. What M5e.3 hands over

| Piece | Where | What M5e.4 does with it |
|---|---|---|
| Fixtures | [`tests/sandbox/registry_fixtures.py`](../tests/sandbox/registry_fixtures.py), `generate(seed, out, marker_dir="/workspace")` | Generate one set per run into a scratch directory; read `manifest.json` for packages by role, markers, routes and hosts. The workspace parts — the npm project and the hostile `.npmrc` — are copied into each case's workspace. |
| Per-run CA | [`tests/net_http/make-pki.sh`](../tests/net_http/make-pki.sh) | `ca.pem` is baked into the tools image at `/etc/direwolf/pip-ca.pem` and `/etc/direwolf/npm-ca.pem`. Origins use `registry-granted` and `registry-ungranted`. The untrusted-issuer cases use `registry-rogue`; the system-store case uses `system.pem` and `registry-system`. |
| Origins | [`tests/net_http/origin.py`](../tests/net_http/origin.py) `--routes manifest.json`, with `--side granted` or `--side ungranted` | One per side, on the runner's loopback. |
| Proxy behaviour | [`crates/dwkd-broker/src/egress/tests.rs`](../crates/dwkd-broker/src/egress/tests.rs) | The broker's `--allow-evidence-egress` fixture maps both names to loopback with an `allow` line. The run's grant names only the granted origin. |

## 4. Decisions M5e.4 must make first

1. **Ports.** The fixtures' URLs name hosts without ports, so pip and npm will `CONNECT` to
   port 443. The grant and the origins must agree. The origins bind `127.0.0.1` on an
   ephemeral port today. Options:
   - **(a)** Serve both origins on port 443 on the hosted runner, on two loopback addresses
     (`127.0.0.1` granted, `127.0.0.2` ungranted). The fixture resolver maps each name to its
     address with two `allow` lines, and the grant names `granted-registry.test:443`. This
     needs `origin.py` to take a bind address and port, and the runner to let it bind 443
     (it has passwordless sudo). The fixtures stay seed-only and deterministic.
   - **(b)** Give `generate()` the ports, putting them in every URL. Fixture bytes would then
     vary per run, and the recorded digest would cover only a fixed-port run.

   (a) is the smaller change and keeps M5e.3's determinism. It is the owner's call.
2. **pip's trust without the profile.** "pip as it is today" trusts its own bundled store, so
   it would refuse the per-run CA and could install nothing. Whether the evidence image
   points pip at the baked CA through image-level configuration — a system `pip.conf`
   `cert = /etc/direwolf/pip-ca.pem`, not a launcher variable — has to be decided and
   stated, because ADR-0055's profile later replaces that with its own pinned `PIP_CERT`
   and `PIP_CONFIG_FILE`.
3. **Case names.** `tests/architecture/test_m5e_plan.py` requires ADR-0054 §8's and ADR-0055
   §9's proposed case names to be new: no task may already require them. Cases of pip as
   it is today must therefore be named apart, for example `registry-pip-*` and
   `registry-npm-*`, or that test changed deliberately. The proposed names belong to the
   profiles' acceptance in M5e.5.
4. **Policy.** The shipped packs deny `pip install` (plan §3, R14). The evidence's operator
   policy must allow it explicitly, recorded as the evidence's, never shipped.

## 5. The registry tools image (hosted only)

- **Built on the runner, never locally.** Package-manager tools are hosted-only (owner
  direction 3, plan §1).
- **Offline `FROM scratch`.** Built with `--network none` and named by content, as
  `scripts/dw.py`'s existing tools image is.
- **Pinned and checked.** Node.js, npm and pip are pinned to exact versions from a
  SHA-pinned setup action or the runner's tool cache, and each archive is checked against
  a checksum recorded in the repository before use (OD-E4). A version change is a reviewed
  diff.
- **Recorded.** The image prints each tool's version and SHA-256, and the evidence records
  them.
- **Trust.** The per-run `ca.pem` is baked at both trust paths, and nothing else is: no
  public roots, since nothing public is reached.

## 6. Proposed evidence cases (names illustrative)

Each case gets a fresh environment and an empty target, with no cache. Every line carries its
level and its enforcement, under the existing attribution contract (`require_attributed_evidence`,
`ATTRIBUTION`). The environment is a measured, conforming `PROXY_ONLY` one.

| Case | Expected | Enforced by |
|---|---|---|
| `registry-pip-granted-index-installs` | the base wheel installed, its files the fixture's | pip; the grant |
| `registry-pip-dependency-from-granted-index` | the dependent wheel's dependency fetched from the same index | pip; the grant |
| `registry-pip-ungranted-index-refused` | nothing installed; `CONNECT` refused | the proxy's decision |
| `registry-pip-file-on-ungranted-host-refused` | nothing installed | the proxy's decision |
| `registry-pip-redirect-to-ungranted-host-refused` | nothing installed | the proxy's decision |
| `registry-pip-direct-route-refused` | no route but the proxy | the namespace's errno |
| `registry-pip-untrusted-issuer-refused` | `registry-rogue` presented; nothing installed | pip's own TLS verification |
| `registry-pip-sdist-built-today` | the build backend's marker **present**: today's gap, stated, not hidden | measured |
| `registry-pip-pth-not-run-by-install` | the `.pth` marker absent after the install | pip; measured |
| `registry-npm-refused-before-anything` | `npm install` and `npm ci` refused `HYGIENE_NOT_EVIDENCED`; no intent, no environment | the authority |
| `registry-census-clean` | every container, network and egress directory the run made removed by label; everything older kept | the census |

## 7. CI task and job

- **Task.** `make sandbox-registry-evidence` in `scripts/dw.py`. It refuses before anything
  unless `DW_REGISTRY_EVIDENCE=1` on a GitHub-hosted runner, as `sandbox-capacity` does with
  its own variable. Locally it reports NOT EXERCISED and fails.
- **Job.** A required `sandbox-registry` job in
  [`.github/workflows/ci.yml`](../.github/workflows/ci.yml), required once by the `ci`
  aggregate, with the `test_ci_*` treatment:
  - present, Linux, unconditional;
  - no `continue-on-error`, no secrets;
  - exactly its command;
  - its case list equal to what the suite prints;
  - its lines' levels and attribution checked;
  - a committed negative control for a dropped case, a wrong level, a missing attribution
    and a weakened workflow.
- **Mutation review.** `make sandbox-registry-mutations`, a manual hosted workflow the owner
  triggers (OD-E7). A hosted-only kill is reported as hosted, never as local.

## 8. Risks and dependencies

- **Port 443 on loopback** (decision 1) needs elevated binding on the runner, and a second
  loopback address.
- **pip's trust** (decision 2) is image configuration, and must not drift into a launcher
  variable before ADR-0055 is accepted.
- **Case-name collision** with the ADRs' proposed cases (decision 3).
- **Tool checksums.** Upstream archives and checksums are maintained by hand, and a
  mismatch fails closed.
- **Runner image churn.** The Ubuntu 26.04 migration already changed `sudo`; the image is
  built from pinned inputs to stay independent of it.
- **Resource ownership.** Every origin process, scratch directory and container is owned by
  the task and removed by it, as the existing census requires.
- **No E6.** No case may weaken a hard rule or a topology; the R-B guard and the attribution
  gate hold that.

## 9. Milestones for a future, authorised implementation

1. **M5e.4a:** the owner's decision (§1), the guard update, and decisions 1–4.
2. **M5e.4b:** the tools image and its checksum task, hosted-only; prints versions and
   digests.
3. **M5e.4c:** origins on the runner and the resolver fixture, with the census.
4. **M5e.4d:** the pip cases.
5. **M5e.4e:** the npm refusal case.
6. **M5e.4f:** the CI job, its `test_ci_*` and negative controls, the mutation workflow, and
   docs.
7. **Exit:** hosted green, and the owner's acceptance of M5e.4. That accepts no ADR and no
   profile.

## 10. As built (2026-11-05; hosted verification pending)

§1's preconditions are met: the owner's sequencing decision is recorded in the plan's §10 and
held by `tests/architecture/test_m5e_r3_closure.py`, and M5e.3 passed hosted (runs
[41916040076](https://github.com/Onwcan/DireWolf/actions/runs/41916040076) and
[41920008027](https://github.com/Onwcan/DireWolf/actions/runs/41920008027), 29 of 29 jobs each).

**The implementation's choices** — §4's four decisions, and the tools' provenance (for the
owner's review; none is an owner decision):

1. **Ports: fixed unprivileged ports, named in the URLs.** The origins listen on loopback at
   18443 (granted), 18444 (ungranted) and 18445 (the granted name under the rogue issuer).
   `generate()` takes `granted_port` and `ungranted_port`, and `origin.py` takes `--port`.
   This is §4's option (b) with fixed ports rather than per-run ones. Why: nothing binds 443,
   needs a second loopback address, sudo or a sysctl, or changes the runner. The fixtures stay
   deterministic per seed and ports, and the default's bytes and recorded digest are
   unchanged. The cost: a port already taken on the runner fails the run, closed, before the
   origin is ready.
2. **pip's trust: the workload's own `--cert`.** The run's anchor sits in the workspace, as
   the agent evidence's does, and every pip command names it. There is no image `pip.conf`,
   no `/etc/direwolf/pip-ca.pem` and no launcher variable, so nothing exists for ADR-0055's
   pinned `PIP_CERT`/`PIP_CONFIG_FILE` to replace or undo. pip keeps its bundled roots, as
   pip does today, and no fixture name reaches them. This differs from §5's "baked at both
   trust paths": the image is built once by the task, before the per-run PKI exists, and
   carries no trust store at all.
3. **Case names:** `registry-pip-*`, `registry-npm-*` and `registry-*`, apart from ADR-0054
   §8's and ADR-0055 §9's proposed names.
4. **Policy:** the evidence's own operator policy. It allows the image's Python and npm, by
   path and digest, in a sandbox, under the shipped packs' `workspace_exec_hygiene` obligation
   and without their `argv_safe`. It is never shipped.
5. **Provenance (OD-E4): the publishers' own archives.** OD-E4's follow-up (the plan's §10)
   names the source as "a SHA-pinned setup action or the runner's tool cache". The
   implementation instead fetches each publisher's own archive — the python-build-standalone
   GitHub release, nodejs.org, PyPI — and checks it against the SHA-256 recorded in the
   repository before use. What OD-E4 decided holds: exact versions, checksum-verified, a
   version change a reviewed diff. The mechanism differs, and needs the owner's acceptance as
   such. Why: no third-party action's code runs in the job, and nothing depends on what a
   runner image happens to cache.

**What was built:**

- **Pins:** `tests/sandbox/registry_tools.toml` holds CPython 3.12.15
  (python-build-standalone 20261013), pip 26.2.2, and Node.js 24.22.1 with npm 11.19.1. Each
  entry has its upstream URL and SHA-256, cross-checked against the publisher's own list when
  pinned, and again on 2026-11-05: python-build-standalone's `SHA256SUMS`, Node.js's
  `SHASUMS256.txt` (which also names npm 11.19.1 as the npm it bundles), PyPI's file digest.
  Node.js and pip were released on 2026-10-20 and the CPython build on 2026-10-13, each at
  least two weeks before it was pinned. Their source is decision 5's.
- **Tools image** (`scripts/dw.py`, `_registry_tools_image`), built on the runner only:
  - each archive is fetched over https from its own host only and checked before use;
  - archives are extracted through tarfile's `data` filter;
  - pip's wheel replaces the build's bundled pip;
  - `bin/npm` is one launcher started by the pinned Node.js;
  - the image is built `FROM scratch` with `--network none`;
  - every version is read back from inside the image, and any mismatch fails closed.
- **Task:** `make sandbox-registry-evidence` refuses before anything unless
  `DW_REGISTRY_EVIDENCE=1` on a GitHub-hosted runner. It takes a census of containers and
  networks before and after, removes its images, and gates the suite's lines through
  `require_attributed_evidence` (19 cases, `dwkp-end-to-end`, each outcome held by
  `REGISTRY_OUTCOMES`).
- **Suite:** `crates/dwkd-authority/tests/sandbox_registry.rs` runs two hosted-only tests.
  The suite checks again where it is before anything starts. It uses a real DWKP client on
  the released `serve --sandbox-config` and broker, with a fresh measured `PROXY_ONLY`
  environment per pip case. pip runs with no cache, no compiled files and no retry, in an
  empty target each time. `tests/sandbox/registry_inspect.py` reads the results inside the
  environment and holds them to the fixture's wheels on the host.
- **Job:** `sandbox-registry` in `.github/workflows/ci.yml` is required once by `ci` and held
  by `tests/architecture/test_ci_sandbox_registry.py`. That test carries negative controls
  for a dropped case, a wrong level, a missing or wrong attribution, a hidden gap, a weakened
  workflow, a floating pin, a digest or version mismatch, and the task starting work before
  its check.

**Not built:** `make sandbox-registry-mutations` and its manual workflow (§7, OD-E7). No kill
is claimed. **Not yet run:** the evidence itself, which only the hosted job runs.

**Risks the hosted run will settle first:**

- whether the standalone CPython and the official Node.js run in a `FROM scratch` image with
  the runner's shared objects (the task's in-image version checks fail closed if they do not);
- how pip 26 reports each refusal, which the suite reads from its own output: a proxy's
  `403`, `Errno 101`, a resolver failure, `CERTIFICATE_VERIFY_FAILED`;
- whether pip's truststore-backed context honours `--cert` beside its bundled roots.

Each fails the job, closed, rather than passing it.
