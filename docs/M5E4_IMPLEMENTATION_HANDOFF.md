# M5e.4 — pip, and npm refused: implementation handoff

**Project:** [DireWolf](https://github.com/Onwcan/DireWolf)\
**Prepared:** 2026-11-04, on `main` at `6be8c414e42d09d90c817d217a6c22a01e4cb68e` plus M5e.3's
completion (unstaged at the time of writing)\
**Status (as prepared, 2026-11-04):** **NOT STARTED.** This was preparation only.\
**Status (2026-11-05):** **IN PROGRESS — implementation complete, hosted verification
pending.** The owner authorised M5e.4 ahead of M5e.2's close
([M5E_ASSURANCE_PLAN.md](M5E_ASSURANCE_PLAN.md) §10, "M5e.4's sequencing"); M5e.5 and M5e.6
are not authorised. What was built, and how §4's decisions were made, is §10 below. Locally the
evidence is NOT EXERCISED by design.\
**Status (2026-11-06):** **IMPLEMENTATION REPAIRED / HOSTED REVERIFICATION PENDING.** The first
hosted run failed at the first Python workload (§11). It is repaired, unstaged, and M5e.4 is not
complete until the hosted job passes and the owner accepts it.\
**Status (2026-11-07):** **REPAIR COMMIT-READY / HOSTED VERIFICATION PENDING.** The second hosted
run got past the interpreter and installed from the granted index. It failed on the suite's own
count of the proxy's refusals, which included the environment's probe (§12). The test's
accounting is repaired, unstaged; nothing in production changed.\
**Status (2026-11-07, later):** **HOSTED VERIFIED / OWNER ACCEPTANCE PENDING.** The owner committed the repair as `7aa784a`. Hosted runs 42390237238, 42392419869, 42394667883 and 42397671369 (run nos. 134–137) passed 30 of 30 jobs each, `sandbox-registry` and the `ci` aggregate among them. The closeout record and the decision it asks of the owner are §13.\
**Status (2026-11-09):** **COMPLETE.** M5e.4 was accepted on runs 134–137, with the OD-E4 mechanism as built ([M5E_ASSURANCE_PLAN.md](M5E_ASSURANCE_PLAN.md) §10, "M5e.4's acceptance"); §13 records it.\
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
  least two weeks before it was pinned. Their source is decision 5's. The CPython pin is the
  release's stripped build since 2026-11-06 (§11).
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

## 11. The first hosted run, and its repair (2026-11-06)

**What happened.** Hosted run
[42112947252](https://github.com/Onwcan/DireWolf/actions/runs/42112947252) (run no. 130,
`3e322ad`) passed 28 of 30 jobs. In `sandbox-registry`, the image built, every pinned version
read back correctly and npm's three refusal cases passed. The pip test stopped at its first
workload with `ToolFailedV5 { reason: ExecutableChanged, environment_destroyed: Some(false) }`.

**The cause, traced end to end.** The name misleads: nothing changed.

| Step | What it showed |
|---|---|
| The archive | SHA-256 `5d546fc0…`, as pinned |
| `python/bin/python3.12` in it | 68 023 040 bytes, SHA-256 `b61d8a15…` |
| `dw.py`, `DW_REGISTRY_PYTHON_SHA256`, policy, manifest | that same digest, printed by the run |
| `docker container cp` | a tar stream longer than the broker reads |
| `process/run.rs`, `oci.rs` | cut at 67 174 400 bytes (`MAX_ARCHIVE_BYTES`): `stdout_cut`, `Verdict::Fail` |
| `ready_workload` | `BrokerRefusal::DigestMismatch`, for any verdict but `PASS` |
| `workload_ops.rs`, `workload_route.rs` | `EXECUTABLE_DIGEST_MISMATCH`, then `ExecutableChanged` |

So the broker refused an executable it could not wholly read. That is the behaviour wanted: the
bound was the probe's, and it had never met an executable this large. The interpreter is 848 640
bytes past the copy's limit.

**The repair, and why not the bound.** The bound is what the broker holds in memory for each
launch, and a fixture's debug symbols are no reason to raise it for production. The pin is now
the same release's `install_only_stripped` build: archive SHA-256 `178d3d83…`, in the release's
own `SHA256SUMS`; interpreter 31 009 064 bytes, SHA-256 `eaaa3080…`, measured from the archive.
That hash is a real change of the expected digest, derived from the new pin, never chosen.

**What keeps it from recurring.**

- `registry_tools.toml` records the interpreter's size and SHA-256. `load_registry_pins` refuses
  a size past the broker's bound, in `make test`, and an architecture test holds the constant in
  `dw.py` to the one in `digest.rs`.
- `_registry_tools_image` holds the extracted file to both, before anything is built.
- `sandbox-workload-evidence` stands on both sides of the bound on a real runtime:
  `workload-executable-at-the-copy-bound-runs` and
  `workload-executable-past-the-copy-bound-refused`, the second at the size the run measured.
- The broker logs `workload_executable_refused verdict=… cause=…`, with `past-the-copy-bound`,
  `not-the-pinned-file`, `malformed-archive`, `copy-failed` or `runtime-unavailable`. It names
  no path and no digest, and the refusal on the wire is unchanged. The registry suite prints the
  broker's last events when a workload does not run.

**Not relaxed:** the bound, the digest comparison, tar parsing, any refusal, `REGISTRY_CASES`,
`REGISTRY_OUTCOMES`, the job or the hosted-only gate.

**A limit operators should know.** An executable past 64 MiB cannot run in an environment, and
the wire says `EXECUTABLE_CHANGED`; the log says why. The official Node.js binary is past it.
M5e.4 is unaffected, since `npm`'s launcher is the file pinned and hashed, and M5e.5 must keep
that in view.

## 12. The second hosted run, and its repair (2026-11-07)

**What happened.** Hosted run
[42296614431](https://github.com/Onwcan/DireWolf/actions/runs/42296614431) (run no. 133,
`cb76b67`; the two runs before it were cancelled by the next push) passed 28 of 30 jobs.
`sandbox-registry` failed, and the `ci` aggregate with it. The stripped interpreter worked:
`registry-tools-pinned-in-the-environment` was printed with SHA-256 `eaaa3080…`. The pip test
then stopped at `sandbox_registry.rs:1151` with `left: 1, right: 0`.

**What that line is.** It is not pip's exit code. The exit-code assertion two cases above it
(`:1142`) prints `Some(…)` and pip's whole output; the assertion at `:1151` is the count of
`TARGET_NOT_GRANTED` refusals in the environment's destruction record, held to zero, with no
message. So, by the panic's line and values (the job's log needs a sign-in and was not read
here), the granted install had exited 0, installed the base wheel byte for byte, fetched its
file from the granted origin once and left the ungranted origin untouched. Then the proxy's
count for that environment was 1.

**The cause.** Every measurement of a `PROXY_ONLY` environment asks the proxy for a name no grant
can hold: `CONTAINER_PROXY_REACHABLE` sends one `CONNECT direwolf-probe.invalid:443`
(`crates/dwk-sandbox-probe/src/network.rs`, `proxy_reachable`) and passes only on DireWolf's
own `403 TARGET_NOT_GRANTED`. The proxy counts that refusal like any other
(`crates/dwkd-broker/src/egress/tunnel.rs`), and the destruction's record reports the
environment's counters (`egress_fields`, `crates/dwkd-authority/src/state/environment.rs`). The
probe runs at preparation and at each later measurement; a workload's launch is judged from
the host and asks nothing (`judged_for_work`, `crates/dwkd-broker/src/sandbox/oci.rs`). So every
environment the suite makes ends with one `TARGET_NOT_GRANTED` that is the boundary measuring
itself. The broker's own real-runtime evidence already counted it ("the counters say what the
probe asked", `crates/dwkd-broker/tests/sandbox_egress.rs`, at least 2 after a preparation and
one more measurement); the registry suite did not.

**Reproduced.** In process, with no runtime: the broker's
`egress::tests::a_target_that_is_not_granted_is_refused_before_anything_is_resolved` sends the
probe's exact request and counts it `TARGET_NOT_GRANTED`; it passes. The suite's new
`a_probes_own_question_is_never_counted_as_a_workloads_refusal` holds the run's own numbers
(`TARGET_NOT_GRANTED=1`, one measurement: no refusal of the workload's).

**Two more defects of the same kind, found reading the rest of the test.**

- The untrusted-issuer case held the raw count to zero too. It would have failed the same way.
- The three refused cases (`ungranted-index`, `file-on-ungranted-host`, `redirect`) required a
  raw count of at least one. **The probe's question alone satisfied that**, so those assertions
  could pass with the workload refused nothing. pip's `403` was asserted separately, so the
  evidence did not rest on the count alone, but the count proved nothing.

**The repair: the test's accounting, not the boundary.** `beyond_the_probe` takes the probe's
questions out of the destruction's count. `Lab::probe_questions` derives them from the audit
log: the environment's `environment.ready` record, with `CONTAINER_PROXY_REACHABLE` neither
failed nor unobservable, plus every `environment.measured` record. A count below the questions
is an error, never zero. The granted install, the dependency, the granted control, both
direct-route cases and the untrusted issuer now hold the workload to exactly no refusal. The
three refused cases hold it to at least one of its own. `registry-egress-counted-at-destruction`
reports the workloads' counts, `probe-questions-excluded`.

**Observability.** Every pip assertion now reports, bounded:

- the invocation, exit code and environment;
- the last 4 KiB of stdout and stderr, with key or certificate material and credential headers
  withheld;
- the destruction's dispositions and each origin's request count and last paths;
- the broker's last 24 events.

`a_failures_report_is_bounded_and_withholds_key_material` holds the bound and the withholding.

**Guarded.** `tests/architecture/test_ci_sandbox_registry.py` refuses any raw disposition count
outside `beyond_the_probe`, and checks five more things:

- the accounting test runs everywhere;
- the preparation's own question is counted;
- six cases hold the workload to no refusal;
- three hold it to at least one;
- every one of those holds is caught by a negative control.

**Not changed:** production code, the probe, the proxy, any grant, TLS, the pins, the image,
`REGISTRY_CASES`, `REGISTRY_OUTCOMES`, the job and the hosted-only gate.

**Still unproven until the next hosted run.** Everything after the granted install has never run
on any host: the dependency, the refused and direct cases, pip's error texts (`403`,
`[Errno 101]`, `[Errno -N]`, `CERTIFICATE_VERIFY_FAILED`), the source distribution's backend
and the `.pth` cases. If one fails, its report now says why. M5e.4 stays **IN PROGRESS** until
that run passes and the owner accepts it, the OD-E4 provenance deviation included.

## 13. Closeout record (2026-11-07)

**What ran.** Four pushes to `main`, each a hosted run of the `CI` workflow with 30 of 30 jobs
successful, `sandbox registry evidence (make sandbox-registry-evidence)` and the `ci` aggregate
among them:

| Run | No. | Commit | What the commit changed |
|---|---|---|---|
| [42390237238](https://github.com/Onwcan/DireWolf/actions/runs/42390237238) | 134 | `7aa784a` | this repair (§12): the suite's accounting, its diagnostics and their guard |
| [42392419869](https://github.com/Onwcan/DireWolf/actions/runs/42392419869) | 135 | `bbe3561` | M5e.5's sequencing record and its evidence-only option, inert without it |
| [42394667883](https://github.com/Onwcan/DireWolf/actions/runs/42394667883) | 136 | `7df0840` | M5e.5's profiles, reached only through that option |
| [42397671369](https://github.com/Onwcan/DireWolf/actions/runs/42397671369) | 137 | `6a702d7` | M5e.5's evidence, manual job and mutation review, required by nothing |

The runs, their jobs and their conclusions were read from GitHub's public Actions API on
2026-11-07. The job's log needs a GitHub sign-in, so this record does not quote its lines. The
owner read run 137's log, which ends `attributed evidence: 19 cases reported`.

**What a green `sandbox-registry` job shows.** A green exit means every one of the following
held, because the task fails on any one of them:

- **Where it ran.** The task and the suite refuse unless `DW_REGISTRY_EVIDENCE=1` on a
  GitHub-hosted runner (`registry_refusal`; the suite's own `hosted()`), and refuse Docker
  Desktop. The workloads ran in measured `PROXY_ONLY` environments on the runner's Docker
  Engine, through the released `serve --sandbox-config`, the released broker and a real DWKP
  client: `dwkp-end-to-end`, not an in-process simulation.
- **What it ran.** The suite's two tests both passed (`test result: ok. 2 passed`), and
  `require_attributed_evidence` accepted the output. That means all 19 of `REGISTRY_CASES`
  reported, none twice and none NOT EXERCISED. Each was at `dwkp-end-to-end` and attributed to
  a mechanism its `ATTRIBUTION` rule allows, and each outcome began with what
  `REGISTRY_OUTCOMES` requires. An install shows what it installed; a refusal shows nothing was
  installed; the source distribution's build is shown as today's gap; npm is refused
  `OBLIGATION_UNENFORCEABLE` before anything is prepared.
- **What it counted.** The proxy's refusals are each case's own beyond the probe's questions
  (§12): six cases had none, and each refused case had at least one of its own.
- **Provenance and cleanup.** Each pinned archive matched its recorded SHA-256 before a byte
  was read. The interpreter matched its pinned size and digest, below the broker's copy bound.
  Every tool's version was read back from inside the image. Afterwards no container or network
  the evidence made remained, every one that predated it was kept, and the images were removed.

**Nothing was weakened to get there.** Between the failed run 133 and run 134, the only change
was §12's accounting in the suite, its diagnostics and its guard. No production line, pin,
case, outcome, level, attribution, job or gate changed. Runs 135–137 add M5e.5's code, which
production reaches only through the evidence-only option the plan's §10 fences.

**The OD-E4 deviation, for the owner's review.** OD-E4 decided pinned versions verified by
checksum, and its follow-up named "a SHA-pinned setup action or the runner's tool cache" as the
mechanism. As built, the task fetches each publisher's own archive over https and checks it
against the SHA-256 recorded in `tests/sandbox/registry_tools.toml` before use (§10; the plan's
§8 and §10). OD-E4's substance holds: exact versions, checksum-verified, a version change a
reviewed diff. The mechanism differs: no third-party action's code runs, and nothing depends on
what a runner image caches.

**Decision requested:**

1. Accept M5e.4 as complete on runs 134–137.
2. Accept the OD-E4 mechanism as built, or name the one to use instead.

**When the owner accepts,** a separate change records it. It adds an acceptance record to the
plan's §10, changes this document's, the plan's and the ROADMAP's status to say M5e.4 closed,
and changes `tests/architecture/test_m5e_r3_closure.py`, which today refuses any status document
that calls M5e.4 complete, to allow that one step. Nothing else changes. M5e.2 stayed PARTIALLY
IMPLEMENTED / ASSURANCE BLOCKED ([issue #19](https://github.com/Onwcan/DireWolf/issues/19)) until
its own closure on 2026-11-09.

**Decided (2026-11-09).** Both points are decided. M5e.4 is **COMPLETE** on
runs 134–137, and OD-E4's mechanism is accepted as built — each publisher's archive fetched
over https and checked against `tests/sandbox/registry_tools.toml`'s SHA-256 before use. The
change that records it adds the plan's §10 record ("M5e.4's acceptance"), updates the plan's,
the ROADMAP's, the README's and this document's status, and lets `test_m5e_r3_closure.py`
accept M5e.4 called complete only while that record stands. No production line, pin, case,
outcome, level, attribution, job or gate changes.
