# DireWolf developer commands.
#
# These are the documented interface.  Each target delegates to
# scripts/dw.py, which prints every command it runs; `make` is a thin,
# familiar front door and not a second source of truth.  Native Windows has no
# `make`, so contributors there run `python scripts/dw.py <task>` directly --
# the tasks are identical, and CI runs the same ones.

PY := python3
ifeq (,$(shell command -v python3 2>/dev/null))
PY := python
endif
DW := $(PY) scripts/dw.py

.DEFAULT_GOAL := help
.PHONY: help dev check test lint fmt fmt-check typecheck arch adr-history schema schema-check \
        eval eval-check eval-one capability-evidence policy-benchmark \
        authority-state-evidence filesystem-canonicalization-evidence \
        authority-transport-evidence authority-write-probe broker-fs-read-evidence \
        filesystem-operations-evidence process-broker-evidence secret-broker-evidence \
        sandbox-foundation-evidence sandbox-egress-evidence sandbox-workload-evidence \
        net-http-evidence net-http-mutations sandbox-workload-mutations sandbox-secret-evidence \
        sandbox-secret-mutations sandbox-workspace-evidence sandbox-workspace-mutations \
        sandbox-agent-evidence sandbox-agent-mutations sandbox-release-evidence \
        sandbox-release-mutations sandbox-restart-evidence sandbox-capacity-evidence \
        sandbox-proxy-weakened-evidence sandbox-proxy-weakened-review \
        sandbox-registry-evidence sandbox-hygiene-evidence sandbox-registry-mutations m5e-evidence-bundle m5e-gate-check \
        sandbox-neighbour-mutations d11-hardening-evidence d11-hardening-mutations d11-posture fuzz-smoke fuzz security docs \
        preflight tools hooks clean

help:            ## List available commands
	@$(DW) --list

dev:             ## Set up or verify a development checkout (idempotent)
	@$(DW) dev

check:           ## Every gate CI runs: format, lint, types, boundaries, tests, deps
	@$(DW) check

fmt:             ## Format Rust and Python in place
	@$(DW) fmt

fmt-check:       ## Fail if anything is unformatted
	@$(DW) fmt-check

lint:            ## clippy -D warnings, and ruff check
	@$(DW) lint

typecheck:       ## mypy --strict
	@$(DW) typecheck

test:            ## cargo test and pytest
	@$(DW) test

arch:            ## Architecture boundary checks (hygiene, not containment)
	@$(DW) arch

adr-history:     ## Accepted ADRs against the history that accepted them (CI: DW_ADR_BASE_REF, DW_ADR_BEFORE)
	@$(DW) adr-history

schema:          ## Regenerate schemas/ from dwk-proto and Python bindings from schemas/
	@$(DW) schema

schema-check:    ## Fail if generated schemas, docs or Python bindings are stale
	@$(DW) schema-check

eval:            ## Run every evaluation suite (deterministic; no model calls)
	@$(DW) eval

eval-check:      ## The eval merge gate: deterministic subset vs the baseline
	@$(DW) eval-check

eval-one:        ## Re-run one eval: make eval-one ID=<eval id> [SEED=<n>]
	@$(DW) eval-one

capability-evidence: ## The 10^6 delegation-chain capability campaign (DW_EVIDENCE_SEED replays)
	@$(DW) capability-evidence

policy-benchmark: ## The 300-rule policy evaluation benchmark (release; p99 < 200us)
	@$(DW) policy-benchmark

authority-state-evidence: ## M3d real-file state evidence: crash windows, audit, contention, latency
	@$(DW) authority-state-evidence

filesystem-canonicalization-evidence: ## M4a real-fs resolver evidence: symlinks, races, roots (Linux)
	@$(DW) filesystem-canonicalization-evidence

authority-transport-evidence: ## M3e real-process DWKP evidence; cross-uid half needs DW_PEER_AS
	@$(DW) authority-transport-evidence

authority-write-probe: ## Attempt runtime writes to authority state as DW_PROBE_AS (two identities)
	@$(DW) authority-write-probe

broker-fs-read-evidence: ## M4b real-process brokered fs.read evidence; three identities need DW_BROKER_AS, DW_PEER_AS
	@$(DW) broker-fs-read-evidence

filesystem-operations-evidence: ## M4c filesystem tools: plans, atomicity, races, crashes; three identities need DW_BROKER_AS, DW_PEER_AS, DW_WRITE_GROUP
	@$(DW) filesystem-operations-evidence

process-broker-evidence: ## M4d process execution: re-proof, races, output, kill, crashes; three identities need DW_BROKER_AS, DW_PEER_AS
	@$(DW) process-broker-evidence

secret-broker-evidence: ## M4e secrets: backends, mode A, the injection primitive, redaction, residue, crashes; three identities need DW_BROKER_AS, DW_PEER_AS, core contract DW_M4E_CORE_EVIDENCE=1
	@$(DW) secret-broker-evidence

sandbox-foundation-evidence: ## M5a real OCI containers: strict profile measured, weakened profiles, probe tamper, lifecycle, foreign safety; M5e.2 every hard rule judged in process, PROXY_ONLY included
	@$(DW) sandbox-foundation-evidence

sandbox-egress-evidence: ## M5b PROXY_ONLY on real OCI containers: relay, CONNECT proxy, guard, pinning, SNI, budgets, bypasses, weakened topologies
	@$(DW) sandbox-egress-evidence

sandbox-workload-evidence: ## M5d.1-M5d.2 workloads in real OCI environments: identity, bounds, wall clock, process trees ended, digests, drift, escapes, an agent-shaped workload, the authority's gates, ledger and crash windows; the public process.exec over real DWKP, serve --sandbox-config, the hygiene launcher with real git/Python/pytest; M5e.2 cross-run isolation
	@$(DW) sandbox-workload-evidence

sandbox-workload-mutations: ## M5d.1-M5d.2 mutation review: each workload guard weakened in turn must fail a unit suite or sandbox-workload-evidence (slow)
	@$(DW) sandbox-workload-mutations

sandbox-secret-evidence: ## M5d.3 secret modes B/C in a real OCI environment: a synthetic credential through the trusted launcher on fd 3 or the operator's variable, absent from argv, records, events and logs, redacted on return; the authority's pipeline, crash windows and the shipped packs, over real DWKP and serve --secrets-file
	@$(DW) sandbox-secret-evidence

sandbox-secret-mutations: ## M5d.3 mutation review: each credential guard weakened in turn must fail a unit suite or sandbox-secret-evidence (slow)
	@$(DW) sandbox-secret-mutations

sandbox-workspace-evidence: ## M5d.4 workspace ownership and measured quota: group 10001 interop, refusals never repaired, drift and mount substitution, real ENOSPC on a dedicated 64 MiB fs; provisioned cases need DW_WORKSPACE_PRIVILEGED=1 (hosted)
	@$(DW) sandbox-workspace-evidence

sandbox-workspace-mutations: ## M5d.4 mutation review: each workspace guard weakened in turn must fail a unit suite or sandbox-workspace-evidence (slow)
	@$(DW) sandbox-workspace-mutations

sandbox-agent-evidence: ## M5d.5 an agent-shaped workload in PROXY_ONLY over real DWKP and the released serve: granted HTTPS only, every other path refused and attributed, budgets, reap, crashes, no replay; three host identities need DW_AGENT_PRIVILEGED=1, DW_BROKER_AS, DW_PEER_AS, DW_AGENT_OUTSIDER (hosted)
	@$(DW) sandbox-agent-evidence

sandbox-agent-mutations: ## M5d.5 mutation review: each identity, proxy, policy, cleanup and non-replay guard weakened in turn must fail a unit suite or sandbox-agent-evidence (slow)
	@$(DW) sandbox-agent-mutations

sandbox-release-evidence: ## M5d.6 a run's release ends its environment: durable before the broker, exactly its own, an in-flight workload and its descendants ended, crashes and a lost broker reconciled, nothing replayed, other runs and foreign containers kept; a fake broker, then real OCI over real DWKP and the released serve
	@$(DW) sandbox-release-evidence

sandbox-release-mutations: ## M5d.6 mutation review: each release guard weakened in turn must fail a unit suite or sandbox-release-evidence (slow)
	@$(DW) sandbox-release-mutations

sandbox-restart-evidence: ## M5e.2 R11, HOSTED ONLY: restarts the runner's Docker Engine under a running authority; refuses anywhere but a disposable GitHub-hosted runner (DW_RUNTIME_RESTART=1)
	@$(DW) sandbox-restart-evidence

sandbox-capacity-evidence: ## M5e.2 R8 at the cap, HOSTED ONLY: every live environment the authority allows, all but one at their own task bound, the last prepared, measured and served (ADR-0056); refuses anywhere but a disposable GitHub-hosted runner (DW_CAPACITY_EVIDENCE=1)
	@$(DW) sandbox-capacity-evidence

sandbox-proxy-weakened-evidence: ## M5e.2 R3's E6, HOSTED ONLY: every oci-strict hard rule weakened in turn in a real PROXY_ONLY environment the released broker prepares, measured from both vantages and refused (ADR-0057's R-B, ADR-0058); refuses anywhere but a disposable GitHub-hosted runner (DW_E6_EVIDENCE=1)
	@$(DW) sandbox-proxy-weakened-evidence

sandbox-proxy-weakened-review: ## M5e.2 R3's E6, offline: verify a downloaded hosted sandbox-proxy-weakened job log, every observation from its bytes (DW_E6_LOG=<file>); needs no runtime
	@$(DW) sandbox-proxy-weakened-review

sandbox-registry-evidence: ## M5e.4, HOSTED ONLY: pip as it is today against the fixture registries, npm refused before anything is prepared; builds the registry tools image from its checksum-verified pins; refuses anywhere but a disposable GitHub-hosted runner (DW_REGISTRY_EVIDENCE=1)
	@$(DW) sandbox-registry-evidence

sandbox-hygiene-evidence: ## M5e.5, HOSTED ONLY: npm and pip under their profiles (ADR-0054 §8, ADR-0055 §9, accepted); refuses anywhere but a disposable GitHub-hosted runner (DW_HYGIENE_EVIDENCE=1); required by ci (sandbox-hygiene)
	@$(DW) sandbox-hygiene-evidence

m5e-evidence-bundle: ## M5e.6 (G1), HOSTED ONLY: seal what this job's M5 evidence task kept (target/m5e-evidence/<task>) with the run's provenance, for the job to upload to the M5 gate; NOT EXERCISED anywhere but a disposable GitHub-hosted runner
	@$(DW) m5e-evidence-bundle

m5e-gate-check: ## M5e.6 (G2), HOSTED ONLY: the M5 gate -- judge again every bundle this run's evidence jobs uploaded (target/m5e-gate) and print the M5e acceptance verdict; NOT EXERCISED anywhere but its own job on a GitHub-hosted runner
	@$(DW) m5e-gate-check

sandbox-registry-mutations: ## M5e.5's mutation review (ADR-0054 §9, ADR-0055 §10): unit mutants anywhere; hosted ones only in the manual job, NOT EXERCISED elsewhere
	@$(DW) sandbox-registry-mutations

sandbox-neighbour-mutations: ## M5e.2 R8 negative control (ADR-0056 §6): the task backstop put back at 256 must fail both neighbour tests as finding F-R8 (needs a runtime)
	@$(DW) sandbox-neighbour-mutations

d11-hardening-evidence: ## D11 hardening: the worker's syscall filter, vouching from the kernel, start-up window, swap posture; real workers, observers, cgroups; root-only cases need DW_D11_PRIVILEGED=1
	@$(DW) d11-hardening-evidence

d11-hardening-mutations: ## D11 hardening mutation review: each guard weakened in turn must fail the broker's suites (slow)
	@$(DW) d11-hardening-mutations

d11-posture:     ## Read-only: what this host gives D11 hardening (Yama, binary mode, swap, cgroup, page zeroing, WSL2)
	@$(DW) d11-posture

net-http-evidence: ## M5c net.http, no internet: SSRF/DNS, redirects, TLS, credential binding and residue, crashes, budgets (DW_CPU_CONTENTION=n adds load)
	@$(DW) net-http-evidence

net-http-mutations: ## M5c mutation review: each net.http safeguard weakened in turn must fail net-http-evidence (slow)
	@$(DW) net-http-mutations

fuzz-smoke:      ## Stable mutation fuzzing of dwk-proto (not coverage-guided)
	@$(DW) fuzz-smoke

fuzz:            ## Coverage-guided cargo-fuzz run, every target (nightly; DW_FUZZ_SECONDS)
	@$(DW) fuzz

security:        ## cargo-deny and pip-audit
	@$(DW) security

docs:            ## Check relative links and ADR citations
	@$(DW) docs

preflight:       ## Report the toolchain this machine has
	@$(DW) preflight

tools:           ## Install cargo-hosted tools the gates need
	@$(DW) tools

hooks:           ## Install the optional fast pre-commit hook
	@$(DW) hooks

clean:           ## Remove build output and the virtualenv
	@$(DW) clean
