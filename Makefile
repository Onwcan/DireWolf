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
.PHONY: help dev check test lint fmt fmt-check typecheck arch schema schema-check \
        eval eval-check eval-one capability-evidence policy-benchmark \
        authority-state-evidence authority-write-probe fuzz-smoke \
        fuzz security docs \
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

authority-write-probe: ## Attempt runtime writes to authority state as DW_PROBE_AS (two identities)
	@$(DW) authority-write-probe

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
