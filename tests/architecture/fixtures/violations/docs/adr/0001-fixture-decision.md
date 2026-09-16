# ADR-0001: A fixture decision that was edited after it was accepted

**Status:** Accepted · **Date:** 2026-01-01

## Context

FIXTURE: deliberately invalid. The digest recorded for this file in
`accepted.sha256` does not match its contents, which is what an edit to an
accepted ADR looks like when nobody re-recorded the digest (ADR001).

An edit whose author *did* re-record it leaves no trace in this directory at
all, which is why the real gate is the history anchor rather than the manifest.
That one cannot be proved from a fixture tree, because it needs a repository
with commits: see `tools/dwcheck/tests/test_checks.py`.

## Decision

Nothing. This file exists to be rejected.
