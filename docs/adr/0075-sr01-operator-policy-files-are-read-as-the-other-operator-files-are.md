# ADR-0075: SR-01 -- an operator's policy files are read as its other files are

**Status:** Accepted · **Date:** 2026-11-23 (proposed 2026-11-22, found by the security review of 2026-11-22 as SR-01; OD-1 accepted 2026-11-22 on this record and its change as committed in `f45eacf` and `f7f5aae`; hosted: both regression tests ran and passed in CI #209 (run 45056220111, `f7f5aae`) and in every run since, among them CI #213 (run 45250010413, `8b771a7`); the Decision below is unchanged from that review, and only this line, the migration bullet, one residual and the evidence were added at acceptance) · **Builds on:** [ADR-0046](0046-m4e-secret-handles-backends-injection-and-redaction.md) §8 (the trusted-file walk), [ADR-0052](0052-m5d-sandboxed-process-exec.md) §2a (the operator's sandbox file), [ADR-0071](0071-f06-an-operator-egress-allowlist-every-shipped-network-rule-requires.md) (the egress allowlist) · **Changes:** `--policy-file`'s operator contract -- a relative path, a symlink, or a file or directory another uid could change no longer starts the authority · **Leaves unchanged:** DWKP, the private protocol, the store, the shipped packs, composition, the revision and every decision

> **A policy file is trusted exactly as the operator's other files are.** It
> is read through the same walk as `--secrets-file`, `--sandbox-config` and
> `--egress-allowlist`: an absolute path from `/` with no symlink, every
> directory one only root or the authority can change (or sticky), the file
> regular, owned by root or the authority, writable by nobody else, within
> the loader's bound -- or the authority does not start.

## Context

The policy decides what the authority allows: within the mode's ceiling and
the operator's egress ceiling (both flags), it is the authorization input. Before
this change `PolicySet::from_files` (`crates/dwkd-authority/src/state/policy_state.rs`)
followed a symlink and checked only that the file was regular, bounded and
UTF-8; it checked neither its owner, its mode, nor the directories above it.
The three other operator files already refuse all of that through
`crate::secret::backend::read_operator_file`.

The consequence needs a deployment mistake to be reachable: a uid other than
root and the authority's that can write the file, replace a directory on its
path, or plant a symlink there decides the next incarnation's policy -- the
uid the authority exists to constrain, if it is a runtime's. The other loaders
refuse the same mistake; this one accepted it silently.

## Decision

1. `PolicySet::from_files(profile, files, trusted_owner)` reads each file with
   `read_operator_file(path, trusted_owner, MAX_SOURCE_BYTES, "--policy-file")`.
2. `server::start` reads the policy once the authority's own uid is known
   (from preparing the socket's place), and passes that uid as the trusted
   owner. The order is otherwise the same: nothing is served before the
   policy loads, and the authority does not start if it does not.
3. Nothing else changes: the logical source name (the file name), the
   revision over the loaded bytes, composition and every decision.

## Consequences

- An operator whose policy files are root's or the authority's, not writable
  by others, under such directories, and named by absolute path sees no
  change. Any other start now fails with the flag and the reason.
- Migration: `chown root:root` (or the authority's user) and `chmod go-w`
  every directory above the files that another uid owns or can write; pass
  absolute paths; replace a symlink with the file. A file another uid could
  write is **replaced, not re-moded**: a descriptor that uid already opened
  for writing keeps writing after `chmod go-w` (the second security review's
  ISR2-04), so a fresh file is made by the trusted owner, restricted before
  it holds anything, and renamed over the old name
  ([OPERATIONS.md](../OPERATIONS.md) §4, "Making an operator file
  trusted").

## Alternatives considered

- **Document only** (the state before): rejected -- the policy is the
  operator input of highest value, and a document does not stop a start.
- **Warn and continue**: rejected -- a warning leaves another uid deciding the
  policy.
- **A digest pinned on the command line** (`--policy-sha256`): stronger
  against a replacement the walk would accept (root's own), at the cost of a
  second thing to keep in step. Not now; revisit if policies are distributed.

## Residuals

- Root, and the authority's own uid, can still change the files: they are
  the operator. Each start records the revision it loaded (`policy.installed`),
  so a change between starts is visible in the audit record.
- A policy is read at start only; nothing reloads it.
- The walk judges a file's owner and mode when it reads it; Linux checks a
  descriptor's write permission when it is opened, not when it is used. A
  process of another uid that opened the file for writing while it was
  writable keeps that descriptor after the mode changes (ISR2-04), which is
  why migration replaces such a file instead of re-moding it. Against root
  or the authority's own uid, which are the operator, the walk promises
  nothing.

## Owner decisions

- **OD-1** accept the fail-closed contract for policy files (an
  operator-visible change). **Accepted 2026-11-22.**

## Evidence

- `crates/dwkd-authority/tests/transport_server.rs`
  (`the_policy_loader_refuses_a_file_another_uid_could_change`): a file in
  its owner's private directory loads; group- or other-writable, a symlink,
  a file in a directory everyone can write, a relative path, and a file
  whose owner is not the trusted one are refused; and
  (`an_operator_policy_file_is_trusted_only_as_the_other_operator_files_are`):
  the released binary serves with the good file and refuses to start with
  each of the others, naming `--policy-file`.
- Hosted: both tests ran and passed in `tests (make test) (ubuntu-latest)`
  and in `authority boundary (make authority-transport-evidence)` of CI #209
  (run 45056220111, `f7f5aae`) and of every run since, among them CI #213
  (run 45250010413, `8b771a7`).
- The walk itself: `crates/dwkd-authority/src/secret/backend/tests.rs`
  (`the_operator_file_walk_refuses_a_symlinked_directory_and_a_set_id_file`,
  ISR2-03) refuses a symlinked directory on the path and a set-id file, and
  reads the owner's file in a sticky directory; hosted in CI #213's
  `make test` on ubuntu.

## Rollback and deployment

Reverting restores the permissive read. Nothing is stored or migrated.

## Revisit if

Policies are reloaded at runtime, supplied other than by file, or distributed
with a digest.
