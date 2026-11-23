# ADR-0076: ISR2-01 -- `audit_level=full` is not kept on a `net.http` hop

**Status:** Proposed · **Date:** 2026-11-23 (found by the second security review of 2026-11-22 as ISR2-01; built 2026-11-23 and committed as `85ddb7d`; hosted evidence observed on CI #212 (run 45240438449, `02bb256`) and CI #213 (run 45250010413, `8b771a7`): the regression test and its `obligation-unenforceable` case in `make net-http-evidence`; nothing here is accepted) · **Would amend (on acceptance):** [ADR-0050](0050-m5c-kernel-performed-net-http-ssrf-redirects-and-credential-egress.md) §5 step 6 (which obligations a hop keeps) · **Leaves unchanged:** ADR-0050 §11 and §13 (a hop's record keeps no path, query, header value or body), DWKP, the private protocol, the store, the shipped packs, and every other route's obligations

> **A hop keeps `max_output_bytes` and nothing else.** `audit_level=full`
> asks for the canonical request on record; a hop's record holds its URL as
> a digest and none of its headers or body, by design. So a rule that asks
> for it is not kept, and the hop is denied `OBLIGATION_UNENFORCEABLE` --
> the answer every other obligation a hop cannot keep already gets.

## Context

The policy obligation `audit_level(full)` means "record full canonical
arguments, not just the hash" ([POLICY.md](../POLICY.md)). An `ALLOW` whose
obligations the authority cannot keep is denied `OBLIGATION_UNENFORCEABLE`.

ADR-0050 §5 step 6 lists `audit_level` among the obligations a hop keeps,
and the hop's obligation check counted it kept. ADR-0050 §13, in the same
record, keeps no payload, header value, body, path or query in the audit, and
§11 stores the URL as its digest: a hop has nowhere to keep the full request.
The second security review (ISR2-01,
[INDEPENDENT_SECURITY_REREVIEW_2026-11-22.md](../INDEPENDENT_SECURITY_REREVIEW_2026-11-22.md))
reproduced the result on `f7f5aae`: a hop matched by a rule carrying
`max_output_bytes=16, audit_level=full` was allowed, and neither `audit.log`
nor `kernel.db` held its path or query -- only `url_sha256`. A rule's
author was told an obligation was kept that was not.

Elsewhere the obligation is truthful or already denied: a host launch's and
a workload's intent records carry the full argv
([ADR-0045](0045-m4d-process-execution-broker.md) §14,
[ADR-0052](0052-m5d-sandboxed-process-exec.md)), and the file routes deny it.
A workload's tunnel, which is opaque by design and decided on its
destination ([ADR-0061](0061-workload-egress-decided-by-policy-novelty-and-exposure.md)),
and a credential's own `secret.use` action keep it as their records decided;
this record does not revisit them.

## Decision

1. A `net.http` hop keeps `max_output_bytes` only. A hop whose `ALLOW`
   carries `audit_level=full` is denied `OBLIGATION_UNENFORCEABLE`, before any
   exchange, as one carrying `network_deny` already is
   (`crates/dwkd-authority/src/state/net_http/plan.rs`, `obligations`).
2. ADR-0050 §11 and §13 stand: no path, query, header value or body enters
   the durable record. Recording the URL to keep the obligation was the
   alternative, and is rejected below.
3. Nothing else changes: the credential's own action (`secret.use`) still
   keeps `audit_level`; the process, workload and tunnel routes keep it as
   before; the file routes deny it as before. The response bound
   (`max_output_bytes`) is unaffected.

## Consequences

- An operator rule that put `audit_level=full` on a `network.https` rule now
  denies the `net.http` hops it matches; it allowed them before while
  recording less than it asked. The workload tunnels the same rule decides
  are unaffected. No shipped pack uses the obligation.
- Migration: drop `audit_level=full` from network rules, or accept that the
  hops it matches are denied.
- M6 binds a decision's obligations into an approval's binding hash and
  shows them to the approver (APPROVALS.md §2); an obligation is now never
  displayed as kept on a hop where it is not.

## Alternatives considered

- **Record the full URL, headers and body under `audit_level=full`.**
  Rejected: it breaks ADR-0050 §13's rule that a hop's record holds no
  path, query or payload -- which keeps a request's data out of a durable,
  append-only log -- for whichever rule asked.
- **Redefine `audit_level=full` on a hop as "the record a hop keeps".**
  Rejected: the obligation would then mean nothing on this route while
  meaning the full argv on the others; a rule's author could not tell.
- **Refuse the policy at load when a network rule carries it.** Rejected:
  the same `network.https` rule also decides a sandboxed workload's tunnels
  (ADR-0061), which keep the obligation, so the loader cannot tell from the
  rule which route will evaluate it; and a deny at decision time is the
  contract every other unkept obligation follows.

## Residuals

- What a hop sent to an allowed origin is recoverable from the record only
  as a digest, as ADR-0050 decided. The obligation cannot change that.

## Owner decisions

- **OD-1** accept the deny: a network rule carrying `audit_level=full`
  stops allowing hops (an operator-visible change).

## Evidence

- `crates/dwkd-authority/src/state/net_http/tests.rs`
  (`a_tainted_run_reaches_no_new_origin_and_obligations_narrow_or_deny`):
  a hop under a rule carrying `audit_level=full` is denied
  `OBLIGATION_UNENFORCEABLE` and no exchange reaches the broker; the
  `max_output_bytes` rule still narrows the response bound. The test's
  `obligation-unenforceable` evidence case, required by
  `make net-http-evidence`, is printed only after both hold.
- Hosted: in CI #212 (run 45240438449, `02bb256`) and CI #213 (run
  45250010413, `8b771a7`) the `net.http` job printed
  `NET-EVIDENCE {"suite":"authority-net-pipeline","case":"obligation-unenforceable","outcome":"OBLIGATION_UNENFORCEABLE","count":1}`
  among its 193 cases. That one case line covers both of the test's
  unenforceable obligations, `network_deny` and `audit_level=full`: it is
  printed only after the two assertions above it held, so it is this
  record's evidence, though not by a name of its own.
- CI #211 at `85ddb7d` shows failed: its macOS `make test` job was
  cancelled when the next push started CI #212 (`cancel-in-progress`), not
  by a test.

## Rollback and deployment

Reverting restores the counted-as-kept behaviour. Nothing is stored or
migrated.

## Revisit if

A hop gains a durable record of its full request, or `audit_level` gains a
level a hop can keep.
