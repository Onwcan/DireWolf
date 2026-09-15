# ADR-0013: Subagents are runs; capabilities attenuate; budgets are subtractive

**Status:** Accepted · workspace portion superseded by [ADR-0025](0025-subagent-workspace-clone.md) · **Date:** 2026-09-11

> **PARTIALLY SUPERSEDED by [ADR-0025](0025-subagent-workspace-clone.md).** Attenuation, subtractive budgets, the context firewall and orphan reaping all stand. Point 6's "git worktree" does not: a linked worktree shares config and hooks with the parent, so either the isolation claim is false or git does not work in the child. Subagent repo workspaces are now independent clones.

## Context

Delegation is where capability models usually collapse. One comparable system derives child capability "from depth automatically" with no per-task least privilege, producing uniform-privilege trees. Separately, per-child budgets that are not debited from the parent make fan-out a cost-amplification primitive.

## Decision

1. **A subagent is a run** — own context, own budget reservation, own workspace, own lifecycle. Not a function call.
2. **`child_caps ⊑ parent_caps`**, enforced by the **kernel's** Capability Broker at mint time. The orchestrator asks; it cannot grant. Property-tested over 10⁶ generated chains.
3. **Depth attenuation supplements explicit per-child requests; it never substitutes for them.** Authority derived from depth alone produces trees where a leaf researcher holds a root's power.
4. **Budgets are subtractive.** A child's reservation comes out of the parent's remaining budget and unused portions return on completion. Ten children cannot each receive the parent's budget.
5. **Context firewall.** The parent receives a schema-validated result, not the child's transcript. This is context economy *and* security: a child that read hostile content does not relay it verbatim upward. The full transcript stays in the event log for the operator.
6. **Workspace isolation** via git worktree or COW copy; children produce `PATCH` artifacts and **merge conflicts are surfaced as conflicts**, never resolved last-writer-wins.
7. **Orphans are reaped.** Child grants are tied to the parent's lease epoch, so a child cannot outlive its parent's authority.

## Consequences

An agent tree has a provable authority ceiling and a provable cost ceiling. Parallel coding agents cannot silently destroy each other's work. `direwolf run lineage` answers "why did this subagent run?" back to a human sentence.

Cost: explicit per-child capability requests are more work for the orchestrator than inheriting everything; merge conflicts require resolution instead of being hidden.

## Alternatives considered

- **Children inherit the parent's full set.** Simple, and it means one compromised leaf has root-equivalent authority.
- **Independent per-child budgets.** Makes fan-out a denial-of-wallet primitive.
- **Shared workspace with file locking.** Locks do not compose with agents that fail mid-edit.

