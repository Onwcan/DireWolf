# ADR-0025: Subagent repo workspaces are independent clones, not linked worktrees

**Status:** Accepted · **Date:** 2026-09-12 · **Supersedes:** the workspace portion of [ADR-0013](0013-subagent-isolation.md)

## Context

ADR-0013 specified workspace isolation "via git worktree or COW copy."

Review finding H8: a linked worktree's `.git` is a **file** pointing into the parent repository's `.git/worktrees/<name>`, and config and hooks live in the shared common directory — outside the child's workspace root. So either:

- the parent's common directory is mounted into the child's sandbox, in which case the child can write the parent's `config` and `hooks/` and the isolation claim is **false** — and, given that allowlisted interpreters execute repository-controlled configuration (`SANDBOX.md` §4a), a low-privilege research child obtains code execution in the parent's next git command; or
- it is not mounted, in which case **git does not function** in the child's sandbox at all.

Neither is acceptable, and the original ADR did not say which was intended.

## Decision

| Workspace kind | Mechanism | When |
|---|---|---|
| `SHARED_RO` | same directory, read-only mount | reviewers, researchers |
| `GIT_CLONE` | **independent local clone with its own `.git`** | the workspace is a repo — **default for coders** |
| `COW_COPY` | copy-on-write clone (reflink / overlayfs) | non-repo workspaces; fast path where the filesystem supports it |
| `FRESH` | empty scratch | generation from nothing |

Rules:

1. **`git worktree` is not used for subagent workspaces.**
2. **`--shared` and `--reference` are forbidden** — they reintroduce the shared object store and with it the shared config/hooks problem.
3. The child's `.git` is its own: config, hooks, and objects.
4. Children return **`PATCH` artifacts**; they never write into the parent's workspace.
5. Merge is explicit and deterministic: apply in task-id order, validate against the recorded base revision, three-way merge if the base moved.
6. **A merge conflict is a first-class outcome** — a `CONFLICT` artifact and a task in `BLOCKED`, never last-writer-wins.

## Consequences

**Positive.** The isolation claim becomes true. Git works in the child. The cross-workspace code-execution path via shared hooks is closed.

**Negative.** Disk and clone time for large repositories — the real cost of this decision. `COW_COPY` on a reflink-capable filesystem (APFS, btrfs, XFS with reflink, ZFS) is the fast path and is preferred where available; a shallow clone is a fallback for very large repos where full history is not needed.

**Unchanged from ADR-0013:** subagents are runs; `child ⊑ parent` enforced kernel-side; subtractive budgets; depth attenuation as a supplement to explicit per-child requests; the context firewall; orphan reaping tied to the parent's lease epoch.

## Alternatives considered

- **Worktree with the common dir mounted read-only.** Git requires write access to the common directory for ordinary operations (index, refs, logs). Does not work.
- **Worktree plus hook/config neutralisation.** Relies on enumerating every config key that can execute — the blocklist problem, in the component where we least want it.
- **Bare shared object store with per-child refs.** Same shared-config exposure.

