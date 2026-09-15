# Artifacts

First-class, content-addressed, provenance-carrying outputs. Artifacts keep large data out of the context window and make results durable beyond a run.

---

## 1. Model

```python
Artifact:
    id: ArtifactId                # art_<uuidv7>
    sha256: str                   # content address
    size: int
    mime: str

    run_id, agent_id, task_id
    created_by: ToolInvocationId | AgentId
    workspace_id: WorkspaceId | None

    trust: TrustLabel
    provenance: ProvenanceChain
    source_ref: SourceRef | None   # URL or path it came from

    kind: OUTPUT | DOWNLOAD | PATCH | REPORT | SCREENSHOT | DATASET | LOG | ARCHIVE
    label: str
    sensitivity: PUBLIC | PRIVATE | SECRET
    retention: RUN | SESSION | DURABLE | PINNED
    quarantined: bool              # downloads start true
    expires_at: Timestamp | None
```

Storage: `artifacts/<sha[0:2]>/<sha[2:4]>/<sha256>`. Identical content is stored once and referenced by many metadata rows — cheap, and it makes "did this change since last run?" a hash comparison.

## 2. Three jobs

1. **Context economy.** Tool output above `inline_budget_bytes` (default 32 KiB) spills here and the model gets a structure-aware excerpt. This is what makes a 500 MB build log cost 4 KB of context instead of the run.
2. **Durability.** Results outlive the run and are exportable.
3. **Provenance anchoring.** A taint source *is* an artifact id. When policy says a run is `EXTERNAL_UNTRUSTED` because of `art_01J8…`, the operator can read exactly what came in — which is what makes the approval prompt's taint warning actionable rather than ominous.

## 3. Lifecycle

```
create (hash → classify MIME → redact → store)
  → [quarantine, if a download]
  → reference from context / read / excerpt
  → export | expire | delete
```

**Creation is kernel-side.** The runtime cannot write to the store directly; it streams content to the kernel, which hashes it, applies secret redaction, enforces quota, and writes it. A store the constrained process can write to would make recorded provenance meaningless.

### Downloads are quarantined

Anything fetched from the network or produced by a browser starts `quarantined = true`:

- never executed, never auto-opened, never placed on a `PATH`
- MIME **sniffed**, not taken from `Content-Type` or the extension
- archives never auto-extracted (zip-slip, nested bombs)
- writing it into the workspace needs a separate capability; for executable types, an approval
- clearing quarantine is an explicit, audited operator action

### Retention and GC

| Policy | Default for |
|---|---|
| `RUN` | intermediate tool output |
| `SESSION` | session working files |
| `DURABLE` | reports, patches, deliverables |
| `PINNED` | operator-marked, never auto-deleted |

Garbage collection is reference-counted against the event log, context manifests and memory provenance. **An artifact reachable from a provenance chain is never collected**, because otherwise "why was this run untrusted?" would decay into a dangling id.

## 4. Excerpting

The excerpt is what the model actually sees, so it is chosen by content type rather than by blind truncation (strategies in [TOOL_SYSTEM.md](TOOL_SYSTEM.md) §6).

Two hard rules: excerpting is **deterministic** — same artifact, same excerpt, which replay depends on — and it never splits a multi-byte character or an escape sequence.

The reference given to the model is structured so the agent can choose to look closer:

```json
{"artifact":"art_01J8XQ…","mime":"text/plain","size":524288000,
 "excerpt_strategy":"log_head_tail","lines":1840221,"truncated":true,
 "read_more":"artifact.read(id, offset, length) | fs.search(artifact=id, pattern=...)"}
```

## 5. Patches as artifacts

Code changes are artifacts of kind `PATCH`: unified diff plus the base revision. This makes an agent's work reviewable *before* application, makes subagent merges explicit ([ORCHESTRATION.md](ORCHESTRATION.md)), and makes "show me what it did" one command.

`fs.patch` applies atomically: validate against the base revision, apply to a temp copy, fsync the file, rename, fsync the parent directory. A base-revision mismatch is a **conflict**, never a force.

**Every path inside the diff is canonicalised, not just the target root.** A patch is the one tool that writes N attacker-chosen paths from a single authorised call, and the patch is authored by an untrusted component — a subagent, or a model. So for each `+++ b/…` header the kernel resolves the path under the pinned target root fd with `RESOLVE_BENEATH`, and the whole patch is rejected if any hunk:

- escapes the root (`../`, absolute paths, drive letters, UNC) — patch-shaped zip-slip;
- creates or writes through a symlink;
- sets a mode with setuid/setgid or adds the executable bit to a file that did not have it;
- touches a control-surface path (§4a) without the corresponding approval.

Rejection is whole-patch, never partial: applying half a diff is a worse outcome than applying none.

## 6. Export

```console
$ direwolf artifact export art_01J8... --out ./report.pdf
$ direwolf run export run_01J8... --out ./run.tar.zst   # artifacts + manifests + events
```

Exporting a `SECRET`-sensitivity artifact requires confirmation. Bundles carry a manifest with hashes so they are independently verifiable.

## 7. Security

| Threat | Defence |
|---|---|
| Secret written into an artifact | Redaction on the creation path; `secret.redaction_hit` audited |
| Malicious download executed | Quarantine; no auto-open; approval for executable types |
| Zip-slip / decompression bomb | No auto-extract; extraction under `fsize` rlimit and path containment |
| MIME confusion | Content sniffing, not declared type |
| Store poisoning by the runtime | Store is kernel-owned; runtime has no direct write path |
| Disk exhaustion | Per-run and global quotas; creation fails closed |
| Cross-session leakage | Artifacts are scoped; reads require a matching capability |
| Dangling provenance | GC respects provenance reachability |
