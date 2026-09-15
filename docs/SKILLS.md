# Skills

**A skill is procedural memory with a capability declaration and an integrity hash.** It is not a prompt snippet, and it is not trusted because the agent wrote it.

---

## 0. What "skills" means in V1

The word covers five separable things. Only the first is in V1, and everything else has a named owning milestone. **Anything without an owning milestone is not in V1.**

| Capability | V1? | Owning milestone |
|---|---|---|
| **Consuming built-in and explicitly-installed static skills** — `SKILL.md` + manifest from a local directory or a pinned git URL, verified by content hash, capability-intersected at admission | **Yes** | **M11a** (new; sits with the Context Engine, which is where skill content enters the prompt) |
| Skill registry / public marketplace | No | Not scheduled. Requires signing and publisher revocation first ([PLUGINS.md](PLUGINS.md) §7) |
| Learned skill synthesis (agent drafts a candidate from a trajectory) | No | M25 |
| Automated validation pipeline (static inspection → sandbox tests → security eval → approval) | No | M25 — synthesis without validation is a persistence mechanism, so they ship together or not at all |
| Procedural consolidation / learning from repeated use | No | M25+ |

Two consequences worth stating, because they were ambiguous before this section existed:

- **Skill *verification* is kernel-side even in V1.** The registry that assigns trust levels and the hash check at load live in `dwkd-authority`, not the runtime — a trust label the constrained process can write is not a trust label ([ADR-0028](adr/0028-policy-input-ownership.md)). The runtime's Skill Resolver selects and renders; it does not decide trust.
- **The capability intersection is computed by the kernel at admission**, from the kernel's own record of which skills are active and verified. The runtime cannot suppress a skill to widen its grant, nor declare one it does not have.

Sections 4 (learned skills), 8 (distribution/registry) and parts of 5 (the validation pipeline) therefore describe **M25 design, fixed now so V1 does not foreclose it** — not V1 behaviour.

## 1. Structure

```
skills/python-testing/
  SKILL.md              # frontmatter + procedure (the only required file)
  manifest.toml         # machine-readable declarations
  scripts/              # optional executables the skill drives
  tests/                # required for TRUSTED status
  examples/
  references/           # progressive-disclosure detail, loaded on demand
```

```toml
# manifest.toml
schema_version = 1

[skill]
name        = "python-testing"
version     = "1.4.0"
publisher   = "direwolf-builtin"          # or a user/org id
purpose     = "Run and interpret Python test suites"
trust       = "SYSTEM_TRUSTED"            # asserted here, VERIFIED by the registry

[triggers]
keywords    = ["pytest", "unit test", "test failure"]
file_globs  = ["**/test_*.py", "**/conftest.py"]
task_kinds  = ["CODE", "TEST"]

[requires]
capabilities = ["fs.read:${WORKSPACE}",
                "fs.write:${WORKSPACE}",
                "process.exec:/usr/bin/pytest",
                "process.exec:/usr/bin/python3"]
binaries     = ["pytest", "python3"]
environments = ["sandbox"]
platforms    = ["linux", "darwin", "windows"]

[io]
input_schema  = "schemas/input.json"
output_expect = "test_report"

[integrity]
content_hash  = "sha256:3f2a..."          # over every file in the directory
signature     = "..."                      # publisher signature, if any
```

## 2. Capabilities narrow, never widen

```
effective = agent_capabilities ∩ skill.requires.capabilities
```

A skill **cannot grant authority**. Declaring `process.exec:*` in a manifest gets you nothing if the agent lacks it; declaring `fs.write:/etc` gets you nothing in any profile.

The declaration serves two purposes: it lets the operator see what a skill *wants* before installing it, and it lets a run activate a skill with a reduced set — a run using only `python-testing` does not need network, so it does not get network, even if its agent profile would have allowed it.

This is intersection, not union. It is the single most important line in this document.

## 3. Trust levels

| Level | Meaning | How it is reached |
|---|---|---|
| `SYSTEM_TRUSTED` | Shipped with DireWolf, signed | Release process |
| `USER_TRUSTED` | Operator reviewed and approved | Explicit `direwolf skill trust` |
| `COMMUNITY_UNVERIFIED` | Installed from a registry, not reviewed | Install |
| `GENERATED_UNTRUSTED` | Written by an agent | Synthesis |
| `QUARANTINED` | Failed validation or hash mismatch | Automatic |

**Trust is assigned by the registry, never read from the manifest.** A manifest claiming `trust = "SYSTEM_TRUSTED"` is claiming, not proving. The registry checks the signature against the shipped public key; failure means `COMMUNITY_UNVERIFIED` at best, and the mismatch is reported to the operator.

Trust level is visible to the model as metadata on the skill, so the agent knows it is following a procedure it wrote itself versus a reviewed one. That is useful context, not a control.

## 4. Learned skills

The pipeline from "that worked" to "reusable procedure":

```
successful trajectory
  → candidate extraction       repeated tool sequences with a stable shape
  → synthesis                  model drafts SKILL.md + manifest
  → static inspection          §5
  → sandboxed test execution   in an isolated workspace, capabilities = skill's declared set
  → security evaluation        injection probes, exfiltration probes
  → behavioural evaluation     does it reproduce the original success on held-out cases?
  → HUMAN APPROVAL             diff shown, capabilities shown, provenance shown
  → registry commit at USER_TRUSTED
```

**Every stage before approval is mandatory, and approval is never automatic.** A skill that skips straight from synthesis to the registry is a persistence mechanism: it is content the agent wrote, re-injected into every future context, and if the agent was manipulated once it stays manipulated. Comparable systems default this gate to off; we do not offer the option.

Until approved, a candidate lives in `skills/candidates/` at `GENERATED_UNTRUSTED`, usable **only** in the run that created it, and never auto-loaded.

```console
$ direwolf skill review sk_01J8...
  Candidate: fix-flaky-async-tests  v0.1.0    GENERATED_UNTRUSTED
  Derived from: run_01J8… (2026-09-11), 3 similar trajectories
  Requests:  fs.read:${WORKSPACE}  fs.write:${WORKSPACE}  process.exec:/usr/bin/pytest
  Static:    PASS   Sandbox tests: PASS (7/7)   Security eval: PASS   Behavioural: 5/6
  [v] view  [d] diff vs similar  [t] trust  [r] reject  [e] edit
```

## 5. Static inspection

Applied to every skill at install and at every load (hash mismatch → `QUARANTINED`):

- **Capability escalation attempts** — requesting more than the installing agent holds is flagged prominently, not silently intersected away, because it tells the operator something about intent.
- **Instruction-override patterns** — "ignore previous instructions", "you are now", attempts to redefine the system role, attempts to describe policy as if it were configuration.
- **Exfiltration shapes** — reading credential-ish paths, encoding data into URLs, base64 of file contents, novel outbound destinations.
- **Obfuscation** — invisible Unicode (TAG, bidi, zero-width), homoglyphs, excessive encoding layers, scripts whose behaviour is not statically apparent.
- **Delimiter forgery** — content resembling DireWolf's context fences.
- **Script analysis** — shell metacharacters in command construction, `curl | sh`, `eval` of downloaded content, writes outside the workspace.
- **Prompt-injection payloads** aimed at a *future* reader, including at the human reviewer.

Static inspection is **a review aid, not a boundary.** It catches known shapes and will be evaded by novel ones. The boundary is that the skill runs with capabilities the agent already had, in a sandbox, under the same policy pipeline as everything else. We say this explicitly because tools like this are routinely over-trusted.

## 6. Progressive disclosure

Skills cost context. Three levels:

| Level | Loaded | Cost |
|---|---|---|
| L0 | name, purpose, triggers | ~30 tokens each, all skills |
| L1 | full `SKILL.md` | ~500–2000, on activation |
| L2 | a named `references/` file | on explicit request |

L0 for every installed skill sits in the stable context prefix. L1 loads when a skill activates, which is a cache break — so activation is decided once at run start where possible, not renegotiated per turn ([CONTEXT.md](CONTEXT.md) §3).

## 7. Resolution

```
score(skill) = keyword_match·0.3 + file_glob_match·0.3
             + task_kind_match·0.2 + historical_success·0.2
```

Filtered by: capability compatibility (a skill needing capabilities the run lacks is not offered — it would only produce denials), platform, binary availability, and trust floor from policy. `SAFE` can be configured to a `USER_TRUSTED` floor, excluding community and generated skills entirely.

Ties break toward higher trust, then higher historical success. At most `max_active_skills` (default 3) activate per run; more than that and they start contradicting each other.

## 8. Versioning and distribution

Semver: patch = wording, minor = additive steps, **major = changed capabilities or changed behaviour**. A major bump re-enters review — a skill you trusted at 1.x is not a skill you trusted at 2.0.

V1 distribution is local directories and explicit git URLs. **No registry ships in V1** (see [ROADMAP.md](ROADMAP.md) §Deferred): a public skill marketplace is a supply-chain attack surface that deserves its own design, and shipping one before the validation pipeline is proven would be backwards.

Skills are exportable and importable with full provenance. **Imported skills always enter at `COMMUNITY_UNVERIFIED`** regardless of the trust level recorded in the bundle — a trust label in a file you downloaded is a claim by the file's author.

## 9. Security summary

| Threat | Defence |
|---|---|
| Skill grants itself capabilities | Intersection, not union; declarations are requests |
| Agent silently installs a privileged skill | Human approval mandatory; no configuration disables it |
| Injected content becomes a skill | Full validation pipeline; provenance recorded; approval shows the source |
| Skill content steers future runs | Trust level visible; untrusted skills excluded under `SAFE`; static inspection for override patterns |
| Skill modified after approval | Content hash verified at every load; mismatch → `QUARANTINED` |
| Skill exfiltrates via its scripts | Scripts run sandboxed under the intersected capability set; network requires an explicit capability |
| Malicious import | Always `COMMUNITY_UNVERIFIED`; re-validated on import |
| Skill reads secrets | Secrets are per-invocation and kernel-injected; there is no ambient credential for a skill to read |
