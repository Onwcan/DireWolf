# ADR-0072: The operator's model library is an offline command-line tool; a model download is egress the authority must decide, and waits for a download operation the broker does not have

**Status:** Proposed · **Date:** 2026-11-18 (the offline library designed, built and tested locally 2026-11-18; its tests passed on Linux, Windows and macOS on CI #198 (run 44706359028, `3584f3e`, 2026-11-20); OM-1 to OM-4 decided 2026-11-20; the ADR is not accepted) · **Proposes a change to:** [ROADMAP.md](../ROADMAP.md) M7, whose providers (Hugging Face, Ollama, llama.cpp, LM Studio) explicitly exclude downloading models and launching their servers · **Builds on:** [ADR-0071](0071-f06-an-operator-egress-allowlist-every-shipped-network-rule-requires.md) (the operator's egress allowlist), [ADR-0050](0050-m5c-kernel-performed-net-http-ssrf-redirects-and-credential-egress.md) (the broker's one HTTPS client), [ADR-0020](0020-provider-request-path-v2.md) (model calls) · **Leaves unchanged:** DWKP, the private broker protocol, the authority, the broker, every policy pack and TX044

> **Managing model artifacts and running inference are different security
> operations, and stay apart.** What is built is an **offline library** an
> operator manages from `direwolf models`: local files imported, hashed,
> identified by their own headers without running anything in them, listed,
> verified again, removed, and sized against the host. It contacts no daemon,
> exposes no DWKP operation, and reaches no network. **Downloading** -- from
> Hugging Face, through Ollama, anywhere -- is egress, and DireWolf's egress is
> the authority's decision, performed by the broker's one HTTPS client
> (TX044). That needs a private-protocol operation that streams to the
> library, which does not exist; until it does, no download, search or
> pause/resume is built, and no command pretends to be.

## Context

The owner asked for an LM Studio-like manager: discovery and downloads from
Hugging Face, Ollama management, llama.cpp integration, quantisation choice,
pause and resume, SHA-256 verification, revision pinning, licence and disk
information, hardware recommendations and safetensors support. M7 names the
same providers for **inference**, and keeps downloading and launching out of
its scope.

Three facts bound what can be built now:

- **TX044:** TLS and HTTP crates are used only in the broker's HTTPS client.
  A command-line downloader would be a second, unpoliced egress path -- no
  allowlist (F-06), no address guard, no pinning, no audit.
- **The broker's client is for requests, not artifacts.** A `net.http` hop
  is bounded to 256 KiB, buffered in an exchange worker, and answered on the
  private channel; a multi-gigabyte, resumable, verified transfer into the
  library needs a new private-protocol operation and a worker that streams
  to a descriptor the authority opened.
- **Inference is M7's.** Selecting a model for a run is a provider route;
  none exists.

## Decision

### 1. Separate operations

| | model management | model inference |
|---|---|---|
| who asks | the operator, at a terminal | an agent, through a run |
| what it touches | the library's files | content a run sends to a model |
| network | a download: the authority's `model_download` path (not built) | M7's provider egress (not built) |
| credentials | a Hub token, the operator's | a provider key, bound to its origin |

Neither implies the other: a downloaded model is not a provider, and a
provider route grants no download.

### 2. Built: the offline library (`direwolf models`)

```text
<library>/objects/sha256/<hex>   read-only, never executable, never replaced
<library>/manifests/<name>.json  strict canonical JSON, written whole and renamed
<library>/tmp/                   what an interrupted import left; emptied first
<library>/lock                   one operation at a time
```

- **Import** copies each file into `tmp/`, hashing exactly the bytes written,
  places it by its digest, and then **identifies the copy** -- what is
  identified is what is kept. A model is one weights format: one GGUF file or
  every part of a split one (each part's own `split.no`/`split.count`), or
  one safetensors file or every shard its index names. JSON configuration and
  tokenizer files are parsed as strict JSON; `tokenizer.model` is opaque and
  bounded. A refused import keeps nothing it made.
- **Never executed, never extracted.** A pickle (`0x80`, protocol 2-5) and a
  zip archive (a PyTorch checkpoint) are refused by their bytes, whatever
  their names say; Python files, scripts and unknown formats are refused; no
  `trust_remote_code`, no conversion, no archive extraction.
- **Bounded readers.** GGUF: version 2 or 3, at most 65 536 keys, 1 MiB per
  string, 16 Mi elements per array, 256 MiB of metadata, 4 096 parts, no
  nested arrays. Safetensors: the format's 100 MiB header bound, every
  member defined, every dtype known, every byte after the header indexed by
  exactly one tensor whose shape and dtype fill it -- no hole, overlap or
  overflow.
- **Quantisation from the file.** `general.file_type` names it (Q4_0,
  Q4_K_M, Q5_0, Q5_K_M, Q8_0, and the rest of llama.cpp's table); a file's
  name is never its quantisation. A repository that offers no Q5 has no Q5.
- **What a manifest says.** Each file's SHA-256, length and format; the
  model's quantisation, architecture, context, layer and head counts, and
  licence as its metadata states them; and its states, never one score:
  `verified = LOCAL_DIGEST_ONLY` (local consistency -- an imported file has
  no trusted expected digest), `publisher_authenticated = false`,
  `format_supported = true`, `backend_compatible` by format only, and
  `ready_for_inference = false`.
- **Verify** hashes every object again and names what changed: absent, not a
  regular file (a symlink in its place), executable, another length, another
  digest.
- **Remove** deletes the manifest, then only `objects/sha256/<digest>` files
  no remaining manifest names. Nothing outside the library is touched; a
  model name is never a path; no name a file contains becomes a path.
- **Recommend** reads the CPU architecture, hardware threads and (Linux)
  `/proc/meminfo`; probes no GPU (graphics memory only as the operator states
  it, `--vram-gib`); and estimates weights + key-value cache + overhead in
  integer arithmetic: FITS, LIKELY_FITS, MAY_NOT_FIT, DOES_NOT_FIT, or UNKNOWN
  whenever a fact is missing -- never a promise from a file's size.

### 3. Not built: the authority's download path

When it is built, it is one reviewed change:

1. **Authority**: an operator-only, locally authenticated request (the
   operator's uid, never a DWKP run) names a source exactly -- a Hugging Face
   repository, a revision, and files -- and the authority resolves the
   revision to a commit, decides every origin against the operator's egress
   allowlist under a new `model_download` path (ADR-0071 OF-3) -- never
   `net_http` or `workload` -- records a durable job, and opens the library's
   staging file for the broker.
2. **Broker**: a streaming download worker writes into that descriptor,
   checks `Content-Length`, `Content-Range` and the entity tag on resume,
   refuses a full answer to a range request, follows no redirect the
   authority did not decide, sends the Hub token only to its bound origin,
   and stops at the declared size.
3. **Verification**: the local SHA-256 against the revision-bound LFS digest
   the Hub states for that commit -- then, and only then,
   `PUBLISHER_DIGEST_MATCHED`. A Git commit hash, an LFS object id, a Xet
   content identifier and an entity tag are different things and are never
   compared with each other.
4. **Jobs**: QUEUED, RESOLVING, DOWNLOADING, PAUSED, VERIFYING, READY, FAILED,
   CANCELLED, INTERRUPTED; a paused job holds its partial file and its
   commit; resuming re-checks both.
5. **Ollama** pulls with its own daemon's egress, which is not DireWolf's: a
   pull is a request to an operator-declared, authenticated daemon profile,
   and its transfer is that daemon's, reported as such. **llama.cpp** and
   **LM Studio** are M7 provider profiles; nothing here launches a server.
6. **Gated repositories**: never fetched through a mirror; the operator's
   accepted terms and token, nothing else.

This needs the private-protocol migration (ADR-0070 OD-3's protocol 13, or
its successor) and is proposed as its own milestone after M7's provider
route.

## Feature status

| # | requested | status |
|---|---|---|
| 1 | Hugging Face search | BLOCKED (TX044; §3) |
| 2 | repository inspection | BLOCKED (online); `inspect` reads local files |
| 3 | GGUF download | BLOCKED (§3) |
| 4 | Q4/Q5/Q8 selection | PARTIAL: identified from local files' metadata; no remote choice |
| 5 | pause/resume | BLOCKED (§3) |
| 6 | SHA-256 verification | IMPLEMENTED_AND_TESTED (local digest; publisher digest BLOCKED) |
| 7 | revision pinning | BLOCKED (§3) |
| 8 | licence information | PARTIAL: as GGUF metadata states it; Hub metadata BLOCKED |
| 9 | disk requirement | PARTIAL: weight bytes and the quota check; free space not probed |
| 10 | Ollama pull/list/inspect | BLOCKED (§3.5, M7) |
| 11 | llama.cpp | PARTIAL: GGUF compatibility by format; server profiles M7 |
| 12 | safetensors | IMPLEMENTED_AND_TESTED (single, sharded with index) |
| 13 | other safe formats | PARTIAL: JSON companions, `tokenizer.model` |
| 14 | hardware recommendations | IMPLEMENTED_AND_TESTED (RAM; GPU only as stated) |
| 15 | operator-only authorisation | IMPLEMENTED_AND_TESTED (a CLI; no DWKP operation) |
| 16 | model library storage | IMPLEMENTED_AND_TESTED |
| 17 | crash recovery | IMPLEMENTED_AND_TESTED (tmp swept; manifest last) |
| 18 | secure egress | BLOCKED (§3: no download path exists) |
| 19 | CLI commands | IMPLEMENTED_AND_TESTED (offline set) |
| 20 | real integration evidence | NOT_IMPLEMENTED (no online path to integrate) |

## Consequences

- An operator can keep, check and size local model files with DireWolf,
  with no new network path and no claim of inference.
- M7 keeps its scope; model downloads become a proposed milestone of their
  own, after M7's provider route.

## Residuals

- A locally imported file's publisher is unknown: `LOCAL_DIGEST_ONLY` says so.
- The lock is a file; a killed process leaves it, and the next command says
  which file to remove.
- Free disk space is not probed (no library call outside std is added).

## Alternatives considered

- **A downloader in the CLI.** Refused: a second egress path, outside F-06,
  the address guard and the audit (TX044).
- **Downloads as `net.http`.** Refused: a 256 KiB, buffered, agent-facing hop
  is the wrong shape and the wrong principal.
- **Mock online commands.** Refused: a command that exists but cannot work
  invites callers to form around it (the CLI's own rule since M1).

## Owner decisions

- **OM-1** accept the offline library as built;
- **OM-2** place the download path (§3) as its own milestone after M7's
  provider route, with the `model_download` allowlist path;
- **OM-3** whether Ollama's own egress is acceptable outside DireWolf's, or
  only from a daemon run in a DireWolf environment;
- **OM-4** whether a GPU probe (vendor tool or driver interface) is ever
  acceptable for recommendations.

**Decided 2026-11-20.** The status stays **Proposed**.

- **OM-1 -- approved as implemented.** The offline library is the scope
  built: content-addressed objects, format validation, checksums verified
  again, safe import and removal, conservative recommendations.
- **OM-2 -- approved as a roadmap decision.** Downloads are their own
  reviewed milestone after M7's provider route, and the authority decides a
  download apart from inference and from any agent's network capability.
  Not built.
- **OM-3 -- accepted as a security constraint.** An external Ollama
  daemon's own egress is not DireWolf's: it is never described as covered
  by DireWolf's egress enforcement unless the daemon is confined and its
  traffic mediated.
- **OM-4 -- approved with restrictions.** Read-only hardware inspection
  only: no vendor GPU tool run, no driver installed, no downloaded binary
  run, no privileged host access. What is built (`/proc/meminfo` and a
  size the operator states) is within it.

## Evidence

- `crates/direwolf-cli/src/models/tests.rs`: hand-built GGUF and safetensors
  headers (valid, truncated, oversized, hostile, disguised), pickles and
  zips refused, the library on real files (atomic manifests, read-only
  objects, corruption, symlinks, split and sharded models whole or not at
  all, nothing kept on refusal, quota, lock, sweep, reference-aware removal),
  estimates on fixed facts for Linux, Windows and macOS, and a command set
  without any online command.
- `tests/architecture/test_models_offline.py`: no HTTP or TLS crate in the
  CLI, no network call in its source, and no online command.
- CI #198 (run 44706359028, `3584f3e`, 2026-11-20): `make test` passed on ubuntu-latest
  and macos-latest (16 library tests each) and windows-latest (14: the
  two that need Unix permissions and symlinks are Unix-only).

## Rollback and deployment

Removing the command removes nothing else: the library is the operator's own
directory, and no daemon reads it.

## Revisit if

The private protocol gains a streaming download operation; M7's provider
route is built; or TX044 changes.
