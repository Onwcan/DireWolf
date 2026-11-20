# The operator's model library (`direwolf models`)

Decision record: [ADR-0072](adr/0072-the-operators-model-library-is-offline-and-a-download-is-egress-the-authority-decides.md)
(Proposed). This page is the command reference.

**What it is.** An offline library of local model files that an operator
manages from the terminal. It contacts no daemon, exposes no DWKP operation,
reaches no network, and runs nothing it reads. A model in it is **not** a
provider: nothing here serves inference (M7 does), and every manifest says
`ready_for_inference: false`.

**What it is not, yet.** Search, download, pause and resume, Hugging Face
revisions, Ollama, llama.cpp server profiles and choosing a model for
inference are not built. A download is egress, and DireWolf's egress is the
authority's decision through the broker's one HTTPS client (TX044); the
download operation that needs does not exist (ADR-0072 §3).

## Commands

| command | does | exit |
|---|---|---|
| `direwolf models status [--library <DIR>]` | how many models; what is not built | 0 |
| `direwolf models inspect <FILE>...` | identify each file by its own header, without importing it | 1 if any is refused |
| `direwolf models import --library <DIR> --name <NAME> [--quota-bytes <N>] <FILE>...` | copy one model's files in, hash them, identify the copies, write the manifest last | 1 if refused; nothing kept |
| `direwolf models list --library <DIR> [--json]` | every model, its format, quantisation and size | 0 |
| `direwolf models verify --library <DIR> <NAME>` | hash every file again; name what changed | 1 if anything is corrupt |
| `direwolf models remove --library <DIR> <NAME>` | the manifest, then every object no other model names | 1 if refused |
| `direwolf models recommend [--library <DIR>] [--context <N>] [--vram-gib <N>]` | this host's memory, and each model's estimated headroom | 0 |

A usage error exits 2. `--library` is always named: an absolute directory,
never a symlink, created private (0700) on first use.

## Files a model may hold

- **GGUF** weights: one file, or every part of a split one (each part's own
  `split.no` and `split.count` decide; a missing part refuses the import).
- **safetensors** weights: one file, or every shard its
  `*.safetensors.index.json` names (a missing or unnamed shard refuses it).
- **Companions:** JSON configuration and tokenizer files (strict JSON, at most
  16 MiB) and `tokenizer.model` (at most 64 MiB).
- **Refused by their bytes:** pickles (`pytorch_model.bin`, `.pt`, `.pkl`
  whatever the name), zip archives, scripts and any other format.

The quantisation shown is the one the GGUF file's own `general.file_type`
states (Q4_0, Q4_K_M, Q5_0, Q5_K_M, Q8_0, F16, BF16, …), never its file name.

## What "verified" means

`verified: LOCAL_DIGEST_ONLY` -- the SHA-256 of the bytes the library holds,
computed when they were copied in, and checked again by `verify`. It proves
the files did not change; it does not prove who published them
(`publisher_authenticated: false`). Objects are read-only and never
executable; `verify` reports a symlink, an executable bit, another length or
another digest as `CORRUPT`.

## Estimates

`recommend` reads the CPU architecture, hardware threads and, on Linux,
`/proc/meminfo`. It probes no GPU: `--vram-gib` states graphics memory and
makes it the budget. A GGUF model needs its weights, its key-value cache at
the context asked for (at most its own), and overhead; the answer is FITS,
LIKELY_FITS, MAY_NOT_FIT, DOES_NOT_FIT, or UNKNOWN when a fact is missing.
Safetensors models have no local backend in this build: UNKNOWN, unless the
weights alone exceed the memory.

## Example

```text
$ direwolf models import --library /srv/direwolf/models --name tiny-q4 \
    ~/Downloads/tiny-Q4_K_M.gguf ~/Downloads/config.json
imported tiny-q4 (GGUF, quantization Q4_K_M): 2 file(s), verified LOCAL_DIGEST_ONLY -- the publisher's authenticity is not known; not ready for inference
$ direwolf models verify --library /srv/direwolf/models tiny-q4
VERIFIED 4f1c… tiny-Q4_K_M.gguf
VERIFIED 9a07… config.json
```
