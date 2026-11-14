# Evidence archive

DireWolf's security claims rest on evidence that hosted CI produces: the M5
gate's fourteen evidence bundles in every `CI` run, and one coverage-guided
libFuzzer record per target in every `Fuzz` run. GitHub Actions keeps each of
those artifacts for **7 days** (`retention-days: 7`, the M5 gate's decision
G-D2) and then deletes it. After that, the run's page still says it passed, but
the bytes that showed why are gone.

[`scripts/evidence_archive.py`](../scripts/evidence_archive.py) keeps them. It copies a finished run's artifacts
into a directory the owner controls, outside the repository, with a manifest
that anyone can check later, offline, without GitHub. This document is how to
use it, what it proves, and what it does not.

> **An archive is HISTORICAL / OFFLINE evidence.** It shows what a past hosted
> run produced. It is never current hosted acceptance: nothing in CI reads an
> archive, and the M5 gate refuses every bundle that is not of the run it
> judges. A change is accepted by its own hosted run, not by an archive of an
> earlier one.

## 1. Two layers

| Layer | Where | Kept | For |
|---|---|---|---|
| 1. Transport | GitHub Actions artifacts of the run | 7 days | the M5 gate in the same run, and debugging |
| 2. Durable archive | a directory the owner chooses, outside the repository | as long as the owner keeps it | the record, review, audit |

Layer 1 is unchanged: every evidence job uploads its bundle or record exactly
as before, the `m5e-gate` job downloads only its own run's bundles, and no
workflow knows the archive exists. Layer 2 is owner-invoked. Nothing archives
automatically, nothing is uploaded anywhere, and the archive never enters the
repository: the tool refuses an archive root or a restore destination inside
the checkout.

## 2. What is archived

**M5 evidence** (`.github/workflows/ci.yml`, class `m5-evidence`). The M5 gate
(M5e.6, [M5E_ASSURANCE_PLAN.md](M5E_ASSURANCE_PLAN.md)) works in two steps. Each of its fourteen evidence jobs keeps exactly
what its task judged and sealed it with the run's id, attempt, commit, ref and
runner (`make m5e-evidence-bundle`), and uploads it as `m5e-evidence-<job>`.
The `m5e-gate` job then judges every bundle again (`make m5e-gate-check`). A
complete archive holds all fourteen bundles. Each one is checked by the gate's
own bundle check, `_gate_bundle` in `scripts/dw.py`, unchanged, against the
archived run: its fields, its provenance, each judged file at its digest, and
the judgements its task must have made. A run may also upload `eval-results`
when its eval gate fails; that artifact is kept as a diagnostic and never
judged.

**Coverage-guided fuzzing** (`.github/workflows/fuzz.yml`, class
`fuzz-campaign`). Each of the eight libFuzzer jobs (F-07) uploads
`fuzz-evidence-<target>`, its own record, and, when it fails, the reproducer as
`fuzz-artifacts-<target>`. Each record is judged by `fuzz_verdict` in
`scripts/dw.py`, unchanged, as the run's own `make fuzz-report` judged it:
against the archived run's identity, the budget the plan fixes for the trigger
(30 s for a pull request, 900 s on the schedule, the operator's choice for a
manual run), and how the job's `make fuzz` step ended. A campaign is **PASS**
only when every one of the eight targets passed at one budget, in a job that
succeeded. A campaign with some targets missing is INCOMPLETE, never PASS. The
budget is recorded as `full` (900 s or more) or `short`. The stable mutation
smoke job (`make fuzz-smoke`) is not coverage-guided; it is named in the
manifest and never counted.

Each class's expected inventory is a **contract**, frozen per version in the
tool (`M5_CONTRACTS`, `FUZZ_CONTRACTS`). A manifest names the version it was
captured against, so an archive keeps verifying after the gate grows. The tests
fail when the current version no longer equals `M5E_GATE_TASKS` or
`FUZZ_TARGETS` in `scripts/dw.py`; the fix is a new version, never an edit of
an old one.

## 3. Capturing a run

GitHub lets anyone read a public repository's run, its jobs and its artifact
list, including each artifact's SHA-256 digest. Downloading an artifact needs
a signed-in client, even for a public repository. So capture reads the run's
metadata from GitHub's REST API itself, and takes the ZIPs one of two ways.

**Downloaded ZIPs (`--staged`).** Download each artifact from the run's page
while signed in to GitHub, keep the file names GitHub gives them
(`<artifact name>.zip`), and point the tool at the directory. The tool takes a
staged ZIP only if its SHA-256 and size equal what GitHub's API reports for that
artifact. A staged file that differs makes the whole capture refuse. No token is
involved.

```bash
python3 scripts/evidence_archive.py capture --run 43640168802 \
    --archive-root ~/direwolf-evidence --staged ~/Downloads/run-172 --strict
```

**A read-only token (`--token-env`).** Name the environment variable that holds
a token able to read the repository, such as a fine-grained token with
read-only access to public repositories and no other permission. The tool sends
it to `api.github.com` only. It never prints it and never writes it into the
archive. It never forwards it to the storage host GitHub redirects a download
to; that redirect is a short-lived signed URL, and only its host name is ever
reported.

```bash
python3 scripts/evidence_archive.py capture --run 43640168802 \
    --archive-root ~/direwolf-evidence --token-env DIREWOLF_ARCHIVE_TOKEN --strict
```

The two can be combined: staged ZIPs are used first, and the token fetches the
rest. Neither needs any write permission on GitHub.

**What capture refuses.**

- **Always refused:**
  - a run that has not completed, or that is of another repository or of a
    workflow other than `ci.yml` and `fuzz.yml`;
  - a partial API answer, where the pages do not add up to GitHub's total;
  - two artifacts of one name;
  - an artifact of another run, commit or repository;
  - a ZIP that is not at GitHub's digest, or is unsafe (§5);
  - a bundle or record that is of another run, attempt or commit than the
    archived one;
  - a capture where nothing at all could be archived.
- **Refused only with `--strict`:** an archive that would be INCOMPLETE, or
  whose evidence verdict is not PASS.

Without `--strict`, a failing run's evidence is still worth keeping: the
archive records it as FAIL, with every problem named.

**Expired and unavailable artifacts.** An artifact GitHub reports as expired is
recorded as EXPIRED and never fetched. One that could not be obtained — not
staged, no token, a failed download — is recorded as UNAVAILABLE, with the
reason. Either way the archive is INCOMPLETE, and the manifest lists what is
missing. Nothing is ever reconstructed: an artifact GitHub no longer has is
gone, unless an owner's backup of the exact bytes still exists, and those bytes
are taken only at the digest GitHub's API reports for that artifact.

**Never replaced, never half-written.** An archive is written into a fresh
`runs/.capture-*` directory, verified there as a complete archive, and only
then renamed to `runs/<run id>-a<attempt>`. A capture of a run that is already
archived is refused, and the existing archive is left as it was. To capture
again, use another archive root. An interrupted capture leaves at most a
`.capture-*` directory, which `inventory` names as such and which is safe to
delete.

GitHub lists one set of artifacts per run, so the run's latest attempt is the
one archived. `--attempt N` refuses unless the run is at attempt N.

## 4. The archive

```
<archive root>/
  runs/
    43640168802-a1/
      manifest.json      the manifest (canonical JSON)
      manifest.sha256    "<SHA-256 of manifest.json>  manifest.json"
      artifacts/
        m5e-evidence-evals.zip    each artifact's ZIP, the bytes GitHub served
        ...
```

The ZIPs are stored exactly as GitHub served them, never unpacked. The manifest
(`direwolf.evidence-archive`, version 1) records:

| Field | What | Source |
|---|---|---|
| `schema`, `version`, `class`, `contract` | the format, the class (`m5-evidence` or `fuzz-campaign`), and the expected inventory | the tool |
| `label`, `provenance` | the HISTORICAL / OFFLINE label, and what each part rests on, verbatim | the tool |
| `github.repository`, `github.run` | repository; run id, attempt, number, workflow name, path and id, commit, branch, trigger, status, conclusion, times, page URL | **GitHub's API** |
| `github.jobs` | every job of the attempt: id, name, conclusion, times, runner group, labels, each step's conclusion | **GitHub's API** |
| `github.sources` | the API URLs read, and the run's page, for independent inspection | the tool |
| `artifacts[].github` | each artifact's id, size, digest, creation and expiry times, and whether it had expired | **GitHub's API** |
| `artifacts[]` `name`, `class`, `status`, `reason` | ARCHIVED, EXPIRED or UNAVAILABLE, and why | the capture |
| `artifacts[].zip` | the stored file, its size and SHA-256, where the bytes came from (`github-download` or `operator-staged`), and whether they were checked against GitHub's digest | **observed** |
| `artifacts[].entries` | every file in the ZIP: name, size, SHA-256 | **observed** |
| `evidence` | each bundle's verdict from the gate's bundle check, with its sealed run, runner and judged files; or each target's `fuzz_verdict` with its libFuzzer runs, coverage, budget, duration, toolchain and crash | **observed**, computed again by every verification |
| `verdict` | completeness, what is missing or not archived and why, the evidence verdict (PASS, FAIL or INCOMPLETE), and its problems | computed again by every verification |
| `capture` | when, by which tool (version and SHA-256 of the tool and of `scripts/dw.py`, and the checkout's commit), whether a token or staged files were used, `--strict`, the operator's note | **the operator's machine**: recorded, never verified |

**Canonical form.** The manifest is serialised one way only: UTF-8 JSON, keys
sorted, a two-space indent, ASCII with everything else escaped, no NaN or
infinity, and one final newline. Lists have a fixed order: artifacts by name,
jobs by name and id, steps by number, entries by name, bundles by job, targets
by name. A manifest in any other form fails verification, as does a repeated
key.

## 5. Verifying an archive

```bash
python3 scripts/evidence_archive.py verify ~/direwolf-evidence/runs/43640168802-a1 --strict
```

Verification uses no network. It checks:

- the layout: exactly `manifest.json`, `manifest.sha256` and `artifacts/`, with
  only the listed ZIPs, and no link or other file type anywhere;
- the manifest: its size, strict JSON, its fields, the supported schema and
  version, the canonical form, the digest file, its label and provenance
  statement, the contract, and the archive's name against its run;
- each archived ZIP: size and SHA-256 equal to the recorded ones and to
  GitHub's digest; safe to read; its entries equal to the recorded ones;
- each artifact's classification, recomputed from its exact name;
- every bundle and record judged again from the bytes, against the archived
  run's id, attempt and commit. The result must equal what the manifest says,
  so an archive that calls a failed campaign PASS fails verification;
- completeness, recomputed against the contract.

A ZIP is read in memory and never extracted. It is refused, not repaired, if it
is truncated, has bytes before its first header or after its end record, is
encrypted, uses a compression other than stored or deflate, holds more than 256
entries, holds an entry over 32 MiB, or holds more than 128 MiB in all. It is
also refused if it holds anything but uniquely named regular files at its top
level. That rules out a directory, a symbolic link, a device, a name with a
separator, `..`, a leading or trailing dot, a space or a Windows device name,
and two names that differ only in case.

The output is labelled HISTORICAL / OFFLINE and reports three things: the
**integrity** (OK or FAILED, with every problem), the **completeness**, and the
**evidence** verdict. `verify` exits 1 when integrity fails, and with
`--strict` also unless the archive is COMPLETE with evidence PASS.

**Replaying the M5 gate (`--replay-gate`).** For an M5 archive this runs the
gate itself, `m5e_gate_verdict` in `scripts/dw.py`, unchanged, over the
archived bundles in a scratch directory, as the run's own `m5e-gate` job did.
It re-judges every output and checks the whole attributed inventory. It uses
**this checkout's** case tables. For an archive of the same commit, or one with
the same tables, it repeats the hosted verdict. For an older commit a refusal
is expected: the inventory has grown since. The replay is informational and is
never an integrity failure.

**When the validators change.** Verification judges the bytes with this
checkout's `scripts/dw.py`. If a later change alters what `_gate_bundle` or
`fuzz_verdict` accept, or how they word a refusal, an older archive's recorded
evidence can differ from the recomputed one. The integrity of its bytes is
unaffected. The manifest records the SHA-256 of the tool and of `dw.py` that
captured it, and the checkout's commit. Verify with that commit's tools to
reproduce the original judgement.

## 6. Inventory, inspection and restore

```bash
python3 scripts/evidence_archive.py inventory --archive-root ~/direwolf-evidence --verify \
    --backup-root /media/backup/direwolf-evidence
python3 scripts/evidence_archive.py inspect ~/direwolf-evidence/runs/43602590762-a1
python3 scripts/evidence_archive.py inspect ~/direwolf-evidence/runs/43602590762-a1 \
    --entry fuzz-evidence-url_parse/url_parse.json
python3 scripts/evidence_archive.py restore ~/direwolf-evidence/runs/43640168802-a1 \
    --to ~/review/run-172
```

**`inventory`** prints one line per archive, with:

- the run, workflow, commit and trigger;
- when it was captured;
- the completeness, what is missing, and the evidence verdict;
- the size, and when GitHub's own copy expires;
- the manifest's SHA-256;
- with `--verify`, the integrity of each archive;
- with `--backup-root`, whether a second copy holds the same manifest.

It also names anything else under `runs/`, such as an interrupted capture.

**`inspect`** verifies the archive, then summarises it or prints one archived
file, read from its ZIP in memory.

**`restore`** verifies the archive, then writes its files read-only into a new
directory: one directory per artifact, as the download action lays bundles
out, with the manifest and a `HISTORICAL-OFFLINE.txt` notice. It refuses:

- a destination that already exists;
- a destination inside the repository;
- an archive that does not verify.

Restored bundles cannot pass a later run's M5 gate. The gate refuses every
bundle that is not of the run it judges, and the notice and manifest are not
bundles of the gate either.

## 7. What a SHA-256 does and does not prove

| Property | What the archive gives | What it does not |
|---|---|---|
| **Integrity** | Any change to a stored byte after capture is found, against the manifest's digests and GitHub's. | Nothing, if the manifest is rewritten consistently along with the bytes: a hash next to the data it covers can be recomputed by whoever changes the data. |
| **Provenance** | Each ZIP equals the artifact GitHub's API described for that run, at capture, over TLS. Each bundle and record names the same run, attempt and commit. The jobs, runners and conclusions are GitHub's own report. | Proof to a third party. GitHub does not sign its API answers, so the manifest's GitHub sections are a record of what was read, not a signature. |
| **Authenticity** | None beyond the above: a manifest is not signed, and its origin cannot be proved from the archive alone. | An owner-controlled signature or attestation would provide it (§9). |
| **Tamper evidence** | Against accident and careless edits: the digest file, the canonical form, and verdicts recomputed from the bytes. Against a deliberate forger: only if the manifest's SHA-256 is recorded somewhere the forger cannot also change. | Without that out-of-band record, a forger who rewrites bytes, manifest and digest file together is not detected. |
| **Independent timestamp** | None. `captured_at` is the capturing machine's clock. GitHub's own times (`created_at`, the artifacts' creation times) are recorded as GitHub reported them. | A trusted timestamp (RFC 3161, a transparency log) is a separate service (§9). |
| **Long-term retention** | Whatever the owner's storage gives. | GitHub's copy ends after 7 days whatever happens to the archive. |

So the practical rule is this: after each capture, record the manifest's
SHA-256 from `inventory` somewhere separate from the archive and outside the
forger's reach. A second machine, a printed record, or a signed note all work.
Comparing that digest later is what turns the hashes into tamper evidence.

## 8. Storage, backup and recovery

- **Location.** One archive root outside every working tree, for example
  `~/direwolf-evidence` or a dedicated directory on the owner's machine. The
  tool refuses one inside the repository. Archives are small: a CI run's
  fourteen bundles are about 100 KB, a fuzz campaign's eight records about
  10 KB. Never commit an archive to the repository, and never push one
  anywhere without a deliberate decision.
- **Access.** Only the owner should be able to write to the archive root
  (`chmod 700` on Linux and macOS). The archived bytes are what any signed-in
  GitHub user could download while the artifact lasted, so they are not
  secret. The archive's value as a record depends on who can change it.
  Publishing an archive anywhere is a separate decision.
- **Backup.** At least one second copy on another device, kept as a plain
  copy of the archive root (`runs/` and everything under it). Check it with
  `inventory --backup-root`: each archive should report `backup present, same
  manifest digest`. Keep the manifests' digests apart from both copies (§7).
- **Recovery.** Copy the archive's directory back from the backup. Run
  `verify` on it, and compare its manifest SHA-256 with the digest recorded
  apart from the archive. If they agree, the copy is the original.
- **Retention.** Keep an archive as long as its claim matters. Evidence a
  milestone's completion or a finding's closure rests on should be kept at
  least until a later run on a later commit stands in for it, and for review
  records, indefinitely.
- **Housekeeping.** `inventory` names every `.capture-*` leftover; delete those
  by hand. Never delete or edit anything inside an archive: verification fails,
  and nothing repairs it.

## 9. Future decisions, not implemented

Each of these needs an owner-controlled trust anchor, a CI permission or a
service. None exists today, so none is implemented. Each is a separate
decision:

- **Signing manifests** with an owner key (for example `minisign`, SSH or
  OpenPGP signatures), so that a manifest's origin can be proved to a third
  party.
- **GitHub artifact attestations** (`actions/attest-build-provenance`) for
  evidence artifacts. These need `id-token: write` and `attestations: write`
  in the evidence jobs, which CI's read-only token does not have today.
- **Trusted timestamps** for manifest digests, from an RFC 3161 authority or a
  transparency log.
- **Immutable storage**, such as object storage with an object lock, in place
  of, or beside, an owner's disk.
- **Longer GitHub retention** (`retention-days`, up to 90 days on public
  repositories), as a wider capture window only. It is still not a record.
