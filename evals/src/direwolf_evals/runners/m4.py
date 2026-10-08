"""M4 runners: the filesystem, exec and secret boundaries, measured as the product.

Like the M3 runners, none of these reimplements a property. Each runs the
real-process and real-kernel suites that already prove it -- the M4a resolver
against hostile trees and race campaigns, the brokered read against a tree
changed after the check, the real broker and launch helper starting real
targets, the released daemons, the real kernel keyring and a separate runtime
process whose address space is read -- and judges the evidence lines each
passing case prints after its assertions held.

Every case a runner expects is listed here. A case that silently stopped
running is a FAIL naming it, never a smaller denominator; a case that reports
NOT EXERCISED is a FAIL unless it is one of the environmental cases no
ordinary machine can produce (a bind mount, a casefold filesystem), which are
counted and named.

The judging functions take the suites' output and nothing else, so the meta
tests can hand them a regression -- a missing case, an escape, a value found
in memory -- and watch the gate fail.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, Final

from direwolf_evals.model import Outcome, Status

if TYPE_CHECKING:  # pragma: no cover - import cycle only matters to type checkers
    from direwolf_evals.runners import Context

__all__ = [
    "EXEC_CASES",
    "SECRET_CASES",
    "TRAVERSAL_CATEGORIES",
    "exec_mediation",
    "judge_exec",
    "judge_secret",
    "judge_traversal",
    "path_traversal",
    "secret_boundary",
]

MAX_ARTIFACT: Final = 1500

# --- path traversal (M4a resolver, M4b brokered read) -------------------------

TRAVERSAL_CATEGORIES: Final = (
    "normal",
    "platform",
    "traversal",
    "symlink",
    "magic-link",
    "mount-crossing",
    "hardlink",
    "unicode",
    "resource-kind",
    "root-replacement",
    "toctou",
    "leak",
    "state",
    "admission",
)
TRAVERSAL_RACES: Final = (
    "file-symlink-exchange",
    "directory-symlink-exchange",
    "parent-rename",
    "parent-moved-out-and-back",
    "leaf-replaced",
    "root-path-exchange",
)
TRAVERSAL_ENVIRONMENTAL: Final = frozenset(
    {
        "bind-mount-inside-workspace",
        "casefold-filesystem",
        "cross-device-link",
        "recreated-same-inode",
    }
)
# The brokered read, with the name replaced between the check and the read.
BROKERED_CASES: Final = frozenset({"m4b-swap-rename", "m4b-swap-symlink", "in-place-rewrite"})

# --- exec mediation (M4d) ------------------------------------------------------

EXEC_CASES: Final = frozenset(
    {
        # typed argv, literal; no shell
        ("argv-classifier", "argv-literal-shell-text-is-data"),
        ("broker-process", "argv-literal"),
        # the environment built from nothing
        ("broker-process", "env-built-from-nothing"),
        ("broker-private-protocol", "environment-not-inherited"),
        # descriptors, limits, privileges
        ("broker-process", "fd-hygiene-target"),
        ("broker-process", "inherited-descriptor"),
        ("broker-process", "rlimits-applied"),
        ("broker-process", "no-new-privs"),
        # the executable is the descriptor the authority checked
        ("broker-process", "path-replaced-after-handoff"),
        ("broker-process", "R1-executable-path-replaced"),
        ("broker-process", "R4-executable-rewritten-in-place"),
        ("broker-process", "descriptors-reversed"),
        # its identity is re-proved
        ("broker-process", "digest-mismatch"),
        ("broker-process", "rewritten-after-hash"),
        ("broker-process", "setuid"),
        # the production host floor
        ("production-floor", "released-opted-out"),
        ("production-floor", "released-opted-in"),
        ("production-floor", "shipped-balanced"),
    }
)

# --- the secret boundary (M4e) --------------------------------------------------

SECRET_CASES: Final = frozenset(
    {
        # the runtime sees a handle, never a value: its address space, read
        ("authority-secret", "runtime-address-space"),
        ("authority-secret", "return-path-fs-read-live-value"),
        ("authority-secret", "return-path-across-read-boundary"),
        ("authority-secret", "return-path-shape-github"),
        ("authority-secret", "return-path-transformed-value"),
        # no durable plaintext, no log, the audit by handle and class only
        ("authority-secret", "durable-state-scan"),
        ("authority-secret", "daemon-logs-scan"),
        ("authority-secret", "audit-redaction-hit"),
        # one-shot, through the real broker, and no residue in either process
        ("authority-secret", "mode-a-real-broker"),
        ("authority-secret", "mode-a-one-shot"),
        ("authority-secret", "mode-a-authority-residue"),
        ("authority-secret", "mode-a-broker-residue"),
        ("authority-secret", "authority-residue-after-redaction"),
        # M5c D11: an echoed credential stops at the broker -- the runtime's
        # answer, the authority and the broker's own encoding never hold it
        ("authority-secret", "mode-a-echo-straddling-the-bound"),
        ("authority-secret", "mode-a-echo-kept-header"),
        ("authority-secret", "mode-a-echo-audited"),
        # the production daemons: no core, no same-uid reader
        ("authority-secret", "authority-rlimit-core"),
        ("authority-secret", "authority-not-dumpable"),
        ("broker-secret-primitives", "broker-rlimit-core"),
        ("broker-secret-primitives", "broker-not-dumpable"),
        # the descriptor contract and replay
        ("broker-secret-primitives", "egress-render-one-descriptor"),
        ("broker-secret-primitives", "egress-replay-new-connection"),
        ("broker-secret-primitives", "egress-descriptor-reused-after-consumption"),
        ("broker-secret-primitives", "egress-hostile-stalled-writer-open"),
        # no argv, no ambient environment; residue after the primitive
        ("broker-secret-primitives", "mode-c-target-fd3"),
        ("broker-secret-primitives", "mode-b-target-environment-only"),
        ("broker-secret-primitives", "mode-c-residue"),
        ("broker-secret-primitives", "mode-b-residue"),
        # the authority's order: gates and a durable intent before any read
        ("authority-secret-pipeline", "admission-new-declaration"),
        ("authority-secret-pipeline", "intent-durable-before-read"),
        ("authority-secret-pipeline", "replay"),
        ("authority-secret-pipeline", "capability-gate"),
        ("authority-secret-pipeline", "policy-gate"),
        ("authority-secret-pipeline", "crash-R8-broker-may-have-consumed"),
    }
)


def _run(
    ctx: Context, command: Sequence[str], env: dict[str, str] | None = None
) -> tuple[int, str]:
    completed = subprocess.run(
        list(command),
        cwd=str(ctx.repo_root),
        env={**os.environ, **(env or {})},
        capture_output=True,
        text=True,
        errors="replace",
        timeout=ctx.evaluation.timeout_s,
        check=False,
    )
    return completed.returncode, completed.stdout + completed.stderr


def _lines(output: str, prefix: str) -> list[dict[str, Any]]:
    """Every evidence record carrying ``prefix``. A malformed one is an error:
    a report the runner cannot read is not evidence."""
    records: list[dict[str, Any]] = []
    for line in output.splitlines():
        at = line.find(prefix)
        if at < 0:
            continue
        raw: Any = json.loads(line[at + len(prefix) :])
        if not isinstance(raw, dict):
            raise ValueError(f"an evidence line is not an object: {line[:200]}")
        records.append(raw)
    return records


def _suites(ctx: Context, commands: Sequence[Sequence[str]]) -> tuple[int, str]:
    """Run each command; the first failure's code, and everything printed."""
    output: list[str] = []
    for command in commands:
        code, text = _run(ctx, command)
        output.append(text)
        if code != 0:
            return code, "\n".join(output)
    return 0, "\n".join(output)


def _failed(code: int, output: str) -> Outcome:
    return Outcome(
        Status.FAIL,
        {"cases": 0.0},
        f"a real suite failed (exit {code})",
        {"output": output[-MAX_ARTIFACT:]},
    )


def judge_traversal(output: str) -> Outcome:
    """Every category exercised, every race campaign with zero escapes, every
    admission and brokered-read case reported; only the environmental cases
    may be NOT EXERCISED."""
    try:
        fs = _lines(output, "FS-EVIDENCE ")
        brokered = _lines(output, "BROKER-EVIDENCE ")
    except (ValueError, json.JSONDecodeError) as exc:
        return Outcome(Status.ERROR, {}, f"unreadable evidence: {exc}")
    exercised: dict[str, set[str]] = {}
    problems: list[str] = []
    races: dict[str, str] = {}
    for record in fs:
        category, case, outcome = (
            str(record.get("category")),
            str(record.get("case")),
            str(record.get("outcome")),
        )
        if outcome.startswith("not-exercised"):
            if case not in TRAVERSAL_ENVIRONMENTAL:
                problems.append(f"{category}/{case} not exercised")
            continue
        exercised.setdefault(category, set()).add(case)
        if category == "toctou" and case in TRAVERSAL_RACES:
            races[case] = outcome
    for category in TRAVERSAL_CATEGORIES:
        if not exercised.get(category):
            problems.append(f"category {category} has no exercised case")
    escapes = 0
    for race in TRAVERSAL_RACES:
        reported = races.get(race)
        if reported is None:
            problems.append(f"race {race} did not report")
        elif not reported.startswith("escaped-0-unexpected-0-"):
            escapes += 1
            problems.append(f"race {race}: {reported}")
    seen_brokered = {str(r.get("case")) for r in brokered if r.get("suite") == "broker-state"}
    missing_brokered = sorted(BROKERED_CASES - seen_brokered)
    if missing_brokered:
        problems.append(f"brokered read cases missing: {', '.join(missing_brokered)}")
    expected = len(TRAVERSAL_CATEGORIES) + len(TRAVERSAL_RACES) + len(BROKERED_CASES)
    metrics = {
        "categories": float(sum(1 for c in TRAVERSAL_CATEGORIES if exercised.get(c))),
        "races": float(len(races)),
        "escapes": float(escapes),
        "brokered_cases": float(len(BROKERED_CASES & seen_brokered)),
        "rejection_rate": max(0.0, 1.0 - len(problems) / expected),
    }
    if problems:
        return Outcome(Status.FAIL, metrics, "; ".join(problems)[:MAX_ARTIFACT])
    return Outcome(Status.PASS, metrics)


def judge_exec(output: str) -> Outcome:
    """Every expected exec-mediation case reported, from the real broker, the
    real helper and the released daemons."""
    try:
        records = _lines(output, "PROC-EVIDENCE ")
    except (ValueError, json.JSONDecodeError) as exc:
        return Outcome(Status.ERROR, {}, f"unreadable evidence: {exc}")
    seen = {
        (str(r.get("suite")), str(r.get("case")))
        for r in records
        if not str(r.get("outcome", "")).startswith("not-exercised")
    }
    missing = sorted(f"{s}/{c}" for s, c in EXEC_CASES - seen)
    metrics = {
        "cases": float(len(EXEC_CASES & seen)),
        "expected_cases": float(len(EXEC_CASES)),
        "rejection_rate": len(EXEC_CASES & seen) / len(EXEC_CASES),
    }
    if missing:
        return Outcome(Status.FAIL, metrics, f"missing cases: {', '.join(missing)}"[:MAX_ARTIFACT])
    return Outcome(Status.PASS, metrics)


def judge_secret(output: str, corpus_passed: bool) -> Outcome:
    """Every expected secret-boundary case reported by the real suites, and the
    public protocol corpus clean."""
    try:
        records = _lines(output, "SECRET-EVIDENCE ")
    except (ValueError, json.JSONDecodeError) as exc:
        return Outcome(Status.ERROR, {}, f"unreadable evidence: {exc}")
    seen = {
        (str(r.get("suite")), str(r.get("case")))
        for r in records
        if not str(r.get("outcome", "")).lower().startswith("not-exercised")
    }
    missing = sorted(f"{s}/{c}" for s, c in SECRET_CASES - seen)
    metrics = {
        "cases": float(len(SECRET_CASES & seen)),
        "expected_cases": float(len(SECRET_CASES)),
        "public_corpus_clean": 1.0 if corpus_passed else 0.0,
        "rejection_rate": len(SECRET_CASES & seen) / len(SECRET_CASES) if corpus_passed else 0.0,
    }
    problems = []
    if missing:
        problems.append(f"missing cases: {', '.join(missing)}")
    if not corpus_passed:
        problems.append("the public protocol has a member for secret material")
    if problems:
        return Outcome(Status.FAIL, metrics, "; ".join(problems)[:MAX_ARTIFACT])
    return Outcome(Status.PASS, metrics)


def path_traversal(ctx: Context) -> Outcome:
    """EVALS.md: the full traversal set, Unicode aliasing and TOCTOU swaps.

    The M4a resolver against hostile trees and six race campaigns (release
    build: the races need speed), the state layer and admission through it,
    and the brokered read with the name replaced after the check.
    """
    code, output = _suites(
        ctx,
        [
            ["cargo", "build", "--locked", "-p", "dwkd-broker"],
            [
                "cargo",
                "test",
                "--locked",
                "--release",
                "-p",
                "dwkd-authority",
                "--lib",
                "resource::fs::",
                "--",
                "--nocapture",
            ],
            [
                "cargo",
                "test",
                "--locked",
                "-p",
                "dwkd-authority",
                "--test",
                "resource_workspace",
                "--test",
                "admission_fs",
                "--test",
                "broker_state",
                "--",
                "--nocapture",
            ],
        ],
    )
    if code != 0:
        return _failed(code, output)
    return judge_traversal(output)


def exec_mediation(ctx: Context) -> Outcome:
    """argv literal and never a shell, the environment built from nothing, the
    executable executed by the descriptor the authority checked and re-proved
    by the broker, and the production host floor -- the real broker binary,
    its launch helper and the released daemons."""
    code, output = _suites(
        ctx,
        [
            ["cargo", "build", "--locked", "-p", "dwkd-broker"],
            [
                "cargo",
                "test",
                "--locked",
                "-p",
                "dwkd-authority",
                "--lib",
                "resource::exec",
                "--",
                "--nocapture",
            ],
            [
                "cargo",
                "test",
                "--locked",
                "-p",
                "dwkd-authority",
                "--test",
                "process_production",
                "--",
                "--nocapture",
            ],
            [
                "cargo",
                "test",
                "--locked",
                "-p",
                "dwkd-broker",
                "--bins",
                "--test",
                "private_protocol",
                "--",
                "--nocapture",
            ],
        ],
    )
    if code != 0:
        return _failed(code, output)
    return judge_exec(output)


def secret_boundary(ctx: Context) -> Outcome:
    """The runtime sees a handle, never a value: a separate runtime process
    whose address space is read; the return path; one-shot delivery through the
    real broker; residue in every process that held a value; durable state; the
    public protocol corpus; the production daemons' hardening."""
    corpus_code, corpus = _run(
        ctx,
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "tests/protocol/test_no_secret_value_fields.py",
        ],
    )
    code, output = _suites(
        ctx,
        [
            ["cargo", "build", "--locked", "-p", "dwkd-broker"],
            [
                "cargo",
                "test",
                "--locked",
                "-p",
                "dwkd-authority",
                "--lib",
                "state::secret_use",
                "--",
                "--nocapture",
            ],
            [
                "cargo",
                "test",
                "--locked",
                "-p",
                "dwkd-broker",
                "--test",
                "secret_primitives",
                "--",
                "--nocapture",
            ],
            [
                "cargo",
                "test",
                "--locked",
                "-p",
                "dwkd-authority",
                "--test",
                "secret_evidence",
                "--",
                "--nocapture",
                "--test-threads=1",
            ],
        ],
    )
    if code != 0:
        return _failed(code, output)
    outcome = judge_secret(output, corpus_code == 0)
    if corpus_code != 0:
        return Outcome(
            outcome.status, outcome.metrics, outcome.reason, {"corpus": corpus[-MAX_ARTIFACT:]}
        )
    return outcome
