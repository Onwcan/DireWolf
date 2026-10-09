"""M5c runner: kernel-performed net.http, measured as the product.

Like every runner since M3, this reimplements nothing. It runs the real
evidence task -- `scripts/dw.py net-http-evidence`: the broker's HTTPS client
against real TLS origins, the authority's per-hop pipeline and mode A's
consumer against a fake broker with real keyring values, and the released
broker with local HTTPS origins, its evidence-only fixture resolver and test
trust anchor, and the authority's library -- and judges the evidence lines
each passing case prints after its assertions held (ADR-0050 §16).

Every case the runner expects is listed here. A case that silently stopped
running is a FAIL naming it, never a smaller denominator; an SSRF or DNS case
whose outcome is not a refusal is a FAIL; a credential that reached another
origin is a FAIL; a residue the task did not report as absent or as the one
documented limitation is a FAIL; the task's own failure -- including NOT
EXERCISED -- is a FAIL.

The judging function takes the task's output and nothing else, so the meta
tests can hand it a regression and watch the gate fail.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import TYPE_CHECKING, Any, Final

from direwolf_evals.model import Outcome, Status

if TYPE_CHECKING:  # pragma: no cover - import cycle only matters to type checkers
    from direwolf_evals.runners import Context

__all__ = ["ECHO_RESIDUE", "M5C_CASES", "REFUSALS", "judge_net_http", "net_http"]

MAX_ARTIFACT: Final = 1500
PREFIX: Final = "NET-EVIDENCE "

# Every case `net-http-evidence` requires (scripts/dw.py, NET_HTTP_CASES).
M5C_CASES: Final = frozenset(
    {
        ("authority-net-credential", "credential-cross-origin-redirect"),
        ("authority-net-credential", "credential-same-origin-redirect"),
        ("authority-net-credential", "echoed-credential"),
        ("authority-net-credential", "runtime-sets-credential-header"),
        ("authority-net-credential", "secret-in-request-body"),
        ("authority-net-credential", "secret-in-request-header"),
        ("authority-net-credential", "secret-in-request-url"),
        ("authority-net-pipeline", "broker-lost-after-send"),
        ("authority-net-pipeline", "broker-refusal-before-send"),
        ("authority-net-pipeline", "budget-bytes"),
        ("authority-net-pipeline", "budget-never-refilled"),
        ("authority-net-pipeline", "budget-origins"),
        ("authority-net-pipeline", "budget-requests"),
        ("authority-net-pipeline", "crash-N1-after-resolve"),
        ("authority-net-pipeline", "crash-N2-after-intent"),
        ("authority-net-pipeline", "crash-N3-after-exchange"),
        ("authority-net-pipeline", "crash-N4-after-outcome"),
        ("authority-net-pipeline", "final-denial-before-resolution"),
        ("authority-net-pipeline", "guard-loopback-answer"),
        ("authority-net-pipeline", "guard-metadata-ip-answer"),
        ("authority-net-pipeline", "guard-mixed-answer"),
        ("authority-net-pipeline", "idempotency-key-reused"),
        ("authority-net-pipeline", "idempotency-one-namespace"),
        ("authority-net-pipeline", "metadata-name-before-resolution"),
        ("authority-net-pipeline", "no-resolution-without-grant"),
        ("authority-net-pipeline", "obligation-max-output-bytes"),
        ("authority-net-pipeline", "obligation-unenforceable"),
        ("authority-net-pipeline", "order-guard-intent-exchange"),
        ("authority-net-pipeline", "per-hop-reauthorisation-max-requests"),
        ("authority-net-pipeline", "policy-per-pinned-address"),
        ("authority-net-pipeline", "preview-without-address"),
        ("authority-net-pipeline", "protocol-v4-net-http"),
        ("authority-net-pipeline", "redirect-303-to-get"),
        ("authority-net-pipeline", "redirect-307-with-body"),
        ("authority-net-pipeline", "redirect-blocked-target"),
        ("authority-net-pipeline", "redirect-cross-origin-headers"),
        ("authority-net-pipeline", "redirect-downgrade"),
        ("authority-net-pipeline", "redirect-loop"),
        ("authority-net-pipeline", "redirect-metadata-name"),
        ("authority-net-pipeline", "redirect-mixed-target"),
        ("authority-net-pipeline", "redirect-not-followed"),
        ("authority-net-pipeline", "redirect-policy-denied"),
        ("authority-net-pipeline", "redirect-same-origin-pinned"),
        ("authority-net-pipeline", "redirect-sixth-hop"),
        ("authority-net-pipeline", "redirect-ungranted-host"),
        ("authority-net-pipeline", "resolution-failed"),
        ("authority-net-pipeline", "resolution-timeout"),
        ("authority-net-pipeline", "runtime-credential-header"),
        ("authority-net-pipeline", "taint-novel-destination"),
        ("authority-net-pipeline", "taint-seen-destination"),
        ("authority-net-pipeline", "url-digest-only-in-audit"),
        ("authority-net-pipeline", "userinfo-and-literals"),
        ("authority-net-pipeline", "worker-failed-before-send"),
        ("authority-net-pipeline", "worker-unconfirmed-after-send"),
        ("broker-http", "bad-chunk-size"),
        ("broker-http", "body-past-bound-cut"),
        ("broker-http", "broker-rejudges-pinned-addresses"),
        ("broker-http", "close-delimited"),
        ("broker-http", "concurrent-workers"),
        ("broker-http", "credential-composed-in-broker"),
        ("broker-http", "credential-header-injection-refused"),
        ("broker-http", "echo-body-redacted-before-encoding"),
        ("broker-http", "echo-header-dropped-whole"),
        ("broker-http", "echo-in-a-broken-response"),
        ("broker-http", "echo-straddling-the-bound"),
        ("broker-http", "exchange-in-a-worker"),
        ("broker-http", "evidence-ca-under-production-trust"),
        ("broker-http", "expired"),
        ("broker-http", "gzip"),
        ("broker-http", "head-parser-mutation"),
        ("broker-http", "head-past-64-kib"),
        ("broker-http", "header-bomb"),
        ("broker-http", "http-1-0"),
        ("broker-http", "http2-only-server"),
        ("broker-http", "length-and-chunked"),
        ("broker-http", "other-transfer-coding"),
        ("broker-http", "pinned-request-rendered"),
        ("broker-http", "redirect-not-followed-by-broker"),
        ("broker-http", "response-parser-mutation"),
        ("broker-http", "resolution-judged-whole"),
        ("broker-http", "self-signed"),
        ("broker-http", "slow-head"),
        ("broker-http", "stalled-body"),
        ("broker-http", "status-past-599"),
        ("broker-http", "switching-protocols"),
        ("broker-http", "tls-handshake-timeout"),
        ("broker-http", "truncated-body"),
        ("broker-http", "two-lengths"),
        ("broker-http", "two-locations"),
        ("broker-http", "untrusted-authority"),
        ("broker-http", "worker-killed-after-sending"),
        ("broker-http", "worker-refuses-a-stranger"),
        ("broker-http", "worker-unavailable"),
        ("broker-http", "wrong-name"),
        ("net-http", "broker-killed-takes-its-worker"),
        ("net-http", "budget-redirect-hop"),
        ("net-http", "budget-requests"),
        ("net-http", "crash-after-exchange"),
        ("net-http", "crash-after-intent"),
        ("net-http", "crash-after-resolve"),
        ("net-http", "credential-bound-origin"),
        ("net-http", "credential-broker-residue-after-send"),
        ("net-http", "credential-cross-origin-redirect"),
        ("net-http", "credential-durable-state"),
        ("net-http", "credential-echo-broker-residue"),
        ("net-http", "credential-echo-redacted"),
        ("net-http", "credential-port-confusion"),
        ("net-http", "credential-same-origin-redirect"),
        ("net-http", "credential-unbound-origin"),
        ("net-http", "dns-rebinding-next-request"),
        ("net-http", "dns-rebinding-pinned-within-request"),
        ("net-http", "dns-resolution-failed"),
        ("net-http", "dns-resolution-timeout"),
        ("net-http", "https-get-pinned"),
        ("net-http", "idempotency-key-reused"),
        ("net-http", "origin-confusion-backslash"),
        ("net-http", "origin-confusion-encoded-dot-segment"),
        ("net-http", "origin-confusion-idna-label"),
        ("net-http", "origin-confusion-port"),
        ("net-http", "origin-confusion-trailing-dot"),
        ("net-http", "origin-confusion-uppercase"),
        ("net-http", "origin-confusion-userinfo"),
        ("net-http", "plaintext-refused"),
        ("net-http", "policy-balanced"),
        ("net-http", "policy-power-internal-range"),
        ("net-http", "policy-safe"),
        ("net-http", "redirect-303-to-get"),
        ("net-http", "redirect-307-with-body"),
        ("net-http", "redirect-blocked-address"),
        ("net-http", "redirect-cross-origin"),
        ("net-http", "redirect-downgrade"),
        ("net-http", "redirect-loop"),
        ("net-http", "redirect-metadata-name"),
        ("net-http", "redirect-mixed-address"),
        ("net-http", "redirect-not-followed"),
        ("net-http", "redirect-same-origin"),
        ("net-http", "redirect-sixth-hop"),
        ("net-http", "redirect-ungranted-origin"),
        ("net-http", "response-101"),
        ("net-http", "response-bad-chunk-size"),
        ("net-http", "response-close-delimited"),
        ("net-http", "response-encoded"),
        ("net-http", "response-header-bomb"),
        ("net-http", "response-length-and-chunked"),
        ("net-http", "response-malformed-status"),
        ("net-http", "response-never-answers"),
        ("net-http", "response-past-the-bound"),
        ("net-http", "response-set-cookie"),
        ("net-http", "runtime-authorization-header"),
        ("net-http", "runtime-cookie-header"),
        ("net-http", "secret-in-request"),
        ("net-http", "ssrf-6to4"),
        ("net-http", "ssrf-ip-literal-decimal"),
        ("net-http", "ssrf-ip-literal-dotted"),
        ("net-http", "ssrf-ip-literal-hex"),
        ("net-http", "ssrf-ip-literal-octal"),
        ("net-http", "ssrf-ip-literal-v6"),
        ("net-http", "ssrf-ipv4-mapped"),
        ("net-http", "ssrf-ipv6-loopback"),
        ("net-http", "ssrf-loopback-not-excepted"),
        ("net-http", "ssrf-metadata-address"),
        ("net-http", "ssrf-metadata-name"),
        ("net-http", "ssrf-mixed-answer"),
        ("net-http", "ssrf-nat64"),
        ("net-http", "ssrf-private-answer"),
        ("net-http", "ssrf-teredo"),
        ("net-http", "ssrf-ungranted-host-not-resolved"),
        ("net-http", "taint-novel-destination"),
        ("net-http", "taint-seen-destination"),
        ("net-http", "tls-expired"),
        ("net-http", "tls-self-signed"),
        ("net-http", "tls-test-authority-under-production-trust"),
        ("net-http", "tls-untrusted-root"),
        ("net-http", "tls-wrong-name"),
    }
)

# What an SSRF or DNS case on the real daemons may come to: a refusal, never
# a response.
REFUSALS: Final = frozenset(
    {
        "ADDRESS_BLOCKED",
        "ADDRESS_MIXED",
        "RESOLUTION_FAILED",
        "RESOLUTION_TIMEOUT",
        "URL_INVALID",
        "PLAINTEXT_UNSUPPORTED",
    }
)

# An origin that echoes the credential back hands the exchange response
# plaintext holding it, which `rustls`'s record copies and the `http` crate's
# header map free without zeroing. The exchange runs in a short-lived worker
# (ADR-0050 §9, D11) that is gone before the broker answers, so the evidence
# asserts the long-lived broker's memory holds none of it -- and this gate
# accepts that outcome alone: a residue reported present is a failure.
ECHO_RESIDUE: Final = ("net-http", "credential-echo-broker-residue")
ECHO_RESIDUE_OUTCOMES: Final = frozenset({"absent-the-exchange-worker-is-gone"})


def _records(output: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in output.splitlines():
        at = line.find(PREFIX)
        if at < 0:
            continue
        raw: Any = json.loads(line[at + len(PREFIX) :])
        if not isinstance(raw, dict):
            raise ValueError(f"an evidence line is not an object: {line[:200]}")
        records.append(raw)
    return records


def judge_net_http(output: str, code: int) -> Outcome:
    """Every expected case reported, every SSRF and DNS shape refused, no
    credential across origins, residue as reported, and the task passed."""
    try:
        records = _records(output)
    except (ValueError, json.JSONDecodeError) as exc:
        return Outcome(Status.ERROR, {}, f"unreadable evidence: {exc}")
    outcome_of = {
        (str(r.get("suite")), str(r.get("case"))): str(r.get("outcome"))
        for r in records
        if not str(r.get("outcome", "")).lower().startswith("not-exercised")
    }
    found = M5C_CASES & set(outcome_of)
    missing = sorted(f"{s}/{c}" for s, c in M5C_CASES - set(outcome_of))
    answered = sorted(
        case
        for (suite, case), outcome in outcome_of.items()
        if suite == "net-http"
        and case.startswith(("ssrf-", "dns-resolution-"))
        and outcome not in REFUSALS
        and not outcome.startswith("NO_CAPABILITY")
    )
    crossed = sorted(
        f"{suite}/{case}"
        for (suite, case), outcome in outcome_of.items()
        if case == "credential-cross-origin-redirect" and outcome != "never-attached"
    )
    residue = outcome_of.get(ECHO_RESIDUE)
    residue_ok = residue is None or residue in ECHO_RESIDUE_OUTCOMES
    sound = code == 0 and not answered and not crossed and residue_ok
    metrics = {
        "cases": float(len(found)),
        "expected_cases": float(len(M5C_CASES)),
        "ssrf_answered": float(len(answered)),
        "credential_crossed": float(len(crossed)),
        "rejection_rate": (len(found) / len(M5C_CASES)) if sound else 0.0,
    }
    problems = []
    if code != 0:
        problems.append(f"the evidence task failed (exit {code})")
    if missing:
        problems.append(f"missing cases: {', '.join(missing)}")
    if answered:
        problems.append(f"SSRF or DNS cases not refused: {', '.join(answered)}")
    if crossed:
        problems.append(f"a credential crossed origins: {', '.join(crossed)}")
    if not residue_ok:
        problems.append(f"an undocumented residue outcome: {residue}")
    if problems:
        return Outcome(
            Status.FAIL,
            metrics,
            "; ".join(problems)[:MAX_ARTIFACT],
            {"output": output[-MAX_ARTIFACT:]},
        )
    return Outcome(Status.PASS, metrics)


def net_http(ctx: Context) -> Outcome:
    """ADR-0050: the authority decides every hop, the broker performs each to
    twice-guarded pinned addresses, a credential reaches only its bound
    origin, and everything is bounded and fails closed -- the real evidence
    task."""
    completed = subprocess.run(
        [sys.executable, "scripts/dw.py", "net-http-evidence"],
        cwd=str(ctx.repo_root),
        env=dict(os.environ),
        capture_output=True,
        text=True,
        errors="replace",
        timeout=ctx.evaluation.timeout_s,
        check=False,
    )
    return judge_net_http(completed.stdout + completed.stderr, completed.returncode)
