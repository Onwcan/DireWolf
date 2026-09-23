"""``python -m direwolf_evals`` — run, list, check, inventory.

    run        run suites (optionally the gate subset) and write results
    check      the merge gate: gate subset + baseline comparison
    list       what exists, without running it
    inventory  which security properties can be measured yet, and which cannot
    baseline   record the current run as the expected outcome (deliberate)

The exit code is what CI reads: 0 when nothing failed and no baseline
regression was found, 1 otherwise, 2 for a usage or configuration error.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from direwolf_evals import baseline as baseline_module
from direwolf_evals import inventory as inventory_module
from direwolf_evals import report as report_module
from direwolf_evals.discovery import DiscoveryError, discover
from direwolf_evals.results import RunReport, write_jsonl
from direwolf_evals.runner import collect, not_exercised, run_eval, run_suites

__all__ = ["main"]

DEFAULT_RESULTS = Path("target/evals/results.jsonl")
DEFAULT_BASELINE = Path("baselines/main.json")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="direwolf_evals",
        description="DireWolf evaluation harness. Measures claims; implements none of them.",
    )
    parser.add_argument("--evals-root", type=Path, default=None, help="the evals/ directory")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run suites and write results")
    run.add_argument("--suite", action="append", default=[], help="suite id (repeatable)")
    run.add_argument("--eval", default=None, help="one eval id, for reproduction")
    run.add_argument("--gate", action="store_true", help="only the deterministic gate subset")
    run.add_argument("--seed", type=int, default=None, help="override every eval's seed")
    run.add_argument("--out", type=Path, default=None, help="results file (JSONL)")
    run.add_argument("--verbose", action="store_true")

    check = sub.add_parser("check", help="merge gate: gate subset plus baseline comparison")
    check.add_argument("--baseline", type=Path, default=None)
    check.add_argument("--out", type=Path, default=None)
    check.add_argument("--all", action="store_true", help="every suite, not only the gate subset")
    check.add_argument(
        "--require-exercised",
        action="store_true",
        help="fail on any gating eval this machine cannot exercise (CI's gate)",
    )

    sub.add_parser("list", help="list suites and evals without running them")
    sub.add_parser("inventory", help="security properties by milestone")

    record = sub.add_parser("baseline", help="record the current run as expected (deliberate)")
    record.add_argument("--baseline", type=Path, default=None)
    record.add_argument("--all", action="store_true")

    args = parser.parse_args(argv)
    evals_root = (args.evals_root or Path(__file__).resolve().parents[2]).resolve()
    repo_root = evals_root.parent

    try:
        if args.command == "list":
            return _list(evals_root)
        if args.command == "inventory":
            return _inventory()
        if args.command == "run":
            return _run(args, repo_root, evals_root)
        if args.command == "check":
            return _check(args, repo_root, evals_root)
        if args.command == "baseline":
            return _baseline(args, repo_root, evals_root)
    except DiscoveryError as exc:
        print(f"direwolf_evals: {exc}", file=sys.stderr)
        return 2
    except baseline_module.BaselineError as exc:
        print(f"direwolf_evals: {exc}", file=sys.stderr)
        return 2
    return 2


def _run(args: argparse.Namespace, repo_root: Path, evals_root: Path) -> int:
    if args.eval:
        report = RunReport()
        for suite, evaluation in collect(evals_root):
            if evaluation.id == args.eval:
                for result in run_eval(
                    suite,
                    evaluation,
                    repo_root=repo_root,
                    evals_root=evals_root,
                    seed_override=args.seed,
                ):
                    report.add(result)
        if not report.results:
            print(f"direwolf_evals: no eval with id {args.eval!r}", file=sys.stderr)
            return 2
    else:
        report = run_suites(
            repo_root,
            evals_root,
            suites=args.suite,
            gate_only=args.gate,
            seed_override=args.seed,
        )
    out = args.out or (repo_root / DEFAULT_RESULTS)
    write_jsonl(out, report.results)
    print(report_module.render(report, verbose=args.verbose))
    print(f"\nresults: {_display(out, repo_root)}")
    return 1 if report.failed else 0


def _check(args: argparse.Namespace, repo_root: Path, evals_root: Path) -> int:
    report = run_suites(repo_root, evals_root, gate_only=not args.all)
    out = args.out or (repo_root / DEFAULT_RESULTS)
    write_jsonl(out, report.results)
    print(report_module.render(report))

    path = args.baseline or (evals_root / DEFAULT_BASELINE)
    known = {evaluation.id for _, evaluation in collect(evals_root)}
    # Strict, CI's gate: an eval this machine cannot exercise fails. Lenient,
    # a contributor's machine: it is listed as NOT EXERCISED, never passed.
    unexercised = frozenset() if args.require_exercised else not_exercised(evals_root)
    comparison = baseline_module.compare(
        baseline_module.Baseline.load(path), report.results, known, unexercised
    )
    rendered = baseline_module.render(comparison)
    if rendered:
        print()
        print(rendered)
    if report.failed or not comparison.ok:
        print(
            "\ndirewolf_evals: the gate failed. A baseline change is a reviewed edit to "
            f"{_display(path, repo_root)}, never an automatic rewrite.",
            file=sys.stderr,
        )
        return 1
    counts = report.counts()
    unexercised_count = len(comparison.not_exercised)
    print(
        f"\ndirewolf_evals: gate ok ({counts['pass']} passed, {counts['pending']} pending, "
        f"{counts['skip']} skipped, {unexercised_count} not exercised here) against "
        f"{_display(path, repo_root)}"
    )
    return 0


def _baseline(args: argparse.Namespace, repo_root: Path, evals_root: Path) -> int:
    report = run_suites(repo_root, evals_root, gate_only=not args.all)
    path = args.baseline or (evals_root / DEFAULT_BASELINE)
    baseline_module.write(path, report.results)
    print(f"recorded {_display(path, repo_root)}")
    print("Review the diff: this file is what 'no regression' means.")
    return 0


def _list(evals_root: Path) -> int:
    for suite in discover(evals_root):
        gate = " [gate]" if suite.gate else ""
        print(f"{suite.id}{gate} — {suite.title}")
        print(f"    score: {suite.score_meaning}")
        for evaluation in suite.evals:
            # What it will run, and what is stopping it -- separately, because
            # conflating them is how a milestone-owned eval stayed dormant.
            marker = evaluation.runner or "(no runner yet)"
            waiting = (
                f"  waiting on {', '.join(evaluation.requires)}" if evaluation.requires else ""
            )
            print(f"    {evaluation.id:<46} {marker}{waiting}")
    return 0


def _inventory() -> int:
    print("measurable now")
    for item in inventory_module.available():
        print(f"  [{item.milestone:<4}] {item.property}")
        print(f"           suite: {item.suite} — {item.note}")
    print("\npending — not measurable yet, and therefore not passing")
    for item in inventory_module.pending():
        print(f"  [{item.milestone:<4}] {item.property}")
        print(f"           {item.note}")
    return 0


def _display(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root).as_posix()
    except ValueError:
        return str(path)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
