"""The ADR history gate's anchor cannot quietly become a weaker one.

`make adr-history` (scripts/dw.py) decides which revision `dwcheck adr` anchors
accepted ADRs to: the merge base with a pull request's target branch, the
previous tip of a pushed branch (`github.event.before`), or -- with neither --
HEAD. Hosted run 40119301603 showed the gap this closes: the push replaced its
previous tip (an amended commit, force-pushed), so that tip was on no ref, the
full-depth checkout did not hold it, and the check stopped with ADR007 before
it had verified anything. The anchor is now fetched by its exact identifier on
a hosted runner and verified before use; anything that cannot be verified
fails, and nothing weaker -- HEAD, a merge base, the digest manifest -- is put
in its place.

The decision is driven here through a scripted `git` that records every call
and answers from a script: no repository is created, no commit is made, and
nothing is fetched. The one case that needs real history -- an altered
accepted ADR rejected against the revision that accepted it -- reads this
repository's own history without writing to it.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from dwcheck.checks_adr import _immutable_adrs, check_adr_history
from dwcheck.config import load

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES = REPO_ROOT / "architecture.toml"
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import dw  # noqa: E402  - imported after the path is extended

# The three commits of hosted run 40119301603: the replaced previous tip, the
# pushed head, and the one ancestor they share.
PREVIOUS = "bae601ad8583592d1598686990b97a3f513e8a92"
PUSHED = "35f68f1db8de83aec6e7a3fe856a1eb837e52fdb"
COMMON = "5e66edae64921af80f11f14dfda5a2e435788b20"

Answer = tuple[int, str, str]
OK: Answer = (0, "", "")
MISSING: Answer = (1, "", "")


def found(commit: str) -> Answer:
    return (0, f"{commit}\n", "")


def resolves(commit: str) -> tuple[str, ...]:
    return ("rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}")


def fetch_exactly(commit: str) -> tuple[str, ...]:
    return ("fetch", "--no-tags", "--quiet", "origin", commit)


class ScriptedGit:
    """`git`, as a script: every call's argv is recorded and answered from
    `answers` (argv -> answers, consumed in order, the last one repeating);
    an unscripted call fails as git does for a revision it does not have."""

    def __init__(self, answers: dict[tuple[str, ...], list[Answer]] | None = None) -> None:
        self.answers = {argv: list(queue) for argv, queue in (answers or {}).items()}
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, *args: str) -> subprocess.CompletedProcess[str]:
        self.calls.append(args)
        queue = self.answers.get(args)
        if not queue:
            return subprocess.CompletedProcess(args, 128, "", "fatal: Needed a single revision")
        code, out, err = queue.pop(0) if len(queue) > 1 else queue[0]
        return subprocess.CompletedProcess(args, code, out, err)


# --- a push: the previous tip -------------------------------------------------


def test_case_a_a_previous_tip_already_here_is_used_as_it_is() -> None:
    git = ScriptedGit({resolves(PREVIOUS): [found(PREVIOUS)]})
    assert dw.adr_history_anchor("", PREVIOUS, hosted=True, git=git) == PREVIOUS
    assert git.calls == [resolves(PREVIOUS)], "nothing is fetched that is already here"


def test_case_b_a_previous_tip_missing_here_is_fetched_by_identity_and_verified() -> None:
    git = ScriptedGit(
        {resolves(PREVIOUS): [MISSING, found(PREVIOUS)], fetch_exactly(PREVIOUS): [OK]}
    )
    assert dw.adr_history_anchor("", PREVIOUS, hosted=True, git=git) == PREVIOUS
    assert git.calls == [resolves(PREVIOUS), fetch_exactly(PREVIOUS), resolves(PREVIOUS)]
    # A depth would make the clone shallow, which the checker refuses (and a
    # truncated history is the stand-in anchor the checker exists to refuse).
    assert not any(arg.startswith("--depth") for call in git.calls for arg in call)


def test_case_c_divergent_history_never_swaps_the_previous_tip_for_their_ancestor() -> None:
    """          COMMON (5e66eda)
                /             \\
    PREVIOUS (bae601a)   PUSHED (35f68f1)

    The previous tip is not an ancestor of the pushed head. Their common
    ancestor would be a weaker anchor -- whatever the replaced commit accepted
    is not in it -- and is never consulted, let alone used."""
    git = ScriptedGit(
        {
            resolves(PREVIOUS): [MISSING, found(PREVIOUS)],
            fetch_exactly(PREVIOUS): [OK],
            ("merge-base", PREVIOUS, "HEAD"): [found(COMMON)],
            ("merge-base", "--is-ancestor", PREVIOUS, "HEAD"): [MISSING],
            resolves("HEAD"): [found(PUSHED)],
        }
    )
    anchor = dw.adr_history_anchor("", PREVIOUS, hosted=True, git=git)
    assert anchor == PREVIOUS
    assert anchor not in (COMMON, PUSHED, "HEAD")
    assert not [call for call in git.calls if call[0] == "merge-base"]


def test_case_d_a_previous_tip_origin_does_not_serve_fails_closed() -> None:
    refused = (128, "", f"fatal: remote error: upload-pack: not our ref {PREVIOUS}")
    git = ScriptedGit({resolves(PREVIOUS): [MISSING], fetch_exactly(PREVIOUS): [refused]})
    with pytest.raises(dw.TaskError) as failure:
        dw.adr_history_anchor("", PREVIOUS, hosted=True, git=git)
    message = str(failure.value)
    for said in (PREVIOUS, "github.event.before", "not our ref", "nothing weaker"):
        assert said in message, f"the failure does not say {said!r}: {message}"
    assert f"--adr-base {PREVIOUS} --require-adr-history" in message, "no way to verify by hand"


def test_case_d_a_fetch_that_does_not_produce_that_exact_commit_fails_closed() -> None:
    # The fetch "succeeds" but the commit still does not resolve...
    git = ScriptedGit({resolves(PREVIOUS): [MISSING], fetch_exactly(PREVIOUS): [OK]})
    with pytest.raises(dw.TaskError, match="did not resolve to itself"):
        dw.adr_history_anchor("", PREVIOUS, hosted=True, git=git)
    # ...or resolves to something that is not it.
    git = ScriptedGit({resolves(PREVIOUS): [MISSING, found(COMMON)], fetch_exactly(PREVIOUS): [OK]})
    with pytest.raises(dw.TaskError, match="cannot verify accepted ADRs"):
        dw.adr_history_anchor("", PREVIOUS, hosted=True, git=git)


def test_case_d_off_a_hosted_runner_nothing_is_fetched_and_the_check_fails() -> None:
    git = ScriptedGit({resolves(PREVIOUS): [MISSING]})
    with pytest.raises(dw.TaskError, match="not in this clone"):
        dw.adr_history_anchor("", PREVIOUS, hosted=False, git=git)
    assert git.calls == [resolves(PREVIOUS)], "a developer's clone is never fetched into"


def test_the_task_runs_the_checker_only_on_a_verified_anchor_in_strict_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checked: list[tuple[str, ...]] = []
    monkeypatch.setattr(dw, "uvrun", lambda *args: checked.append(args))
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.delenv("DW_ADR_BASE_REF", raising=False)
    monkeypatch.setenv("DW_ADR_BEFORE", PREVIOUS)
    monkeypatch.setattr(
        dw, "_git", ScriptedGit({resolves(PREVIOUS): [MISSING], fetch_exactly(PREVIOUS): [MISSING]})
    )
    with pytest.raises(dw.TaskError, match="cannot verify accepted ADRs"):
        dw.task_adr_history()
    assert checked == [], "the checker ran against an anchor nobody verified"
    monkeypatch.setattr(
        dw,
        "_git",
        ScriptedGit(
            {resolves(PREVIOUS): [MISSING, found(PREVIOUS)], fetch_exactly(PREVIOUS): [OK]}
        ),
    )
    dw.task_adr_history()
    assert checked == [("dwcheck", "--adr-base", PREVIOUS, "--require-adr-history", "adr")]


# --- an accepted ADR altered: still rejected ----------------------------------


def _git_dir() -> Path | None:
    git = shutil.which("git")
    if git is None:
        return None
    out = subprocess.run(
        [git, "-C", str(REPO_ROOT), "rev-parse", "--absolute-git-dir"],
        capture_output=True,
        text=True,
        check=False,
    )
    return Path(out.stdout.strip()) if out.returncode == 0 else None


def test_case_e_an_altered_accepted_adr_is_still_rejected_against_real_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The gate the task runs, on this repository's own history (read, never
    written: `GIT_DIR` points the checker at it, the working tree is a copy of
    the ADRs). Skipped only where there is no history to read -- a shallow
    checkout -- as the positive control in test_boundaries.py is; dwcheck's
    own suite proves the rejection on a history of its own everywhere."""
    git_dir = _git_dir()
    if git_dir is None:
        pytest.skip("no git, or not a git checkout")
    directory = load(REPO_ROOT, RULES).adr.directory
    shutil.copytree(REPO_ROOT / directory, tmp_path / directory)
    monkeypatch.setenv("GIT_DIR", str(git_dir))
    unchanged = check_adr_history(load(tmp_path, RULES), "HEAD", require_history=True)
    if [f.rule for f in unchanged] == ["ADR007-adr-history-unavailable"]:
        pytest.skip(unchanged[0].message)
    assert unchanged == [], "the control: an unaltered copy matches its history"

    config = load(tmp_path, RULES)
    excepted = {e.file for e in config.adr.history_exceptions}
    victim = next(p for p in _immutable_adrs(config) if p.name not in excepted)
    victim.write_text(
        victim.read_text(encoding="utf-8") + "\nA note appended after acceptance.\n",
        encoding="utf-8",
    )
    findings = check_adr_history(load(tmp_path, RULES), "HEAD", require_history=True)
    assert [(f.rule, f.path) for f in findings] == [
        ("ADR004-accepted-adr-altered-since-acceptance", f"{directory}/{victim.name}")
    ]


# --- a pull request: the merge base, as before ---------------------------------


def _pull_request_git(base: str = "main") -> ScriptedGit:
    return ScriptedGit(
        {
            ("check-ref-format", f"refs/heads/{base}"): [OK],
            (
                "fetch",
                "--no-tags",
                "--quiet",
                "origin",
                f"+refs/heads/{base}:refs/remotes/origin/{base}",
            ): [OK],
            ("merge-base", f"refs/remotes/origin/{base}", "HEAD"): [found(COMMON)],
        }
    )


def test_case_f_a_pull_request_is_anchored_to_its_merge_base_with_the_target() -> None:
    git = _pull_request_git()
    assert dw.adr_history_anchor("main", "", hosted=True, git=git) == COMMON
    assert [call[0] for call in git.calls] == ["check-ref-format", "fetch", "merge-base"]
    # A pull request's own `before` (a synchronize event has one) never moves it.
    git = _pull_request_git()
    assert dw.adr_history_anchor("main", PREVIOUS, hosted=True, git=git) == COMMON
    assert resolves(PREVIOUS) not in git.calls
    # Off a hosted runner the target branch is read as it is, never fetched.
    git = _pull_request_git()
    assert dw.adr_history_anchor("main", "", hosted=False, git=git) == COMMON
    assert [call[0] for call in git.calls] == ["check-ref-format", "merge-base"]


def test_case_f_a_pull_request_without_a_merge_base_fails() -> None:
    git = ScriptedGit({("check-ref-format", "refs/heads/main"): [OK]})
    with pytest.raises(dw.TaskError, match="no merge base"):
        dw.adr_history_anchor("main", "", hosted=False, git=git)


# --- what is not a revision is never used as one -------------------------------


@pytest.mark.parametrize(
    "before",
    [
        "abc",
        "-c",
        "--output=/tmp/x",
        "HEAD",
        "HEAD~1",
        "main",
        "0" * 39,
        "0" * 41,
        "g" * 40,
        PREVIOUS.upper(),
        f" {PREVIOUS}",
        f"{PREVIOUS}\n",
        f"{PREVIOUS};id",
        PREVIOUS[:12],
    ],
)
def test_case_g_a_malformed_previous_tip_is_refused_before_any_git_runs(before: str) -> None:
    git = ScriptedGit()
    with pytest.raises(dw.TaskError, match="not a full commit identifier"):
        dw.adr_history_anchor("", before, hosted=True, git=git)
    assert git.calls == []


@pytest.mark.parametrize(
    "base_ref",
    ["-b", "--upload-pack=x", "main;id", "$(id)", "main id", "a..b", "../main", "/main", "@{-1}"],
)
def test_case_g_a_malformed_base_branch_is_refused_before_anything_is_fetched(
    base_ref: str,
) -> None:
    git = ScriptedGit()
    with pytest.raises(dw.TaskError, match="not a branch name"):
        dw.adr_history_anchor(base_ref, "", hosted=True, git=git)
    assert git.calls == []


def test_case_g_a_name_git_refuses_is_refused_too() -> None:
    git = ScriptedGit({("check-ref-format", "refs/heads/main.lock"): [MISSING]})
    with pytest.raises(dw.TaskError, match="not a branch name"):
        dw.adr_history_anchor("main.lock", "", hosted=True, git=git)
    assert git.calls == [("check-ref-format", "refs/heads/main.lock")]


def test_case_g_no_previous_tip_is_head_and_runs_no_git() -> None:
    """A manual run has neither input; a push that created the branch reports
    the all-zero identifier. Both are HEAD, as before -- `make arch`'s anchor --
    and no zero commit is ever looked up."""
    for before in ("", "0" * 40):
        git = ScriptedGit()
        assert dw.adr_history_anchor("", before, hosted=True, git=git) == "HEAD"
        assert git.calls == []


# --- the workflow runs the task ------------------------------------------------


def _architecture_job() -> str:
    text = CI.read_text(encoding="utf-8")
    start = text.index("\n  architecture:\n")
    end = text.index("\n  schema:\n", start)
    return text[start:end]


def test_the_architecture_job_runs_the_task_with_the_events_revisions() -> None:
    job = _architecture_job()
    assert re.search(r"^\s+fetch-depth: 0\s*$", job, re.MULTILINE), "the full history is kept"
    step = job[job.index("- name: Accepted ADRs must match the history that accepted them") :]
    step = step[: step.index("\n      - ")]
    assert "DW_ADR_BASE_REF: ${{ github.base_ref }}" in step
    assert "DW_ADR_BEFORE: ${{ github.event.before }}" in step
    assert re.search(r"^\s+run: make adr-history\s*$", step, re.MULTILINE)
    # Event values reach the task through the environment only, never the shell.
    run = [line for line in step.splitlines() if "run:" in line]
    assert all("${{" not in line for line in run), run
    assert "continue-on-error" not in job
    assert "permissions:" not in job, "the job keeps the workflow's read-only token"
    assert "accepted the deliberately-invalid fixture tree" in job, "the fixture proof stays"
    assert "adr-history" in dw.TASKS
