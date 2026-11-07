"""M5e.5's evidence cannot lose a case, drift from its ADRs, run anywhere
unsafe, or turn a profile on outside its fence.

ADR-0054 §8 and ADR-0055 §9 require their cases by name; the authority keeps
the profiles only under `serve --allow-unaccepted-hygiene-profile`, which no
shipped configuration may spell; and the evidence runs only in a manual job
on a disposable GitHub-hosted runner, required by no `ci` job until the owner
adds it after M5e.4's repair passes hosted (the plan's §10, "M5e.5's
sequencing"). These tests hold each, reading the ADRs, the sources and the
workflows as text, with a negative control for each way. Nothing here
downloads, builds or runs a package manager.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ADR_NPM = REPO_ROOT / "docs" / "adr" / "0054-m5e-npm-hygiene-profile.md"
ADR_PIP = REPO_ROOT / "docs" / "adr" / "0055-m5e-pip-hygiene-profile.md"
SUITE = REPO_ROOT / "crates" / "dwkd-authority" / "tests" / "sandbox_hygiene.rs"
HYGIENE_RS = REPO_ROOT / "crates" / "dwkd-authority" / "src" / "resource" / "exec" / "hygiene.rs"
PROFILE_RS = REPO_ROOT / "crates" / "dwk-sandbox-profile" / "src" / "lib.rs"
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
MANUAL = WORKFLOWS / "m5e5-evidence.yml"
CI = WORKFLOWS / "ci.yml"
OPTION = "--allow-unaccepted-hygiene-profile"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import dw  # noqa: E402  - imported after the path is extended

HOSTED = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}


def _section(text: str, heading: str) -> str:
    start = text.index(heading)
    end = text.find("\n### ", start + len(heading))
    return text[start : end if end >= 0 else len(text)]


def _table_cases(adr: Path, heading: str) -> list[str]:
    """The case names of an ADR's evidence table: each row's first cell."""
    section = _section(adr.read_text(encoding="utf-8"), heading)
    return re.findall(r"^\| `([a-z0-9-]+)` \|", section, re.MULTILINE)


def _case_problems(npm: list[str], pip: list[str]) -> list[str]:
    problems = []
    if sorted(npm) != sorted(dw.HYGIENE_NPM_CASES):
        drift = sorted(set(npm) ^ set(dw.HYGIENE_NPM_CASES))
        problems.append(f"npm's cases are not ADR-0054 §8's: {drift}")
    if sorted(pip) != sorted(dw.HYGIENE_PIP_CASES):
        drift = sorted(set(pip) ^ set(dw.HYGIENE_PIP_CASES))
        problems.append(f"pip's cases are not ADR-0055 §9's: {drift}")
    return problems


def test_the_cases_are_the_adrs_own_by_name() -> None:
    npm = _table_cases(ADR_NPM, "### 8. The evidence acceptance requires")
    pip = _table_cases(ADR_PIP, "### 9. The evidence acceptance requires")
    assert len(npm) == 22 and len(pip) == 21, (len(npm), len(pip))
    assert _case_problems(npm, pip) == []
    # The one case beyond the ADRs' is D4's, and named as such.
    assert dw.HYGIENE_EXTRA_CASES == ("pip-interpreter-module-refused",)
    names = [case for _, case in dw.HYGIENE_CASES]
    assert len(names) == len(set(names)) == 44


@pytest.mark.parametrize("change", ["dropped", "renamed", "added"])
def test_a_case_that_drifts_from_its_adr_fails(change: str) -> None:
    npm = _table_cases(ADR_NPM, "### 8. The evidence acceptance requires")
    pip = _table_cases(ADR_PIP, "### 9. The evidence acceptance requires")
    if change == "dropped":
        npm = npm[1:]
    elif change == "renamed":
        pip = [*pip[:-1], "pip-plan-records-prefix"]
    else:
        npm = [*npm, "npm-also-this"]
    assert _case_problems(npm, pip) != []


def test_every_case_has_its_outcome_its_level_and_what_enforced_it() -> None:
    names = {case for _, case in dw.HYGIENE_CASES}
    assert set(dw.HYGIENE_OUTCOMES) == names
    for case in sorted(names):
        contract = dw.attribution(dw.HYGIENE_SUITE, case)
        assert contract is not None, f"{case} is unattributed"
        level, _mechanisms = contract
        assert level == "dwkp-end-to-end", (case, level)
        # An outcome that does not show what it claims is refused.
        assert dw.outcome_problem(dw.HYGIENE_SUITE, case, "fine", "x") is not None, case
        good = dw.HYGIENE_OUTCOMES[case] + "x"
        assert dw.outcome_problem(dw.HYGIENE_SUITE, case, good, "x") is None, case


def _suite_problems(text: str) -> list[str]:
    problems = []
    # A case is printed by `evidence(` itself or from a loop over its name.
    printed = re.findall(r'"((?:npm|npx|pip)-[a-z0-9-]+)"', text)
    names = {case for _, case in dw.HYGIENE_CASES}
    missing = names - set(printed)
    if missing:
        problems.append(f"the suite never prints {sorted(missing)}")
    for test in dw.HYGIENE_TESTS:
        name = test.removeprefix("linux::")
        found = re.search(r'#\[ignore = "([^"]*)"\]\n( *)fn ' + name + r"\(\) \{", text)
        if found is None:
            problems.append(f"{name} is not an #[ignore]d test of the suite")
        elif "hosted only" not in found.group(1):
            problems.append(f"{name} is not marked hosted only")
    new = text[text.find("fn new(tag: &str, setup: Setup)") :]
    if not (0 <= new.find("hosted();") < new.find("Pins::load()") < new.find("Broker::start(")):
        problems.append("the lab does not check where it is before it starts anything")
    if "beyond_the_probe(" not in text or "fn probe_questions(" not in text:
        problems.append("the suite counts the probe's own question as a workload's refusal")
    if 'const LEVEL: &str = "dwkp-end-to-end";' not in text:
        problems.append("the suite's level is not dwkp-end-to-end")
    # A missing trust file fails closed only if nothing was tunnelled: a
    # failed TLS handshake after a fallback to another store looks the same
    # from the exit status (npm ignores a missing `cafile`).
    trust = text[text.find("fn without_a_trust_file_both_fail_closed()") :]
    trust = trust[: trust.find("\n    }\n")]
    if trust.count("tunnels(") < 2 or "fn tunnels(" not in text:
        problems.append("a missing trust file is not shown to have tunnelled nothing")
    return problems


def test_the_suite_prints_every_case_and_checks_where_it_is_first() -> None:
    assert _suite_problems(SUITE.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize(
    ("mutate", "said"),
    [
        (lambda t: t.replace('"npx-still-refused"', '"npx-refused"', 1), "never prints"),
        (lambda t: t.replace('#[ignore = "hosted only', '#[ignore = "later', 1), "hosted only"),
        (lambda t: t.replace("            hosted();\n", "", 1), "where it is"),
        (lambda t: t.replace("beyond_the_probe(", "counted_raw("), "probe's own question"),
        (lambda t: t.replace("tunnels(&", "sum_of(&"), "tunnelled nothing"),
    ],
    ids=["case-lost", "not-hosted", "no-guard", "raw-count", "trust-by-exit-status"],
)
def test_a_weakened_suite_fails(mutate: object, said: str) -> None:
    text = SUITE.read_text(encoding="utf-8")
    weakened = mutate(text)  # type: ignore[operator]
    assert weakened != text, "the negative control changed nothing"
    assert any(said in p for p in _suite_problems(weakened)), _suite_problems(weakened)


def _pairs(rust: str, name: str) -> list[tuple[str, str]]:
    """A `&[(&str, &str)]` constant's pairs, constants resolved."""
    body = rust[rust.index(f"pub const {name}: &[(&str, &str)] = &[") :]
    body = body[: body.index("];")]
    constants = dict(re.findall(r'pub const ([A-Z_]+): &str = "([^"]*)";', rust))
    pairs = []
    for key, value in re.findall(r'\("([^"]+)",\s*("?[^)"]*"?)\)', body):
        pairs.append((key, value.strip('"') if value.startswith('"') else constants[value]))
    return pairs


def _adr_variables(adr: Path, heading: str) -> set[tuple[str, str]]:
    section = _section(adr.read_text(encoding="utf-8"), heading)
    section = section[: section.index("**By the authority**")]
    return set(re.findall(r"`([A-Za-z_]+)=([^`]+)`", section))


def test_the_launcher_sets_exactly_the_variables_each_adr_proposes() -> None:
    rust = PROFILE_RS.read_text(encoding="utf-8")
    npm = set(_pairs(rust, "HYGIENE_NPM_ENVIRONMENT"))
    pip = set(_pairs(rust, "HYGIENE_PIP_ENVIRONMENT"))
    # ADR-0054 §2 names `npm_config_ignore_scripts` too, which the hygiene
    # launch already sets; the npm launch sets both lists.
    proposed_npm = _adr_variables(ADR_NPM, "### 2. How it is kept")
    assert proposed_npm - {("npm_config_ignore_scripts", "true")} == npm
    assert ("npm_config_ignore_scripts", "true") in set(_pairs(rust, "HYGIENE_ENVIRONMENT"))
    assert _adr_variables(ADR_PIP, "### 2. How it is kept") == pip
    # Until acceptance, no other launch sets any of them (the handoff's D1).
    hygiene = {k for k, _ in _pairs(rust, "HYGIENE_ENVIRONMENT")}
    assert not ({k for k, _ in npm} | {k for k, _ in pip}) & hygiene


def test_the_trust_paths_and_prefixes_are_spelled_alike_everywhere() -> None:
    rust = PROFILE_RS.read_text(encoding="utf-8")
    hygiene = HYGIENE_RS.read_text(encoding="utf-8")
    suite = SUITE.read_text(encoding="utf-8")
    constants = dict(re.findall(r'pub const ([A-Z_]+): &str = "([^"]*)";', rust))
    assert constants["NPM_TRUST_FILE"] == dw.HYGIENE_NPM_TRUST == "/etc/direwolf/npm-ca.pem"
    assert constants["PIP_TRUST_FILE"] == dw.HYGIENE_PIP_TRUST == "/etc/direwolf/pip-ca.pem"
    assert f'pub const PIP_TRUST_FILE: &str = "{dw.HYGIENE_PIP_TRUST}";' in hygiene
    for name in ("NPM_PREFIX", "PIP_PREFIX"):
        source = hygiene[hygiene.index(f"const {name}: &[&str] = &[") :]
        source = source[: source.index("];")]
        words = re.findall(r'"([^"]+)"', source)
        if name == "PIP_PREFIX":
            words.append(dw.HYGIENE_PIP_TRUST)
        evidence = suite[suite.index(f"const {name}: [&str; ") :]
        evidence = evidence[: evidence.index("];")]
        assert re.findall(r'"([^"]+)"', evidence) == words, name


def _fence_problems(files: dict[str, str]) -> list[str]:
    """Where the evidence-only option may be spelled: the server's command
    line (TX060 holds the source), this suite, and documents that describe
    it -- never a policy pack, a workflow or the task runner."""
    problems = []
    for name, text in files.items():
        if OPTION in text and (
            name.startswith(("policy/", ".github/"))
            or name == "scripts/dw.py"
            or name.endswith((".toml", ".yml", ".yaml"))
        ):
            problems.append(f"{name} spells {OPTION}")
    return problems


def _fenced_files() -> dict[str, str]:
    paths = [
        *sorted((REPO_ROOT / "policy").rglob("*")),
        *sorted(WORKFLOWS.glob("*.yml")),
        REPO_ROOT / "scripts" / "dw.py",
        REPO_ROOT / "Makefile",
    ]
    return {
        str(p.relative_to(REPO_ROOT).as_posix()): p.read_text(encoding="utf-8")
        for p in paths
        if p.is_file()
    }


def test_the_option_is_spelled_in_no_policy_workflow_or_runner() -> None:
    files = _fenced_files()
    assert any(name.startswith("policy/") for name in files), "no policy pack was read"
    assert _fence_problems(files) == []
    assert _fence_problems({"policy/balanced.toml": f"# {OPTION} npm"}) != []
    assert _fence_problems({".github/workflows/ci.yml": f"run: dw {OPTION} pip"}) != []


def _workflow_problems(manual: str, ci: str) -> list[str]:
    problems = []
    on = manual[manual.index("\non:") : manual.index("\npermissions:")]
    if re.search(r"^\s{2}(push|pull_request|schedule|workflow_run)\b", on, re.MULTILINE):
        problems.append("the manual workflow runs on something other than a dispatch")
    if "workflow_dispatch" not in on:
        problems.append("the manual workflow cannot be dispatched")
    if "make sandbox-hygiene-evidence" not in manual:
        problems.append("the manual workflow does not run the hygiene task")
    if dw.HYGIENE_FLAG in ci or "sandbox-hygiene" in ci:
        problems.append("ci.yml sets the hygiene flag or runs or requires its job")
    return problems


def test_the_evidence_is_manual_and_required_by_nothing() -> None:
    manual = MANUAL.read_text(encoding="utf-8")
    assert _workflow_problems(manual, CI.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize(
    ("mutate_manual", "mutate_ci", "said"),
    [
        (
            lambda t: t.replace("\non:\n", "\non:\n  push:\n", 1),
            lambda t: t,
            "other than a dispatch",
        ),
        (
            lambda t: t.replace("make sandbox-hygiene-evidence", "true"),
            lambda t: t,
            "hygiene task",
        ),
        (
            lambda t: t,
            lambda t: t.replace(", sandbox-registry,", ", sandbox-registry, sandbox-hygiene,", 1),
            "ci.yml",
        ),
    ],
    ids=["on-push", "no-task", "required"],
)
def test_a_weakened_workflow_fails(mutate_manual: object, mutate_ci: object, said: str) -> None:
    manual = MANUAL.read_text(encoding="utf-8")
    ci = CI.read_text(encoding="utf-8")
    weakened = (mutate_manual(manual), mutate_ci(ci))  # type: ignore[operator]
    assert weakened != (manual, ci), "the negative control changed nothing"
    problems = _workflow_problems(*weakened)
    assert any(said in p for p in problems), problems


def test_the_task_refuses_anywhere_but_a_hosted_runner_with_its_flag() -> None:
    assert dw.hygiene_refusal({}) is not None
    assert dw.hygiene_refusal(HOSTED) is not None
    assert dw.hygiene_refusal({dw.HYGIENE_FLAG: "1"}) is not None
    assert dw.hygiene_refusal({**HOSTED, dw.HYGIENE_FLAG: "0"}) is not None
    assert dw.hygiene_refusal({**HOSTED, dw.HYGIENE_FLAG: "1"}) is None
    # The registry's own flag never stands in for the hygiene's.
    assert dw.hygiene_refusal({**HOSTED, "DW_REGISTRY_EVIDENCE": "1"}) is not None


def _rust_tests() -> set[str]:
    """Every Rust test function's name in the crates the review runs."""
    names: set[str] = set()
    for path in (REPO_ROOT / "crates").rglob("*.rs"):
        names.update(
            re.findall(r"#\[test\]\n(?:\s*#\[[^\]]*\]\n)*\s*fn (\w+)\(", path.read_text("utf-8"))
        )
    return names


def test_every_mutant_targets_its_guard_exactly_once_and_names_its_detector() -> None:
    kinds = {mutant[4] for mutant in dw.HYGIENE_MUTATIONS}
    assert kinds == {"unit", "hosted"}
    names = [mutant[0] for mutant in dw.HYGIENE_MUTATIONS]
    names += [name for name, *_ in dw.HYGIENE_EQUIVALENT_MUTATIONS]
    assert len(names) == len(set(names))
    tests = _rust_tests()
    hosted = {test.removeprefix("linux::") for test in dw.HYGIENE_TESTS}
    for name, rel, old, new, kind, expect in dw.HYGIENE_MUTATIONS:
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        assert text.count(old) == 1, f"{name}: its target is in {rel} {text.count(old)} times"
        assert old != new, name
        assert expect, f"{name} names no test that must fail"
        # A unit mutant is killed by a unit test; a hosted one by the
        # hosted suite's own tests; a name that does not exist kills nothing.
        known = tests if kind == "unit" else hosted
        assert set(expect) <= known, f"{name}: no such test {sorted(set(expect) - known)}"
    for name, rel, old, why in dw.HYGIENE_EQUIVALENT_MUTATIONS:
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        assert text.count(old) == 1, f"{name}: its target is in {rel} {text.count(old)} times"
        assert len(why) > 40, f"{name}: an equivalent mutant says why"


_PASSED = "test result: ok. 3 passed; 0 failed\n"
_FAILED = (
    "test resource::exec::hygiene::tests::the_expected_one ... FAILED\n\n"
    "failures:\n    resource::exec::hygiene::tests::the_expected_one\n\n"
    "test result: FAILED. 2 passed; 1 failed\n"
)


def test_a_mutant_is_killed_only_by_a_test_it_names() -> None:
    expect = ("the_expected_one",)
    assert dw.mutant_verdict(_FAILED, True, expect) == "killed"
    assert dw.failed_tests(_FAILED) == {"resource::exec::hygiene::tests::the_expected_one"}
    # The negative controls: another test failing, a mutant that does not
    # build, a step that failed with no test named, and nothing failing.
    assert dw.mutant_verdict(_FAILED, True, ("another_one",)) == "failed-elsewhere"
    broken = "error[E0308]: mismatched types\nerror: could not compile `dwkd-authority`\n"
    assert dw.mutant_verdict(broken + _FAILED, True, expect) == "not-compiled"
    assert dw.mutant_verdict("error: no such command\n", True, expect) == "failed-elsewhere"
    assert dw.mutant_verdict(_PASSED, False, expect) == "survived"
    # The hosted suite's own report: `--nocapture` splits its result line.
    hosted = (
        "test linux::npm_under_its_proposed_profile ... \nthread panicked\n"
        "failures:\n    linux::npm_under_its_proposed_profile\n\ntest result: FAILED.\n"
    )
    assert dw.mutant_verdict(hosted, True, ("npm_under_its_proposed_profile",)) == "killed"


def test_the_hygiene_images_carry_their_mount_points_and_trust_as_asked(tmp_path: Path) -> None:
    profile = PROFILE_RS.read_text(encoding="utf-8")
    targets = {
        name: re.search(rf'pub const {name}: &str = "([^"]+)";', profile)
        for name in ("WORKSPACE_TARGET", "TMP_TARGET", "VAR_TMP_TARGET")
    }
    assert all(targets.values()), targets
    assert set(dw.HYGIENE_MOUNT_POINTS) == {m.group(1) for m in targets.values() if m}
    base = tmp_path / "registry"
    (base / "rootfs" / "opt" / "direwolf" / "python" / "bin").mkdir(parents=True)
    (base / "rootfs" / "opt" / "direwolf" / "node" / "bin").mkdir(parents=True)
    pki = tmp_path / "pki"
    pki.mkdir()
    (pki / "ca.pem").write_text("anchor\n", encoding="utf-8")
    (pki / "system.pem").write_text("system\n", encoding="utf-8")
    for trusted in (True, False):
        rootfs = dw.hygiene_rootfs(
            base, tmp_path / f"image-{trusted}", pki, "3.12", trusted=trusted
        )
        for point in dw.HYGIENE_MOUNT_POINTS:
            assert (rootfs / point.lstrip("/")).is_dir(), point
        for trust in (dw.HYGIENE_NPM_TRUST, dw.HYGIENE_PIP_TRUST):
            assert (rootfs / trust.lstrip("/")).is_file() == trusted, trust
        for store in dw.HYGIENE_SYSTEM_STORES:
            assert (rootfs / store.lstrip("/")).read_text(encoding="utf-8") == "system\n"
        assert (rootfs / "etc" / "pip.conf").read_text(encoding="utf-8") == dw.HYGIENE_PIP_CONF
