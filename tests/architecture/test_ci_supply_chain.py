"""CI's supply chain is what CONTRIBUTING.md "CI security" says it is (F-11).

Four claims, each held here rather than in a comment:

**Every action pin is a commit, labelled with the release it is.** Every file
GitHub Actions reads `uses:` from is found -- workflows and composite actions
anywhere in the tree -- and each external reference is exactly
`owner/repo@<40-hex commit> # vX.Y.Z`, one commit per action, one release per
commit. Whether the label is TRUE needs the network: `make action-pins` (part
of `make security`) asks upstream for the tag; here it is driven with a
stand-in for `git ls-remote`.

**Dependabot can see every pin.** `directory: "/"` reads only
`.github/workflows` and a root `action.yml`; a composite action elsewhere needs
its directory listed. The coverage rule below is GitHub's documented one, and
the test fails for a file that pins an action outside the configuration.

**uv is installed by SHA-256, and a wrong digest fails.** The setup action's
argv is read from the file and run -- with the real pip of the locked
environment, offline, against a local stand-in wheel -- so a mismatched,
missing or malformed digest, or a release with no wheel, is shown to fail
rather than assumed to. uv.lock carries a hash for every registry file, which
is what makes `uv sync --frozen` check what it installs.

**Nothing in CI is privileged that need not be.** Only allow-listed triggers;
no write permission in any spelling; `sudo` only for the account and kernel
administration the evidence jobs need, never for an installer.

These read the files as text or through a strict YAML-subset reader that
raises on any construct it does not know: a check that silently skipped what
it could not parse would pass exactly the change it exists to catch.
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import re
import shlex
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GITHUB = REPO_ROOT / ".github"
SETUP_ACTION = GITHUB / "actions" / "setup" / "action.yml"
UV_REQUIREMENTS = GITHUB / "actions" / "setup" / "uv-requirements.txt"
DEPENDABOT = GITHUB / "dependabot.yml"
WORKFLOWS = sorted(p for p in (GITHUB / "workflows").iterdir() if p.suffix in (".yml", ".yaml"))

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import dw  # noqa: E402  - imported after the path is extended

SHA_A = "a" * 40
SHA_B = "b" * 40


def _strip_comment(line: str) -> str:
    """`line` without a YAML comment: a `#` at the start or after a space,
    outside quotes."""
    out = []
    quote = ""
    for index, char in enumerate(line):
        if quote:
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char == "#" and (index == 0 or line[index - 1] in " \t"):
            break
        out.append(char)
    return "".join(out).rstrip()


# --- a strict reader for the YAML subset dependabot.yml uses ------------------

_KEY = re.compile(r"^([A-Za-z0-9_.-]+):(?:\s+(.*))?$")
type Yaml = dict[str, Yaml] | list[Yaml] | str | int | None


def _yaml_scalar(text: str) -> Yaml:
    text = text.strip()
    if text.startswith("["):
        if not text.endswith("]"):
            raise ValueError(f"unterminated flow list: {text!r}")
        inner = text[1:-1].strip()
        return [_yaml_scalar(item) for item in inner.split(",")] if inner else []
    if text[:1] in set("{&*!|>%@`"):
        raise ValueError(f"YAML this reader does not support: {text!r}")
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    if text.isdigit():
        return int(text)
    return text


def _yaml_block(lines: list[tuple[int, str]], i: int, indent: int) -> tuple[Yaml, int]:
    if lines[i][1] == "-" or lines[i][1].startswith("- "):
        items: list[Yaml] = []
        while i < len(lines) and lines[i][0] == indent and lines[i][1].startswith("- "):
            rest = lines[i][1][2:].strip()
            if _KEY.match(rest):
                lines[i] = (indent + 2, rest)
                value, i = _yaml_mapping(lines, i, indent + 2)
            else:
                value, i = _yaml_scalar(rest), i + 1
            items.append(value)
        return items, i
    return _yaml_mapping(lines, i, indent)


def _yaml_mapping(lines: list[tuple[int, str]], i: int, indent: int) -> tuple[Yaml, int]:
    result: dict[str, Yaml] = {}
    while i < len(lines) and lines[i][0] == indent:
        match = _KEY.match(lines[i][1])
        if match is None:
            raise ValueError(f"not a mapping entry: {lines[i][1]!r}")
        key, rest = match.group(1), match.group(2)
        if key in result:
            raise ValueError(f"duplicate key {key!r}")
        i += 1
        if rest:
            result[key] = _yaml_scalar(rest)
        elif i < len(lines) and lines[i][0] > indent:
            result[key], i = _yaml_block(lines, i, lines[i][0])
        elif i < len(lines) and lines[i][0] == indent and lines[i][1].startswith("- "):
            result[key], i = _yaml_block(lines, i, indent)
        else:
            result[key] = None
    if i < len(lines) and lines[i][0] > indent:
        raise ValueError(f"unexpected indentation at {lines[i][1]!r}")
    return result, i


def read_yaml_subset(text: str) -> Yaml:
    """Block mappings, block lists, flow lists of scalars, quoted and plain
    scalars, comments. Anything else raises."""
    lines: list[tuple[int, str]] = []
    for raw in text.splitlines():
        code = _strip_comment(raw)
        if not code.strip():
            continue
        if "\t" in code[: len(code) - len(code.lstrip())]:
            raise ValueError("tab indentation")
        lines.append((len(code) - len(code.lstrip(" ")), code.strip()))
    value, end = _yaml_block(lines, 0, lines[0][0])
    if end != len(lines):
        raise ValueError(f"unread YAML from {lines[end][1]!r}")
    return value


def dependabot_updates(text: str | None = None) -> list[dict[str, Yaml]]:
    config = read_yaml_subset(text if text is not None else DEPENDABOT.read_text("utf-8"))
    assert isinstance(config, dict) and config.get("version") == 2
    updates = config["updates"]
    assert isinstance(updates, list)
    assert all(isinstance(u, dict) for u in updates)
    return [u for u in updates if isinstance(u, dict)]


def _directories(update: dict[str, Yaml]) -> list[str]:
    """`directory` or `directories`: exactly one of them (the reference
    presents them as alternatives)."""
    if ("directory" in update) == ("directories" in update):
        raise ValueError("an update entry needs exactly one of `directory` and `directories`")
    value = update["directory"] if "directory" in update else update["directories"]
    values = value if isinstance(value, list) else [value]
    if not values or not all(isinstance(v, str) and v.startswith("/") for v in values):
        raise ValueError(f"directories must be absolute: {value!r}")
    return [v for v in values if isinstance(v, str)]


def dependabot_covers(pattern: str, directory: str) -> bool:
    """Whether a `directories` entry reads the action files in `directory`.

    For GitHub Actions, `/` means `.github/workflows` and the root
    `action.yml` -- both of which `needed_directory` maps to `/` -- and any
    other entry the action file in that one directory. `*` matches within one
    path segment, `**` across segments (only `directories` takes globs).
    """
    pattern = pattern.rstrip("/") or "/"
    regex = ""
    index = 0
    while index < len(pattern):
        if pattern.startswith("**", index):
            regex += ".*"
            index += 2
        elif pattern[index] == "*":
            regex += "[^/]*"
            index += 1
        else:
            regex += re.escape(pattern[index])
            index += 1
    return re.fullmatch(regex, directory) is not None


def needed_directory(relative: str) -> str:
    """The Dependabot directory that reads the action file at `relative`."""
    parent = Path(relative).parent.as_posix()
    if parent in (".", ".github/workflows"):
        return "/"
    return "/" + parent


def uncovered(pinned_files: set[str], updates: list[dict[str, Yaml]]) -> list[str]:
    patterns = [
        d
        for u in updates
        if u.get("package-ecosystem") == "github-actions"
        for d in _directories(u)
    ]
    return sorted(
        f
        for f in pinned_files
        if not any(dependabot_covers(p, needed_directory(f)) for p in patterns)
    )


# --- action pins --------------------------------------------------------------


def test_every_file_actions_read_is_found() -> None:
    found = {p.relative_to(REPO_ROOT).as_posix() for p in dw.action_files()}
    for workflow in WORKFLOWS:
        assert workflow.relative_to(REPO_ROOT).as_posix() in found
    assert ".github/actions/setup/action.yml" in found


def test_action_files_are_found_wherever_they_are(tmp_path: Path) -> None:
    """A composite action is found without anyone listing it; build output
    and fuzzing state are not searched."""
    for relative in (
        ".github/workflows/a.yml",
        ".github/workflows/b.yaml",
        ".github/workflows/notes.txt",
        ".github/actions/one/action.yml",
        "tools/deep/two/action.yaml",
        "action.yml",
        "target/debug/x/action.yml",
        "crates/c/target/action.yml",
        ".venv/lib/action.yml",
        "fuzz/corpus/url_parse/action.yml",
    ):
        (tmp_path / relative).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / relative).write_text("", encoding="utf-8")
    found = {p.relative_to(tmp_path).as_posix() for p in dw.action_files(tmp_path)}
    assert found == {
        ".github/workflows/a.yml",
        ".github/workflows/b.yaml",
        ".github/actions/one/action.yml",
        "tools/deep/two/action.yaml",
        "action.yml",
    }


def test_every_external_action_is_a_commit_with_its_release() -> None:
    pins, problems = dw.action_pins()
    assert problems == []
    assert pins, "no pinned action found: the checker reads nothing"


def test_the_checker_accounts_for_every_uses_line() -> None:
    """An independent, loose count: every non-local `uses:` outside a comment
    is one pin the strict reader produced."""
    loose = 0
    for path in dw.action_files():
        for line in path.read_text(encoding="utf-8").splitlines():
            code = _strip_comment(line)
            match = re.search(r"uses\s*:\s*(\S+)", code)
            if match and not match.group(1).startswith("./"):
                loose += 1
    pins, _ = dw.action_pins()
    assert loose == len(pins)


def test_anything_but_a_labelled_commit_is_a_problem(tmp_path: Path) -> None:
    workflow = tmp_path / ".github" / "workflows" / "w.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "\n".join(
            [
                "jobs:",
                "  j:",
                "    steps:",
                f"      - uses: actions/checkout@{SHA_A} # v7.0.1",  # the one good pin
                "      - uses: ./.github/actions/setup",  # local: no pin
                "      # - uses: actions/checkout@v4  (a comment)",
                "      - uses: actions/checkout@v4",  # a tag
                "      - uses: actions/checkout@main",  # a branch
                f"      - uses: actions/checkout@{SHA_A[:12]} # v7.0.1",  # short SHA
                f"      - uses: actions/checkout@{SHA_A}",  # no release comment
                f"      - uses: actions/checkout@{SHA_A} # v7",  # not vX.Y.Z
                f"      - uses: actions/checkout@{SHA_A} # v7.0.1 extra",
                f'      - uses: "actions/checkout@{SHA_A}" # v7.0.1',  # quoted
                "      - uses: docker://alpine:3.20",  # an image
                f"      - {{uses: actions/checkout@{SHA_A}}}",  # flow mapping
                "      - uses: ./x@v1",  # a local action with a version
                "",
            ]
        ),
        encoding="utf-8",
    )
    pins, problems = dw.action_pins(tmp_path)
    assert [(p.repo, p.sha, p.version, p.line) for p in pins] == [
        ("actions/checkout", SHA_A, "v7.0.1", 4)
    ]
    assert len(problems) == 10, problems
    assert all(problem.startswith(".github/workflows/w.yml:") for problem in problems)


def test_one_commit_per_action_and_one_release_per_commit() -> None:
    pins, _ = dw.action_pins()
    assert dw.action_pin_problems(pins) == []

    def pin(repo: str, sha: str, version: str) -> dw.ActionPin:
        return dw.ActionPin("w.yml", 1, repo, repo, sha, version)

    drifted = [pin("actions/cache", SHA_A, "v6.1.0"), pin("actions/cache", SHA_B, "v4.3.0")]
    assert [p.split(" ")[0] for p in dw.action_pin_problems(drifted)] == ["actions/cache"]
    mislabelled = [
        pin("actions/checkout", SHA_A, "v7.0.1"),
        pin("actions/checkout", SHA_A, "v5.0.1"),
    ]
    (problem,) = dw.action_pin_problems(mislabelled)
    assert "labelled as ['v5.0.1', 'v7.0.1']" in problem


def test_only_githubs_own_actions_run_and_the_docs_name_each() -> None:
    """CONTRIBUTING.md and ci.yml say the only external actions are GitHub's
    own and name them; a new owner or a new action is a reviewed change to
    that text as well as to the pin."""
    pins, _ = dw.action_pins()
    repos = {p.repo for p in pins}
    assert {repo.split("/")[0] for repo in repos} == {"actions"}
    contributing = (REPO_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    section = contributing[contributing.index("## CI security") :]
    ci = (GITHUB / "workflows" / "ci.yml").read_text(encoding="utf-8")
    header = ci[: ci.index("\non:")]
    for repo in repos:
        assert f"`{repo}`" in section, f"CONTRIBUTING.md 'CI security' does not name {repo}"
        assert repo in header, f"ci.yml's security posture does not name {repo}"


def test_action_pins_compare_each_pin_with_its_upstream_tag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pins, _ = dw.action_pins()
    truth = {(p.repo, p.version): p.sha for p in pins}
    asked: list[tuple[str, str]] = []

    def upstream(repo: str, tag: str) -> str | None:
        asked.append((repo, tag))
        return truth[(repo, tag)]

    monkeypatch.setattr(dw, "_upstream_tag_commit", upstream)
    dw.task_action_pins()
    assert sorted(asked) == sorted(truth)

    victim = sorted(truth)[0]
    monkeypatch.setattr(
        dw, "_upstream_tag_commit", lambda r, t: SHA_B if (r, t) == victim else truth[(r, t)]
    )
    with pytest.raises(dw.TaskError, match=rf"but upstream {victim[1]} is {SHA_B}"):
        dw.task_action_pins()

    monkeypatch.setattr(
        dw, "_upstream_tag_commit", lambda r, t: None if (r, t) == victim else truth[(r, t)]
    )
    with pytest.raises(dw.TaskError, match=rf"upstream has no tag {victim[1]}"):
        dw.task_action_pins()

    def unreachable(_repo: str, _tag: str) -> str | None:
        raise dw.TaskError("could not ask github.com")

    monkeypatch.setattr(dw, "_upstream_tag_commit", unreachable)
    with pytest.raises(dw.TaskError, match=r"could not ask github.com"):
        dw.task_action_pins()


class _Completed:
    def __init__(self, returncode: int, stdout: str, stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_the_upstream_lookup_peels_an_annotated_tag(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[list[str], dict[str, str]]] = []
    answer = _Completed(0, "")

    def fake_run(argv: list[str], **kwargs: object) -> _Completed:
        env = kwargs.get("env")
        calls.append((argv, env if isinstance(env, dict) else {}))
        return answer

    monkeypatch.setattr(subprocess, "run", fake_run)
    answer = _Completed(0, f"{SHA_A}\trefs/tags/v1.2.3\n{SHA_B}\trefs/tags/v1.2.3^{{}}\n")
    assert dw._upstream_tag_commit("actions/cache", "v1.2.3") == SHA_B
    argv, env = calls[-1]
    assert argv[:4] == ["git", "-c", "credential.helper=", "ls-remote"]
    assert argv[4:] == [
        "--tags",
        "https://github.com/actions/cache.git",
        "refs/tags/v1.2.3",
        "refs/tags/v1.2.3^{}",
    ]
    assert env.get("GIT_TERMINAL_PROMPT") == "0"

    answer = _Completed(0, f"{SHA_A}\trefs/tags/v1.2.3\n")
    assert dw._upstream_tag_commit("actions/cache", "v1.2.3") == SHA_A
    answer = _Completed(0, "")
    assert dw._upstream_tag_commit("actions/cache", "v1.2.3") is None
    answer = _Completed(128, "", "fatal: unable to access")
    with pytest.raises(dw.TaskError, match="exit code 128"):
        dw._upstream_tag_commit("actions/cache", "v1.2.3")


def test_make_security_runs_the_action_pin_check() -> None:
    source = (REPO_ROOT / "scripts" / "dw.py").read_text(encoding="utf-8")
    body = source[source.index("def task_security()") : source.index("def task_check()")]
    assert "task_action_pins()" in body
    assert dw.TASKS["action-pins"] is dw.task_action_pins
    ci = (GITHUB / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert re.search(r"\n  supply-chain:\n(?:    .*\n|\n)*?      - run: make security\n", ci)


# --- Dependabot -----------------------------------------------------------------


def test_dependabot_reads_every_file_that_pins_an_action() -> None:
    pins, _ = dw.action_pins()
    pinned_files = {p.path for p in pins}
    assert ".github/actions/setup/action.yml" in pinned_files
    assert uncovered(pinned_files, dependabot_updates()) == []


def test_the_coverage_rule_finds_what_root_alone_misses() -> None:
    """GitHub's documented rule, applied to the configuration as it was
    before F-11: the composite action's pins were invisible."""
    files = {".github/workflows/ci.yml", ".github/actions/setup/action.yml", "action.yml"}
    before = 'version: 2\nupdates:\n  - package-ecosystem: github-actions\n    directory: "/"\n'
    assert uncovered(files, dependabot_updates(before)) == [".github/actions/setup/action.yml"]
    after = (
        "version: 2\nupdates:\n  - package-ecosystem: github-actions\n"
        '    directories:\n      - "/"\n      - "/.github/actions/*"\n'
    )
    assert uncovered(files, dependabot_updates(after)) == []
    # `*` stays within one segment: a nested action needs `**` or its own entry.
    nested = files | {".github/actions/group/inner/action.yml"}
    assert uncovered(nested, dependabot_updates(after)) == [
        ".github/actions/group/inner/action.yml"
    ]
    both = before.replace('directory: "/"', 'directory: "/"\n    directories: ["/"]')
    with pytest.raises(ValueError, match="exactly one"):
        uncovered(files, dependabot_updates(both))


def test_the_yaml_reader_refuses_what_it_does_not_understand() -> None:
    for text in (
        "a: &anchor 1\n",
        "a: {b: c}\n",
        "a: |\n  text\n",
        "a: 1\na: 2\n",
        "a:\n    b: 1\n  c: 2\n",
    ):
        with pytest.raises(ValueError):
            read_yaml_subset(text)


def test_one_action_is_updated_everywhere_in_one_pull_request() -> None:
    """Grouped by dependency name across directories: a bump that reached
    the workflows but not the setup action is the drift F-11 found."""
    (actions,) = [u for u in dependabot_updates() if u["package-ecosystem"] == "github-actions"]
    groups = actions.get("groups")
    assert isinstance(groups, dict) and len(groups) == 1
    (group,) = groups.values()
    assert group == {"patterns": ["*"], "group-by": "dependency-name"}


def test_dependabot_stays_reviewable_and_owner_controlled() -> None:
    """Weekly, capped, labelled pull requests; nothing that narrows what
    the actions and uv entries see; nothing in CI that merges or approves."""
    updates = dependabot_updates()
    ecosystems = sorted(str(u["package-ecosystem"]) for u in updates)
    assert ecosystems == ["cargo", "github-actions", "pip", "uv"]
    for update in updates:
        schedule = update.get("schedule")
        assert schedule == {"interval": "weekly"}, update
        limit = update.get("open-pull-requests-limit")
        assert isinstance(limit, int) and 1 <= limit <= 5, update
        labels = update.get("labels")
        assert isinstance(labels, list) and "dependencies" in labels, update
    for update in updates:
        if update["package-ecosystem"] in ("github-actions", "pip"):
            assert set(update) <= {
                "package-ecosystem",
                "directory",
                "directories",
                "schedule",
                "open-pull-requests-limit",
                "groups",
                "labels",
            }, f"an option that changes what Dependabot proposes needs review: {update}"
    for update in updates:
        if update["package-ecosystem"] in ("cargo", "uv"):
            groups = update.get("groups")
            assert isinstance(groups, dict) and list(groups.values()) == [{"patterns": ["*"]}]
    for workflow in WORKFLOWS:
        text = _strip_all_comments(workflow.read_text(encoding="utf-8"))
        for forbidden in ("gh pr merge", "--auto", "auto-merge", "automerge", "--approve"):
            assert forbidden not in text, f"{workflow.name}: {forbidden}"
        assert "dependabot" not in text.lower(), f"{workflow.name} special-cases Dependabot"


def test_the_uv_pin_has_its_own_dependabot_entry() -> None:
    (pip,) = [u for u in dependabot_updates() if u["package-ecosystem"] == "pip"]
    assert _directories(pip) == ["/" + UV_REQUIREMENTS.parent.relative_to(REPO_ROOT).as_posix()]
    assert pip["open-pull-requests-limit"] == 1


def _strip_all_comments(text: str) -> str:
    return "\n".join(_strip_comment(line) for line in text.splitlines())


# --- uv: pinned by version and SHA-256 -----------------------------------------

_REQUIREMENT = re.compile(
    r"uv==(?P<version>[0-9]+\.[0-9]+\.[0-9]+)(?P<hashes>(?:\s+--hash=sha256:[0-9a-f]{64})+)"
)


def uv_requirement(text: str | None = None) -> tuple[str, list[str]]:
    """The one requirement in uv-requirements.txt: (version, digests)."""
    text = text if text is not None else UV_REQUIREMENTS.read_text(encoding="utf-8")
    logical = " ".join(
        line.split("#", 1)[0].rstrip().removesuffix("\\")
        for line in text.splitlines()
        if line.split("#", 1)[0].strip()
    )
    match = _REQUIREMENT.fullmatch(logical.strip())
    if match is None:
        raise ValueError(f"not `uv==X.Y.Z --hash=sha256:<64 hex>...`: {logical!r}")
    digests = re.findall(r"[0-9a-f]{64}", match.group("hashes"))
    return match.group("version"), digests


def test_uv_is_pinned_by_version_and_by_digest() -> None:
    version, digests = uv_requirement()
    assert digests and len(set(digests)) == len(digests)
    # Every file PyPI publishes for the version: a wheel per platform, so any
    # runner CI uses (Linux x86_64, Windows x86_64, macOS arm64) finds its own.
    assert len(digests) >= 3
    for bad in (
        "uv>=0.12.13 --hash=sha256:" + "a" * 64,
        "uv==0.12.13",
        "uv==0.12.13 --hash=md5:" + "a" * 32,
        "uv==0.12.13 --hash=sha256:" + "a" * 63,
        "--index-url https://example.invalid/simple\nuv==0.12.13 --hash=sha256:" + "a" * 64,
        "uv==0.12.13 --hash=sha256:" + "a" * 64 + "\nother==1.0 --hash=sha256:" + "b" * 64,
    ):
        with pytest.raises(ValueError):
            uv_requirement(bad)
    assert version == uv_requirement()[0]


def _install_step_run() -> str:
    """The setup action's `Install uv` step's command, folded as YAML folds `>-`."""
    lines = SETUP_ACTION.read_text(encoding="utf-8").splitlines()
    (start,) = [i for i, line in enumerate(lines) if re.match(r"\s+- name: Install uv\b", line)]
    step_indent = len(lines[start]) - len(lines[start].lstrip()) + 2
    command: list[str] = []
    for line in lines[start + 1 :]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent < step_indent:
            break
        if indent == step_indent:
            key = line.strip().split(":", 1)[0]
            assert key in ("shell", "run"), f"the install step has `{key}:`; nothing may soften it"
            if key == "shell":
                assert line.strip() == "shell: bash"
            elif line.strip() == "run: >-":
                command = []
            else:
                pytest.fail(f"write the install command as a `>-` block: {line.strip()}")
        else:
            command.append(line.strip())
    assert command, "the install step has no command"
    return " ".join(command)


def install_argv() -> list[str]:
    return shlex.split(_install_step_run())


def test_the_setup_action_installs_uv_in_hash_checking_mode() -> None:
    argv = install_argv()
    assert argv[:4] == ["python", "-m", "pip", "install"]
    options = argv[4:]
    expected = [
        "--disable-pip-version-check",
        "--quiet",
        "--require-hashes",
        "--only-binary",
        ":all:",
        "--no-deps",
        "--requirement",
        "$GITHUB_ACTION_PATH/" + UV_REQUIREMENTS.name,
    ]
    assert options == expected, (
        "the uv install takes exactly these options: no index, find-links, trusted host, "
        "pre-release or bare requirement can be added without this test changing"
    )
    run = _install_step_run()
    assert "||" not in run and ";" not in run and "&&" not in run


def test_uv_is_installed_once_and_only_by_digest() -> None:
    """The only pip install in CI is the setup action's; no `uv==` pin, uv
    installer script or uv setup action anywhere else."""
    installs = []
    for path in dw.action_files():
        text = _strip_all_comments(path.read_text(encoding="utf-8"))
        installs += [path.name for _ in re.finditer(r"\bpip3?\s+install\b", text)]
        assert "uv==" not in text, f"{path.name} pins uv itself"
        assert "astral.sh" not in text and "setup-uv" not in text, path.name
    assert installs == ["action.yml"]
    assert "continue-on-error" not in _strip_all_comments(SETUP_ACTION.read_text(encoding="utf-8"))


# Real pip, offline: the setup action's own options against a local wheel.


def _stub_wheel(directory: Path, version: str, *, requires: str | None = None) -> Path:
    """A minimal, valid wheel named like uv's: what the digests are tested on."""
    info = f"uv-{version}.dist-info"
    metadata = f"Metadata-Version: 2.1\nName: uv\nVersion: {version}\n"
    if requires:
        metadata += f"Requires-Dist: {requires}\n"
    files = {
        "uv_f11_stub/__init__.py": b"",
        f"{info}/METADATA": metadata.encode(),
        f"{info}/WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: direwolf-test\nRoot-Is-Purelib: true\n"
            b"Tag: py3-none-any\n"
        ),
    }
    record = []
    for name, data in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
        record.append(f"{name},sha256={digest.decode()},{len(data)}")
    record.append(f"{info}/RECORD,,")
    files[f"{info}/RECORD"] = ("\n".join(record) + "\n").encode()
    directory.mkdir(parents=True, exist_ok=True)
    wheel = directory / f"uv-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return wheel


def _stub_sdist(directory: Path, version: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    sdist = directory / f"uv-{version}.tar.gz"
    payload = f"Metadata-Version: 2.1\nName: uv\nVersion: {version}\n".encode()
    with tarfile.open(sdist, "w:gz") as archive:
        member = tarfile.TarInfo(f"uv-{version}/PKG-INFO")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    return sdist


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _pip(requirements: str, links: Path, tmp_path: Path) -> tuple[int, str, bool]:
    """Install as the setup action does -- its argv, its options -- except
    offline: the index replaced by `links`, the install by a target directory.
    Returns (exit code, output, whether uv's metadata was installed)."""
    req = tmp_path / "requirements.txt"
    req.write_text(requirements, encoding="utf-8")
    target = tmp_path / "target"
    argv = install_argv()
    argv[0] = sys.executable
    argv[argv.index("--requirement") + 1] = str(req)
    argv += ["--no-index", "--find-links", str(links), "--target", str(target), "--no-cache-dir"]
    env = {k: v for k, v in os.environ.items() if not k.startswith("PIP_")}
    env |= {"PIP_CONFIG_FILE": os.devnull, "PIP_NO_INPUT": "1"}
    result = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=300, check=False)
    installed = target.is_dir() and any(target.glob("uv-*.dist-info"))
    return result.returncode, result.stdout + result.stderr, installed


@pytest.fixture(scope="module")
def pinned_version() -> str:
    return uv_requirement()[0]


def test_pip_installs_the_file_whose_digest_is_listed(tmp_path: Path, pinned_version: str) -> None:
    wheel = _stub_wheel(tmp_path / "links", pinned_version)
    code, output, installed = _pip(
        f"uv=={pinned_version} --hash=sha256:{_sha256(wheel)}\n", wheel.parent, tmp_path
    )
    assert (code, installed) == (0, True), output


def test_pip_refuses_a_file_whose_digest_does_not_match(
    tmp_path: Path, pinned_version: str
) -> None:
    wheel = _stub_wheel(tmp_path / "links", pinned_version)
    other = "0" * 64 if _sha256(wheel) != "0" * 64 else "1" * 64
    code, output, installed = _pip(
        f"uv=={pinned_version} --hash=sha256:{other}\n", wheel.parent, tmp_path
    )
    assert code != 0 and not installed, output
    assert "DO NOT MATCH THE HASHES" in output, output


def test_pip_refuses_a_requirement_without_a_digest(tmp_path: Path, pinned_version: str) -> None:
    wheel = _stub_wheel(tmp_path / "links", pinned_version)
    code, output, installed = _pip(f"uv=={pinned_version}\n", wheel.parent, tmp_path)
    assert code != 0 and not installed, output
    assert "Hashes are required in --require-hashes mode" in output, output


@pytest.mark.parametrize("kind", ["not-hex", "empty", "truncated", "weak-algorithm"])
def test_pip_refuses_a_malformed_digest(tmp_path: Path, pinned_version: str, kind: str) -> None:
    wheel = _stub_wheel(tmp_path / "links", pinned_version)
    digest = {
        "not-hex": "sha256:" + "z" * 64,
        "empty": "sha256:",
        "truncated": "sha256:" + _sha256(wheel)[:63],
        "weak-algorithm": "md5:" + "0" * 32,
    }[kind]
    code, output, installed = _pip(
        f"uv=={pinned_version} --hash={digest}\n", wheel.parent, tmp_path
    )
    assert code != 0 and not installed, output


def test_pip_never_builds_uv_from_source(tmp_path: Path, pinned_version: str) -> None:
    """With only an sdist available -- even one whose digest is listed -- the
    install fails: `--only-binary :all:` leaves nothing to fall back to."""
    sdist = _stub_sdist(tmp_path / "links", pinned_version)
    code, output, installed = _pip(
        f"uv=={pinned_version} --hash=sha256:{_sha256(sdist)}\n", sdist.parent, tmp_path
    )
    assert code != 0 and not installed, output
    assert "No matching distribution found" in output, output


def test_pip_resolves_nothing_but_uv(tmp_path: Path, pinned_version: str) -> None:
    """A dependency the wheel declares is not fetched, from anywhere."""
    wheel = _stub_wheel(tmp_path / "links", pinned_version, requires="f11-not-a-package")
    code, output, installed = _pip(
        f"uv=={pinned_version} --hash=sha256:{_sha256(wheel)}\n", wheel.parent, tmp_path
    )
    assert (code, installed) == (0, True), output
    assert not any((tmp_path / "target").glob("f11*not*")), output


def test_pip_reads_the_real_requirements_file(tmp_path: Path, pinned_version: str) -> None:
    """The checked-in file parses in hash-checking mode and asks for the
    pinned uv: with nothing to install from, pip fails on the missing
    distribution, not on the file."""
    (tmp_path / "links").mkdir()
    code, output, installed = _pip(
        UV_REQUIREMENTS.read_text(encoding="utf-8"), tmp_path / "links", tmp_path
    )
    assert code != 0 and not installed
    assert f"No matching distribution found for uv=={pinned_version}" in output, output


def test_every_registry_file_in_uv_lock_has_a_hash() -> None:
    """`uv sync --frozen` refuses a file whose bytes do not match uv.lock's
    hash, but installs an entry that carries no hash unchecked. So every
    registry file must carry one, and no package may come from a source that
    has none (a git or URL source)."""
    lock = tomllib.loads((REPO_ROOT / "uv.lock").read_text(encoding="utf-8"))
    registry = 0
    for package in lock["package"]:
        source = package.get("source", {})
        kinds = set(source)
        assert kinds in ({"registry"}, {"editable"}, {"virtual"}, {"directory"}), (
            f"{package['name']} comes from {source}; only the registry or this repository"
        )
        if kinds != {"registry"}:
            continue
        assert source["registry"] == "https://pypi.org/simple", package["name"]
        registry += 1
        files = [*package.get("wheels", []), *([package["sdist"]] if "sdist" in package else [])]
        assert files, f"{package['name']} lists no file"
        for entry in files:
            assert re.fullmatch(r"sha256:[0-9a-f]{64}", str(entry.get("hash", ""))), (
                f"{package['name']}: {entry.get('url')} has no SHA-256 in uv.lock"
            )
    assert registry > 0


# --- triggers, permissions, privilege --------------------------------------------

ALLOWED_TRIGGERS = {"push", "pull_request", "workflow_dispatch", "schedule"}


def workflow_triggers(text: str) -> set[str]:
    lines = [_strip_comment(line) for line in text.splitlines()]
    (start,) = [i for i, line in enumerate(lines) if re.match(r"^[\"']?on[\"']?:", line)]
    inline = lines[start].split(":", 1)[1].strip()
    if inline:
        return {name.strip(" '\"") for name in inline.strip("[]").split(",") if name.strip()}
    names: set[str] = set()
    child_indent = None
    for line in lines[start + 1 :]:
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 0:
            break
        child_indent = child_indent or indent
        if indent == child_indent:
            names.add(line.strip().split(":", 1)[0].strip("'\""))
    return names


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_workflows_run_only_on_allowlisted_triggers(workflow: Path) -> None:
    """`pull_request_target`, `workflow_run` and the comment and review
    events run with the base repository's token on input a fork controls;
    none is needed."""
    triggers = workflow_triggers(workflow.read_text(encoding="utf-8"))
    assert triggers and triggers <= ALLOWED_TRIGGERS, f"{workflow.name}: {sorted(triggers)}"


def test_the_trigger_reader_sees_every_spelling() -> None:
    assert workflow_triggers("on: [push, pull_request_target]\n") == {
        "push",
        "pull_request_target",
    }
    assert workflow_triggers("on: workflow_run\n") == {"workflow_run"}
    assert workflow_triggers("on:\n    issue_comment:\n    push:\n      branches: [main]\n") == {
        "issue_comment",
        "push",
    }


def permission_problems(text: str) -> list[str]:
    """Every `permissions:` in a workflow grants read or none, scope by scope;
    the workflow-wide block exists, so no job inherits the repository default."""
    problems = []
    lines = [_strip_comment(line) for line in text.splitlines()]
    workflow_wide = False
    for index, line in enumerate(lines):
        match = re.match(r"^(\s*)permissions:\s*(.*)$", line)
        if match is None:
            continue
        indent, inline = len(match.group(1)), match.group(2).strip()
        workflow_wide = workflow_wide or indent == 0
        if inline:
            if inline != "{}":
                problems.append(f"line {index + 1}: `permissions: {inline}`")
            continue
        scopes = 0
        for child in lines[index + 1 :]:
            if not child.strip():
                continue
            if len(child) - len(child.lstrip()) <= indent:
                break
            scope = re.fullmatch(r"\s*([a-z-]+):\s*['\"]?(read|none)['\"]?\s*", child)
            if scope is None:
                problems.append(f"after line {index + 1}: `{child.strip()}`")
            scopes += 1
        if scopes == 0:
            problems.append(f"line {index + 1}: an empty `permissions:` block")
    if not workflow_wide:
        problems.append("no workflow-wide `permissions:` block")
    return problems


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_no_workflow_grants_write_in_any_spelling(workflow: Path) -> None:
    assert permission_problems(workflow.read_text(encoding="utf-8")) == []


def test_the_permission_reader_sees_every_spelling() -> None:
    good = "permissions:\n  contents: read\njobs:\n  a:\n    permissions: {}\n"
    assert permission_problems(good) == []
    for bad in (
        "permissions: write-all\n",
        "permissions: read-all\n",
        "permissions:\n  contents: write\n",
        "permissions:\n  contents: 'write'\n",
        "permissions:\n  contents: read\njobs:\n  a:\n    permissions:\n      id-token: write\n",
        "permissions:\n  contents: ${{ inputs.level }}\n",
        "jobs:\n  a:\n    permissions:\n      contents: read\n",
    ):
        assert permission_problems(bad), bad


# `sudo` in CI creates the evidence jobs' accounts and opens the one kernel
# switch the sandbox evidence needs. Anything else -- an installer above all --
# would run a downloaded dependency as root.
SUDO_ALLOWED = {"useradd", "groupadd", "usermod", "userdel", "groupdel", "sysctl"}


def sudo_problems(text: str) -> list[str]:
    problems = []
    for number, line in enumerate(text.splitlines(), start=1):
        code = _strip_comment(line)
        for match in re.finditer(r"(?<![\w-])sudo(?![\w-])((?:\s+-\S+)*)(?:\s+(\S+))?", code):
            command = match.group(2) or ""
            if command not in SUDO_ALLOWED:
                problems.append(f"line {number}: `{code.strip()}`")
    return problems


@pytest.mark.parametrize("path", dw.action_files(), ids=lambda p: p.relative_to(REPO_ROOT).name)
def test_nothing_is_installed_or_run_as_root(path: Path) -> None:
    """Workflow and action text only: `scripts/dw.py`'s own use of sudo,
    which drops to a less privileged user, is not this check's."""
    assert sudo_problems(path.read_text(encoding="utf-8")) == []


def test_the_sudo_reader_sees_an_installer() -> None:
    assert sudo_problems("run: sudo useradd --system dwbroker\n") == []
    assert sudo_problems("run: sudo sysctl -w kernel.x=0\n") == []
    for bad in (
        "run: sudo pip install uv\n",
        "run: sudo -E python -m pip install x\n",
        "run: sudo make security\n",
        "run: true && sudo bash -c 'curl x'\n",
        "run: sudo\n",
    ):
        assert sudo_problems(bad), bad
    assert sudo_problems("# sudo pip install x\n    # run: sudo make security\n") == []


def test_the_setup_action_needs_no_privilege() -> None:
    assert "sudo" not in _strip_all_comments(SETUP_ACTION.read_text(encoding="utf-8"))


# --- pinned toolchains and cross-platform reach ---------------------------------


def test_every_installed_tool_stays_pinned() -> None:
    """The fuzz toolchain (F-07's), cargo-deny, and every other `cargo
    install` and `rustup toolchain install`: an exact version, `--locked`."""
    assert re.fullmatch(r"nightly-\d{4}-\d{2}-\d{2}", dw.FUZZ_NIGHTLY)
    assert re.fullmatch(r"\d+\.\d+\.\d+", dw.CARGO_FUZZ_VERSION)
    toolchain = tomllib.loads((REPO_ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))
    assert re.fullmatch(r"\d+\.\d+\.\d+", toolchain["toolchain"]["channel"])
    installs = 0
    for path in dw.action_files():
        text = _strip_all_comments(path.read_text(encoding="utf-8"))
        for match in re.finditer(r"cargo install ([^\n]*)", text):
            installs += 1
            assert re.search(r"--version \d+\.\d+\.\d+\b", match.group(1)), match.group(0)
            assert "--locked" in match.group(1), match.group(0)
        for match in re.finditer(r"rustup toolchain install([^\n|]*)", text):
            assert re.fullmatch(r"( nightly-\d{4}-\d{2}-\d{2} --profile minimal)?", match.group(1))
    fuzz = (GITHUB / "workflows" / "fuzz.yml").read_text(encoding="utf-8")
    assert f"rustup toolchain install {dw.FUZZ_NIGHTLY} --profile minimal" in fuzz
    assert f"cargo install cargo-fuzz --version {dw.CARGO_FUZZ_VERSION} --locked" in fuzz
    assert installs >= 2


def test_the_hash_checked_install_runs_on_every_ci_platform() -> None:
    """The install step has no condition, runs in bash (on every hosted
    image), and the test matrix still covers all three platforms: the hosted
    run, not this test, is what shows each platform found its wheel."""
    text = SETUP_ACTION.read_text(encoding="utf-8")
    step = text[text.index("- name: Install uv") :]
    step = step[: step.index("\n    - name:")]
    assert "\n      if:" not in step
    ci = (GITHUB / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "os: [ubuntu-latest, windows-latest, macos-latest]" in ci
