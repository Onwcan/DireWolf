"""SR-06: a bind mount inside a workspace, on the real kernel.

**A real mount, or nothing.** The authority's resolver refuses a mount
crossing with `RESOLVE_NO_XDEV` (ADR-0042). Its unit suite shows that on the
host's own mounts; a bind mount inside a workspace -- the same filesystem
seen through a second mount -- needs a mount namespace, which the authority's
`src/` may not start a process to make (TX010). So the case is an integration
test's: `a_bind_mount_inside_a_workspace_is_never_crossed` starts itself in a
user and mount namespace of its own, bind-mounts a directory from outside the
workspace into it, and resolves through the production path.

**Counted only when it ran.** Where no such namespace can be made it reports
the case NOT EXERCISED; `make namespace-evidence`, which the hosted
`sandbox-egress` job runs after lifting Ubuntu's restriction, refuses that and
requires the case line, which the test prints only after the namespace
child's every assertion held.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
AUTHORITY = REPO_ROOT / "crates" / "dwkd-authority"
WORKSPACE_TESTS = AUTHORITY / "tests" / "resource_workspace.rs"
RESOLVER_TESTS = AUTHORITY / "src" / "resource" / "fs" / "linux" / "tests.rs"
CASE = "bind-mount-inside-workspace"

sys.path.insert(0, str(REPO_ROOT / "scripts"))

import dw  # noqa: E402  - imported after the path is extended


def _read(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def _function(source: str, name: str) -> str:
    start = source.index(f"fn {name}(")
    end = source.find("\n    }\n", start)
    return source[start : end + 6]


def test_the_case_is_the_integration_tests_alone() -> None:
    tests = _read(WORKSPACE_TESTS)
    assert "fn a_bind_mount_inside_a_workspace_is_never_crossed()" in tests
    assert f'const BIND_CASE: &str = "{CASE}";' in tests
    assert '\\"case\\":\\"{BIND_CASE}\\"' in tests
    # The resolver's unit suite no longer reports the case at all: one test
    # reports it, so an exercised line and a placeholder never meet.
    assert CASE not in _read(RESOLVER_TESTS).replace(f"`{CASE}`", "")
    # Still environmental for the filesystem evidence, which runs where the
    # namespaces are restricted.
    assert CASE in dw.FS_ENVIRONMENTAL


def test_the_child_asserts_before_it_says_so_and_the_parent_before_the_case_line() -> None:
    tests = _read(WORKSPACE_TESTS)
    child = _function(tests, "bind_mount_in_the_namespace")
    held = child.index('println!("{BIND_HELD}");')
    for assertion in (
        "assert!(same_device",
        'assert_eq!(resolve("/workspace/mnt/secret"), crossing);',
        'assert_eq!(resolve("/workspace/mnt"), crossing);',
        'assert_eq!(resolve("/workspace/src/main.rs"), None);',
    ):
        assert child.index(assertion) < held, assertion
    assert '.arg("--bind")' in child
    parent = _function(tests, "a_bind_mount_inside_a_workspace_is_never_crossed")
    line = parent.index('mount_evidence("refused:MOUNT_CROSSING", 1);')
    assert parent.index("assert!(\n            output.status.success(),") < line
    assert parent.index("assert!(text.contains(BIND_HELD)") < line
    # The namespaces are the broker's full-filesystem test's: no shell, a
    # private propagation, the test binary itself started again by name.
    assert '"--propagation",\n        "private",' in tests
    assert '"sh"' not in parent and '"-c"' not in parent


def test_the_task_requires_it_beside_the_broker_tests() -> None:
    ((binary, test, markers),) = dw.AUTHORITY_NAMESPACE_EVIDENCE
    assert binary == "resource_workspace"
    assert test == "linux::a_bind_mount_inside_a_workspace_is_never_crossed"
    assert markers == (
        'FS-EVIDENCE {"category":"mount-crossing","case":"bind-mount-inside-workspace",'
        '"outcome":"refused:MOUNT_CROSSING","count":1}',
    )
    # The broker's four tests and nine markers are as they were.
    assert len(dw.NAMESPACE_EVIDENCE) == 4
    assert sum(len(m) for _, m in dw.NAMESPACE_EVIDENCE) == 9


def _ran(*markers: str) -> str:
    lines = [f"test {m} ... {m}" for m in markers]
    return "\n".join([*lines, "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured"])


def test_the_task_runs_each_test_alone_and_counts_all_of_them(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[tuple[str, ...]] = []
    outputs = {t: _ran(*m) for t, m in dw.NAMESPACE_EVIDENCE}
    outputs.update({t: _ran(*m) for _, t, m in dw.AUTHORITY_NAMESPACE_EVIDENCE})

    def run_captured(*command: str) -> str:
        calls.append(command)
        return outputs[command[-1]]

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(dw, "run_captured", run_captured)
    dw.task_namespace_evidence()
    assert "namespace evidence: 5 tests, 10 markers, each exercised" in capsys.readouterr().out
    authority = [c for c in calls if "dwkd-authority" in c]
    assert authority == [
        (
            "cargo", "test", "--locked", "-p", "dwkd-authority", "--test", "resource_workspace",
            "--", "--exact", "--nocapture", "--test-threads=1",
            "linux::a_bind_mount_inside_a_workspace_is_never_crossed",
        )
    ]  # fmt: skip
    assert len(calls) == 5
    assert all(c[-4:-1] == ("--exact", "--nocapture", "--test-threads=1") for c in calls)


@pytest.mark.parametrize(
    ("output", "why"),
    [
        # The test could not make its namespaces.
        (
            "NOT EXERCISED: no unprivileged user and mount namespace here\n"
            'FS-EVIDENCE {"category":"mount-crossing","case":"bind-mount-inside-workspace",'
            '"outcome":"not-exercised:needs-mount-privileges","count":0}\n'
            "test result: ok. 1 passed; 0 failed; 0 ignored",
            "NOT EXERCISED",
        ),
        # It passed, and printed no case line: no evidence.
        ("test result: ok. 1 passed; 0 failed; 0 ignored", "did not report"),
        # The wrong outcome is not the marker.
        (
            'FS-EVIDENCE {"category":"mount-crossing","case":"bind-mount-inside-workspace",'
            '"outcome":"resolved","count":1}\ntest result: ok. 1 passed; 0 failed; 0 ignored',
            "did not report",
        ),
        # The filter selected nothing (a renamed test), or the test failed.
        ("test result: ok. 0 passed; 0 failed; 0 ignored", "did not run"),
        ("test result: FAILED. 0 passed; 1 failed; 0 ignored", "did not run"),
        # Nothing at all.
        ("", "did not run"),
    ],
)
def test_anything_but_the_real_case_fails_the_task(output: str, why: str) -> None:
    ((_, test, markers),) = dw.AUTHORITY_NAMESPACE_EVIDENCE
    with pytest.raises(dw.TaskError, match=why):
        dw.require_namespace_evidence(output, test, markers)
    dw.require_namespace_evidence(_ran(*markers), test, markers)


def test_the_egress_job_names_the_case_it_now_lifts_the_restriction_for() -> None:
    ci = _read(REPO_ROOT / ".github" / "workflows" / "ci.yml")
    job = ci[ci.index("\n  sandbox-egress:\n") :]
    job = job[: job.index("\n  sandbox-workload:\n")]
    assert "- name: Let a test have a namespace of its own (F-04, F-05, F-16, SR-06)" in job
    assert job.count("- run: make namespace-evidence\n") == 1
