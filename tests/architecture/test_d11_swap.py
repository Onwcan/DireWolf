"""D11 hardening's swap cases on a host with no swap device.

Some GitHub-hosted runners have no swap device: CI #176's D11 job (run
43656395503) ran on an AWS-hosted runner whose /proc/swaps was empty, and the
cases that need swap -- a hop refused on it, a hop and memory pressure under a
cgroup that caps it at zero -- could not be exercised, which fails the task.
On the disposable hosted job only, `make d11-hardening-evidence` gives such a
host a temporary swap file for those cases and removes it after them. What
these tests hold:

* the file is added only where `DW_D11_PRIVILEGED=1` provides sudo and the
  host reports no swap at all; a developer's machine, or a host with swap, is
  never changed;
* it is added with sudo alone, proved on (`SwapTotal` above zero), and
  removed -- switched off, deleted, proved gone -- whatever the cases did, and
  before the root-only cases run;
* a failure part-way is undone, and a file left behind fails the task.

Everything is faked: no sudo, no swap, no cargo.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import dw  # noqa: E402  - imported after the path is extended

SWAPS_HEADER = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"


class Host:
    """A runner as /proc and sudo show it: a swap device or none, and the
    temporary swap file's state."""

    def __init__(self, swap_kib: int = 0, fail: str | None = None) -> None:
        self.base = swap_kib
        self.fail = fail
        self.file = False
        self.on = False
        self.calls: list[tuple[str, ...]] = []
        self.ignore_swapoff = False
        self.ignore_swapon = False

    def read(self, path: str) -> str | None:
        if path == "/proc/meminfo":
            total = self.base + (dw.D11_SWAP_MIB * 1024 if self.on else 0)
            return f"MemTotal:       16000000 kB\nSwapTotal:      {total} kB\nSwapFree: 0 kB\n"
        if path == "/proc/swaps":
            line = f"{dw.D11_SWAP_FILE}\tfile\t131068\t0\t-2\n" if self.on else ""
            return SWAPS_HEADER + line
        return None

    def run(self, *command: str, cwd: Path | None = None) -> None:
        del cwd
        self.calls.append(command)
        assert command[:2] == ("sudo", "-n"), command
        program = command[2]
        if program == self.fail:
            raise dw.TaskError(f"`{' '.join(command)}` failed with exit code 1")
        if program == "dd":
            self.file = True
        elif program == "install":
            pass
        elif program == "swapon" and not self.ignore_swapon:
            self.on = True
        elif program == "swapoff" and not self.ignore_swapoff:
            self.on = False
        elif program == "rm":
            self.file = False

    def state(self) -> tuple[bool, bool]:
        """(the swap file is on, the swap file exists)."""
        return self.on, self.file

    def programs(self) -> list[str]:
        return [command[2] for command in self.calls]


@pytest.fixture
def host(monkeypatch: pytest.MonkeyPatch) -> Iterator[Host]:
    fake = Host()
    monkeypatch.setattr(dw, "_read", fake.read)
    monkeypatch.setattr(dw, "run", fake.run)
    monkeypatch.setattr(dw, "d11_privileged", lambda: True)
    yield fake


def test_swap_is_read_from_meminfo() -> None:
    assert dw.swap_total_kib("MemTotal: 1 kB\nSwapTotal:       0 kB\n") == 0
    assert dw.swap_total_kib("SwapTotal:  4194300 kB\nSwapFree: 1 kB\n") == 4194300
    assert dw.swap_total_kib("MemTotal: 1 kB\n") is None
    assert dw.swap_total_kib("SwapTotal: lots\n") is None


def test_a_hosted_runner_without_swap_gets_a_temporary_swap_file_and_loses_it(
    host: Host,
) -> None:
    assert dw.d11_provide_swap() is True
    assert host.programs() == ["install", "dd", "chmod", "mkswap", "swapon"]
    assert host.state() == (True, True)
    # A directory only root can enter, never a fixed name in a shared one.
    assert host.calls[0][-3:] == ("-m", "0700", dw.D11_SWAP_DIRECTORY)
    assert dw.D11_SWAP_FILE.startswith(dw.D11_SWAP_DIRECTORY + "/")
    shared = ("/tmp", "/var/tmp", "/dev/shm")  # noqa: S108 - where it must never be
    assert not dw.D11_SWAP_DIRECTORY.startswith(shared)
    assert f"of={dw.D11_SWAP_FILE}" in host.calls[1]
    assert host.calls[2] == ("sudo", "-n", "chmod", "0600", dw.D11_SWAP_FILE)
    dw.d11_remove_swap()
    assert host.programs()[5:] == ["swapoff", "rm"]
    assert host.calls[-1] == ("sudo", "-n", "rm", "-rf", dw.D11_SWAP_DIRECTORY)
    assert host.state() == (False, False)


def test_a_host_with_swap_or_a_developers_machine_is_never_changed(
    host: Host, monkeypatch: pytest.MonkeyPatch
) -> None:
    host.base = 4194300
    assert dw.d11_provide_swap() is False
    host.base = 0
    monkeypatch.setattr(dw, "d11_privileged", lambda: False)
    assert dw.d11_provide_swap() is False
    assert host.calls == []


@pytest.mark.parametrize("fails", ["install", "dd", "chmod", "mkswap", "swapon"])
def test_a_provision_that_fails_part_way_is_undone(host: Host, fails: str) -> None:
    host.fail = fails
    with pytest.raises(dw.TaskError, match="failed with exit code 1"):
        dw.d11_provide_swap()
    assert host.programs()[-1] == "rm" and host.state() == (False, False)


def test_a_swap_file_the_host_does_not_count_is_undone(host: Host) -> None:
    host.ignore_swapon = True
    with pytest.raises(dw.TaskError, match="the host reports no swap"):
        dw.d11_provide_swap()
    assert host.programs()[-1] == "rm"


def test_a_swap_file_left_on_fails_the_task(host: Host) -> None:
    assert dw.d11_provide_swap() is True
    host.ignore_swapoff = True
    with pytest.raises(dw.TaskError, match="is still there"):
        dw.d11_remove_swap()


@pytest.mark.parametrize("breaks", [None, "a_credential_hop_runs_under_a_real_no_swap_cap"])
def test_the_task_removes_the_swap_file_before_the_root_only_cases_whatever_happened(
    monkeypatch: pytest.MonkeyPatch, breaks: str | None
) -> None:
    events: list[str] = []
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(dw, "run", lambda *_command, **_options: None)
    monkeypatch.setattr(dw, "broker_unit_binary", lambda: "/target/debug/deps/dwkd_broker-x")
    monkeypatch.setattr(dw, "require_tests_ran", lambda _output: None)
    monkeypatch.setattr(dw, "no_swap_scope", lambda *_properties: ["systemd-run", "--"])
    monkeypatch.setattr(dw, "d11_privileged", lambda: True)

    def provide() -> bool:
        events.append("provide")
        return True

    monkeypatch.setattr(dw, "d11_provide_swap", provide)
    monkeypatch.setattr(dw, "d11_remove_swap", lambda: events.append("remove"))

    def privileged(_binary: str, _outputs: list[str]) -> list[str]:
        events.append("root-only cases")
        return []

    monkeypatch.setattr(dw, "d11_privileged_cases", privileged)

    def captured(*command: str, fresh_keyring: bool = False) -> str:
        del fresh_keyring
        name = command[-1].removeprefix(dw.HARDENING)
        events.append(name if "--ignored" in command else "suites")
        if name == breaks:
            raise dw.TaskError("NOT EXERCISED: this process's memory is not capped")
        return ""

    monkeypatch.setattr(dw, "run_captured", captured)
    with pytest.raises(dw.TaskError):
        dw.task_d11_hardening_evidence()
    swap_cases = [
        "on_a_host_with_swap_the_production_policy_refuses_a_credential_hop",
        "a_credential_hop_runs_under_a_real_no_swap_cap",
        "memory_pressure_under_the_cap_ends_in_the_oom_killer_never_in_swap",
    ]
    if breaks is None:
        assert events == ["suites", "provide", *swap_cases, "remove", "root-only cases"]
    else:
        assert events == ["suites", "provide", *swap_cases[:2], "remove"]


def test_the_hosted_job_is_the_only_privileged_one() -> None:
    ci = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    job = ci.split("\n  d11-hardening:\n")[1].split("\n\n  #")[0]
    assert "run: make d11-hardening-evidence" in job and 'DW_D11_PRIVILEGED: "1"' in job
    assert "cat /proc/swaps" in job  # the host's swap is shown before the task
    assert ci.count("DW_D11_PRIVILEGED:") == 1  # one job sets it
