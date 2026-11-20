"""Code scanning #10-#13 (`py/insecure-protocol`): the evidence's two TLS
clients -- the agent's network tool (`agent_net.py`, run by an image's Python
inside an environment) and the registry origins' verifying client -- hold
their own floor at TLS 1.2.

Python 3.10 and later default to TLS 1.2; an older interpreter, or one whose
default was lowered, must not lower what these clients accept. So the test
gives them a default context that still offers TLS 1.0 and requires the
floor back.
"""

from __future__ import annotations

import importlib.util
import ssl
import sys
import warnings
from pathlib import Path
from types import ModuleType

import pytest

HERE = Path(__file__).resolve().parent


def _load(name: str, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """The module at `tests/sandbox/<name>.py`, loaded apart from its tests
    (registered while the test runs: its dataclasses look themselves up)."""
    spec = importlib.util.spec_from_file_location(f"tls_floor_{name}", HERE / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


def _offers_tls_1_0(*_args: object, **_kwargs: object) -> ssl.SSLContext:
    """A default client context as an interpreter before 3.10 made one."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        context.minimum_version = ssl.TLSVersion.TLSv1
    return context


@pytest.mark.parametrize(
    ("module", "helper", "cafile"),
    [
        ("agent_net", "_tls_context", "ca.pem"),
        ("test_registry_origins", "_verifying", Path("ca.pem")),
    ],
)
def test_an_evidence_tls_client_never_accepts_less_than_tls_1_2(
    monkeypatch: pytest.MonkeyPatch, module: str, helper: str, cafile: object
) -> None:
    loaded = _load(module, monkeypatch)
    monkeypatch.setattr(ssl, "create_default_context", _offers_tls_1_0)
    context = getattr(loaded, helper)(cafile)
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname
