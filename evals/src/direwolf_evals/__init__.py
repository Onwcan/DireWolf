"""DireWolf evaluation harness.

M2.5 builds the machinery that later milestones must satisfy. It measures named
properties of the code that exists, and says **PENDING** — never PASS — about
properties whose implementation does not exist yet.

What this package may claim:

* suites are discovered and run deterministically;
* hostile protocol inputs are decided by the real decoder and counted;
* a known-bad result fails the gate;
* replay is byte-deterministic and fixture-integrity is checked;
* the fault-injection harness controls a dummy process.

What it may not claim: anything about authority, policy, capabilities,
approvals, sandboxing, secrets or model egress. Those systems do not exist, and
their suites are declared pending with the milestone that owns them.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.0.0"
