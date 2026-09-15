"""DireWolf wire mechanics for the Python runtime.

Hand-written, standard library only, and deliberately small. Everything here is
**mechanism** that cannot be derived from a schema: framing, the strict JSON
reader, RFC 8785 canonicalisation, identifier and timestamp checks, and the
envelope decode order. The *content* of messages -- which fields exist, their
bounds, which envelope fields each operation permits -- is generated from
``schemas/`` into :mod:`direwolf.proto` and never written by hand.

The Rust crate ``dwk-proto`` is the source of truth and the enforcement point:
``dwkd-authority`` decodes every DWKP message it acts on. This package gives the
runtime the same strictness so malformed messages fail early on the untrusted
side too, and the shared vectors in ``tests/protocol/vectors`` prove the two
implementations agree. It is a parity implementation, not a security boundary:
the runtime is untrusted by design.

No networking and no I/O: framing operates on ``bytes``. The kernel client that
owns the socket arrives with its own milestone.
"""

from __future__ import annotations
