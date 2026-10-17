# `direwolf` — the cognition runtime

The Python half of DireWolf that reasons: it proposes, and holds no authority.

**Trust: untrusted.** It holds no credentials, no network route, no
filesystem handles and no ability to execute anything; every side effect is a
request to `dwkd-authority` over DWKP, which decides independently
([docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) §5). It depends on no other
package, and `dwcheck deps` keeps it from depending on an agent framework, an
HTTP client, a process launcher or a socket library.

**What exists.** The protocol's Python side: the wire layer
(`direwolf.wire` — framing, strict JSON, JCS canonicalisation, envelope
validation) and the bindings generated from `schemas/` (`direwolf.proto`).
The agent loop (M9), the context engine (M11), memory, providers (M7) and the
kernel client are not built yet ([docs/ROADMAP.md](../docs/ROADMAP.md)).

The project, its status, and how to build and test it: the
[repository README](../README.md).
