# ADR-0002: Provider adapters shape requests; the kernel performs them

**Status:** **Superseded by [ADR-0020](0020-provider-request-path-v2.md)** · **Date:** 2026-09-11

> **SUPERSEDED by [ADR-0020](0020-provider-request-path-v2.md).** The `HttpRequestSpec` design below made `model.call` a transitive unpoliced network channel (Phase 0 review H1). The runtime now supplies a typed `ModelCall`; the kernel renders the request from a declarative provider profile. Retained as a historical record.

## Context

Model providers differ in tool-calling format, streaming, structured output, caching, token accounting, reasoning controls and error semantics. The naive abstraction — a `chat()` method per provider — leaks provider concepts into the loop and makes the credential-holding component the runtime.

## Decision

Split the provider concern in two:

- **Provider adapters (runtime, Python)** build an `HttpRequestSpec` and parse responses into `CanonicalDelta`. They hold **no credential and open no socket**.
- **Model egress (kernel, Rust)** validates the upstream against policy and privacy class, injects the credential, performs the HTTPS call, meters usage via a declarative JSON-pointer extractor, debits the budget, audits, and relays the stream.

The loop speaks only `CanonicalRequest` / `CanonicalDelta`. Provider differences are absorbed by **capability negotiation with declared degradation strategies**, not by try/except.

`grep -rniE 'anthropic|openai|ollama|gemini' runtime/direwolf --exclude-dir=providers` must return nothing. CI enforces it.

## Consequences

Budget enforcement becomes structural — there is no unmetered path, because the runtime cannot make a model call at all. Privacy-class enforcement lands at the credential. Adding a provider is one adapter file plus a TOML profile with usage pointers, and the kernel stays generic.

Cost: streaming is relayed rather than direct, adding a small latency hop. Provider-specific response quirks must be expressible as JSON pointers, or the provider needs a small kernel-side profile extension.

A model that cannot do native tool use is declared **ineligible for tool-bearing runs** rather than shimmed with XML parsing. Fail closed, not "parse and hope."

## Alternatives considered

- **SDK per provider in the runtime.** Simplest, and the credential lands in the untrusted plane. Rejected — this is the whole point.
- **LiteLLM or similar unified gateway.** Framework capture; an extra trust boundary we do not control; and it would still hold credentials in the runtime.
- **Kernel builds requests too.** Would put provider-format churn inside the TCB. Rejected.

