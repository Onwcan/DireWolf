//! `dwk-proto` — the DireWolf wire contract.
//!
//! # What this crate is
//!
//! Wire types and protocol value objects, and nothing else: framing, a strict
//! JSON lexer, RFC 8785 canonical JSON, the common envelope, version
//! negotiation, the DWKP operation inventory, and the message types for the
//! three protocol families. It is the **single source of truth** for the wire
//! format: JSON Schema is emitted from these types, and Python bindings are
//! generated from that schema ([ADR-0033]).
//!
//! It also holds [`brokerp`], the private authority → broker protocol (M4b,
//! ADR-0043): the one other thing both daemons must agree on. It is not DWKP,
//! it is emitted into no schema and no binding, and the cognition side cannot
//! name it.
//!
//! # What this crate must never contain
//!
//! Policy evaluation, authorisation, capability decisions, approval matching,
//! budget arithmetic, secret lookup, filesystem, process or network access,
//! sandbox control, or orchestration. From M3 it is linked into
//! `dwkd-authority`, which makes its dependency closure part of the trusted
//! computing base; a `common` crate that accumulates behaviour is how the
//! authority/broker boundary of ADR-0018 would quietly collapse. `dwcheck`
//! rejects `std::fs`, `std::net`, `std::process`, `std::env`, `std::os` and
//! `unsafe` in this crate's sources (TX002), any in-tree dependency (RS009), and
//! any third-party dependency outside the authority allowlist (RS004, RS006).
//!
//! # What it guarantees, precisely
//!
//! A message that decodes successfully under the DWKP profile is **structurally
//! unambiguous**: well-framed, valid UTF-8, grammatical JSON with no duplicate
//! keys, within the depth and number limits,
//! with no unknown fields, a known operation, a supported version, and every
//! value inside its declared bounds.
//!
//! It does **not** mean the message is authorised, that its epoch is current,
//! that the peer may send it, or that anything it asks for should happen. Those
//! are decisions, and decisions belong to `dwkd-authority` (M3 onward). A
//! malformed message is a protocol error, never a policy denial.
//!
//! [ADR-0033]: ../../../docs/adr/0033-protocol-source-of-truth-and-tcb-dependencies.md

#![warn(clippy::pedantic)]
// A wire-contract crate exports its error type from many functions; documenting
// the same error on each would bury the documentation that matters.
#![allow(clippy::missing_errors_doc)]

pub mod brokerp;
pub mod dwcp;
pub mod dwkp;
pub mod envelope;
pub mod error;
pub mod events;
pub mod frame;
pub mod json;
pub mod limits;
pub mod schema;
pub mod version;
pub mod wire;

pub use error::{ErrorCode, ProtocolError, Violation};

// Dev-dependencies used only by integration tests; acknowledged here so the
// workspace `unused_crate_dependencies` lint stays meaningful for real
// dependencies.
#[cfg(test)]
use proptest as _;
#[cfg(test)]
use serde_json as _;
