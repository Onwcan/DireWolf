//! JSON: the value model, the strict lexer, and RFC 8785 canonicalisation.
//!
//! These three are the whole of the crate's JSON handling. There is no
//! general-purpose serializer and no "lenient" parse mode: every profile
//! enforces UTF-8, RFC 8259 grammar, the depth limit and key uniqueness under
//! NFC. Profiles differ only in which numbers they admit.

pub mod jcs;
pub mod lex;
pub mod number;
pub mod value;

pub use jcs::{to_canonical_bytes, to_canonical_string};
pub use lex::{NumberDomain, ParseOptions, parse};
pub use value::{Number, Object, Value};
