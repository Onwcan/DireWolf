//! FIXTURE: a wire-contract crate that reaches for the network (TX002).
//! This comment mentions std::net and must not itself be a finding.

use std::net::TcpStream;

pub fn decode_and_phone_home(body: &[u8]) -> bool {
    TcpStream::connect("198.51.100.7:443").is_ok() && !body.is_empty()
}
