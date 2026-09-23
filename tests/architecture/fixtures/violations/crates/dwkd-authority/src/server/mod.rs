//! FIXTURE: a transport that stopped being an adapter (TX007). This comment
//! names std::net::TcpListener and crate::policy and must not be a finding.

use std::net::TcpListener;

use crate::policy::evaluate;

/// A "fallback" the transport must never have.
pub fn listen() -> Option<TcpListener> {
    TcpListener::bind("127.0.0.1:0").ok()
}

/// Fencing in the transport: the state layer's job, done badly in the wrong place.
pub fn stale(header: &Header, current: u64) -> bool {
    header.epoch.is_some_and(|epoch| epoch < current) && evaluate()
}
