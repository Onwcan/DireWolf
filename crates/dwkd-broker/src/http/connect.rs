//! The HTTPS client's one outbound dial (M5c, ADR-0050 §6): a TCP connection
//! to **a pinned address** — one the guard allowed, in the order the resolver
//! gave it — and nothing else. Never a name: there is no resolution here, and
//! nothing that could resolve (`TcpStream::connect` with a host is not called;
//! the address is a `SocketAddr` already). Never through a proxy: no
//! environment is read.
//!
//! One of the two files in the broker that may dial (TX037, as amended by
//! ADR-0050): this, and `egress/tunnel.rs`.

use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// Connect to the first of `pinned` that accepts, at `port`, before `until`.
/// Each address gets an equal share of the time left, so one that never
/// answers cannot spend the others' time.
///
/// `None` when none accepted in time: nothing was sent anywhere.
pub(crate) fn dial(pinned: &[IpAddr], port: u16, until: Instant) -> Option<TcpStream> {
    for (index, address) in pinned.iter().enumerate() {
        let now = Instant::now();
        if now >= until {
            return None;
        }
        let left = until - now;
        let remaining = u32::try_from(pinned.len().saturating_sub(index)).unwrap_or(u32::MAX);
        let share = left.checked_div(remaining.max(1)).unwrap_or(left);
        let share = share.max(Duration::from_millis(1));
        if let Ok(stream) = TcpStream::connect_timeout(&SocketAddr::new(*address, port), share) {
            let _ = stream.set_nodelay(true);
            return Some(stream);
        }
    }
    None
}
