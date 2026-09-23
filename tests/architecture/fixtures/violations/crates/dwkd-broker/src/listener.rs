//! FIXTURE: a second listener the runtime could reach (TX009). ADR-0018: the
//! runtime speaks to the authority, never to the broker.

use std::os::unix::net::UnixListener;

pub fn open() -> std::io::Result<UnixListener> {
    UnixListener::bind("/tmp/broker.sock")
}
