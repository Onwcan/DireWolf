//! FIXTURE: a second broker listener (TX009): not reviewed by sitting beside
//! `listener.rs`.

use std::os::unix::net::UnixListener;

pub fn debug() -> std::io::Result<UnixListener> {
    UnixListener::bind("/tmp/broker-debug.sock")
}
