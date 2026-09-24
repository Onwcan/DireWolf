//! FIXTURE: a "debug" socket in the authority, outside the server (TX009).

use std::os::unix::net::UnixListener;

pub fn debug() -> std::io::Result<UnixListener> {
    UnixListener::bind("/tmp/authority-debug.sock")
}
