//! FIXTURE: the broker's one listener (TX009 exempts exactly this file). It
//! is not a finding; the listeners beside it are.

use std::os::unix::net::UnixListener;

pub fn open(path: &std::path::Path) -> std::io::Result<UnixListener> {
    UnixListener::bind(path)
}
