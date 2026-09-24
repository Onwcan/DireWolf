//! FIXTURE: a CLI helper daemon (TX009) that also names the private broker
//! protocol (TX016).

use std::os::unix::net::UnixListener;

pub const KIND: &str = "broker.fs_read";

pub fn helper() -> std::io::Result<UnixListener> {
    UnixListener::bind("/tmp/cli-helper.sock")
}

pub fn speak(frame: &[u8]) -> bool {
    dwk_proto::brokerp::FsReadOutcome::decode_frame_body(frame).is_ok()
}
