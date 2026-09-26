//! FIXTURE: the one place the broker spawns -- its own binary as the launch
//! helper, with an empty environment (TX021 exempts this file by name). Not a
//! finding.

use std::process::{Command, Stdio};

pub fn helper(binary: &std::path::Path) -> std::io::Result<std::process::Child> {
    Command::new(binary)
        .arg("exec-helper")
        .env_clear()
        .stdin(Stdio::null())
        .spawn()
}
