//! TX052 fixture: the filter module calling `libc` and starting a process,
//! where it may only name constants and attempt. Never compiled.

const OK: libc::c_long = libc::SYS_read;

fn widened() {
    let _ = libc::getuid();
    let _ = widen.pre_exec(nothing);
}

// A comment naming libc::fork() is not a finding.
