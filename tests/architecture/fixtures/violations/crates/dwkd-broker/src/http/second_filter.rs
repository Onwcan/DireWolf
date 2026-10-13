//! TX051 fixture: a second seccomp program, outside the reviewed module.
//! Never compiled: `dwcheck` reads it as text.

use seccompiler::apply_filter;

fn allow_everything() {
    let _ = libc::SYS_socket;
    let _ = SECCOMP_RET_ALLOW;
    let _ = apply_filter(&[]);
}

// A comment naming seccompiler is not a finding.
use libc as _;
