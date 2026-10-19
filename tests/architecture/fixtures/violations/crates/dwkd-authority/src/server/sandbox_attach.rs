// VIOLATES TX053: the DWKP server attaching an execution environment
// outside `server/sandbox.rs`, the one reviewed place (ADR-0052 §2a).
fn attach_elsewhere(authority: &mut Authority, config: SandboxConfig) {
    let _ = authority.attach_sandbox(config);
}
