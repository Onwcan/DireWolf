// VIOLATES TX058: the workspace's modes spelled again.
const ROOT_MODE: u32 = 0o2770;
fn launch() {
    umask(0o007);
    umask(0o0007);
    // 0o2770 in a comment is not a finding.
}
