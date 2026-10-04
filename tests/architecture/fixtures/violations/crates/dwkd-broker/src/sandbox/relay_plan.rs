// VIOLATES TX041: a relay plan that adds a second capability and runs the
// relay privileged with the host's network.
pub fn relay() -> Vec<&'static str> {
    vec!["create", "--cap-add", "SYS_ADMIN", "--privileged", "--network", "host"]
}
