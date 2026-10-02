// VIOLATES TX032: a sandbox plan that spells a weakening -- a privileged,
// capability-adding container with an unconfined seccomp profile and the
// runtime's socket mounted.
fn create() -> Vec<&'static str> {
    vec![
        "create",
        "--privileged",
        "--cap-add",
        "SYS_ADMIN",
        "--security-opt",
        "seccomp=unconfined",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
    ]
}
