// VIOLATES TX040: a capability added outside the setup's plan.
pub fn relay_with_raw_sockets() -> Vec<&'static str> {
    vec!["create", "--cap-add", "NET_RAW"]
}
