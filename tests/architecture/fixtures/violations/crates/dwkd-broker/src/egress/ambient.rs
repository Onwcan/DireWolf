// VIOLATES TX042: an environment given the broker's own proxy variable.
pub fn inherited() -> Option<String> {
    std::env::var("HTTPS_PROXY").ok()
}
