// VIOLATES TX034: a profile that reads a file to decide its values.
pub fn pids_limit() -> u64 {
    std::fs::read_to_string("/etc/direwolf/pids").map_or(256, |t| t.trim().parse().unwrap_or(256))
}
