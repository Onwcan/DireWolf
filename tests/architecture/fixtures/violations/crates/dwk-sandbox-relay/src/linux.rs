// VIOLATES TX039: a relay that parses what it carries and decides on it.
pub fn allowed(first_line: &str) -> bool {
    first_line.starts_with("CONNECT ") && !first_line.contains("evil")
}
