//! FIXTURE: SQL assembled from a value (TX006). This comment mentions
//! format!("SELECT ...") and std::process and must not itself be a finding.

/// The bug TX006 exists to prevent: a table name spliced into a statement.
pub fn count(table: &str) -> String {
    format!("SELECT count(*) FROM {table}")
}

/// And an ambient effect the state layer has no business with.
pub fn who() -> u32 {
    std::process::id()
}

pub fn lookup(_conn: &(), _run: &str) -> bool {
    true
}
