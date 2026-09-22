//! FIXTURE: a policy engine that looks things up in kernel.db (TX005). This
//! comment names rusqlite and crate::state and must not itself be a finding.

use rusqlite::Connection;

/// The bug TX005 exists to prevent: a rule's outcome decided by a table the
/// policy engine reads for itself, instead of by the context it was handed.
pub fn is_trusted(conn: &Connection, run: &str) -> bool {
    crate::state::lookup(conn, run)
}
