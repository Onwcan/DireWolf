// VIOLATES TX059: the waiver spelled outside the operator's file.
fn waived(table: &Table) -> bool {
    table.get("unverified_evidence").is_some()
}
