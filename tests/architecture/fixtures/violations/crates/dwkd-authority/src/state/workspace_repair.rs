// VIOLATES TX057: the authority repairing a workspace it should refuse.
fn repaired(root: &Root) {
    set_permissions(root, 0o777);
    fchown(root, None, Some(1000));
    mount("tmpfs", root);
    // Naming chmod in a comment is not a finding.
}
