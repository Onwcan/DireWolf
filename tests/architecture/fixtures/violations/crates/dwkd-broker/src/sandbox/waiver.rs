// VIOLATES TX059: the workspace waiver taken from somewhere but the command line.
fn waived(args: &[&str]) -> bool {
    args.contains(&"--allow-unverified-workspace")
}
