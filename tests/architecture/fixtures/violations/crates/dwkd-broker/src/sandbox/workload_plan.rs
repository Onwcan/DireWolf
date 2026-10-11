// VIOLATES TX050: a workload's command line that spells a weakening -- as
// root, privileged, with a variable the caller chose, attached to a terminal.
fn run(container: &str, value: &str) -> Vec<String> {
    vec![
        "container".into(),
        "exec".into(),
        "--user".into(),
        "0:0".into(),
        "--privileged".into(),
        "--env".into(),
        format!("TOKEN={value}"),
        "-it".into(),
        container.into(),
    ]
}
