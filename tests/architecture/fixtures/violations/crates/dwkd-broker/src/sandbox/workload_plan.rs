// VIOLATES TX050: a workload's command line that spells a weakening -- as
// root, privileged, with variables, attached to a terminal, through `env`.
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
        "/usr/bin/env".into(),
        "GIT_CONFIG_NOSYSTEM=0".into(),
    ]
}
