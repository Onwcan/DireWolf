// VIOLATES TX056: the secret plan spelling a weakening beside its one word.
fn run(container: &str) -> Vec<String> {
    vec![
        "container".into(),
        "exec".into(),
        "--interactive".into(),
        "--user".into(),
        "0:0".into(),
        "--env".into(),
        "TOKEN=x".into(),
        "-e".into(),
        container.into(),
        "/bin/sh".into(),
    ]
}
