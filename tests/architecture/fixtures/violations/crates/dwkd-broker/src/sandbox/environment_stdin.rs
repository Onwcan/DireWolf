// VIOLATES TX055: standard input attached outside the secret plan.
fn step(container: &str) -> Vec<String> {
    vec![
        "container".into(),
        "exec".into(),
        "--interactive".into(),
        "-i".into(),
        "-it".into(),
        container.into(),
    ]
}
