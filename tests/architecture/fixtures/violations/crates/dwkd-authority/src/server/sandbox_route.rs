// VIOLATES TX035: the DWKP server reaching the execution-environment API.
fn serve_environment(authority: &mut Authority, run: &RunId) {
    let _ = authority.environment_prepare(run);
}
