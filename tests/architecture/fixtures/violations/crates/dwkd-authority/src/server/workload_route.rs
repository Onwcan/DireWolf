// VIOLATES TX035: the DWKP server reaching the workload API (M5d.1) -- a
// sandboxed process.exec arriving without its own reviewed public route.
fn serve_workload(authority: &mut Authority, run: &RunId, request: &WorkloadRequest) {
    let _ = authority.workload_run(run, request);
}
