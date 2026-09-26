//! FIXTURE: the authority holding and signalling an operating-system process
//! (TX010). `process.kill` is the broker's, by opaque handle. This comment
//! says pidfd_send_signal and must not be a finding.

pub fn stop(child: &mut std::process::Child) -> bool {
    child.kill().is_ok()
}

pub fn stop_group(group: i32) -> bool {
    kill_process_group(group)
}

fn kill_process_group(_group: i32) -> bool {
    false
}
