//! FIXTURE: the descriptor audit, reading the broker's own procfs view (TX015
//! exempts this file by name). Not a finding.

pub fn open_descriptors() -> usize {
    std::fs::read_dir("/proc/self/fd").map_or(0, Iterator::count)
}
