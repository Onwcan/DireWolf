//! A **test fixture**, never the probe (M5a evidence, ADR-0047 §8): a static
//! program the sandbox evidence puts where the probe belongs, to show what
//! the broker and the authority do with a probe that is not the pinned one,
//! with one that is pinned but says nothing believable, and with ordinary
//! programs pushing against the environment's limits.
//!
//! It is an example target: built only by `make sandbox-foundation-evidence`,
//! carried only in its test images, and never linked into or shipped as
//! anything. Its behaviour is chosen by its arguments and, for `measure`, by
//! the image's `DW_FIXTURE` variable:
//!
//! | argv | what |
//! |---|---|
//! | `hold`, `ptrace-target` | what the probe does: wait |
//! | `measure …` with `DW_FIXTURE=malformed` | print something that is not a report |
//! | `measure …` with `DW_FIXTURE=truncated` | print half of a report that would pass |
//! | `measure …` with `DW_FIXTURE=extra-field` | print a passing report with one member too many |
//! | `measure …` with `DW_FIXTURE=flood` | print far more than any report may be |
//! | `measure …` with `DW_FIXTURE=hang` | print nothing, and never exit |
//! | `pids` | start threads until the environment refuses one; print how many |
//! | `fds` | open descriptors until the limit refuses one; print how many |
//! | `memory` | touch memory in 64 MiB steps up to 4 GiB; the ceiling ends it |
//! | `fsize <path>` | write to `path` in 1 MiB steps up to 2 GiB; the file-size limit ends it |
//! | `spawn` | start a child process and a thread, and wait for both |
//! | `events` | print the cgroup's `memory.events` (how many OOM kills) |
//! | `status` | print its own `/proc/self/status`, for diagnosis |
//! | `mark <path>` | create `path` holding a marker |
//! | `list <dir>` | print the names `dir` holds, one per line |
//! | `child` | exit 0 |

// The probe crate's other dependencies, which the fixture does not use.
#[cfg(not(target_os = "linux"))]
use dwk_proto as _;
use dwk_sandbox_profile as _;
#[cfg(target_os = "linux")]
use linux_keyutils as _;
#[cfg(target_os = "linux")]
use nix as _;
#[cfg(target_os = "linux")]
use rustix as _;

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::main()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("sandbox_fixture: a Linux sandbox test fixture");
    std::process::ExitCode::from(2)
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::Write as _;
    use std::process::ExitCode;
    use std::time::Duration;

    use dwk_proto::brokerp::KernelNumber;
    use dwk_proto::brokerp::sandbox::{
        InvariantCheck, InvariantChecks, ProbeReport, ProbeReportKind, ProbeReportVersion, Verdict,
        probe_invariants,
    };

    fn out(bytes: &[u8]) -> ExitCode {
        let mut stdout = std::io::stdout().lock();
        if stdout
            .write_all(bytes)
            .and_then(|()| stdout.flush())
            .is_ok()
        {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(3)
        }
    }

    fn wait_forever() -> ExitCode {
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    /// The bytes of a report that would pass every container invariant.
    fn passing_report() -> Vec<u8> {
        let checks = probe_invariants()
            .into_iter()
            .map(|invariant| InvariantCheck {
                invariant,
                verdict: Verdict::Pass,
            })
            .collect();
        let report = ProbeReport {
            kind: ProbeReportKind::Report,
            version: ProbeReportVersion::new(1).unwrap_or_else(|| unreachable!("1 is in range")),
            checks: InvariantChecks::new(checks).unwrap_or_else(|| unreachable!("bounded")),
            workspace_device: Some(KernelNumber::from_u64(0)),
            workspace_inode: Some(KernelNumber::from_u64(0)),
        };
        report.to_bytes().unwrap_or_default()
    }

    fn measure() -> ExitCode {
        match std::env::var("DW_FIXTURE").as_deref() {
            Ok("malformed") => out(b"this is not a report\n"),
            Ok("truncated") => {
                let report = passing_report();
                out(report.get(..report.len() >> 1).unwrap_or_default())
            }
            Ok("extra-field") => {
                let report = String::from_utf8(passing_report()).unwrap_or_default();
                out(report
                    .replacen('{', "{\"note\":\"trust me\",", 1)
                    .as_bytes())
            }
            Ok("flood") => {
                let line = [b'x'; 4096];
                for _ in 0..512 {
                    if std::io::stdout().write_all(&line).is_err() {
                        return ExitCode::from(3);
                    }
                }
                ExitCode::SUCCESS
            }
            Ok("hang") => wait_forever(),
            _ => out(b"fixture\n"),
        }
    }

    fn pids() -> ExitCode {
        let mut started = 0u32;
        let mut refused = String::from("none");
        for _ in 0..4096 {
            match std::thread::Builder::new()
                .stack_size(64 * 1024)
                .spawn(|| std::thread::sleep(Duration::from_secs(20)))
            {
                Ok(_) => started += 1,
                Err(error) => {
                    refused = format!("{:?}", error.raw_os_error());
                    break;
                }
            }
        }
        out(format!("threads={started} refused={refused}\n").as_bytes())
    }

    fn fds() -> ExitCode {
        let mut held = Vec::new();
        let mut refused = String::from("none");
        for _ in 0..65_536 {
            match std::fs::File::open("/dev/null") {
                Ok(file) => held.push(file),
                Err(error) => {
                    refused = format!("{:?}", error.raw_os_error());
                    break;
                }
            }
        }
        out(format!("opened={} refused={refused}\n", held.len()).as_bytes())
    }

    fn memory() -> ExitCode {
        const STEP: usize = 64 << 20;
        let mut held: Vec<Vec<u8>> = Vec::new();
        for step in 1..=64 {
            let mut chunk = vec![0u8; STEP];
            // Touch every page so the memory is really charged.
            for page in chunk.chunks_mut(4096) {
                if let Some(first) = page.first_mut() {
                    *first = 1;
                }
            }
            held.push(chunk);
            let _ = out(format!("allocated_mib={}\n", step * 64).as_bytes());
        }
        out(b"memory=unbounded\n")
    }

    fn fsize(path: &str) -> ExitCode {
        let Ok(mut file) = std::fs::File::create(path) else {
            return out(b"fsize=cannot-create\n");
        };
        let chunk = vec![0u8; 1 << 20];
        let mut written = 0usize;
        for _ in 0..2048 {
            match file.write_all(&chunk) {
                Ok(()) => written += chunk.len(),
                Err(error) => {
                    return out(
                        format!("written={written} refused={:?}\n", error.raw_os_error())
                            .as_bytes(),
                    );
                }
            }
        }
        out(format!("written={written} refused=none\n").as_bytes())
    }

    fn spawn() -> ExitCode {
        let Ok(me) = std::env::current_exe() else {
            return out(b"spawn=no-exe\n");
        };
        let child = std::process::Command::new(me)
            .arg("child")
            .env_clear()
            .status()
            .map_or_else(
                |e| format!("error:{:?}", e.raw_os_error()),
                |s| format!("{s}"),
            );
        let thread = std::thread::spawn(|| 7u8)
            .join()
            .map_or_else(|_| "panicked".to_owned(), |v| v.to_string());
        out(format!("child={child} thread={thread}\n").as_bytes())
    }

    pub(super) fn main() -> ExitCode {
        let args: Vec<String> = std::env::args().collect();
        match args.get(1).map(String::as_str) {
            Some("hold" | "ptrace-target") => wait_forever(),
            Some("measure") => measure(),
            Some("pids") => pids(),
            Some("fds") => fds(),
            Some("memory") => memory(),
            Some("fsize") => fsize(args.get(2).map_or("/workspace/fsize", String::as_str)),
            Some("spawn") => spawn(),
            Some("mark") => match args.get(2) {
                Some(path) => match std::fs::write(path, b"marker") {
                    Ok(()) => out(b"marked\n"),
                    Err(_) => ExitCode::from(4),
                },
                None => ExitCode::from(2),
            },
            Some("list") => {
                let mut names = String::new();
                if let Ok(entries) = std::fs::read_dir(args.get(2).map_or("/tmp", String::as_str)) {
                    for entry in entries.flatten() {
                        names.push_str(&entry.file_name().to_string_lossy());
                        names.push('\n');
                    }
                }
                out(names.as_bytes())
            }
            Some("status") => out(&std::fs::read("/proc/self/status").unwrap_or_default()),
            Some("events") => {
                out(&std::fs::read("/sys/fs/cgroup/memory.events").unwrap_or_default())
            }
            Some("child") => ExitCode::SUCCESS,
            _ => ExitCode::from(2),
        }
    }
}
