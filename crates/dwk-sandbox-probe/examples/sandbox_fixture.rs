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
//!
//! M5b's egress evidence (ADR-0048) adds a workload's side of the network —
//! still a fixture, run only by `make sandbox-egress-evidence`, from an
//! image only that evidence builds:
//!
//! | argv | what |
//! |---|---|
//! | `egress-connect <host> <port> <sni> <bytes> [plain\|ech\|front\|hold]` | CONNECT through `169.254.7.1:8080`, then a `ClientHello` naming `sni` (`-`: none), then `bytes` more; print what came back |
//! | `egress-via-variable <host> <port>` | the same, to wherever `HTTPS_PROXY` points |
//! | `egress-direct <tcp\|udp> <ip> <port>` | one direct attempt, ignoring every proxy variable; print the errno |
//! | `egress-dns <ip>` | one DNS question over UDP and TCP; print what happened |
//! | `egress-raw` | raw, packet, ICMP and virtual sockets; print each errno |
//! | `egress-resolve <name>` | the C library's resolver, as a tool that ignores the proxy would use it |
//! | `egress-env` | print the proxy variables the process was given |
//! | `egress-listen <ip> <port>` | (a weakened topology's extra peer) accept and close, forever |
//! | `egress-dns-answer <ip>` | (a weakened topology's fake resolver) answer every question on `ip:53`, forever |

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
            version: ProbeReportVersion::new(2).unwrap_or_else(|| unreachable!("2 is in range")),
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
        if let Some(code) = super::egress::main(&args) {
            return code;
        }
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

/// The egress evidence's workload modes (M5b): what a process in a
/// `PROXY_ONLY` environment can and cannot do with the network.
#[cfg(target_os = "linux")]
mod egress {
    use std::io::{Read as _, Write as _};
    use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::process::ExitCode;
    use std::time::{Duration, Instant};

    use dwk_sandbox_profile::{PROXY_ADDRESS, PROXY_PORT, PROXY_VARIABLE_NAMES};
    use rustix::net::{AddressFamily, SendFlags, SocketType, ipproto, sendto, socket};

    const WAIT: Duration = Duration::from_secs(8);

    fn say(text: &str) -> ExitCode {
        println!("{text}");
        ExitCode::SUCCESS
    }

    /// An errno's name, for the ones the evidence distinguishes.
    fn name(code: i32) -> &'static str {
        match code {
            1 => "EPERM",
            11 => "EAGAIN",
            13 => "EACCES",
            22 => "EINVAL",
            93 => "EPROTONOSUPPORT",
            97 => "EAFNOSUPPORT",
            99 => "EADDRNOTAVAIL",
            101 => "ENETUNREACH",
            104 => "ECONNRESET",
            110 => "ETIMEDOUT",
            111 => "ECONNREFUSED",
            113 => "EHOSTUNREACH",
            115 => "EINPROGRESS",
            _ => "OTHER",
        }
    }

    fn io_errno(error: &std::io::Error) -> String {
        let code = error.raw_os_error().unwrap_or(0);
        format!("errno={code} name={}", name(code))
    }

    fn rustix_errno(errno: rustix::io::Errno) -> String {
        let code = errno.raw_os_error();
        format!("errno={code} name={}", name(code))
    }

    /// A `ClientHello` naming `server` (none for `None`), with ECH if asked.
    fn hello(server: Option<&str>, ech: bool) -> Vec<u8> {
        let mut extensions = Vec::new();
        let mut push = |kind: u16, data: &[u8]| {
            extensions.extend_from_slice(&kind.to_be_bytes());
            extensions.extend_from_slice(&u16::try_from(data.len()).unwrap_or(0).to_be_bytes());
            extensions.extend_from_slice(data);
        };
        push(0x000a, &[0x00, 0x02, 0x00, 0x1d]);
        if let Some(server) = server {
            let name = server.as_bytes();
            let mut entry = vec![0u8];
            entry.extend_from_slice(&u16::try_from(name.len()).unwrap_or(0).to_be_bytes());
            entry.extend_from_slice(name);
            let mut data = u16::try_from(entry.len())
                .unwrap_or(0)
                .to_be_bytes()
                .to_vec();
            data.extend_from_slice(&entry);
            push(0x0000, &data);
        }
        push(0x002b, &[0x02, 0x03, 0x04]);
        if ech {
            push(0xfe0d, &[0x00, 0x01, 0x02, 0x03]);
        }
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
        body.extend_from_slice(&u16::try_from(extensions.len()).unwrap_or(0).to_be_bytes());
        body.extend_from_slice(&extensions);
        let length = u32::try_from(body.len()).unwrap_or(0).to_be_bytes();
        let mut message = vec![1u8];
        message.extend_from_slice(length.get(1..).unwrap_or_default());
        message.extend_from_slice(&body);
        let mut record = vec![22u8, 0x03, 0x01];
        record.extend_from_slice(&u16::try_from(message.len()).unwrap_or(0).to_be_bytes());
        record.extend_from_slice(&message);
        record
    }

    /// The response head, up to its blank line, as text.
    fn head(stream: &mut TcpStream) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") && head.len() < 4096 {
            match stream.read(&mut byte) {
                Ok(1) => head.extend_from_slice(&byte),
                _ => break,
            }
        }
        String::from_utf8_lossy(&head).into_owned()
    }

    fn connect_via(
        proxy: SocketAddr,
        host: &str,
        port: &str,
        server: Option<&str>,
        bytes: usize,
        how: &str,
    ) -> ExitCode {
        let mut stream = match TcpStream::connect_timeout(&proxy, WAIT) {
            Ok(stream) => stream,
            Err(error) => return say(&format!("connect {}", io_errno(&error))),
        };
        let _ = stream.set_read_timeout(Some(WAIT));
        let _ = stream.set_write_timeout(Some(WAIT));
        let request = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
        if let Err(error) = stream.write_all(request.as_bytes()) {
            return say(&format!("request {}", io_errno(&error)));
        }
        let head = head(&mut stream);
        let status = head.lines().next().unwrap_or("").to_owned();
        let decision = head
            .lines()
            .find_map(|l| l.strip_prefix("X-DireWolf-Egress: "))
            .unwrap_or("-")
            .to_owned();
        if !status.starts_with("HTTP/1.1 200 ") {
            return say(&format!(
                "status={status:?} decision={decision} sent=0 received=0"
            ));
        }
        let mut first = match how {
            "plain" => b"GET / HTTP/1.1\r\nHost: plain\r\n\r\n".to_vec(),
            _ => hello(server, how == "ech"),
        };
        if how == "front" {
            // What TLS would hide: a request for another origin behind the
            // allowed name. Plain bytes here, so the origin can show it got
            // them — the proxy cannot tell them from ciphertext.
            first.extend_from_slice(b"GET / HTTP/1.1\r\nHost: fronted.example\r\n\r\n");
        }
        let mut sent = 0usize;
        let mut end = String::from("eof");
        if stream.write_all(&first).is_ok() {
            sent += first.len();
            let chunk = vec![b'u'; 4096];
            let mut left = bytes;
            while left > 0 {
                let n = left.min(chunk.len());
                match stream.write_all(chunk.get(..n).unwrap_or_default()) {
                    Ok(()) => {
                        sent += n;
                        left -= n;
                    }
                    Err(error) => {
                        end = format!("write-{}", name(error.raw_os_error().unwrap_or(0)));
                        break;
                    }
                }
            }
        }
        if how == "hold" {
            // Keep the tunnel open, sending nothing more: it holds its slot.
            std::thread::sleep(WAIT * 3);
            return say(&format!("status={status:?} decision={decision} held=true"));
        }
        let _ = stream.shutdown(Shutdown::Write);
        let mut received = 0usize;
        let mut buffer = [0u8; 16 * 1024];
        let started = Instant::now();
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => received += n,
                Err(error) => {
                    end = format!("read-{}", name(error.raw_os_error().unwrap_or(0)));
                    break;
                }
            }
            if started.elapsed() > WAIT * 2 {
                end = String::from("still-open");
                break;
            }
        }
        say(&format!(
            "status={status:?} decision={decision} sent={sent} received={received} end={end}"
        ))
    }

    fn direct(kind: &str, ip: &str, port: &str) -> ExitCode {
        let (Ok(ip), Ok(port)) = (ip.parse::<IpAddr>(), port.parse::<u16>()) else {
            return ExitCode::from(2);
        };
        let target = SocketAddr::new(ip, port);
        match kind {
            "tcp" => match TcpStream::connect_timeout(&target, WAIT) {
                Ok(_) => say("connected"),
                Err(error) => say(&io_errno(&error)),
            },
            "udp" => {
                let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                match UdpSocket::bind(bind).and_then(|s| s.send_to(b"direwolf", target)) {
                    Ok(_) => say("sent"),
                    Err(error) => say(&io_errno(&error)),
                }
            }
            _ => ExitCode::from(2),
        }
    }

    /// `A example.com`, recursion desired.
    const QUESTION: &[u8] = &[
        0x44, 0x57, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 7, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00, 0x01,
    ];

    fn dns(ip: &str) -> ExitCode {
        let Ok(ip) = ip.parse::<IpAddr>() else {
            return ExitCode::from(2);
        };
        let server = SocketAddr::new(ip, 53);
        let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let udp = match UdpSocket::bind(bind) {
            Err(error) => format!("udp-socket {}", io_errno(&error)),
            Ok(socket) => {
                let _ = socket.set_read_timeout(Some(Duration::from_secs(2)));
                match socket.send_to(QUESTION, server) {
                    Err(error) => format!("udp-send {}", io_errno(&error)),
                    Ok(_) => {
                        let mut answer = [0u8; 512];
                        match socket.recv(&mut answer) {
                            Ok(n) => format!("udp-answered bytes={n}"),
                            Err(error) => format!("udp-no-answer {}", io_errno(&error)),
                        }
                    }
                }
            }
        };
        let tcp = match TcpStream::connect_timeout(&server, WAIT) {
            Ok(_) => "tcp-connected".to_owned(),
            Err(error) => format!("tcp {}", io_errno(&error)),
        };
        say(&format!("{udp}; {tcp}"))
    }

    fn raw() -> ExitCode {
        let attempt = |family, kind, protocol| match socket(family, kind, protocol) {
            Ok(_) => "created".to_owned(),
            Err(errno) => rustix_errno(errno),
        };
        let raw4 = attempt(AddressFamily::INET, SocketType::RAW, Some(ipproto::ICMP));
        let raw6 = attempt(AddressFamily::INET6, SocketType::RAW, Some(ipproto::ICMPV6));
        let packet = attempt(AddressFamily::PACKET, SocketType::RAW, None);
        let vsock = attempt(AddressFamily::VSOCK, SocketType::STREAM, None);
        let ping = match socket(AddressFamily::INET, SocketType::DGRAM, Some(ipproto::ICMP)) {
            Err(errno) => format!("socket-{}", rustix_errno(errno)),
            Ok(fd) => {
                let echo = [8u8, 0, 0, 0, 0, 1, 0, 1];
                let target =
                    rustix::net::SocketAddrV4::new(rustix::net::Ipv4Addr::new(1, 1, 1, 1), 0);
                match sendto(&fd, &echo, SendFlags::empty(), &target) {
                    Ok(_) => "sent".to_owned(),
                    Err(errno) => format!("send-{}", rustix_errno(errno)),
                }
            }
        };
        say(&format!(
            "raw4: {raw4}; raw6: {raw6}; packet: {packet}; ping: {ping}; vsock: {vsock}"
        ))
    }

    fn resolve(host: &str) -> ExitCode {
        use std::net::ToSocketAddrs as _;
        match (host, 443u16).to_socket_addrs() {
            Ok(found) => say(&format!("resolved count={}", found.count())),
            Err(error) => say(&format!("unresolved kind={:?}", error.kind())),
        }
    }

    fn env() -> ExitCode {
        let mut found: Vec<String> = std::env::vars()
            .filter(|(name, _)| {
                PROXY_VARIABLE_NAMES
                    .iter()
                    .any(|n| n.eq_ignore_ascii_case(name))
            })
            .map(|(name, value)| format!("{name}={value}"))
            .collect();
        found.sort();
        say(&found.join("\n"))
    }

    fn listen(ip: &str, port: &str) -> ExitCode {
        let Ok(listener) = TcpListener::bind(format!("{ip}:{port}")) else {
            return say("bind-failed");
        };
        println!("listening");
        for stream in listener.incoming() {
            drop(stream);
        }
        ExitCode::SUCCESS
    }

    fn dns_answer(ip: &str) -> ExitCode {
        let Ok(udp) = UdpSocket::bind(format!("{ip}:53")) else {
            return say("bind-failed");
        };
        if let Ok(tcp) = TcpListener::bind(format!("{ip}:53")) {
            std::thread::spawn(move || {
                for stream in tcp.incoming() {
                    drop(stream);
                }
            });
        }
        println!("answering");
        let mut buffer = [0u8; 512];
        while let Ok((n, from)) = udp.recv_from(&mut buffer) {
            let mut answer = buffer.get(..n).unwrap_or_default().to_vec();
            if let Some(flags) = answer.get_mut(2) {
                *flags |= 0x80;
            }
            let _ = udp.send_to(&answer, from);
        }
        ExitCode::SUCCESS
    }

    /// The egress modes; `None` for any other argument.
    pub(super) fn main(args: &[String]) -> Option<ExitCode> {
        let arg = |n: usize| args.get(n).map_or("", String::as_str);
        let proxy = SocketAddr::from((PROXY_ADDRESS, PROXY_PORT));
        Some(match arg(1) {
            "egress-connect" => {
                let server = (arg(4) != "-").then(|| arg(4));
                let bytes = arg(5).parse().unwrap_or(0);
                let how = if arg(6).is_empty() { "tls" } else { arg(6) };
                connect_via(proxy, arg(2), arg(3), server, bytes, how)
            }
            "egress-via-variable" => {
                let Ok(url) = std::env::var("HTTPS_PROXY") else {
                    return Some(say("no-variable"));
                };
                let Some(Ok(proxy)) = url.strip_prefix("http://").map(str::parse::<SocketAddr>)
                else {
                    return Some(say("unparsable-variable"));
                };
                connect_via(proxy, arg(2), arg(3), Some(arg(2)), 0, "tls")
            }
            "egress-direct" => direct(arg(2), arg(3), arg(4)),
            "egress-dns" => dns(arg(2)),
            "egress-raw" => raw(),
            "egress-resolve" => resolve(arg(2)),
            "egress-env" => env(),
            "egress-listen" => listen(arg(2), arg(3)),
            "egress-dns-answer" => dns_answer(arg(2)),
            "egress-unix" => match std::os::unix::net::UnixStream::connect(arg(2)) {
                Ok(_) => say("connected"),
                Err(error) => say(&io_errno(&error)),
            },
            _ => return None,
        })
    }
}
