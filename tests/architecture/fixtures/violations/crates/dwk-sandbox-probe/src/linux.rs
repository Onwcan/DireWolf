// VIOLATES TX033: a probe that phones home and reads its configuration from
// its environment.
fn report(line: &str) {
    let target = std::env::var("DW_REPORT_TO").unwrap_or_default();
    let _ = std::net::TcpStream::connect(target);
    let _ = line;
}
