//! FIXTURE: the broker listening on TCP (TX009, TX013).

pub fn serve() -> std::io::Result<std::net::TcpListener> {
    std::net::TcpListener::bind("127.0.0.1:0")
}
