// VIOLATES TX037: the broker dialling somewhere other than the tunnel -- a
// "direct" fallback that no grant, guard or server-name check stands before.
pub fn fallback(address: std::net::SocketAddr) -> std::io::Result<std::net::TcpStream> {
    std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_secs(1))
}
