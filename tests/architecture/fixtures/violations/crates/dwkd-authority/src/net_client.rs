// VIOLATES TX044 and TX047: the authority as an HTTPS client -- a TLS stack,
// a resolution of its own and an outbound socket in the process that holds the
// keys and decides every hop.
use rustls::ClientConfig;

pub fn fetch(host: &str) -> std::io::Result<std::net::TcpStream> {
    let _ = ClientConfig::builder();
    let _ = (host, 443).to_socket_addrs();
    std::net::TcpStream::connect((host, 443))
}
