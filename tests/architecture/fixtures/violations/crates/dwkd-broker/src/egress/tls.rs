// VIOLATES TX038: an egress proxy that terminates TLS and injects a credential.
use rustls::ClientConfig;

pub fn inject(request: &mut Vec<u8>, token: &str) {
    request.extend_from_slice(format!("Authorization: Bearer {token}\r\n").as_bytes());
    let _ = ClientConfig::builder();
}
