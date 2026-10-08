// VIOLATES TX046: the HTTPS client reading its surroundings -- a proxy
// variable, the host's trust store, a verifier override, a resolver of its
// own.
pub fn configure(config: &mut Config) {
    let _proxy = std::env::var("HTTPS_PROXY");
    let _roots = rustls_native_certs::load_native_certs();
    config.dangerous().set_certificate_verifier(accept_anything());
    let _ = ("api.example.com", 443).to_socket_addrs();
}
