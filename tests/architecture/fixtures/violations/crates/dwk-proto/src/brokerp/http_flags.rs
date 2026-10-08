// VIOLATES TX036: a net.http hop on the private wire that chooses the
// client's configuration -- whether TLS verifies, what it trusts, which name
// the certificate must hold, whether redirects are followed.
wire_struct! {
    HttpExchangeAuthorisation: reject {
        required tls_verify: bool,
        optional trust_roots: PemList,
        optional sni_override: EgressHost,
        required follow_redirects: bool,
    }
}
