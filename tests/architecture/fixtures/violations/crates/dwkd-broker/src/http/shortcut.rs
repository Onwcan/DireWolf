// VIOLATES TX045: a credential header composed outside the render -- no
// refusal of CR or LF, no scrubbing, a copy in an ordinary String.
pub fn attach(request: &mut Vec<u8>, credential: &Credential, value: &str) {
    let prefix = credential.header_prefix.as_deref().unwrap_or("");
    request.extend_from_slice(format!("authorization: {prefix}{value}\r\n").as_bytes());
}
