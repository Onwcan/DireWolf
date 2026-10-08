// VIOLATES TX035: the DWKP server reaching the net.http evidence's exception
// list -- a production loopback bypass.
fn serve_evidence(authority: &mut Authority) {
    let _ = authority.attach_net_evidence(Vec::new());
}
