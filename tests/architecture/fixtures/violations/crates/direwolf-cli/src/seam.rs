// VIOLATES TX054: the CLI serving an authority it built, and running a
// closure on it -- a second door beside the socket.
fn serve(authority: Authority, socket: &Path) -> Served {
    let served = serve_authority(authority, socket, policy(), 60_000).unwrap();
    served.operate(|authority| authority.operator()).unwrap();
    served
}
