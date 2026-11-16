//! FIXTURE: the approver endpoint holding an operation before M6 (TX065) --
//! reading what a peer sends, answering it, and dispatching it as a subject.

use std::io::Read;
pub fn serve(stream: &mut Stream, worker: &Worker, peer: Peer) {
    let _ = stream.read(&mut [0u8; 1]);
    let _ = stream.write_all(b"approved");
    let subject = AuthenticatedSubject::unix_uid(peer.uid);
    worker.dispatch(subject, message);
}
