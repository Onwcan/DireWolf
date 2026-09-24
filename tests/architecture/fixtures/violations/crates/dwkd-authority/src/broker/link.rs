//! FIXTURE: the authority's end of the broker channel. TX008 and TX014
//! exempt exactly this file; it is not a finding.

pub fn send(stream: &std::os::unix::net::UnixStream, fd: std::os::fd::BorrowedFd<'_>) {
    let fds = [fd];
    let _ = rustix::net::SendAncillaryMessage::ScmRights(&fds);
    let _ = rustix::net::sendmsg(stream, &[], &mut rustix::net::SendAncillaryBuffer::default(), rustix::net::SendFlags::empty());
}
