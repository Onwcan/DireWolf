//! The relay, on Linux.

use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use dwk_sandbox_profile::{
    EGRESS_SOCKET_NAME, EGRESS_TARGET, PROXY_ADDRESS, PROXY_PORT, RELAY_MAX_CONNECTIONS,
    RELAY_SERVE, RELAY_SETUP,
};
use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketType, netlink, recv, sendto, socket};

pub(crate) fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match (args.get(1).map(String::as_str), args.len()) {
        (Some(RELAY_SETUP), 2) => setup(),
        (Some(RELAY_SERVE), 2) => serve(),
        _ => {
            eprintln!("usage: dwk-sandbox-relay setup | serve");
            ExitCode::from(2)
        }
    }
}

// ---------------------------------------------------------------------------
// setup: one netlink request.
// ---------------------------------------------------------------------------

/// `RTM_NEWADDR`.
const RTM_NEWADDR: u16 = 20;
/// `NLMSG_ERROR`: the kernel's acknowledgement, error 0 meaning success.
const NLMSG_ERROR: u16 = 2;
/// `NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE`.
const FLAGS: u16 = 0x1 | 0x4 | 0x200 | 0x400;
/// `AF_INET`.
const AF_INET: u8 = 2;
/// `RT_SCOPE_HOST`: the address is for this namespace only.
const RT_SCOPE_HOST: u8 = 254;
/// `IFA_ADDRESS` and `IFA_LOCAL`.
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
/// `EEXIST`: the address is already there — a setup run twice.
const EEXIST: i32 = 17;

/// The `RTM_NEWADDR` request for `PROXY_ADDRESS/32` on interface `index`.
fn request(index: u32) -> Vec<u8> {
    let mut message = Vec::with_capacity(40);
    message.extend_from_slice(&40u32.to_ne_bytes());
    message.extend_from_slice(&RTM_NEWADDR.to_ne_bytes());
    message.extend_from_slice(&FLAGS.to_ne_bytes());
    message.extend_from_slice(&1u32.to_ne_bytes()); // sequence
    message.extend_from_slice(&0u32.to_ne_bytes()); // port id: the kernel's
    message.extend_from_slice(&[AF_INET, 32, 0, RT_SCOPE_HOST]);
    message.extend_from_slice(&index.to_ne_bytes());
    for kind in [IFA_LOCAL, IFA_ADDRESS] {
        message.extend_from_slice(&8u16.to_ne_bytes());
        message.extend_from_slice(&kind.to_ne_bytes());
        message.extend_from_slice(&PROXY_ADDRESS);
    }
    message
}

/// The kernel's answer: `Some(errno)` from an `NLMSG_ERROR` (0 is success),
/// `None` for anything else.
fn acknowledgement(reply: &[u8]) -> Option<i32> {
    let kind = u16::from_ne_bytes(reply.get(4..6)?.try_into().ok()?);
    if kind != NLMSG_ERROR {
        return None;
    }
    let error = i32::from_ne_bytes(reply.get(16..20)?.try_into().ok()?);
    error.checked_neg()
}

/// Add the proxy address to this namespace's loopback.
fn setup() -> ExitCode {
    // NETLINK_ROUTE is protocol 0, which rustix spells `None`.
    let Ok(route) = socket(AddressFamily::NETLINK, SocketType::RAW, None) else {
        return ExitCode::from(3);
    };
    let index = socket(AddressFamily::INET, SocketType::DGRAM, None)
        .ok()
        .and_then(|probe| rustix::net::netdevice::name_to_index(&probe, "lo").ok());
    let Some(index) = index else {
        return ExitCode::from(3);
    };
    let kernel = netlink::SocketAddrNetlink::new(0, 0);
    if sendto(&route, &request(index), SendFlags::empty(), &kernel).is_err() {
        return ExitCode::from(3);
    }
    let mut reply = [0u8; 512];
    let Ok((read, _)) = recv(&route, &mut reply, RecvFlags::empty()) else {
        return ExitCode::from(3);
    };
    match acknowledgement(reply.get(..read).unwrap_or_default()) {
        Some(0 | EEXIST) => ExitCode::SUCCESS,
        _ => ExitCode::from(4),
    }
}

// ---------------------------------------------------------------------------
// serve: a byte pump, bounded.
// ---------------------------------------------------------------------------

/// Copy `from` into `to` until `from` ends. A clean end (the peer closed its
/// sending side) is passed on as exactly that — `half_close` ends only the
/// writing side of `to`, so a client that sends its request and then waits
/// still gets the answer; a failure ends both connections, both ways, so no
/// thread waits on a dead one. The broker's deadlines bound how long a
/// half-closed tunnel can stay open.
fn pump(
    mut from: impl std::io::Read,
    mut to: impl std::io::Write,
    half_close: &dyn Fn(),
    end: &dyn Fn(),
) {
    let mut chunk = [0u8; 16 * 1024];
    loop {
        match from.read(&mut chunk) {
            Ok(0) => return half_close(),
            Err(_) => return end(),
            Ok(n) => {
                let Some(bytes) = chunk.get(..n) else {
                    return end();
                };
                if to.write_all(bytes).is_err() {
                    return end();
                }
            }
        }
    }
}

fn forward(client: TcpStream, upstream: &str) {
    let Ok(broker) = UnixStream::connect(upstream) else {
        let _ = client.shutdown(Shutdown::Both);
        return;
    };
    let (Ok(client_read), Ok(broker_write)) = (client.try_clone(), broker.try_clone()) else {
        let _ = client.shutdown(Shutdown::Both);
        return;
    };
    let ends = {
        let (client, broker) = (client.try_clone(), broker.try_clone());
        move || {
            if let Ok(c) = &client {
                let _ = c.shutdown(Shutdown::Both);
            }
            if let Ok(b) = &broker {
                let _ = b.shutdown(Shutdown::Both);
            }
        }
    };
    let ends = Arc::new(ends);
    let up = {
        let ends = Arc::clone(&ends);
        let broker_half = broker.try_clone();
        std::thread::spawn(move || {
            pump(
                client_read,
                broker_write,
                &|| {
                    if let Ok(b) = &broker_half {
                        let _ = b.shutdown(Shutdown::Write);
                    }
                },
                &*ends,
            );
        })
    };
    let client_half = client.try_clone();
    pump(
        broker,
        client,
        &|| {
            if let Ok(c) = &client_half {
                let _ = c.shutdown(Shutdown::Write);
            }
        },
        &*ends,
    );
    let _ = up.join();
}

fn serve() -> ExitCode {
    let address = SocketAddr::from((PROXY_ADDRESS, PROXY_PORT));
    let Ok(listener) = TcpListener::bind(address) else {
        return ExitCode::from(3);
    };
    let upstream = format!("{EGRESS_TARGET}/{EGRESS_SOCKET_NAME}");
    let open = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        let Ok(client) = incoming else { continue };
        // Beyond the bound a connection is closed, unread: the broker's own
        // grant refuses far fewer tunnels than this.
        if open.fetch_add(1, Ordering::SeqCst) >= RELAY_MAX_CONNECTIONS {
            open.fetch_sub(1, Ordering::SeqCst);
            let _ = client.shutdown(Shutdown::Both);
            continue;
        }
        let (counted, upstream) = (Arc::clone(&open), upstream.clone());
        let spawned = std::thread::Builder::new().spawn(move || {
            forward(client, &upstream);
            counted.fetch_sub(1, Ordering::SeqCst);
        });
        if spawned.is_err() {
            open.fetch_sub(1, Ordering::SeqCst);
        }
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::{Read as _, Write as _};
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;

    use super::{EEXIST, NLMSG_ERROR, acknowledgement, pump, request};

    #[test]
    fn a_clean_end_is_passed_on_as_a_half_close_and_a_failure_as_an_end() {
        let pair = || UnixStream::pair().unwrap_or_else(|e| unreachable!("{e}"));
        // The sender writes, then closes its sending side: the bytes arrive,
        // and only the half-close is passed on.
        let (mut sender, from) = pair();
        let (to, mut receiver) = pair();
        let (half, end) = (Cell::new(0), Cell::new(0));
        let _ = sender.write_all(b"request");
        let _ = sender.shutdown(Shutdown::Write);
        pump(&from, &to, &|| half.set(half.get() + 1), &|| {
            end.set(end.get() + 1)
        });
        drop(to);
        let mut got = Vec::new();
        let _ = receiver.read_to_end(&mut got);
        assert_eq!(got, b"request");
        assert_eq!((half.get(), end.get()), (1, 0));
        // A write that fails ends everything.
        let (mut sender, from) = pair();
        let (to, receiver) = pair();
        drop(receiver);
        let _ = sender.write_all(b"x");
        let (half, end) = (Cell::new(0), Cell::new(0));
        pump(&from, &to, &|| half.set(half.get() + 1), &|| {
            end.set(end.get() + 1)
        });
        assert_eq!((half.get(), end.get()), (0, 1));
    }

    #[test]
    fn the_request_is_one_bounded_rtm_newaddr_for_the_proxy_address() {
        let message = request(1);
        assert_eq!(message.len(), 40);
        assert_eq!(message.get(0..4), Some(&40u32.to_ne_bytes()[..]));
        assert_eq!(message.get(4..6), Some(&20u16.to_ne_bytes()[..]));
        // AF_INET, a /32, host scope, on loopback's index.
        assert_eq!(message.get(16..20), Some(&[2u8, 32, 0, 254][..]));
        assert_eq!(message.get(20..24), Some(&1u32.to_ne_bytes()[..]));
        assert_eq!(message.get(28..32), Some(&[169u8, 254, 7, 1][..]));
        assert_eq!(message.get(36..40), Some(&[169u8, 254, 7, 1][..]));
    }

    fn reply(kind: u16, error: i32) -> Vec<u8> {
        let mut bytes = vec![0u8; 36];
        if let Some(slot) = bytes.get_mut(4..6) {
            slot.copy_from_slice(&kind.to_ne_bytes());
        }
        if let Some(slot) = bytes.get_mut(16..20) {
            slot.copy_from_slice(&error.to_ne_bytes());
        }
        bytes
    }

    #[test]
    fn only_an_error_message_is_an_acknowledgement() {
        assert_eq!(acknowledgement(&reply(NLMSG_ERROR, 0)), Some(0));
        assert_eq!(acknowledgement(&reply(NLMSG_ERROR, -EEXIST)), Some(EEXIST));
        assert_eq!(acknowledgement(&reply(NLMSG_ERROR, -1)), Some(1));
        assert_eq!(acknowledgement(&reply(16, 0)), None);
        assert_eq!(acknowledgement(&[0u8; 8]), None);
        assert_eq!(acknowledgement(&[]), None);
    }
}
