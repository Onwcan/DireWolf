//! Destruction's proxy lifetime (ADR-0048 §10), in process: real proxy
//! listeners, with runtime re-proof refused before a client can be launched.
//! No OCI runtime or container is used, and none is claimed.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dwk_proto::brokerp::egress::{EgressByteBudget, EgressGrant, EgressTargets, EgressTunnelLimit};
use dwk_proto::brokerp::sandbox::StoreInstance;
use dwk_proto::brokerp::{
    BrokerGeneration, BrokerRefusal, ChannelNonce, Common, EnvironmentDestroyAuthorisation,
    OutcomeResult, RuntimeSpec,
};
use dwk_proto::wire::id::{EnvironmentId, InvocationId, RunId};
use dwk_proto::wire::scalar::{ContentDigest, HostPath};
use dwk_sandbox_profile::EGRESS_SOCKET_NAME;

use crate::egress::Limits;
use crate::egress::proxy::Proxies;
use crate::egress::resolve::SystemResolver;

use super::{Sandbox, SandboxFiles};

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "dw-destroy-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A proxy that refuses every target before resolving any name.
fn empty_grant() -> EgressGrant {
    EgressGrant {
        targets: EgressTargets::new(Vec::new()).unwrap(),
        max_tunnels: EgressTunnelLimit::new(1).unwrap(),
        max_upload_bytes: EgressByteBudget::new(1024).unwrap(),
        max_download_bytes: EgressByteBudget::new(1024).unwrap(),
    }
}

#[test]
fn destruction_closes_only_its_proxy_even_when_the_runtime_cannot_be_reproved() {
    for expected in [
        BrokerRefusal::IdentityMismatch,
        BrokerRefusal::DigestMismatch,
        BrokerRefusal::Unsupported,
    ] {
        let scratch = Scratch::new();
        let uid = rustix::process::geteuid().as_raw();
        let proxies = Arc::new(
            Proxies::new(
                scratch.0.join("egress"),
                uid,
                Arc::new(SystemResolver),
                Limits::PRODUCTION,
            )
            .unwrap(),
        );
        let environment = EnvironmentId::parse("env_01M24BB8G3E0A851TRWE3M8FZF").unwrap();
        let neighbour = "env_01M24BB8G3E0A851TRWE3M8FZG";
        // Empty grants refuse before resolving any name: neither listener
        // has an outbound destination, and the test needs no network peer.
        let target_dir = proxies.start(environment.as_str(), empty_grant()).unwrap();
        let neighbour_dir = proxies.start(neighbour, empty_grant()).unwrap();
        let neighbour_socket = neighbour_dir.join(EGRESS_SOCKET_NAME);
        let before = fs::symlink_metadata(&neighbour_socket).unwrap();
        assert!(proxies.is_open(environment.as_str()) && proxies.is_open(neighbour));

        // These bytes are never executed: the named digest intentionally
        // differs. The other cases fail even before hashing the file.
        let executable = scratch.0.join("client");
        fs::write(&executable, b"\x7fELFnot-a-runtime").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let meta = fs::metadata(&executable).unwrap();
        let cwd = fs::metadata(&scratch.0).unwrap();
        let runtime = RuntimeSpec {
            socket: HostPath::new("/nonexistent/runtime.sock").unwrap(),
            argv0: HostPath::new("/nonexistent/client").unwrap(),
            executable: (
                meta.dev(),
                meta.ino()
                    .wrapping_add(u64::from(expected == BrokerRefusal::IdentityMismatch)),
            ),
            sha256: ContentDigest::new("d".repeat(64)).unwrap(),
            cwd: (cwd.dev(), cwd.ino()),
        };
        let sandbox = Sandbox::new(
            PathBuf::from("/nonexistent/dwkd-broker"),
            uid,
            SandboxFiles {
                seccomp: if expected == BrokerRefusal::Unsupported {
                    PathBuf::from(std::ffi::OsString::from_vec(vec![b'/', 0xff]))
                } else {
                    scratch.0.join("seccomp.json")
                },
                client_config: scratch.0.clone(),
            },
            (false, false, BrokerGeneration::new("a".repeat(32)).unwrap()),
            Arc::clone(&proxies),
        );
        let authorisation = EnvironmentDestroyAuthorisation::new(
            Common {
                channel: ChannelNonce::new("c".repeat(32)).unwrap(),
                invocation_id: InvocationId::parse("inv_01M24BB8G3E0A851TRWE3M8FZF").unwrap(),
            },
            (
                environment.clone(),
                RunId::parse("run_01M24BB8G3E0A851TRWE3M8FZF").unwrap(),
                StoreInstance::new("0a1b").unwrap(),
            ),
            None,
            runtime,
        );
        let answer = sandbox.destroy(
            &authorisation,
            (
                File::open(&executable).unwrap().into(),
                File::open(&scratch.0).unwrap().into(),
            ),
            Instant::now() + Duration::from_secs(10),
        );
        let target_closed = !proxies.is_open(environment.as_str())
            && proxies.dir(environment.as_str()).is_none()
            && !target_dir.exists()
            && UnixStream::connect(target_dir.join(EGRESS_SOCKET_NAME)).is_err();
        let remaining = proxies.environments();
        let after = fs::symlink_metadata(&neighbour_socket).unwrap();
        let neighbour_preserved = proxies.is_open(neighbour)
            && (before.dev(), before.ino()) == (after.dev(), after.ino());
        let mut peer = UnixStream::connect(&neighbour_socket).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        peer.write_all(b"CONNECT ungranted.test:443 HTTP/1.1\r\n\r\n")
            .unwrap();
        let mut reply = String::new();
        peer.read_to_string(&mut reply).unwrap();
        // Clean up even on the fail-before tree: no test-owned listener
        // survives the assertion that detects the missing close.
        let _ = proxies.close(environment.as_str());
        let _ = proxies.close(neighbour);

        assert_eq!(answer, OutcomeResult::Refused(expected), "{expected:?}");
        assert!(
            target_closed,
            "{expected:?}: destruction left its proxy open"
        );
        assert_eq!(remaining, [neighbour.to_owned()], "{expected:?}");
        assert!(neighbour_preserved, "{expected:?}: neighbour changed");
        assert!(reply.contains("TARGET_NOT_GRANTED"), "{reply:?}");
        assert!(proxies.environments().is_empty());
    }
}
