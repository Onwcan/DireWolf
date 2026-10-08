use super::{
    Authorisation, BrokerDone, BrokerHello, BrokerOutcome, BrokerRefusal, ChannelNonce, Common,
    FsDeleteAuthorisation, FsListAuthorisation, FsMoveAuthorisation, FsReadAuthorisation,
    FsReadDone, FsStatAuthorisation, FsWriteAuthorisation, Indeterminate, KernelNumber, LeafName,
    MAX_AUTHORISATION_BODY, MoveSide, OutcomeResult, PrivateKind, RawName, encode_frame,
};
use crate::frame::{FrameDecoder, HEADER_LEN};
use crate::limits::{MAX_FRAME_BODY, MAX_FS_READ_BYTES, MAX_FS_WRITE_BYTES};
use crate::wire::id::InvocationId;
use crate::wire::scalar::{HexContent, ListLimit, ReadLimit, StatKind};

fn channel() -> ChannelNonce {
    ChannelNonce::new("0123456789abcdef0123456789abcdef").unwrap_or_else(|| unreachable!())
}

fn invocation() -> InvocationId {
    InvocationId::parse("inv_01M24BB8G3E0A851TRWE3M8FZF").unwrap_or_else(|| unreachable!())
}

fn common() -> Common {
    Common::new(channel(), invocation())
}

fn leaf(name: &str) -> LeafName {
    LeafName::new(name).unwrap_or_else(|| unreachable!("{name}"))
}

fn body(frame: &[u8]) -> Vec<u8> {
    let mut decoder = FrameDecoder::new();
    match decoder.feed(frame) {
        Ok((_, Some(frame))) => frame.body,
        other => unreachable!("{other:?}"),
    }
}

#[test]
fn each_message_round_trips_and_is_not_another() {
    let hello = BrokerHello::new(channel());
    let bytes = body(&encode_frame(&hello).unwrap_or_default());
    assert_eq!(BrokerHello::decode_frame_body(&bytes), Ok(hello));
    assert!(Authorisation::decode_frame_body(&bytes).is_err());
    assert!(BrokerOutcome::decode_frame_body(&bytes).is_err());

    let limit = ReadLimit::new(4096).unwrap_or_else(|| unreachable!());
    let authorisation = FsReadAuthorisation::new(channel(), invocation(), 2049, u64::MAX, limit);
    let bytes = body(&encode_frame(&authorisation).unwrap_or_default());
    let decoded = FsReadAuthorisation::decode_frame_body(&bytes);
    assert_eq!(decoded.as_ref().map(|a| a.inode.value()), Ok(u64::MAX));
    assert_eq!(decoded, Ok(authorisation));
    assert!(BrokerHello::decode_frame_body(&bytes).is_err());

    // Every authorisation decodes as exactly its own kind.
    let list_limit = ListLimit::new(8).unwrap_or_else(|| unreachable!());
    for (authorisation, kind) in [
        (
            Authorisation::FsStat(FsStatAuthorisation::new(common(), 1, 2)),
            PrivateKind::FsStat,
        ),
        (
            Authorisation::FsList(FsListAuthorisation::new(common(), 1, 2, list_limit)),
            PrivateKind::FsList,
        ),
        (
            Authorisation::FsDelete(FsDeleteAuthorisation::new(
                common(),
                (1, 2),
                leaf("a.txt"),
                (1, 3),
                StatKind::RegularFile,
            )),
            PrivateKind::FsDelete,
        ),
        (
            Authorisation::FsMove(FsMoveAuthorisation::new(
                common(),
                MoveSide {
                    parent: (1, 2),
                    leaf: leaf("a"),
                },
                (1, 3),
                MoveSide {
                    parent: (1, 2),
                    leaf: leaf("b"),
                },
            )),
            PrivateKind::FsMove,
        ),
    ] {
        let bytes = body(&authorisation.encode_frame().unwrap_or_default());
        let decoded = Authorisation::decode_frame_body(&bytes);
        assert_eq!(decoded.as_ref().map(Authorisation::kind), Ok(kind));
        assert_eq!(decoded, Ok(authorisation));
        assert!(FsReadAuthorisation::decode_frame_body(&bytes).is_err());
    }
}

#[test]
fn a_kind_declares_its_own_descriptor_count_and_no_other() {
    // A stat carries one descriptor; declaring two is refused at decode, before
    // any descriptor count is compared.
    let stat = FsStatAuthorisation::new(common(), 1, 2);
    let text = String::from_utf8(body(&encode_frame(&stat).unwrap_or_default()))
        .unwrap_or_default()
        .replace(r#""descriptors":1"#, r#""descriptors":2"#);
    assert!(Authorisation::decode_frame_body(text.as_bytes()).is_err());
    // A move carries two.
    assert_eq!(PrivateKind::FsMove.descriptors(), Some(2));
    assert_eq!(PrivateKind::FsPatch.descriptors(), Some(2));
    assert_eq!(PrivateKind::Hello.descriptors(), None);
}

#[test]
fn a_write_names_its_target_exactly_when_it_replaces_one() {
    let content = HexContent::from_bytes(b"x").unwrap_or_else(|| unreachable!());
    let create = FsWriteAuthorisation::new(common(), (1, 2), leaf("n"), None, content.clone());
    let replace =
        FsWriteAuthorisation::new(common(), (1, 2), leaf("n"), Some((1, 9)), content.clone());
    for write in [create.clone(), replace.clone()] {
        let bytes = body(
            &Authorisation::FsWrite(write.clone())
                .encode_frame()
                .unwrap_or_default(),
        );
        assert_eq!(
            Authorisation::decode_frame_body(&bytes),
            Ok(Authorisation::FsWrite(write))
        );
    }
    assert_eq!(replace.target(), Some((1, 9)));
    assert_eq!(create.target(), None);
    // A creation that names a target, or a replacement that does not.
    let mut bad = create;
    bad.target_device = Some(KernelNumber::from_u64(1));
    bad.target_inode = Some(KernelNumber::from_u64(9));
    assert!(Authorisation::FsWrite(bad).encode_frame().is_err());
    let mut bad = replace;
    bad.target_inode = None;
    assert!(Authorisation::FsWrite(bad).encode_frame().is_err());
}

#[test]
fn a_leaf_is_one_component_whatever_the_sender_validated() {
    for bad in ["", ".", "..", "a/b", "/a", "a\0b", &"a".repeat(256)] {
        assert!(LeafName::new(bad).is_none(), "{bad:?}");
    }
    // 255 bytes of a four-byte character is 63 characters and fits; 64 does not.
    assert!(LeafName::new("\u{1F600}".repeat(63)).is_some());
    assert!(LeafName::new("\u{1F600}".repeat(64)).is_none());
    for good in ["a", ".hidden", "...", "caf\u{e9}"] {
        assert!(LeafName::new(good).is_some(), "{good:?}");
    }
    // A raw listing name is bytes, UTF-8 or not.
    let raw = RawName::from_bytes(b"\xff\xfe").unwrap_or_else(|| unreachable!());
    assert_eq!(raw.to_bytes(), b"\xff\xfe");
    assert!(RawName::from_bytes(b"").is_none());
    assert!(RawName::from_bytes(&[b'a'; 256]).is_none());
}

#[test]
fn an_outcome_carries_exactly_one_answer() {
    let done = BrokerDone::read(FsReadDone {
        content: HexContent::from_bytes(b"hi").unwrap_or_else(|| unreachable!()),
        eof_observed: true,
    });
    for result in [
        OutcomeResult::done(done.clone()),
        OutcomeResult::Refused(BrokerRefusal::IdentityMismatch),
        OutcomeResult::Indeterminate(Indeterminate::RestoreFailed),
    ] {
        let outcome = BrokerOutcome::new(channel(), invocation(), result.clone());
        let bytes = body(&encode_frame(&outcome).unwrap_or_default());
        let decoded = BrokerOutcome::decode_frame_body(&bytes);
        assert_eq!(decoded.map(|o| o.result()), Ok(result));
    }
    let mut both = BrokerOutcome::new(channel(), invocation(), OutcomeResult::done(done));
    both.refused = Some(BrokerRefusal::ReadFailed);
    assert!(encode_frame(&both).is_err());
    let none = r#"{"channel":"0123456789abcdef0123456789abcdef","invocation_id":"inv_01M24BB8G3E0A851TRWE3M8FZF","kind":"broker.outcome","protocol":7}"#;
    assert!(BrokerOutcome::decode_frame_body(none.as_bytes()).is_err());
    // A done names exactly one operation.
    let two = r#"{"channel":"0123456789abcdef0123456789abcdef","done":{"fs_move":{},"fs_delete":{"debris":false}},"invocation_id":"inv_01M24BB8G3E0A851TRWE3M8FZF","kind":"broker.outcome","protocol":7}"#;
    assert!(BrokerOutcome::decode_frame_body(two.as_bytes()).is_err());
}

#[test]
fn unknown_members_old_versions_and_second_spellings_are_refused() {
    for text in [
        r#"{"channel":"0123456789abcdef0123456789abcdef","kind":"broker.hello","protocol":7,"extra":1}"#,
        r#"{"channel":"0123456789ABCDEF0123456789ABCDEF","kind":"broker.hello","protocol":7}"#,
        // Versions 1 to 6 are not half-understood (ADR-0050 made it 7), and
        // a later one is not guessed at.
        r#"{"channel":"0123456789abcdef0123456789abcdef","kind":"broker.hello","protocol":1}"#,
        r#"{"channel":"0123456789abcdef0123456789abcdef","kind":"broker.hello","protocol":2}"#,
        r#"{"channel":"0123456789abcdef0123456789abcdef","kind":"broker.hello","protocol":3}"#,
        r#"{"channel":"0123456789abcdef0123456789abcdef","kind":"broker.hello","protocol":4}"#,
        r#"{"channel":"0123456789abcdef0123456789abcdef","kind":"broker.hello","protocol":5}"#,
        r#"{"channel":"0123456789abcdef0123456789abcdef","kind":"broker.hello","protocol":6}"#,
        r#"{"channel":"0123456789abcdef0123456789abcdef","kind":"broker.hello","protocol":8}"#,
        r#"{"channel":"0123456789abcdef0123456789abcdef","kind":"broker.hello","kind":"broker.hello","protocol":7}"#,
    ] {
        assert!(
            BrokerHello::decode_frame_body(text.as_bytes()).is_err(),
            "{text}"
        );
    }
    // An unknown kind is not an authorisation.
    let unknown = r#"{"kind":"broker.fs_chmod","protocol":7}"#;
    assert!(Authorisation::decode_frame_body(unknown.as_bytes()).is_err());
    for (text, ok) in [
        ("0", true),
        ("18446744073709551615", true),
        ("007", false),
        ("18446744073709551616", false),
        ("-1", false),
        ("", false),
    ] {
        assert_eq!(KernelNumber::new(text).is_some(), ok, "{text:?}");
    }
}

#[test]
fn the_largest_messages_fit_one_frame() {
    let content = vec![0xffu8; MAX_FS_READ_BYTES];
    let done = BrokerDone::read(FsReadDone {
        content: HexContent::from_bytes(&content).unwrap_or_else(|| unreachable!()),
        eof_observed: false,
    });
    let outcome = BrokerOutcome::new(channel(), invocation(), OutcomeResult::done(done));
    let frame = encode_frame(&outcome).unwrap_or_default();
    assert!(frame.len() > HEADER_LEN + 2 * MAX_FS_READ_BYTES);
    assert!(frame.len() <= HEADER_LEN + MAX_FRAME_BODY);
    // The largest write authorisation.
    let content =
        HexContent::from_bytes(&vec![0u8; MAX_FS_WRITE_BYTES]).unwrap_or_else(|| unreachable!());
    let write = Authorisation::FsWrite(FsWriteAuthorisation::new(
        common(),
        (u64::MAX, u64::MAX),
        leaf(&"a".repeat(255)),
        Some((u64::MAX, u64::MAX)),
        content,
    ));
    let frame = write.encode_frame().unwrap_or_default();
    assert!(frame.len() > HEADER_LEN + 2 * MAX_FS_WRITE_BYTES);
    assert!(frame.len() - HEADER_LEN <= MAX_AUTHORISATION_BODY);
}

// ---------------------------------------------------------------------------
// Version 3: the process operations (ADR-0045).
// ---------------------------------------------------------------------------

fn process_id() -> crate::wire::id::ProcessId {
    crate::wire::id::ProcessId::parse("prc_01M24BB8G3E0A851TRWE3M8FZF")
        .unwrap_or_else(|| unreachable!())
}

fn generation() -> super::BrokerGeneration {
    super::BrokerGeneration::new("00112233445566778899aabbccddeeff")
        .unwrap_or_else(|| unreachable!())
}

fn spec(args: &[&str]) -> super::ProcessSpec {
    use crate::wire::scalar::{ContentDigest, HostPath, ProcessArg};
    let args: Vec<ProcessArg> = args
        .iter()
        .map(|a| ProcessArg::new(*a).unwrap_or_else(|| unreachable!("{a}")))
        .collect();
    super::ProcessSpec {
        process_id: process_id(),
        executable: (2049, 77),
        executable_sha256: ContentDigest::new("ab".repeat(32)).unwrap_or_else(|| unreachable!()),
        cwd: (2049, 2),
        argv0: HostPath::new("/usr/bin/git").unwrap_or_else(|| unreachable!()),
        args: super::ProcessArgs::new(args).unwrap_or_else(|| unreachable!()),
        environment: super::ExecEnvironment::Base,
        stream_limit: super::StreamLimit::new(131_072).unwrap_or_else(|| unreachable!()),
    }
}

#[test]
fn the_process_operations_round_trip_with_their_own_descriptor_counts() {
    use super::{ProcessKillAuthorisation, ProcessStartAuthorisation, ProcessStatusAuthorisation};
    for (authorisation, kind, count) in [
        (
            Authorisation::ProcessStart(ProcessStartAuthorisation::new(
                common(),
                spec(&["status", "--short"]),
            )),
            PrivateKind::ProcessStart,
            2,
        ),
        (
            Authorisation::ProcessStatus(ProcessStatusAuthorisation::new(
                common(),
                process_id(),
                generation(),
            )),
            PrivateKind::ProcessStatus,
            0,
        ),
        (
            Authorisation::ProcessKill(ProcessKillAuthorisation::new(
                common(),
                process_id(),
                generation(),
            )),
            PrivateKind::ProcessKill,
            0,
        ),
    ] {
        let bytes = body(&authorisation.encode_frame().unwrap_or_default());
        let decoded = Authorisation::decode_frame_body(&bytes);
        assert_eq!(decoded.as_ref().map(Authorisation::kind), Ok(kind));
        assert_eq!(
            decoded.as_ref().map(Authorisation::declared_descriptors),
            Ok(count)
        );
        assert_eq!(kind.descriptors(), Some(count));
        assert_eq!(decoded, Ok(authorisation));
    }
    // A status or a kill that declares a descriptor, or a start that declares
    // one, is not that kind's message.
    let mut status = ProcessStatusAuthorisation::new(common(), process_id(), generation());
    status.descriptors = super::DescriptorCount::new(1).unwrap_or_else(|| unreachable!());
    assert!(Authorisation::ProcessStatus(status).encode_frame().is_err());
    let mut start = ProcessStartAuthorisation::new(common(), spec(&[]));
    start.descriptors = super::DescriptorCount::new(1).unwrap_or_else(|| unreachable!());
    assert!(Authorisation::ProcessStart(start).encode_frame().is_err());
}

#[test]
fn a_launch_carries_argv_as_data_and_no_more_of_it_than_the_bound() {
    use super::ProcessStartAuthorisation;
    use crate::limits::{MAX_PROCESS_ARG_BYTES, MAX_PROCESS_ARGV_BYTES};
    // Shell syntax is ordinary bytes on this wire too.
    let literal = spec(&[
        "$(id)",
        "a b",
        ";",
        "|",
        "*",
        "\"quoted\"",
        "line
break",
    ]);
    let authorisation =
        Authorisation::ProcessStart(ProcessStartAuthorisation::new(common(), literal));
    let bytes = body(&authorisation.encode_frame().unwrap_or_default());
    assert_eq!(Authorisation::decode_frame_body(&bytes), Ok(authorisation));
    // Exactly the aggregate bound: accepted. One byte more: refused both ways.
    let per = MAX_PROCESS_ARG_BYTES;
    let full: Vec<String> = (0..MAX_PROCESS_ARGV_BYTES.checked_div(per).unwrap_or(0))
        .map(|_| "a".repeat(per))
        .collect();
    let refs: Vec<&str> = full.iter().map(String::as_str).collect();
    let exact = Authorisation::ProcessStart(ProcessStartAuthorisation::new(common(), spec(&refs)));
    assert!(exact.encode_frame().is_ok());
    let mut over = refs.clone();
    over.push("a");
    let too_many =
        Authorisation::ProcessStart(ProcessStartAuthorisation::new(common(), spec(&over)));
    assert!(too_many.encode_frame().is_err());
    // An environment is a profile, never a variable list.
    let text = String::from_utf8(bytes).unwrap_or_default();
    let with_env = text.replace(
        r#""environment":"BASE""#,
        r#""environment":{"LD_PRELOAD":"x"}"#,
    );
    assert!(Authorisation::decode_frame_body(with_env.as_bytes()).is_err());
}

#[test]
fn the_environment_profiles_hold_no_loader_or_credential_variable() {
    use super::ExecEnvironment;
    for profile in ExecEnvironment::ALL {
        let variables = profile.variables();
        let names: Vec<&str> = variables.iter().map(|(name, _)| *name).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, names, "sorted, one of each");
        for name in names {
            for forbidden in [
                "LD_",
                "DYLD_",
                "PRELOAD",
                "PYTHONPATH",
                "PYTHONHOME",
                "SSH_",
                "AWS_",
                "TOKEN",
                "SECRET",
                "PROXY",
                "proxy",
            ] {
                assert!(!name.contains(forbidden), "{name}");
            }
        }
    }
    assert_eq!(
        ExecEnvironment::Base
            .variables()
            .iter()
            .map(|(n, _)| *n)
            .collect::<Vec<_>>(),
        ["HOME", "LANG", "PATH"]
    );
}

#[test]
fn a_process_result_names_exactly_one_operation() {
    use super::{ProcessKillDone, ProcessStartDone, ProcessStatusDone, ProcessStreamSnapshot};
    use crate::wire::scalar::{ByteCount, KillOutcome, ProcessState, StreamContent};
    let empty = || ProcessStreamSnapshot {
        content: StreamContent::new("").unwrap_or_else(|| unreachable!()),
        observed: ByteCount::new(0).unwrap_or_else(|| unreachable!()),
        truncated: false,
    };
    for done in [
        BrokerDone::process_start(ProcessStartDone {
            generation: generation(),
            state: ProcessState::Running,
            exit_code: None,
            signal: None,
        }),
        BrokerDone::process_status(ProcessStatusDone {
            state: ProcessState::Running,
            exit_code: None,
            signal: None,
            timed_out: false,
            stdout: empty(),
            stderr: empty(),
        }),
        BrokerDone::process_kill(ProcessKillDone {
            outcome: KillOutcome::Signaled,
        }),
    ] {
        let kind = done.kind();
        let outcome = BrokerOutcome::new(channel(), invocation(), OutcomeResult::done(done));
        let bytes = body(&encode_frame(&outcome).unwrap_or_default());
        let decoded = BrokerOutcome::decode_frame_body(&bytes).map(|o| o.result());
        assert!(matches!(decoded, Ok(OutcomeResult::Done(ref d)) if d.kind() == kind));
    }
}

// ---------------------------------------------------------------------------
// Version 4: the secret primitives (ADR-0046); version 7: mode A's value
// travels only with a credential exchange (ADR-0050 §8).
// ---------------------------------------------------------------------------

/// A `net.http` hop that carries a credential: the handle, the operator's
/// header and prefix, and — as the one descriptor — the value.
fn credential_hop() -> super::http::HopSpec {
    use super::http::{
        HopNumber, HopSpec, HttpCredential, HttpMethod, HttpTarget, NetAddress, NetAddresses,
        RequestHeaders, ResponseLimit,
    };
    HopSpec {
        hop: HopNumber::new(1).unwrap_or_else(|| unreachable!()),
        method: HttpMethod::Get,
        host: super::egress::EgressHost::new("api.github.com").unwrap_or_else(|| unreachable!()),
        port: super::egress::EgressPort::new(443).unwrap_or_else(|| unreachable!()),
        target: HttpTarget::new("/user").unwrap_or_else(|| unreachable!()),
        headers: RequestHeaders::new(Vec::new()).unwrap_or_else(|| unreachable!()),
        body: None,
        addresses: NetAddresses::new(vec![NetAddress::from_address(
            crate::wire::guard::Address::V4([140, 82, 112, 6]),
        )])
        .unwrap_or_else(|| unreachable!()),
        response_limit: ResponseLimit::new(4096).unwrap_or_else(|| unreachable!()),
        credential: Some(HttpCredential {
            handle: super::SecretHandle::new("github-primary").unwrap_or_else(|| unreachable!()),
            header_name: super::SecretHeaderName::new("Authorization")
                .unwrap_or_else(|| unreachable!()),
            header_prefix: super::SecretHeaderPrefix::new("Bearer "),
        }),
    }
}

fn spawn_secret(delivery: super::SecretDelivery, env: Option<&str>) -> super::SpawnSecret {
    super::SpawnSecret {
        handle: super::SecretHandle::new("deploy-key").unwrap_or_else(|| unreachable!()),
        delivery,
        env_name: env.map(|name| super::SecretEnvName::new(name).unwrap_or_else(|| unreachable!())),
    }
}

#[test]
fn the_secret_operations_round_trip_and_carry_the_value_in_a_descriptor_only() {
    use super::http::HttpExchangeAuthorisation;
    use super::{SecretDelivery, SecretProcessStartAuthorisation};
    for (authorisation, kind, count) in [
        (
            Authorisation::HttpExchange(HttpExchangeAuthorisation::new(common(), credential_hop())),
            PrivateKind::HttpCredentialExchange,
            1,
        ),
        (
            Authorisation::SecretProcessStart(SecretProcessStartAuthorisation::new(
                common(),
                spec(&["fetch"]),
                spawn_secret(SecretDelivery::FdAtSpawn, None),
            )),
            PrivateKind::SecretProcessStart,
            3,
        ),
        (
            Authorisation::SecretProcessStart(SecretProcessStartAuthorisation::new(
                common(),
                spec(&[]),
                spawn_secret(SecretDelivery::EnvAtSpawn, Some("DEPLOY_TOKEN")),
            )),
            PrivateKind::SecretProcessStart,
            3,
        ),
    ] {
        let bytes = body(&authorisation.encode_frame().unwrap_or_default());
        let decoded = Authorisation::decode_frame_body(&bytes);
        assert_eq!(decoded.as_ref().map(Authorisation::kind), Ok(kind));
        assert_eq!(
            decoded.as_ref().map(Authorisation::declared_descriptors),
            Ok(count)
        );
        assert_eq!(kind.descriptors(), Some(count));
        assert_eq!(decoded, Ok(authorisation));
    }
    // A member for the value, its length or a mode is not part of the
    // language: the strict decoder refuses each.
    let exchange = String::from_utf8(body(
        &Authorisation::HttpExchange(HttpExchangeAuthorisation::new(common(), credential_hop()))
            .encode_frame()
            .unwrap_or_default(),
    ))
    .unwrap_or_default();
    for extra in [
        r#""value":"x","#,
        r#""secret_bytes":1,"#,
        r#""injection_mode":"env","#,
    ] {
        let tampered = exchange.replacen('{', &format!("{{{extra}"), 1);
        assert!(
            Authorisation::decode_frame_body(tampered.as_bytes()).is_err(),
            "{extra}"
        );
    }
    // M4e's render-and-drop is retired: its kind is no longer the language.
    let retired = exchange.replace("broker.http_credential_exchange", "broker.secret_egress");
    assert!(retired.contains("broker.secret_egress"));
    assert!(Authorisation::decode_frame_body(retired.as_bytes()).is_err());
}

#[test]
fn a_secret_launch_names_a_variable_exactly_for_the_environment_mode() {
    use super::{DescriptorCount, SecretDelivery, SecretProcessStartAuthorisation};
    let env_without_name = SecretProcessStartAuthorisation::new(
        common(),
        spec(&[]),
        spawn_secret(SecretDelivery::EnvAtSpawn, None),
    );
    assert!(
        Authorisation::SecretProcessStart(env_without_name)
            .encode_frame()
            .is_err()
    );
    let fd_with_name = SecretProcessStartAuthorisation::new(
        common(),
        spec(&[]),
        spawn_secret(SecretDelivery::FdAtSpawn, Some("DEPLOY_TOKEN")),
    );
    assert!(
        Authorisation::SecretProcessStart(fd_with_name)
            .encode_frame()
            .is_err()
    );
    // Three descriptors, never two: the launch without its secret is not
    // this message.
    let mut two = SecretProcessStartAuthorisation::new(
        common(),
        spec(&[]),
        spawn_secret(SecretDelivery::FdAtSpawn, None),
    );
    two.descriptors = DescriptorCount::new(2).unwrap_or_else(|| unreachable!());
    assert!(
        Authorisation::SecretProcessStart(two)
            .encode_frame()
            .is_err()
    );
    // Its launch is exactly a `process_start`'s.
    let start = SecretProcessStartAuthorisation::new(
        common(),
        spec(&["x"]),
        spawn_secret(SecretDelivery::FdAtSpawn, None),
    );
    assert_eq!(
        start.launch(),
        super::ProcessStartAuthorisation::new(common(), spec(&["x"]))
    );
}

#[test]
fn the_secret_grammars_refuse_what_could_control_a_process_or_break_a_header() {
    use super::{
        SecretEnvName, SecretHandle, SecretHeaderName, SecretHeaderPrefix, SecretOrigin,
        is_control_variable,
    };
    for name in [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "PYTHONPATH",
        "RUSTC_WRAPPER",
        "PATH",
        "HOME",
        "LANG",
        "BASH_ENV",
        "GIT_SSH_COMMAND",
        "NODE_OPTIONS",
        "GLIBC_TUNABLES",
        "lower",
        "1ABC",
        "",
        "A-B",
    ] {
        assert!(SecretEnvName::new(name).is_none(), "{name}");
    }
    assert!(is_control_variable("LD_AUDIT") && !is_control_variable("GITHUB_TOKEN"));
    assert!(SecretEnvName::new("GITHUB_TOKEN").is_some());
    let long = "a".repeat(65);
    for bad in ["Author ization", "X:Y", "a\r\nb", "", long.as_str()] {
        assert!(SecretHeaderName::new(bad).is_none(), "{bad:?}");
    }
    for bad in ["Bearer\r\n", "Bearer\n", "a\u{0}", "", "\u{e9}"] {
        assert!(SecretHeaderPrefix::new(bad).is_none(), "{bad:?}");
    }
    for bad in [
        "api.example.com",
        "api.example.com:0",
        "api.example.com:080",
        "api.example.com:65536",
        "user@api.example.com:443",
        "API.example.com:443",
        "api..example.com:443",
        "https://api.example.com:443",
        "api.example.com:443/x",
        "-a.example.com:443",
    ] {
        assert!(SecretOrigin::new(bad).is_none(), "{bad}");
    }
    assert!(SecretOrigin::new("api.example.com:443").is_some());
    for bad in ["Upper", "1x", "", "a/b", long.as_str()] {
        assert!(SecretHandle::new(bad).is_none(), "{bad}");
    }
}

#[test]
fn a_secret_result_names_its_own_operation_and_says_nothing_of_the_value() {
    use super::ProcessStartDone;
    use crate::wire::scalar::ProcessState;
    let done = BrokerDone::secret_process_start(ProcessStartDone {
        generation: generation(),
        state: ProcessState::Running,
        exit_code: None,
        signal: None,
    });
    let kind = done.kind();
    let outcome = BrokerOutcome::new(channel(), invocation(), OutcomeResult::done(done));
    let bytes = body(&encode_frame(&outcome).unwrap_or_default());
    let decoded = BrokerOutcome::decode_frame_body(&bytes).map(|o| o.result());
    assert!(matches!(decoded, Ok(OutcomeResult::Done(ref d)) if d.kind() == kind));
    // The retired render's acknowledgement is not an answer any more, with
    // or without a member that would describe the value.
    for done in [
        r#"{"secret_egress":{}}"#,
        r#"{"secret_egress":{"length":8}}"#,
    ] {
        let text = format!(
            r#"{{"channel":"0123456789abcdef0123456789abcdef","done":{done},"invocation_id":"inv_01M24BB8G3E0A851TRWE3M8FZF","kind":"broker.outcome","protocol":7}}"#
        );
        assert!(
            BrokerOutcome::decode_frame_body(text.as_bytes()).is_err(),
            "{done}"
        );
    }
}

// ---- M5a: the execution environment (ADR-0047) ------------------------------

fn runtime_spec() -> super::RuntimeSpec {
    super::RuntimeSpec {
        socket: crate::wire::scalar::HostPath::new("/var/run/docker.sock")
            .unwrap_or_else(|| unreachable!()),
        argv0: crate::wire::scalar::HostPath::new("/usr/bin/docker")
            .unwrap_or_else(|| unreachable!()),
        executable: (2049, 77),
        sha256: crate::wire::scalar::ContentDigest::new("b".repeat(64))
            .unwrap_or_else(|| unreachable!()),
        cwd: (2049, 2),
    }
}

fn environment_spec() -> super::EnvironmentSpec {
    use super::sandbox::{EnvironmentProfile, ImageId, NetworkTopology, StoreInstance};
    super::EnvironmentSpec {
        environment_id: crate::wire::id::EnvironmentId::parse("env_01M24BB8G3E0A851TRWE3M8FZF")
            .unwrap_or_else(|| unreachable!()),
        run_id: crate::wire::id::RunId::parse("run_01M24BB8G3E0A851TRWE3M8FZF")
            .unwrap_or_else(|| unreachable!()),
        store: StoreInstance::new("0a1b").unwrap_or_else(|| unreachable!()),
        profile: EnvironmentProfile::OciStrict,
        network: NetworkTopology::NoNetwork,
        image: ImageId::new(format!("sha256:{}", "c".repeat(64))).unwrap_or_else(|| unreachable!()),
        probe_sha256: crate::wire::scalar::ContentDigest::new("d".repeat(64))
            .unwrap_or_else(|| unreachable!()),
        workspace_path: crate::wire::scalar::HostPath::new("/srv/ws")
            .unwrap_or_else(|| unreachable!()),
        workspace: (2049, 131),
        relay_sha256: None,
        egress: None,
    }
}

/// A `PROXY_ONLY` preparation's spec: the relay pinned, one target granted.
fn proxy_spec() -> super::EnvironmentSpec {
    use super::egress::{
        EgressByteBudget, EgressGrant, EgressHost, EgressPort, EgressTarget, EgressTargets,
        EgressTunnelLimit,
    };
    let mut spec = environment_spec();
    spec.network = super::sandbox::NetworkTopology::ProxyOnly;
    spec.relay_sha256 = Some(
        crate::wire::scalar::ContentDigest::new("f".repeat(64)).unwrap_or_else(|| unreachable!()),
    );
    spec.egress = Some(EgressGrant {
        targets: EgressTargets::new(vec![EgressTarget {
            host: EgressHost::new("pypi.org").unwrap_or_else(|| unreachable!()),
            port: EgressPort::new(443).unwrap_or_else(|| unreachable!()),
        }])
        .unwrap_or_else(|| unreachable!()),
        max_tunnels: EgressTunnelLimit::new(4).unwrap_or_else(|| unreachable!()),
        max_upload_bytes: EgressByteBudget::new(1 << 20).unwrap_or_else(|| unreachable!()),
        max_download_bytes: EgressByteBudget::new(1 << 24).unwrap_or_else(|| unreachable!()),
    });
    spec
}

#[test]
fn a_proxy_only_preparation_carries_typed_targets_and_nothing_wider() {
    let prepare = Authorisation::EnvironmentPrepare(super::EnvironmentPrepareAuthorisation::new(
        common(),
        proxy_spec(),
        runtime_spec(),
    ));
    let bytes = body(&prepare.encode_frame().unwrap_or_default());
    let decoded = Authorisation::decode_frame_body(&bytes);
    assert_eq!(decoded, Ok(prepare.clone()));
    let Ok(Authorisation::EnvironmentPrepare(decoded)) = decoded else {
        unreachable!()
    };
    let spec = decoded.environment();
    assert_eq!(spec, proxy_spec());
    assert!(
        spec.egress
            .as_ref()
            .is_some_and(|g| g.permits("pypi.org", 443))
    );
    // A pattern, an address, a range, a second spelling: none is a target.
    let text = String::from_utf8(bytes).unwrap_or_default();
    for (from, to) in [
        ("\"pypi.org\"", "\"*.pypi.org\""),
        ("\"pypi.org\"", "\"10.0.0.1\""),
        ("\"pypi.org\"", "\"PYPI.org\""),
        ("\"pypi.org\"", "\"pypi.org.\""),
        ("\"pypi.org\"", "\"[::1]\""),
        ("\"port\":443", "\"port\":0"),
    ] {
        let bad = text.replacen(from, to, 1);
        assert_ne!(bad, text, "{to}");
        assert!(
            Authorisation::decode_frame_body(bad.as_bytes()).is_err(),
            "{to}"
        );
    }
    for smuggled in [
        r#""cidr":"10.0.0.0/8","#,
        r#""allow_private":true,"#,
        r#""proxy_url":"http://evil:1","#,
    ] {
        let bad = text.replacen("\"targets\"", &format!("{smuggled}\"targets\""), 1);
        assert!(
            Authorisation::decode_frame_body(bad.as_bytes()).is_err(),
            "{smuggled}"
        );
    }
}

#[test]
fn egress_counters_and_roles_travel_and_carry_no_host() {
    use super::egress::{
        EgressCount, EgressCountList, EgressCountValue, EgressCounters, EgressDisposition,
    };
    use super::sandbox::{ContainerRef, ContainerRole, Milliseconds};
    let counters = EgressCounters {
        dispositions: EgressCountList::new(vec![
            EgressCount {
                disposition: EgressDisposition::Closed,
                count: EgressCountValue::new(3).unwrap_or_else(|| unreachable!()),
            },
            EgressCount {
                disposition: EgressDisposition::SniMismatch,
                count: EgressCountValue::new(1).unwrap_or_else(|| unreachable!()),
            },
        ])
        .unwrap_or_else(|| unreachable!()),
        bytes_upstream: crate::wire::scalar::ByteCount::new(10).unwrap_or_else(|| unreachable!()),
        bytes_downstream: crate::wire::scalar::ByteCount::new(20).unwrap_or_else(|| unreachable!()),
    };
    assert_eq!(counters.count(EgressDisposition::Closed), 3);
    assert_eq!(counters.count(EgressDisposition::AddressBlocked), 0);
    let done = BrokerDone::environment_destroy(super::EnvironmentDestroyDone {
        state: super::DestroyState::Removed,
        container: ContainerRef::new("e".repeat(64)),
        destroy_ms: Milliseconds::new(7).unwrap_or_else(|| unreachable!()),
        egress: Some(counters),
    });
    let outcome = BrokerOutcome::new(channel(), invocation(), OutcomeResult::done(done.clone()));
    let bytes = body(&encode_frame(&outcome).unwrap_or_default());
    assert_eq!(
        BrokerOutcome::decode_frame_body(&bytes).map(|o| o.result()),
        Ok(OutcomeResult::done(done))
    );
    let text = String::from_utf8(bytes).unwrap_or_default();
    assert!(!text.contains("host"), "{text}");
    for role in ContainerRole::ALL {
        assert!(!role.label().is_empty());
    }
}

#[test]
fn the_environment_operations_round_trip_with_two_descriptors_and_a_longer_deadline() {
    use super::sandbox::ContainerRef;
    let container = ContainerRef::new("e".repeat(64)).unwrap_or_else(|| unreachable!());
    let spec = environment_spec();
    let ids = (
        spec.environment_id.clone(),
        spec.run_id.clone(),
        spec.store.clone(),
    );
    for (authorisation, kind) in [
        (
            Authorisation::EnvironmentPrepare(super::EnvironmentPrepareAuthorisation::new(
                common(),
                environment_spec(),
                runtime_spec(),
            )),
            PrivateKind::EnvironmentPrepare,
        ),
        (
            Authorisation::EnvironmentMeasure(super::EnvironmentMeasureAuthorisation::new(
                common(),
                environment_spec(),
                container.clone(),
                runtime_spec(),
            )),
            PrivateKind::EnvironmentMeasure,
        ),
        (
            Authorisation::EnvironmentDestroy(super::EnvironmentDestroyAuthorisation::new(
                common(),
                ids.clone(),
                Some(container.clone()),
                runtime_spec(),
            )),
            PrivateKind::EnvironmentDestroy,
        ),
        (
            Authorisation::EnvironmentDestroy(super::EnvironmentDestroyAuthorisation::new(
                common(),
                ids.clone(),
                None,
                runtime_spec(),
            )),
            PrivateKind::EnvironmentDestroy,
        ),
        (
            Authorisation::EnvironmentList(super::EnvironmentListAuthorisation::new(
                common(),
                spec.store.clone(),
                runtime_spec(),
            )),
            PrivateKind::EnvironmentList,
        ),
    ] {
        let bytes = body(&authorisation.encode_frame().unwrap_or_default());
        let decoded = Authorisation::decode_frame_body(&bytes);
        assert_eq!(decoded.as_ref().map(Authorisation::kind), Ok(kind));
        assert_eq!(decoded, Ok(authorisation));
        assert_eq!(kind.descriptors(), Some(2));
        assert!(kind.deadline_seconds() > PrivateKind::FsRead.deadline_seconds());
        // No runtime flag, option map or free-form argument has a field to
        // ride in: an unknown member is refused.
        let text = String::from_utf8(bytes).unwrap_or_default();
        for smuggled in [
            r#""docker_args":["--privileged"],"#,
            r#""extra_flags":"--pid=host","#,
            r#""runtime_options":{"privileged":true},"#,
        ] {
            let bad = text.replacen('{', &format!("{{{smuggled}"), 1);
            assert!(
                Authorisation::decode_frame_body(bad.as_bytes()).is_err(),
                "{smuggled}"
            );
        }
    }
    // A tag, a short container id or a profile nobody defined is not a value.
    let prepare = String::from_utf8(body(
        &Authorisation::EnvironmentPrepare(super::EnvironmentPrepareAuthorisation::new(
            common(),
            environment_spec(),
            runtime_spec(),
        ))
        .encode_frame()
        .unwrap_or_default(),
    ))
    .unwrap_or_default();
    for (from, to) in [
        (
            format!("sha256:{}", "c".repeat(64)),
            "busybox:latest".to_owned(),
        ),
        ("OCI_STRICT".to_owned(), "OCI_PRIVILEGED".to_owned()),
        ("NO_NETWORK".to_owned(), "HOST".to_owned()),
    ] {
        let bad = prepare.replace(&from, &to);
        assert!(
            Authorisation::decode_frame_body(bad.as_bytes()).is_err(),
            "{to}"
        );
    }
}

#[test]
fn an_environment_result_names_exactly_one_operation() {
    use super::sandbox::{
        ContainerRef, InvariantCheck, InvariantChecks, Milliseconds, SandboxInvariant, Verdict,
    };
    let checks = InvariantChecks::new(vec![InvariantCheck {
        invariant: SandboxInvariant::HostRunning,
        verdict: Verdict::Unobservable,
    }])
    .unwrap_or_else(|| unreachable!());
    let measurement = super::EnvironmentMeasurement {
        checks,
        runtime_version: None,
        measure_ms: Milliseconds::new(5).unwrap_or_else(|| unreachable!()),
    };
    let done = BrokerDone::environment_prepare(super::EnvironmentPrepareDone {
        container: ContainerRef::new("e".repeat(64)),
        retained: false,
        measurement: Some(measurement),
        prepare_ms: Milliseconds::new(9).unwrap_or_else(|| unreachable!()),
    });
    assert_eq!(done.kind(), Some(PrivateKind::EnvironmentPrepare));
    let outcome = BrokerOutcome::new(channel(), invocation(), OutcomeResult::done(done.clone()));
    let bytes = body(&encode_frame(&outcome).unwrap_or_default());
    assert_eq!(
        BrokerOutcome::decode_frame_body(&bytes).map(|o| o.result()),
        Ok(OutcomeResult::done(done))
    );
    for refusal in [
        BrokerRefusal::RuntimeUnavailable,
        BrokerRefusal::ImageMissing,
        BrokerRefusal::TopologyUnavailable,
        BrokerRefusal::ForeignEnvironment,
    ] {
        let outcome = BrokerOutcome::new(channel(), invocation(), OutcomeResult::Refused(refusal));
        let bytes = body(&encode_frame(&outcome).unwrap_or_default());
        assert_eq!(
            BrokerOutcome::decode_frame_body(&bytes).map(|o| o.result()),
            Ok(OutcomeResult::Refused(refusal))
        );
    }
    let unknown = BrokerOutcome::new(
        channel(),
        invocation(),
        OutcomeResult::Indeterminate(Indeterminate::EnvironmentUnconfirmed),
    );
    assert!(encode_frame(&unknown).is_ok());
}
