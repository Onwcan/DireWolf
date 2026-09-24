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
        OutcomeResult::Done(done.clone()),
        OutcomeResult::Refused(BrokerRefusal::IdentityMismatch),
        OutcomeResult::Indeterminate(Indeterminate::RestoreFailed),
    ] {
        let outcome = BrokerOutcome::new(channel(), invocation(), result.clone());
        let bytes = body(&encode_frame(&outcome).unwrap_or_default());
        let decoded = BrokerOutcome::decode_frame_body(&bytes);
        assert_eq!(decoded.map(|o| o.result()), Ok(result));
    }
    let mut both = BrokerOutcome::new(channel(), invocation(), OutcomeResult::Done(done));
    both.refused = Some(BrokerRefusal::ReadFailed);
    assert!(encode_frame(&both).is_err());
    let none = r#"{"channel":"0123456789abcdef0123456789abcdef","invocation_id":"inv_01M24BB8G3E0A851TRWE3M8FZF","kind":"broker.outcome","protocol":2}"#;
    assert!(BrokerOutcome::decode_frame_body(none.as_bytes()).is_err());
    // A done names exactly one operation.
    let two = r#"{"channel":"0123456789abcdef0123456789abcdef","done":{"fs_move":{},"fs_delete":{"debris":false}},"invocation_id":"inv_01M24BB8G3E0A851TRWE3M8FZF","kind":"broker.outcome","protocol":2}"#;
    assert!(BrokerOutcome::decode_frame_body(two.as_bytes()).is_err());
}

#[test]
fn unknown_members_old_versions_and_second_spellings_are_refused() {
    for text in [
        r#"{"channel":"0123456789abcdef0123456789abcdef","kind":"broker.hello","protocol":2,"extra":1}"#,
        r#"{"channel":"0123456789ABCDEF0123456789ABCDEF","kind":"broker.hello","protocol":2}"#,
        // Version 1 is not half-understood.
        r#"{"channel":"0123456789abcdef0123456789abcdef","kind":"broker.hello","protocol":1}"#,
        r#"{"channel":"0123456789abcdef0123456789abcdef","kind":"broker.hello","protocol":3}"#,
        r#"{"channel":"0123456789abcdef0123456789abcdef","kind":"broker.hello","kind":"broker.hello","protocol":2}"#,
    ] {
        assert!(
            BrokerHello::decode_frame_body(text.as_bytes()).is_err(),
            "{text}"
        );
    }
    // An unknown kind is not an authorisation.
    let unknown = r#"{"kind":"broker.fs_chmod","protocol":2}"#;
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
    let outcome = BrokerOutcome::new(channel(), invocation(), OutcomeResult::Done(done));
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
