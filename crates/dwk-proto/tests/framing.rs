//! DWKP framing under hostile and fragmented input.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

mod common;

use dwk_proto::ErrorCode;
use dwk_proto::frame::{self, ContentType, FrameDecoder, HEADER_LEN};
use dwk_proto::limits::MAX_FRAME_BODY;

fn header(len: u32, content_type: u8) -> Vec<u8> {
    let mut h = len.to_be_bytes().to_vec();
    h.push(content_type);
    h
}

fn code(result: Result<Vec<frame::Frame>, dwk_proto::ProtocolError>) -> ErrorCode {
    result.expect_err("expected a framing error").code
}

#[test]
fn a_small_valid_frame_round_trips() {
    let encoded = frame::encode(ContentType::Json, b"{}").unwrap();
    assert_eq!(encoded, [0, 0, 0, 2, 1, b'{', b'}']);
    let frames = frame::decode_all(&encoded).unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].body, b"{}");
}

#[test]
fn an_empty_frame_is_rejected() {
    assert_eq!(
        code(frame::decode_all(&header(0, 1))),
        ErrorCode::FrameEmpty
    );
    assert_eq!(
        frame::encode(ContentType::Json, b"").unwrap_err().code,
        ErrorCode::FrameEmpty
    );
}

#[test]
fn exactly_the_maximum_body_is_accepted() {
    let body = vec![b' '; MAX_FRAME_BODY];
    let encoded = frame::encode(ContentType::Json, &body).unwrap();
    assert_eq!(encoded.len(), HEADER_LEN + MAX_FRAME_BODY);
    let frames = frame::decode_all(&encoded).unwrap();
    assert_eq!(frames[0].body.len(), MAX_FRAME_BODY);
}

#[test]
fn one_byte_over_the_maximum_is_rejected_from_the_header_alone() {
    let declared = u32::try_from(MAX_FRAME_BODY + 1).unwrap();
    // Only the header is supplied: the decision must not wait for, or buffer,
    // the body.
    let mut decoder = FrameDecoder::new();
    let err = decoder.feed(&header(declared, 1)).unwrap_err();
    assert_eq!(err.code, ErrorCode::FrameTooLarge);
    let too_big = vec![b' '; MAX_FRAME_BODY + 1];
    assert_eq!(
        frame::encode(ContentType::Json, &too_big).unwrap_err().code,
        ErrorCode::FrameTooLarge
    );
}

#[test]
fn an_absurd_declared_length_is_rejected_without_allocation() {
    let mut decoder = FrameDecoder::new();
    let err = decoder.feed(&header(u32::MAX, 1)).unwrap_err();
    assert_eq!(err.code, ErrorCode::FrameTooLarge);
}

#[test]
fn reserved_content_types_are_rejected() {
    for ct in [0x00_u8, 0x02, 0x7f, 0xff] {
        let bytes = [header(2, ct), b"{}".to_vec()].concat();
        assert_eq!(
            code(frame::decode_all(&bytes)),
            ErrorCode::ContentTypeUnsupported,
            "{ct:#x}"
        );
    }
}

#[test]
fn a_truncated_header_or_body_is_an_error_at_end_of_stream() {
    assert_eq!(
        code(frame::decode_all(&[0, 0, 0])),
        ErrorCode::FrameTruncated
    );
    let short_body = [header(10, 1), b"{}".to_vec()].concat();
    assert_eq!(
        code(frame::decode_all(&short_body)),
        ErrorCode::FrameTruncated
    );
}

#[test]
fn trailing_bytes_after_a_frame_are_an_error_not_ignored() {
    let mut bytes = frame::encode(ContentType::Json, b"{}").unwrap();
    bytes.extend_from_slice(&[0, 0]);
    assert_eq!(code(frame::decode_all(&bytes)), ErrorCode::FrameTruncated);
}

#[test]
fn concatenated_frames_decode_in_order() {
    let a = frame::encode(ContentType::Json, b"[1]").unwrap();
    let b = frame::encode(ContentType::Json, b"[2,2]").unwrap();
    let c = frame::encode(ContentType::Json, b"{}").unwrap();
    let frames = frame::decode_all(&[a, b, c].concat()).unwrap();
    let bodies: Vec<&[u8]> = frames.iter().map(|f| f.body.as_slice()).collect();
    assert_eq!(bodies, [b"[1]".as_slice(), b"[2,2]", b"{}"]);
}

#[test]
fn transport_boundaries_do_not_matter() {
    let stream = [
        frame::encode(ContentType::Json, b"[\"first\"]").unwrap(),
        frame::encode(ContentType::Json, &vec![b'1'; 70_000]).unwrap(),
        frame::encode(ContentType::Json, b"{}").unwrap(),
    ]
    .concat();
    let expected = frame::decode_all(&stream).unwrap();
    // Every chunking, including one byte at a time, yields the same frames.
    for chunk in [1_usize, 2, 3, 4, 5, 6, 7, 13, 4096, 65_536, stream.len()] {
        let mut decoder = FrameDecoder::new();
        let mut frames = Vec::new();
        for piece in stream.chunks(chunk) {
            let mut rest = piece;
            while !rest.is_empty() {
                let (used, frame) = decoder.feed(rest).unwrap();
                if let Some(f) = frame {
                    frames.push(f);
                }
                rest = &rest[used..];
            }
        }
        decoder.finish().unwrap();
        assert_eq!(frames, expected, "chunk size {chunk}");
    }
}

#[test]
fn a_framing_error_poisons_the_stream() {
    let mut decoder = FrameDecoder::new();
    assert!(decoder.feed(&header(0, 1)).is_err());
    // A valid frame after the error is not decoded: the boundary is lost, and
    // guessing where the next frame starts is how a stream gets smuggled into.
    let valid = frame::encode(ContentType::Json, b"{}").unwrap();
    assert_eq!(
        decoder.feed(&valid).unwrap_err().code,
        ErrorCode::FrameEmpty
    );
    assert!(decoder.finish().is_err());
}

#[test]
fn byte_order_is_big_endian() {
    let body = vec![b' '; 0x0102];
    let encoded = frame::encode(ContentType::Json, &body).unwrap();
    assert_eq!(&encoded[..HEADER_LEN], &[0x00, 0x00, 0x01, 0x02, 0x01]);
}
