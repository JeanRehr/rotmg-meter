use rotmg_meter::crypto::{Rc4, Rc4Error};
use rotmg_meter::framing::{FrameDecoder, FrameError};
use rotmg_meter::transport::{TcpDirectionReassembler, payload_offset};

#[test]
fn downstream_code_can_use_tcp_sequence_and_reassembly_apis() {
    assert_eq!(payload_offset(100, 102, false), Some(2));

    let mut stream = TcpDirectionReassembler::new(100, 16);
    assert_eq!(stream.push(102, false, b"cd"), Ok(Vec::new()));
    assert_eq!(stream.push(100, false, b"ab"), Ok(b"abcd".to_vec()));
}

fn frame(packet_id: u8, body: &[u8]) -> Vec<u8> {
    let length = 5 + body.len();
    let mut frame = Vec::with_capacity(length);
    frame.extend_from_slice(&(length as i32).to_be_bytes());
    frame.push(packet_id);
    frame.extend_from_slice(body);
    frame
}

#[test]
fn public_frame_decoder_handles_split_and_coalesced_frames() {
    let first = frame(75, &[1, 2, 3]);
    let second = frame(46, &[4, 5]);
    let mut decoder = FrameDecoder::new(64).unwrap();

    assert_eq!(decoder.push(&first[..2]), Ok(Vec::new()));

    let mut rest = first[2..].to_vec();
    rest.extend_from_slice(&second);
    assert_eq!(decoder.push(&rest), Ok(vec![first, second]));
}

#[test]
fn public_frame_decoder_rejects_invalid_and_oversized_lengths_and_recovers() {
    let mut decoder = FrameDecoder::new(8).unwrap();

    assert_eq!(
        decoder.push(&4_i32.to_be_bytes()),
        Err(FrameError::InvalidLength(4))
    );
    assert_eq!(
        decoder.push(&9_i32.to_be_bytes()),
        Err(FrameError::FrameTooLarge {
            length: 9,
            maximum: 8,
        })
    );
    assert_eq!(decoder.push(&frame(75, &[])), Ok(vec![frame(75, &[])]));
    assert!(matches!(
        FrameDecoder::new(4),
        Err(FrameError::InvalidMaximumFrameSize(4))
    ));
}

#[test]
fn public_rc4_matches_a_known_vector_and_preserves_stream_state_across_chunks() {
    let expected = [
        0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27, 0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11, 0x18,
        0xa8,
    ];

    let mut whole = [0; 16];
    Rc4::new(&[1, 2, 3, 4, 5])
        .unwrap()
        .apply_keystream(&mut whole);
    assert_eq!(whole, expected);

    let mut chunked = [0; 16];
    let mut cipher = Rc4::new(&[1, 2, 3, 4, 5]).unwrap();
    cipher.apply_keystream(&mut chunked[..5]);
    cipher.apply_keystream(&mut chunked[5..]);
    assert_eq!(chunked, expected);
}

#[test]
fn public_rc4_rejects_an_empty_key() {
    assert!(matches!(Rc4::new(&[]), Err(Rc4Error::EmptyKey)));
}
