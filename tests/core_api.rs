use rotmg_meter::transport::{TcpDirectionReassembler, payload_offset};

#[test]
fn downstream_code_can_use_tcp_sequence_and_reassembly_apis() {
    assert_eq!(payload_offset(100, 102, false), Some(2));

    let mut stream = TcpDirectionReassembler::new(100, 16);
    assert_eq!(stream.push(102, false, b"cd"), Ok(Vec::new()));
    assert_eq!(stream.push(100, false, b"ab"), Ok(b"abcd".to_vec()));
}
