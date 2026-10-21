//! Parse Ethernet packets into borrowed TCP segments.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};

/// Result of classifying one Ethernet packet record.
#[derive(Debug, Eq, PartialEq)]
pub enum PacketOutcome<'a> {
    Tcp(TcpSegment<'a>),
    Ignored(IgnoreReason),
}

/// Reason an otherwise valid packet did not produce a TCP segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IgnoreReason {
    /// The network packet is not IPv4 or IPv6.
    UnsupportedNetwork,
    /// The IP packet was fragmented and needs IP reassembly first.
    Fragmented,
    /// The packet does not contain a decoded TCP segment.
    NonTcp,
}

/// TCP control bits, matching the bit positions in the TCP header.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TcpFlags(pub u16);

impl TcpFlags {
    pub const FIN: u16 = 0x001;
    pub const SYN: u16 = 0x002;
    pub const RST: u16 = 0x004;
    pub const PSH: u16 = 0x008;
    pub const ACK: u16 = 0x010;
    pub const URG: u16 = 0x020;
    pub const ECE: u16 = 0x040;
    pub const CWR: u16 = 0x080;
    pub const NS: u16 = 0x100;
}

/// A TCP segment borrowing its payload from the capture packet.
#[derive(Debug, Eq, PartialEq)]
pub struct TcpSegment<'a> {
    pub timestamp: Duration,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub flags: TcpFlags,
    pub payload: &'a [u8],
}

/// Canonical endpoint order for one direction of a bidirectional TCP flow.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FlowKey {
    /// The endpoint that sorts first by `SocketAddr` ordering.
    pub a: SocketAddr,
    /// The endpoint that sorts second by `SocketAddr` ordering.
    pub b: SocketAddr,
}

/// A segment's direction relative to a canonical [`FlowKey`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowDirection {
    /// From endpoint `a` to endpoint `b`.
    AtoB,
    /// From endpoint `b` to endpoint `a`.
    BtoA,
}

impl FlowKey {
    /// Build a bidirectional flow key from a segment's observed endpoints.
    pub fn for_segment(segment: &TcpSegment<'_>) -> Self {
        if segment.source <= segment.destination {
            Self {
                a: segment.source,
                b: segment.destination,
            }
        } else {
            Self {
                a: segment.destination,
                b: segment.source,
            }
        }
    }

    /// Return the segment direction relative to this key, or `None` if it
    /// belongs to a different endpoint tuple.
    pub fn direction_of(&self, segment: &TcpSegment<'_>) -> Option<FlowDirection> {
        if segment.source == self.a && segment.destination == self.b {
            Some(FlowDirection::AtoB)
        } else if segment.source == self.b && segment.destination == self.a {
            Some(FlowDirection::BtoA)
        } else {
            None
        }
    }
}

/// Return a segment's payload offset relative to `origin` using TCP serial
/// number arithmetic. SYN consumes one sequence number before payload bytes.
///
/// Returns `None` when the distance is exactly half the sequence number space,
/// because that distance has no unambiguous forward or backward direction.
pub fn payload_offset(origin: u32, sequence_number: u32, syn: bool) -> Option<i32> {
    let payload_sequence = sequence_number.wrapping_add(u32::from(syn));
    let distance = payload_sequence.wrapping_sub(origin);
    if distance == (1 << 31) {
        None
    } else {
        Some(distance as i32)
    }
}

/// An error encountered while adding a TCP segment to a direction stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReassemblyError {
    /// The sequence number is exactly half the sequence space from the origin.
    AmbiguousSequenceNumber,
    /// A pending byte was retransmitted with a different value.
    ConflictingOverlap,
    /// Pending out-of-order data would exceed the configured byte limit.
    BufferLimitExceeded,
    /// The stream offset exceeded the supported signed offset range.
    OffsetOverflow,
}

/// Reassembles payload bytes for one TCP direction from a known payload origin.
///
/// The origin is the sequence number of the first payload byte. Pending bytes
/// are bounded by `max_pending_bytes`; contiguous bytes are returned by
/// [`push`](Self::push). Old bytes before the next undelivered offset are
/// ignored because emitted bytes are not retained for overlap comparison.
#[derive(Debug)]
pub struct TcpDirectionReassembler {
    origin: u32,
    next_offset: i64,
    max_pending_bytes: usize,
    pending: BTreeMap<i64, u8>,
}

impl TcpDirectionReassembler {
    /// Create a stream whose origin is the sequence number of its first payload
    /// byte, with a limit on buffered out-of-order bytes.
    pub fn new(origin: u32, max_pending_bytes: usize) -> Self {
        Self {
            origin,
            next_offset: 0,
            max_pending_bytes,
            pending: BTreeMap::new(),
        }
    }

    /// Add payload from a segment and return newly contiguous bytes.
    ///
    /// Identical overlaps among pending bytes are treated as retransmissions.
    /// Conflicting pending overlaps and buffer limit violations leave the
    /// stream unchanged.
    pub fn push(
        &mut self,
        sequence_number: u32,
        syn: bool,
        payload: &[u8],
    ) -> Result<Vec<u8>, ReassemblyError> {
        if payload.is_empty() {
            return Ok(Vec::new());
        }

        let offset = payload_offset(self.origin, sequence_number, syn)
            .ok_or(ReassemblyError::AmbiguousSequenceNumber)?;
        let mut prospective = self.pending.clone();

        for (index, byte) in payload.iter().copied().enumerate() {
            let index = i64::try_from(index).map_err(|_| ReassemblyError::OffsetOverflow)?;
            let byte_offset = i64::from(offset)
                .checked_add(index)
                .ok_or(ReassemblyError::OffsetOverflow)?;
            if byte_offset < self.next_offset {
                continue;
            }

            if let Some(existing) = prospective.get(&byte_offset) {
                if *existing != byte {
                    return Err(ReassemblyError::ConflictingOverlap);
                }
            } else {
                prospective.insert(byte_offset, byte);
            }
        }

        let mut next_offset = self.next_offset;
        let mut contiguous = Vec::new();
        while let Some(byte) = prospective.remove(&next_offset) {
            contiguous.push(byte);
            next_offset = next_offset
                .checked_add(1)
                .ok_or(ReassemblyError::OffsetOverflow)?;
        }

        if prospective.len() > self.max_pending_bytes {
            return Err(ReassemblyError::BufferLimitExceeded);
        }

        self.pending = prospective;
        self.next_offset = next_offset;
        Ok(contiguous)
    }
}

/// Parse one Ethernet packet into a TCP segment or a reason it was skipped.
///
/// Malformed or truncated packet headers return `InvalidData`. IP fragments
/// are reported as ignored because they must be reassembled before TCP parsing.
pub fn parse_ethernet_packet<'a>(
    timestamp: Duration,
    packet: &'a [u8],
) -> io::Result<PacketOutcome<'a>> {
    let sliced = SlicedPacket::from_ethernet(packet).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed Ethernet packet: {error}"),
        )
    })?;

    let Some(network) = sliced.net.as_ref() else {
        return Ok(PacketOutcome::Ignored(IgnoreReason::UnsupportedNetwork));
    };
    if network
        .ip_payload_ref()
        .is_some_and(|payload| payload.fragmented)
    {
        return Ok(PacketOutcome::Ignored(IgnoreReason::Fragmented));
    }

    let (source_ip, destination_ip) = match network {
        NetSlice::Ipv4(ipv4) => (
            IpAddr::V4(Ipv4Addr::from(ipv4.header().source())),
            IpAddr::V4(Ipv4Addr::from(ipv4.header().destination())),
        ),
        NetSlice::Ipv6(ipv6) => (
            IpAddr::V6(Ipv6Addr::from(ipv6.header().source())),
            IpAddr::V6(Ipv6Addr::from(ipv6.header().destination())),
        ),
        NetSlice::Arp(_) => {
            return Ok(PacketOutcome::Ignored(IgnoreReason::UnsupportedNetwork));
        }
    };

    let Some(TransportSlice::Tcp(tcp)) = sliced.transport else {
        return Ok(PacketOutcome::Ignored(IgnoreReason::NonTcp));
    };

    let mut bits = 0;
    for (set, bit) in [
        (tcp.fin(), TcpFlags::FIN),
        (tcp.syn(), TcpFlags::SYN),
        (tcp.rst(), TcpFlags::RST),
        (tcp.psh(), TcpFlags::PSH),
        (tcp.ack(), TcpFlags::ACK),
        (tcp.urg(), TcpFlags::URG),
        (tcp.ece(), TcpFlags::ECE),
        (tcp.cwr(), TcpFlags::CWR),
        (tcp.ns(), TcpFlags::NS),
    ] {
        if set {
            bits |= bit;
        }
    }

    Ok(PacketOutcome::Tcp(TcpSegment {
        timestamp,
        source: SocketAddr::new(source_ip, tcp.source_port()),
        destination: SocketAddr::new(destination_ip, tcp.destination_port()),
        sequence_number: tcp.sequence_number(),
        acknowledgment_number: tcp.acknowledgment_number(),
        flags: TcpFlags(bits),
        payload: tcp.payload(),
    }))
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::path::PathBuf;
    use std::time::Duration;

    use etherparse::{PacketBuilder, TcpHeader};

    use super::{
        FlowDirection, FlowKey, IgnoreReason, PacketOutcome, ReassemblyError,
        TcpDirectionReassembler, TcpFlags, parse_ethernet_packet, payload_offset,
    };

    fn ipv4_tcp_packet(payload: &[u8]) -> Vec<u8> {
        let mut tcp = TcpHeader::new(41_000, 2_050, 1234, 4096);
        tcp.ack = true;
        tcp.psh = true;
        tcp.acknowledgment_number = 5678;
        let builder = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4([192, 0, 2, 10], [198, 51, 100, 20], 64)
            .tcp_header(tcp);
        let mut packet = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut packet, payload).unwrap();
        packet
    }

    #[test]
    fn extracts_tcp_metadata_and_borrowed_payload_from_ipv4() {
        let bytes = ipv4_tcp_packet(&[0xaa, 0xbb]);
        let outcome = parse_ethernet_packet(Duration::from_secs(9), &bytes).unwrap();
        let PacketOutcome::Tcp(segment) = outcome else {
            panic!("expected a TCP segment");
        };

        assert_eq!(segment.timestamp, Duration::from_secs(9));
        assert_eq!(
            segment.source,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 41_000)
        );
        assert_eq!(
            segment.destination,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)), 2_050)
        );
        assert_eq!(segment.sequence_number, 1234);
        assert_eq!(segment.acknowledgment_number, 5678);
        assert_eq!(segment.flags, TcpFlags(TcpFlags::ACK | TcpFlags::PSH));
        assert_eq!(segment.payload, &[0xaa, 0xbb]);
    }

    #[test]
    fn flow_key_is_bidirectional_and_reports_segment_direction() {
        let outbound = ipv4_tcp_packet(&[]);
        let mut inbound = outbound.clone();
        // Reverse IPv4 addresses and TCP ports while preserving the packet shape.
        inbound[26..30].copy_from_slice(&[198, 51, 100, 20]);
        inbound[30..34].copy_from_slice(&[192, 0, 2, 10]);
        inbound[34..36].copy_from_slice(&2_050_u16.to_be_bytes());
        inbound[36..38].copy_from_slice(&41_000_u16.to_be_bytes());

        let PacketOutcome::Tcp(outbound) =
            parse_ethernet_packet(Duration::ZERO, &outbound).unwrap()
        else {
            panic!("expected outbound TCP segment");
        };
        let PacketOutcome::Tcp(inbound) = parse_ethernet_packet(Duration::ZERO, &inbound).unwrap()
        else {
            panic!("expected inbound TCP segment");
        };

        let key = FlowKey::for_segment(&outbound);
        assert_eq!(key, FlowKey::for_segment(&inbound));
        assert_eq!(key.direction_of(&outbound), Some(FlowDirection::AtoB));
        assert_eq!(key.direction_of(&inbound), Some(FlowDirection::BtoA));
    }

    #[test]
    fn flow_key_distinguishes_different_endpoint_tuples() {
        let first = ipv4_tcp_packet(&[]);
        let mut other = first.clone();
        other[37] ^= 1; // Change the destination port.

        let PacketOutcome::Tcp(first) = parse_ethernet_packet(Duration::ZERO, &first).unwrap()
        else {
            panic!("expected TCP segment");
        };
        let PacketOutcome::Tcp(other) = parse_ethernet_packet(Duration::ZERO, &other).unwrap()
        else {
            panic!("expected TCP segment");
        };

        assert_ne!(FlowKey::for_segment(&first), FlowKey::for_segment(&other));
        assert_eq!(FlowKey::for_segment(&first).direction_of(&other), None);
    }

    #[test]
    fn payload_offset_handles_forward_and_backward_sequence_numbers() {
        assert_eq!(payload_offset(100, 103, false), Some(3));
        assert_eq!(payload_offset(100, 98, false), Some(-2));
    }

    #[test]
    fn payload_offset_handles_sequence_number_wraparound() {
        assert_eq!(payload_offset(u32::MAX - 1, 1, false), Some(3));
        assert_eq!(payload_offset(1, u32::MAX - 1, false), Some(-3));
    }

    #[test]
    fn payload_offset_accounts_for_syn_consuming_one_sequence_number() {
        assert_eq!(payload_offset(100, 100, false), Some(0));
        assert_eq!(payload_offset(100, 100, true), Some(1));
    }

    #[test]
    fn payload_offset_rejects_ambiguous_half_space_distance() {
        assert_eq!(payload_offset(0, 1 << 31, false), None);
    }

    #[test]
    fn reassembler_emits_out_of_order_payload_when_gap_fills() {
        let mut stream = TcpDirectionReassembler::new(100, 8);

        assert_eq!(stream.push(103, false, b"def"), Ok(Vec::new()));
        assert_eq!(stream.push(100, false, b"abc"), Ok(b"abcdef".to_vec()));
    }

    #[test]
    fn reassembler_ignores_identical_retransmissions_while_pending() {
        let mut stream = TcpDirectionReassembler::new(100, 8);

        assert_eq!(stream.push(103, false, b"def"), Ok(Vec::new()));
        assert_eq!(stream.push(103, false, b"def"), Ok(Vec::new()));
        assert_eq!(stream.push(100, false, b"abc"), Ok(b"abcdef".to_vec()));
    }

    #[test]
    fn reassembler_reports_conflicting_pending_overlaps() {
        let mut stream = TcpDirectionReassembler::new(100, 8);

        assert_eq!(stream.push(103, false, b"def"), Ok(Vec::new()));
        assert_eq!(
            stream.push(104, false, b"X"),
            Err(ReassemblyError::ConflictingOverlap)
        );
        assert_eq!(stream.push(100, false, b"abc"), Ok(b"abcdef".to_vec()));
    }

    #[test]
    fn reassembler_rejects_pending_data_over_buffer_limit() {
        let mut stream = TcpDirectionReassembler::new(100, 2);

        assert_eq!(
            stream.push(103, false, b"def"),
            Err(ReassemblyError::BufferLimitExceeded)
        );
        assert_eq!(stream.push(100, false, b"abc"), Ok(b"abc".to_vec()));
    }

    #[test]
    fn reassembler_places_syn_payload_after_syn_sequence_number() {
        let mut stream = TcpDirectionReassembler::new(101, 8);

        assert_eq!(stream.push(100, true, b"abc"), Ok(b"abc".to_vec()));
    }

    #[test]
    fn extracts_tcp_endpoints_from_ipv6() {
        let builder = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv6(
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
                64,
            )
            .tcp(51_234, 2_050, 8, 9);
        let mut bytes = Vec::with_capacity(builder.size(0));
        builder.write(&mut bytes, &[]).unwrap();

        let outcome = parse_ethernet_packet(Duration::ZERO, &bytes).unwrap();
        let PacketOutcome::Tcp(segment) = outcome else {
            panic!("expected a TCP segment");
        };

        assert_eq!(
            segment.source,
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                51_234,
            )
        );
        assert_eq!(segment.sequence_number, 8);
        assert_eq!(segment.flags, TcpFlags::default());
    }

    #[test]
    fn ignores_non_tcp_packets() {
        let builder = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4([192, 0, 2, 1], [192, 0, 2, 2], 64)
            .udp(1000, 2000);
        let mut bytes = Vec::with_capacity(builder.size(1));
        builder.write(&mut bytes, &[0]).unwrap();

        assert_eq!(
            parse_ethernet_packet(Duration::ZERO, &bytes).unwrap(),
            PacketOutcome::Ignored(IgnoreReason::NonTcp),
        );
    }

    #[test]
    fn reports_fragmented_ip_packets_without_misparsing_tcp() {
        let mut packet = ipv4_tcp_packet(&[1, 2, 3, 4]);
        packet[20] = 0x20; // IPv4 more-fragments flag.

        assert_eq!(
            parse_ethernet_packet(Duration::ZERO, &packet).unwrap(),
            PacketOutcome::Ignored(IgnoreReason::Fragmented),
        );
    }

    #[test]
    fn rejects_truncated_ethernet_ip_and_tcp_headers() {
        for packet in [vec![], vec![0; 10], ipv4_tcp_packet(&[])[..30].to_vec()] {
            assert!(parse_ethernet_packet(Duration::ZERO, &packet).is_err());
        }
    }

    #[test]
    #[ignore = "requires the private PCAP files in the project root"]
    fn local_capture_packets_include_parseable_tcp_segments() {
        for filename in ["rotmg.pcap", "rotmg2.pcap"] {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(filename);
            let file = File::open(&path).unwrap_or_else(|error| {
                panic!("could not open local capture {}: {error}", path.display())
            });
            let mut tcp_segments = 0_u64;
            let mut malformed_packets = 0_u64;
            let summary = crate::capture::visit_pcap(file, |link_type, timestamp, packet| {
                if link_type != pcap_file::DataLink::ETHERNET {
                    return;
                }
                match parse_ethernet_packet(timestamp, packet) {
                    Ok(PacketOutcome::Tcp(_)) => tcp_segments += 1,
                    Ok(PacketOutcome::Ignored(_)) => {}
                    Err(_) => malformed_packets += 1,
                }
            })
            .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));

            assert_eq!(summary.link_type, "ETHERNET", "{}", path.display());
            assert!(
                tcp_segments > 0,
                "no TCP segments found in {}",
                path.display()
            );
            eprintln!(
                "{}: {} TCP segments, {} malformed packet records",
                path.display(),
                tcp_segments,
                malformed_packets
            );
        }
    }
}
