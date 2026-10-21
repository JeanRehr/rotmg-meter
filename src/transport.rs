//! Parse Ethernet packets into borrowed TCP segments.

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
        FlowDirection, FlowKey, IgnoreReason, PacketOutcome, TcpFlags, parse_ethernet_packet,
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
