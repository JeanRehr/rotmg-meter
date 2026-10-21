//! Offline capture inspection.

use std::io::{self, Read};
use std::time::Duration;

use pcap_file::pcap::PcapReader;

/// Summary information that does not expose packet contents.
#[derive(Debug, Default)]
pub struct CaptureSummary {
    /// PCAP file-format version from the global header.
    pub version: (u16, u16),
    /// Link-layer type recorded in the PCAP global header.
    pub link_type: String,
    /// Maximum captured packet size from the global header.
    pub snaplen: u32,
    /// Number of packet records in the file.
    pub packet_count: u64,
    /// Earliest packet timestamp, if the capture contains packets.
    pub earliest_packet: Option<Duration>,
    /// Latest packet timestamp, if the capture contains packets.
    pub latest_packet: Option<Duration>,
    /// Sum of saved packet bytes.
    pub captured_bytes: u64,
    /// Sum of original on-wire packet lengths.
    pub original_bytes: u64,
    /// Number of records whose saved data is shorter than the original packet.
    pub truncated_packets: u64,
}

/// Visit packet records in a classic PCAP stream without retaining their bytes.
///
/// The visitor receives the file's link-layer type, each packet's timestamp,
/// and a borrowed packet slice. The returned summary contains the global
/// header metadata and record totals.
pub fn visit_pcap<R, F>(input: R, mut visitor: F) -> io::Result<CaptureSummary>
where
    R: Read,
    F: FnMut(pcap_file::DataLink, Duration, &[u8]),
{
    let invalid_capture = |error: pcap_file::PcapError| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid PCAP capture: {error}"),
        )
    };
    let mut reader = PcapReader::new(input).map_err(invalid_capture)?;
    let header = reader.header();
    let mut summary = CaptureSummary {
        version: (header.version_major, header.version_minor),
        link_type: format!("{:?}", header.datalink),
        snaplen: header.snaplen,
        ..CaptureSummary::default()
    };

    while let Some(packet) = reader.next_packet() {
        let packet = packet.map_err(invalid_capture)?;
        visitor(header.datalink, packet.timestamp, &packet.data);
        summary.packet_count = summary.packet_count.saturating_add(1);
        summary.earliest_packet = Some(
            summary
                .earliest_packet
                .map_or(packet.timestamp, |earliest| earliest.min(packet.timestamp)),
        );
        summary.latest_packet = Some(
            summary
                .latest_packet
                .map_or(packet.timestamp, |latest| latest.max(packet.timestamp)),
        );
        summary.captured_bytes = summary
            .captured_bytes
            .saturating_add(packet.data.len() as u64);
        summary.original_bytes = summary
            .original_bytes
            .saturating_add(u64::from(packet.orig_len));
        if packet.data.len() < packet.orig_len as usize {
            summary.truncated_packets = summary.truncated_packets.saturating_add(1);
        }
    }

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::time::Duration;

    use pcap_file::pcap::{PcapPacket, PcapWriter};

    use super::visit_pcap;

    fn sample_pcap() -> Vec<u8> {
        let mut writer = PcapWriter::new(Vec::new()).unwrap();
        writer
            .write_packet(&PcapPacket::new_owned(
                Duration::from_secs(6),
                4,
                vec![1, 2, 3, 4],
            ))
            .unwrap();
        writer
            .write_packet(&PcapPacket::new_owned(
                Duration::from_secs(4),
                4,
                vec![5, 6],
            ))
            .unwrap();
        writer.into_writer()
    }

    #[test]
    fn summarizes_metadata_and_truncated_packet_records() {
        let summary = visit_pcap(Cursor::new(sample_pcap()), |_, _, _| {}).unwrap();

        assert_eq!(summary.version, (2, 4));
        assert_eq!(summary.link_type, "ETHERNET");
        assert_eq!(summary.snaplen, 65_535);
        assert_eq!(summary.packet_count, 2);
        assert_eq!(summary.earliest_packet, Some(Duration::from_secs(4)));
        assert_eq!(summary.latest_packet, Some(Duration::from_secs(6)));
        assert_eq!(summary.captured_bytes, 6);
        assert_eq!(summary.original_bytes, 8);
        assert_eq!(summary.truncated_packets, 1);
    }

    #[test]
    fn rejects_malformed_pcap_data() {
        let error = visit_pcap(Cursor::new(b"not a pcap".to_vec()), |_, _, _| {}).unwrap_err();
        assert!(error.to_string().contains("capture"));
    }

    #[test]
    fn rejects_a_truncated_packet_record() {
        let mut bytes = sample_pcap();
        bytes.pop();

        let error = visit_pcap(Cursor::new(bytes), |_, _, _| {}).unwrap_err();
        assert!(error.to_string().contains("capture"));
    }

    #[test]
    fn visits_each_packet_with_its_timestamp_and_borrowed_bytes() {
        let mut visited = Vec::new();
        let summary = visit_pcap(
            Cursor::new(sample_pcap()),
            |link_type, timestamp, packet| {
                visited.push((link_type, timestamp, packet.to_vec()));
            },
        )
        .unwrap();

        assert_eq!(summary.packet_count, 2);
        assert_eq!(
            visited[0],
            (
                pcap_file::DataLink::ETHERNET,
                Duration::from_secs(6),
                vec![1, 2, 3, 4]
            )
        );
        assert_eq!(
            visited[1],
            (
                pcap_file::DataLink::ETHERNET,
                Duration::from_secs(4),
                vec![5, 6]
            )
        );
    }
}
