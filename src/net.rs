use std::net::IpAddr;
use std::collections::BTreeMap;

/// One endpoint of a TCP connection.
/// 
/// Example:
///
///     111.111.1.11:11111
///     22.222.222.22:2222
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct TcpEndpoint {
    pub ip: IpAddr,
    pub port: u16,
}

/// The direction of traffic inside a connection.
#[derive(Debug, Clone, Copy)]
pub enum TcpDirection {
    ClientToServer,
    ServerToClient,
}

/// A bidirectional TCP connection.
#[derive(Debug, Hash, PartialEq, Eq)]
pub struct TcpConnection {
    pub client: TcpEndpoint,
    pub server: TcpEndpoint,
}

impl TcpConnection {
    /// Try to create a RotMG connection from two TCP endpoints.
    pub fn from_endpoints(
        source: TcpEndpoint,
        destination: TcpEndpoint,
    ) -> Option<(Self, TcpDirection)> {
        // TCP port numbers are 16bit fields in the TCP header
        const ROTMG_PORT: u16 = 2050;

        // Destination is port 2050, packet is going from client to server
        if destination.port == ROTMG_PORT {
            let connection: TcpConnection = TcpConnection {
                client: source,
                server: destination,
            };

            return Some((connection, TcpDirection::ClientToServer));
        }

        // Source is port 2050, packet is going from server to client
        if source.port == ROTMG_PORT {
            let connection: TcpConnection = TcpConnection {
                client: destination,
                server: source,
            };

            return Some((connection, TcpDirection::ServerToClient));
        }

        // No endpoint is port 2050
        None
    }
}

/// One TCP segment after we have parsed it.
#[derive(Debug)]
pub struct TcpSegment {
    /// Sequence number of the first data byte in the segment
    pub sequence_number: u32,
    /// Next sequence number the sender expects to receive 
    pub acknowledge_number: u32,

    /// Synchronize sequence numbers
    pub syn: bool,
    /// Acknowledgment field
    pub ack: bool,
    /// If it should push
    pub psh: bool,
    /// Final flag (no more data should be coming)
    pub fin: bool,
    /// Reset the connection
    pub rst: bool,

    /// TCP payload
    pub payload: Vec<u8>,
}

/// Reconstructs a TCP byte stream from TCP segments
#[derive(Debug)]
pub struct TcpStream {
    /// The sequence number of the next byte we want
    pub next_sequence_number: Option<u32>,

    /// Segments that arrived before we had preceding bytes
    pub pending_segments: BTreeMap<u32, Vec<u8>>,

    /// Bytes that have been successfully reconstructed
    pub data: Vec<u8>,
}

impl TcpStream {
    /// Create an empty TCP stream
    pub fn new() -> Self {
        TcpStream {
            next_sequence_number: None,
            pending_segments: BTreeMap::new(),
            data: Vec::new(),
        }
    }

    /// Add one TCP segment to the stream
    /// 
    /// Returns true if some new application data was reconstructed
    pub fn push_segment(&mut self, segment: TcpSegment) -> bool {
        // A segment with no payload contains no application bytes
        if segment.payload.is_empty() {
            return false;
        }

        // First payload bearing segment, use its sequence number as the beginning of stream
        if self.next_sequence_number.is_none() {
            let payload_length: u32 = segment.payload.len() as u32;

            self.next_sequence_number = Some(segment.sequence_number + payload_length);

            self.data.extend_from_slice(&segment.payload);

            return true;
        }

        // We know logically that immediately before this code it can't be None
        // Later it can be written more idiomatically without relying on unwrap()
        let next_sequence_number: u32 = self.next_sequence_number.unwrap();

        // This segment begins where we expect
        if segment.sequence_number == next_sequence_number {
            let payload_length: u32 = segment.payload.len() as u32;

            self.data.extend_from_slice(&segment.payload);

            self.next_sequence_number = Some(next_sequence_number + payload_length);

            self.consume_pending_segments();

            return true;
        }

        // This segment start after the byte we are currently expecting. Therefore there is a gap
        if segment.sequence_number > next_sequence_number {
            self.pending_segments.insert(segment.sequence_number, segment.payload);

            return false;
        }

        // The segment start before the byte we expect

        // For now assume this is a retransmission or overlapping segment, ignore it.
        return false
    }

    /// Move any now contiguous pending segments into the stream.
    fn consume_pending_segments(&mut self) {
        loop {
            let next_sequence_number: u32 = match self.next_sequence_number {
                Some(sequence_number) => sequence_number,
                None => return,
            };

            let pending_payload: Vec<u8> = match self.pending_segments.remove(&next_sequence_number) {
                Some(payload) => payload,
                None => return,
            };

            let payload_length: u32 = pending_payload.len() as u32;

            self.data.extend_from_slice(&pending_payload);

            self.next_sequence_number = Some(next_sequence_number + payload_length);
        }
    }

    /*
     * Now, this is intentionally not our final TCP implementation.
     * There are important limitations:
     * - retransmission handling is simplistic
     * - overlapping segments are ignored
     * - sequence-number wraparound isn't handled
     * - SYN/FIN sequence-space consumption isn't handled
     * - capture loss isn't distinguished from out-of-order delivery
     */
}
