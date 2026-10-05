//! This program right now needs a local .pcap file, I grabbed one with `sudo tcpdump -i enp8s0 -w rotmg.pcap`
//! This is only for debugging and learning right now, not really useful at this stage.

use std::env;
use std::fs::File;
use std::net::IpAddr;
use std::process::ExitCode;

use etherparse::SlicedPacket;
use pcap_file::pcap::PcapReader;

mod net;

use crate::net::{TcpConnection, TcpDirection, TcpEndpoint};

fn main() -> ExitCode {
    // Read the capture filename from the command line
    // 
    // Example:
    //     cargo run -- rotmg.pcap
    let filename: String = match env::args().nth(1) {
        Some(filename) => filename,
        None => {
            eprintln!("usage: rotmg-meter <capture.pcap>"); 
            return ExitCode::FAILURE;
        }
    };

    let file: File = match File::open(&filename) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("failed to open {filename}: {error}");
            return ExitCode::FAILURE;
        }
    };

    let mut reader: PcapReader<File> = match PcapReader::new(file) {
        Ok(reader) => reader,
        Err(error) => {
            eprintln!("failed to read pcap header: {error}");
            return ExitCode::FAILURE;
        }
    };

    // Tell us what kind of link-layer packets are stored in the capture.
    //
    // With the capture made using:
    //
    //     tcpdump -i enp8s0 -w rotmg.pcap
    //
    // expected this to be ETHERNET.
    println!(
        "capture data-link type: {:?}",
        reader.header().datalink
    );

    // This is my specific game connection identified from ss command
    // and from the packet counts in the capture.
    let game_client_ip: IpAddr = "192.168.1.6".parse().expect("Invalid local IP");
    let game_server_ip: IpAddr = "54.234.250.75".parse().expect("Invalid game server IP");
    let game_client_port: u16 = 57168;
    let game_server_port: u16 = 2050;

    // Count how many pcap records we process.
    let mut packet_count: usize = 0;

    // Count how many packets belong to our game connection.
    let mut game_packet_count: usize = 0;

    // Count only packets that actually contain TCP payload.
    let mut game_payload_packet_count: usize = 0;

    // We only want to print the first few payload-bearing packets.
    //
    // Otherwise a capture with thousands of packets would produce
    // an enormous amount of output.
    let max_payload_packets_to_print: usize = 30;

    // next_packet() returns:
    //
    //  Some(Ok(packet))    -> another packet was successfully read
    //  Some(Err(error))    -> another packet existed, but reading failed
    //  None                -> we reached the end of the file     
    while let Some(packet_result) = reader.next_packet() {
        let packet = match packet_result {
            Ok(packet) => packet,
            Err(error) => {
                eprintln!("failed to read packet: {error}");
                return ExitCode::FAILURE;
            }
        };
       
        packet_count += 1;

        // Parse the packet starting at an Ethernet II header
        // SlicedPacket does not copy packet data. It creates
        // slices into the original bytes
        let parsed: SlicedPacket<'_> =
            match SlicedPacket::from_ethernet(packet.data.as_ref()) {
                Ok(parsed) => parsed,
                Err(error) => {
                    eprintln!("packet #{packet_count}: failed to parse Ethernet frame: {error}");
                    continue;
                }
            };

        // Determine whether the network layer is IPv4 or IPv6
        let (source_ip, destination_ip): (IpAddr, IpAddr) = match &parsed.net {
            Some(etherparse::NetSlice::Ipv4(ipv4)) => {
                (
                    IpAddr::V4(ipv4.header().source_addr()),
                    IpAddr::V4(ipv4.header().destination_addr()),
                )
            }
            
            Some(etherparse::NetSlice::Ipv6(ipv6)) => {
                (
                    IpAddr::V6(ipv6.header().source_addr()),
                    IpAddr::V6(ipv6.header().destination_addr()),
                )
            }
            
            Some(etherparse::NetSlice::Arp(_)) | None => continue,
        };

        // Inspect the transport layer, we only care about tcp
        let tcp = match &parsed.transport {
            Some(etherparse::TransportSlice::Tcp(tcp)) => tcp,
            _ => continue,
        };

        // Represent the source and destination as our own types.
        let source: TcpEndpoint = TcpEndpoint {
            ip: source_ip,
            port: tcp.source_port(),
        };

        let destination: TcpEndpoint = TcpEndpoint {
            ip: destination_ip,
            port: tcp.destination_port()
        };

        // Check whether this packet belongs to a RotMG connection
        // using TCP port 2050.
        //
        // We also get the direction of the packet here.
        let connection_info: Option<(TcpConnection, TcpDirection)> = TcpConnection::from_endpoints(source, destination);

        let (connection, direction): (TcpConnection, TcpDirection) = match connection_info {
            Some(connection_info) => connection_info,

            None => { continue; }
        };

        // Check whether this is the exact game connection from the capture
        let is_game_connection: bool =
            connection.client.ip == game_client_ip
                && connection.client.port == game_client_port
                && connection.server.ip == game_server_ip
                && connection.server.port == game_server_port;

        if !is_game_connection { continue; }

        game_packet_count += 1;

        // Get the application data carried by this TCP segment.
        //
        // This is a borrowed &[u8]. We are NOT copying it yet.
        let payload: &[u8] = tcp.payload();

        // ACK-only packets and other control packets can have zero bytes of payload. There is nothing for us to inspect
        if payload.is_empty() { continue; }

        game_payload_packet_count += 1;

        // Only print the first 30 payload bearing packets
        if game_payload_packet_count <= max_payload_packets_to_print {
            let sequence_number: u32 = tcp.sequence_number();
            let acknowledgement_number: u32 = tcp.acknowledgment_number();

            let syn: bool = tcp.syn();        
            let ack: bool = tcp.ack();
            let psh: bool = tcp.psh();
            let fin: bool = tcp.fin();
            let rst: bool = tcp.rst();

            let direction_string: &str = match direction {
                TcpDirection::ClientToServer => "C -> S",
                TcpDirection::ServerToClient => "S -> C",
            };

            println!(
                "{} | seq={:<10} ack={:<10} payload={:<4} | \
                SYN={:<5} ACK={:<5} PSH={:<5} FIN={:<5} RST={:<5}",
                direction_string,
                sequence_number,
                acknowledgement_number,
                payload.len(),
                syn,
                ack,
                psh,
                fin,
                rst,
            );

            print!("\tpayload: ");

            // Print at most the first 16 bytes so the terminal remains readable
            for byte in payload.iter().take(16) {
                print!("{byte:02X}");
            }
            println!();
        }
    }

    println!();
    println!("read {packet_count} packets");
    println!("game TCP packets: {game_packet_count}");
    println!("game payload packets: {game_payload_packet_count}");

    ExitCode::SUCCESS
}
