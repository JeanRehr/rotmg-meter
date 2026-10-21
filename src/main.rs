mod capture;
mod transport;

use pcap_file::DataLink;
use std::fs::File;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;
use transport::{IgnoreReason, PacketOutcome, parse_ethernet_packet};

fn main() -> ExitCode {
    match run(std::env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run(mut args: impl Iterator<Item = String>) -> Result<(), Box<dyn std::error::Error>> {
    let Some(command) = args.next() else {
        return Err("usage: rotmg-meter inspect <capture.pcap> [capture.pcap ...]".into());
    };
    if command != "inspect" {
        return Err(format!("unknown command {command:?}; expected `inspect`").into());
    }

    let paths: Vec<String> = args.collect();
    if paths.is_empty() {
        return Err("usage: rotmg-meter inspect <capture.pcap> [capture.pcap ...]".into());
    }

    let mut had_error = false;
    for path in paths {
        match inspect_path(&path) {
            Ok(()) => {}
            Err(error) => {
                eprintln!("{path}: {error}");
                had_error = true;
            }
        }
    }

    if had_error {
        return Err("one or more captures could not be inspected".into());
    }
    Ok(())
}

fn inspect_path(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let mut tcp_segments = 0_u64;
    let mut non_tcp_packets = 0_u64;
    let mut fragmented_packets = 0_u64;
    let mut unsupported_network_packets = 0_u64;
    let mut unsupported_link_packets = 0_u64;
    let mut malformed_packets = 0_u64;
    let summary = capture::visit_pcap(file, |link_type, timestamp, packet| {
        if link_type != DataLink::ETHERNET {
            unsupported_link_packets += 1;
            return;
        }
        match parse_ethernet_packet(timestamp, packet) {
            Ok(PacketOutcome::Tcp(_)) => tcp_segments += 1,
            Ok(PacketOutcome::Ignored(IgnoreReason::NonTcp)) => non_tcp_packets += 1,
            Ok(PacketOutcome::Ignored(IgnoreReason::Fragmented)) => fragmented_packets += 1,
            Ok(PacketOutcome::Ignored(IgnoreReason::UnsupportedNetwork)) => {
                unsupported_network_packets += 1;
            }
            Err(_) => malformed_packets += 1,
        }
    })?;
    println!("{}", Path::new(path).display());
    println!(
        "  format: classic PCAP {}.{}",
        summary.version.0, summary.version.1
    );
    println!("  link type: {}", summary.link_type);
    println!("  snaplen: {} bytes", summary.snaplen);
    println!("  packets: {}", summary.packet_count);
    println!(
        "  timestamps: {} .. {}",
        format_timestamp(summary.earliest_packet),
        format_timestamp(summary.latest_packet)
    );
    println!("  captured bytes: {}", summary.captured_bytes);
    println!("  original bytes: {}", summary.original_bytes);
    println!("  truncated records: {}", summary.truncated_packets);
    println!("  TCP segments: {tcp_segments}");
    println!("  non-TCP packets: {non_tcp_packets}");
    println!("  fragmented IP packets: {fragmented_packets}");
    println!("  unsupported network packets: {unsupported_network_packets}");
    println!("  unsupported link-layer packets: {unsupported_link_packets}");
    println!("  malformed network packets: {malformed_packets}");
    Ok(())
}

fn format_timestamp(timestamp: Option<Duration>) -> String {
    timestamp.map_or_else(
        || "none".to_owned(),
        |time| format!("{}.{:09}", time.as_secs(), time.subsec_nanos()),
    )
}
