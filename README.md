# RotMG Meter

RotMG Meter is an in-progress Rust project for analyzing Realm of the Mad God
captures. It currently inspects classic PCAP metadata and counts TCP segments
from Ethernet IPv4 and IPv6 packets. It does not yet reassemble TCP streams,
decode RotMG traffic, or calculate combat statistics.

## Build and test

```sh
cargo test
cargo run -- inspect rotmg.pcap
cargo run -- inspect rotmg2.pcap
cargo run -- inspect rotmg.pcap rotmg2.pcap
cargo test local_capture_packets_include_parseable_tcp_segments -- --ignored --nocapture
```

The automated tests use generated in-memory PCAP data and do not require the
private capture files. Keep personal captures local; the repository ignores
`*.pcap` files.

The final test command explicitly runs the ignored local integration test over
both `rotmg.pcap` and `rotmg2.pcap`. It checks that each is Ethernet and that
TCP segments can be extracted; it does not decode application messages.

The inspector reports PCAP version, link-layer type, snapshot length, packet
count, timestamp endpoints, total captured and original packet bytes, packet
truncation, and TCP parsing counts. It does not print packet payloads. IPv4
and IPv6 fragments are reported because IP reassembly is not implemented.
TCP counts currently include every IPv4/IPv6 TCP packet in the capture,
including packets without application payload; connections are not filtered by
service or deduplicated.
