# RotMG Meter

RotMG Meter is an in-progress Rust project for analyzing Realm of the Mad God
captures. The current command inspects classic PCAP metadata and packet-record
lengths; it does not yet decode RotMG traffic or calculate combat statistics.

## Build and test

```sh
cargo test
cargo run -- inspect rotmg.pcap
cargo run -- inspect rotmg2.pcap
cargo run -- inspect rotmg.pcap rotmg2.pcap
```

The automated tests use generated in-memory PCAP data and do not require the
private capture files. Keep personal captures local; the repository ignores
`*.pcap` files.

The inspector reports PCAP version, link-layer type, snapshot length, packet
count, timestamp endpoints, total captured and original packet bytes, and the
number of truncated packet records. It does not print packet payloads.
