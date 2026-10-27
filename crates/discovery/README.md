# discovery 🔍

[![CI](https://github.com/rmediatech/network_scanner/actions/workflows/discovery.yml/badge.svg)](https://github.com/rmediatech/network_scanner/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)

Core discovery engine and CLI for local network observation, ARP inspection, and TCP port scanning.

![Discovery Flow](docs/images/discovery-flow.svg)

---

## Key Behaviors

1. **Passive ARP discovery by default**: Interrogates the system ARP tables without transmitting active probes.
2. **Opt-in active ARP probing (`--probe`)**: Transmits unicast ARP requests to detect live hosts absent from local cache.
3. **Opt-in TCP port scanning (`--portscan`)**: Connect-scans discovered hosts. Built-in port range defaults to `1..=1024`, with `--fast` offering a ~100 port preset, or `--ports` accepting custom lists and ranges.
4. **Automatic Primary CIDR Discovery**: If no CIDR is specified, the CLI interrogates the system interface table to determine the primary subnet automatically.
5. **Hardware OUI Resolution & Dynamic Updates**: Discovered MAC addresses are automatically enriched with hardware manufacturer names from the 32,800+ embedded IEEE OUI database, with `--update-oui` allowing dynamic updates to the local cache.

---

## Command-Line Usage

```bash
# Auto-detect local subnet and discover passively
cargo run --bin discovery-cli

# Target specific subnet and write CSV + companion JSON files
cargo run --bin discovery-cli -- 192.168.1.0/24 --out results.csv --json

# Fast port scan against discovered hosts
cargo run --bin discovery-cli -- 192.168.1.0/24 --portscan --fast

# Explicit port list and custom timeouts
cargo run --bin discovery-cli -- 192.168.1.0/24 --portscan --ports 22,80,443,8000-8080 --timeout 2

# Dynamically update the local IEEE OUI manufacturer registry
cargo run --bin discovery-cli -- --update-oui

# Active ARP probing (requires elevated privileges)
sudo -E cargo run --bin discovery-cli -- 192.168.1.0/24 --probe --portscan
```

---

## Output Formats & Companion Files

When `--json` is specified, the CLI produces:

- `<basename>.json` — Standard array of canonical `DiscoveryRecord` objects.
- `<basename>.target.json` — Streamlined JSON structure for modern downstream ingestion.
- `<basename>.legacy.json` — Drop-in backwards-compatible JSON preserving legacy netscan field names (`IP`, `MAC`, `Vendor`, `Method`, `is_up`).

Custom target or legacy paths can be explicitly specified:
- `--out-target <FILE>`: Direct path for target JSON.
- `--out-legacy <FILE>`: Direct path for legacy JSON.

---

## Library API Example

```rust
use discovery::{Discover, LiveArpDiscover};

let discoverer = LiveArpDiscover::new("192.168.1.0/24")
    .with_workers(32)
    .with_probe(false)
    .with_timeout_secs(1);

let records = discoverer.discover();
for record in records {
    println!("Host: {} | MAC: {:?} | Vendor: {:?}", record.ip, record.mac, record.vendor);
}
```

---

## Testing

```bash
# Unit tests
cargo test -p discovery

# Integration test (loopback listener & port scan)
cargo test -p discovery --test portscan_integration

# CLI companion file test
cargo test -p discovery --test cli_companion_test

# Adversarial self-attack test
cargo test -p discovery --test adversarial_discovery_tests
```
