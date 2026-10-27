# Network Scanner 🔎🦀

[![release](https://img.shields.io/github/v/release/xuoxod/network_scanner)](https://github.com/rmediatech/network_scanner/releases)
[![CI](https://github.com/rmediatech/network_scanner/actions/workflows/discovery.yml/badge.svg)](https://github.com/rmediatech/network_scanner/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![Static Musl](https://img.shields.io/badge/Binary-Static%20Musl-success.svg)](BUILDING.md)

High-performance, auditable local network discovery and diagnostic toolkit written in pure Rust. Built on a strict **passive-first invariant**, deterministic data contracts, and zero-bloat standalone binaries.

![Discovery Flow](crates/discovery/docs/images/discovery-flow.svg)

---

## ⚡ Core Philosophy & Directives

1. **Passive-First Default**: By default, discovery operates completely passively by inspecting the local kernel ARP table (`/proc/net/arp` and `ip neigh`). Zero unsolicited packets are transmitted onto the wire unless active probes (`--probe`) or port scans (`--portscan`) are explicitly enabled.
2. **Canonical Data Contracts (`CONTRACTS.md`)**: Output is guaranteed to adhere to machine-readable formats (uniform 6-column CSV, Canonical JSON, Target JSON, and Legacy JSON) across all tools.
3. **Embedded IEEE OUI Database & Dynamic Updates**: Resolves hardware MAC addresses to manufacturer names instantly in memory via an embedded in-tree registry of 32,800+ authoritative IEEE OUI assignments. Includes dynamic cache refresh (`--update-oui`) supporting local user caching (`~/.local/share/network_scanner/oui.csv`) and custom OUI sources (`--oui-source`).
4. **Standalone Portability**: Compiles to standalone static-pie binaries via `musl` (`~2.9 MB`) requiring zero runtime dependencies, dynamically linked libraries, or glibc versions.
5. **Non-Privileged Diagnostics**: Includes `netcheck` to inspect local egress, default gateway reachability, and network interface status without requiring elevated privileges.
6. **Adversarial Self-Attack TDD Invariants**: All network parsers, CSV serialization pipelines, and CIDR sniffers are hardened against adversarial attacks: CSV formula injection (`=`, `+`, `-`, `@`), terminal ANSI escape bombs, CIDR DoS/OOM allocation attacks, and corrupted/malformed ARP cache poisoning.

---

## 🏗️ Workspace Layout & Crate Registry

The workspace is organized under strict separation of concerns:

| Crate | Purpose | Primary Components |
| :--- | :--- | :--- |
| **[`discovery`](crates/discovery)** | Discovery engine & command-line interface | `LiveArpDiscover`, `discovery-cli` binary, portscan coordinator |
| **[`netutils`](crates/netutils)** | Low-level networking & diagnostics | Interface enumeration, ARP parser/prober, TCP connect port scanner, `netcheck` binary |
| **[`io`](crates/io)** | Data adapters & OUI vendor resolver | Embedded IEEE OUI database, CSV / Target JSON / Legacy JSON serializers |
| **[`formats`](crates/formats)** | Canonical data contracts | `DiscoveryRecord`, Serde roundtrip converters, schema validators |
| **[`enrich`](crates/enrich)** | Metadata enrichment heuristics | Vendor and device classification from hostnames and banners |

```text
network_scanner/
├── Cargo.toml            # Workspace manifest (resolver = "2")
├── Makefile              # Build, test, and static musl packaging targets
├── CONTRACTS.md          # Canonical schema & format definitions
├── BUILDING.md           # Compilation guide (native, musl, cross)
├── crates/
│   ├── discovery/        # Engine & discovery-cli binary
│   ├── netutils/         # Low-level networking & netcheck binary
│   ├── io/               # Adapters, OUI vendor lookup & oui.csv
│   ├── formats/          # DiscoveryRecord schema contract
│   └── enrich/           # Metadata enrichment heuristics
└── scripts/              # Helper automation scripts
```

---

## 🚀 Quickstart

### 1. Pre-Flight Connectivity Check (`netcheck`)

Run non-privileged diagnostics to verify local outbound IP, interface status, default CIDR, and gateway reachability:

```bash
cargo run --bin netcheck
```

Example output:
```text
=== Network Scanner — NetCheck Connectivity Diagnostic ===
  Local Outbound IP: 192.168.1.160
  Primary Interface: wlp2s0 (IPv4: 192.168.1.160, MAC: 04:ea:56:9d:4f:cc, State: UP)
  Detected Local CIDR: 192.168.1.160/24
  Gateway Check (192.168.1.1): REACHABLE (TCP 80/443)
  Outbound Egress (1.1.1.1:53): REACHABLE
===========================================================
```

### 2. Passive Local Subnet Discovery (`discovery-cli`)

Discovers live hosts from the local ARP cache without sending a single probe packet. Automatically detects your primary interface CIDR when omitted:

```bash
# Auto-detect local subnet and export to CSV
cargo run --bin discovery-cli

# Explicit CIDR range with companion JSON files
cargo run --bin discovery-cli -- 192.168.1.0/24 --out results.csv --json
```

### 3. Active ARP Probes & Port Scanning (Opt-In)

> [!NOTE]
> Active network probing transmits packets on the local link. Use only on networks you own or have explicit authorization to scan.

```bash
# Fast port scan (~100 common ports) on discovered hosts
cargo run --bin discovery-cli -- 192.168.1.0/24 --portscan --fast

# Specific port list and ranges with custom timeout
cargo run --bin discovery-cli -- 192.168.1.0/24 --portscan --ports 22,80,443,8000-8080 --timeout 2

# Active ARP probing (requires root/sudo for raw socket or arping)
sudo -E cargo run --bin discovery-cli -- 192.168.1.0/24 --probe --portscan
```

### 4. Dynamic IEEE OUI Database Update

Refresh the local manufacturer database with the latest official IEEE registrations:

```bash
# Download and cache latest IEEE OUI registry
cargo run --bin discovery-cli -- --update-oui

# Or update from an alternate custom registry URL or local file
cargo run --bin discovery-cli -- --update-oui --oui-source https://custom-mirror.local/oui.csv
```

---

## 📖 CLI Reference (`discovery-cli`)

```text
Usage: discovery-cli [OPTIONS] [CIDR]

Arguments:
  [CIDR]  CIDR range to scan (e.g. 192.168.1.0/24). If omitted, automatically detects primary interface CIDR

Options:
      --probe                      Enable active ARP probes (permission required, e.g. sudo)
      --portscan                   Enable TCP port scanning on discovered hosts (off by default)
      --fast                       Fast port preset: scan top ~100 common ports
      --ports <PORTS>              Explicit port list or range to scan (e.g. "22,80,443,8000-8080")
      --concurrency <CONCURRENCY>  Number of concurrent worker threads [default: 64]
      --timeout <TIMEOUT>          Per-target / per-port timeout in seconds [default: 1]
  -o, --out <OUT>                  Output CSV file path [default: discovery_results.csv]
      --json                       Generate companion JSON outputs (.json, .target.json, .legacy.json)
      --out-target <FILE>          Write target-compatible JSON to specified file
      --out-legacy <FILE>          Write legacy-shaped JSON to specified file
      --all                        Include all addresses in CIDR range (by default only discovered/active hosts are reported)
      --update-oui                 Dynamically update the local IEEE OUI manufacturer database (downloads official registry)
      --oui-source <URL_OR_FILE>   Optional custom URL or local CSV path to update OUI database from
  -h, --help                       Print help
  -V, --version                    Print version
```

---

## 📊 Output Formats & Schemas

### 1. Canonical CSV (`discovery_results.csv`)
Uniform 6-column machine-readable format:
```csv
ip,port,banner,mac,vendor,timestamp
192.168.1.1,80,,78:67:0e:ba:7e:74,TP-Link Technologies Co.,,
192.168.1.1,443,,78:67:0e:ba:7e:74,TP-Link Technologies Co.,,
192.168.1.159,80,,64:4e:d7:3b:72:5a,HP Inc.,
192.168.1.160,,,04:ea:56:9d:4f:cc,ASUSTek COMPUTER INC.,
```

### 2. Target-Compatible JSON (`<basename>.target.json`)
Streamlined JSON for modern downstream ingestion pipelines:
```json
[
  {
    "ip": "192.168.1.159",
    "mac": "64:4e:d7:3b:72:5a",
    "vendor": "HP Inc.",
    "method": "arp_passive",
    "ports": [80, 443],
    "is_up": true
  }
]
```

### 3. Legacy Netscan JSON (`<basename>.legacy.json`)
Drop-in backwards-compatible format preserving historical telemetry field names:
```json
[
  {
    "IP": "192.168.1.159",
    "MAC": "64:4e:d7:3b:72:5a",
    "Vendor": "HP Inc.",
    "ports": [80, 443],
    "banners": [],
    "is_up": true,
    "Method": "arp_passive"
  }
]
```

---

## 🛠️ Build & Installation

### Standard Workspace Build

```bash
# Build all binaries in release mode
cargo build --release

# Run all workspace unit and integration tests
cargo test --workspace
```

Binaries will be placed in `target/release/`:
* `target/release/discovery-cli`
* `target/release/netcheck`

### Static Musl Compilation (Zero Dependencies)

Produces standalone static-pie binaries that run across any Linux distribution without glibc dependencies:

```bash
# Using Makefile
make musl

# Or directly with Cargo
cargo build --release --target x86_64-unknown-linux-musl
```

Static binaries are located at:
* `target/x86_64-unknown-linux-musl/release/discovery-cli`
* `target/x86_64-unknown-linux-musl/release/netcheck`

---

## 🛡️ Adversarial Security & Invariants

`network_scanner` is engineered for hostile and untrusted network environments. All parser boundaries and data export routines adhere to strict red-team invariants verified by continuous self-attack testing:

| Attack Vector | Threat Model | Sovereign Defense Mechanism |
| :--- | :--- | :--- |
| **CSV Formula Injection** | Rogue hostnames or banners returning `=cmd\|' /C ...'!A0` or `@SUM(...)` to execute arbitrary code when opening reports in spreadsheet applications | All string fields starting with `=`, `+`, `-`, `@`, `\t`, or `\r` are neutralized with single-quote prefix escaping (`'`) before CSV serialization. |
| **Terminal ANSI Bombs** | Malicious network services transmitting escape sequences (`\x1b[2J`, title-setting codes) to hijack the operator's terminal or spoof logs | Service banners are scrubbed: all ANSI CSI sequences are stripped, control characters sanitized, and output bounded to safe lengths. |
| **CIDR DoS / OOM Exhaustion** | Target CIDRs larger than `/16` (e.g. `/8` or `/0`) causing millions of host allocations, freezing system memory | The CIDR sniffer strictly rejects prefixes `< /16` with an error, preventing memory exhaustion. RFC 3021 `/31` point-to-point and `/32` single-host boundaries are safely handled. |
| **Kernel ARP Cache Poisoning** | Spoofed, non-hex, or corrupted MAC entries in `/proc/net/arp` or `ip neigh` poisoning downstream analytics | Strict bitwise hex parsing validates every hardware address format (`AA:BB:CC:DD:EE:FF` or `AA-BB-CC-DD-EE-FF`) before accepting into records. |
| **OUI Resolution Precedence** | Dynamic cache overrides or offline air-gapped environments | Deterministic 3-tier precedence: `NETWORK_SCANNER_OUI_PATH` env var $\to$ local user XDG cache (`~/.local/share/network_scanner/oui.csv`) $\to$ embedded authoritative 32,800+ IEEE dataset. |

---

## 🧪 Testing & Verification

The suite includes comprehensive unit tests, golden file verifiers, simulated ARP fixtures, and red-team adversarial self-attack suites:

```bash
# Run full test suite across all 5 crates (53 tests)
cargo test --workspace

# Run adversarial self-attack test suites
cargo test --test adversarial_attack_tests
cargo test --test adversarial_netutils_tests
cargo test --test adversarial_discovery_tests

# Run integration tests specifically
cargo test --test portscan_integration
cargo test --test cli_companion_test
```

---

## 📜 License

Licensed under the MIT License. See [LICENSE](LICENSE) for details.
