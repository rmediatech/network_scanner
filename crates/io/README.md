# io 🗄️

[![CI](https://github.com/rmediatech/network_scanner/actions/workflows/discovery.yml/badge.svg)](https://github.com/rmediatech/network_scanner/actions) [![docs.rs](https://docs.rs/io/badge.svg)](https://docs.rs/io) [![crates.io](https://img.shields.io/crates/v/io.svg)](https://crates.io/crates/io)

I/O adapters, canonical serializers, and OUI hardware vendor resolution.

### Responsibilities

- **Embedded 32,800+ IEEE OUI Database**: Embedded authoritative dataset at `crates/io/data/oui.csv` covering 32,811 manufacturer registrations for sub-microsecond offline MAC-to-vendor resolution.
- **Dynamic OUI Caching**: Dynamic updates via `update_oui_cache` supporting local user XDG caching (`~/.local/share/network_scanner/oui.csv`) with automatic fallback to embedded static data.
- **CSV Formula Injection Defense**: Sanitizes all export fields in `to_canonical_csv` (`=`, `+`, `-`, `@`, `\t`, `\r`) with single-quote escaping against spreadsheet code execution.
- **Canonical Serialization**: Implements uniform 6-column CSV, Target JSON, and Legacy JSON adapters.

## Build & Test

```bash
# Build `io` as a library (release)
cargo build --manifest-path crates/io/Cargo.toml --lib --release

# Run unit tests
cargo test -p io

# Run adversarial self-attack tests (formula injection, OUI fuzzing, malformed CSV)
cargo test -p io --test adversarial_attack_tests
```
