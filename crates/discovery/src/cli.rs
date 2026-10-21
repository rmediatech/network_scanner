use clap::Parser;
use discovery::{ports, Discover, LiveArpDiscover};
use formats::DiscoveryRecord;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "discovery-cli",
    about = "Sovereign local network discovery & inspection utility",
    version = "0.1.0"
)]
pub struct Args {
    /// CIDR range to scan (e.g. 192.0.2.0/24). If omitted, automatically detects primary interface CIDR.
    #[arg(value_name = "CIDR")]
    pub cidr: Option<String>,

    /// Enable active ARP probes (permission required, e.g. sudo)
    #[arg(long, default_value_t = false)]
    pub probe: bool,

    /// Enable TCP port scanning on discovered hosts (off by default)
    #[arg(long, default_value_t = false)]
    pub portscan: bool,

    /// Fast port preset: scan top ~100 common ports
    #[arg(long, default_value_t = false)]
    pub fast: bool,

    /// Explicit port list or range to scan (e.g. "22,80,443,8000-8080")
    #[arg(long, value_name = "PORTS")]
    pub ports: Option<String>,

    /// Number of concurrent worker threads
    #[arg(long, default_value_t = 64)]
    pub concurrency: usize,

    /// Per-target / per-port timeout in seconds
    #[arg(long, default_value_t = 1)]
    pub timeout: u64,

    /// Output CSV file path
    #[arg(short, long, default_value = "discovery_results.csv")]
    pub out: PathBuf,

    /// Generate companion JSON outputs (.json, .target.json, .legacy.json)
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Write target-compatible JSON to specified file
    #[arg(long, value_name = "FILE")]
    pub out_target: Option<PathBuf>,

    /// Write legacy-shaped JSON to specified file
    #[arg(long, value_name = "FILE")]
    pub out_legacy: Option<PathBuf>,

    /// Include all addresses in CIDR range (by default only discovered/active hosts are reported)
    #[arg(long, default_value_t = false)]
    pub all: bool,

    /// Dynamically update the local IEEE OUI manufacturer database (downloads official registry)
    #[arg(long, default_value_t = false)]
    pub update_oui: bool,

    /// Optional custom URL or local CSV path to update OUI database from
    #[arg(long, value_name = "URL_OR_FILE")]
    pub oui_source: Option<String>,
}

pub fn run(args: Args) -> Result<(), String> {
    if args.update_oui {
        eprintln!("[discovery-cli] Updating local IEEE OUI manufacturer database...");
        match io::update_oui_cache(args.oui_source.as_deref()) {
            Ok((count, path)) => {
                println!(
                    "[discovery-cli] Successfully updated OUI database ({} vendor prefixes indexed) -> {}",
                    count,
                    path.display()
                );
            }
            Err(e) => {
                return Err(format!("[discovery-cli] Error updating OUI database: {}", e));
            }
        }
        if args.cidr.is_none() {
            return Ok(());
        }
    }

    let target_cidr = match args.cidr.as_ref() {
        Some(c) => c.clone(),
        None => match netutils::iface::get_default_cidr() {
            Ok(net) => {
                let s = net.to_string();
                eprintln!("[discovery-cli] Auto-detected local CIDR: {}", s);
                s
            }
            Err(e) => {
                return Err(format!(
                    "Error: Could not auto-detect primary network interface CIDR: {}. Please provide <CIDR> explicitly (e.g. 192.0.2.0/24).",
                    e
                ));
            }
        },
    };

    let custom_ports = if let Some(ref p_str) = args.ports {
        let parsed = ports::parse_port_list(p_str);
        if parsed.is_empty() {
            eprintln!(
                "[discovery-cli] Warning: no valid ports parsed from '--ports {}', using builtin default",
                p_str
            );
            None
        } else {
            Some(parsed)
        }
    } else if args.fast {
        Some(ports::fast_ports())
    } else {
        None
    };

    let mode_str = if args.probe { "Active ARP Probes" } else { "Passive ARP Cache" };
    eprintln!(
        "[discovery-cli] Target CIDR: {} | Mode: {} | PortScan: {} | Concurrency: {}",
        target_cidr,
        mode_str,
        if args.portscan { "Enabled" } else { "Disabled" },
        args.concurrency
    );

    let mut discover = LiveArpDiscover::new(&target_cidr)
        .with_workers(args.concurrency)
        .with_probe(args.probe)
        .with_timeout_secs(args.timeout)
        .with_portscan(args.portscan)
        .with_port_concurrency(args.concurrency)
        .with_port_timeout_secs(args.timeout);

    if custom_ports.is_some() {
        discover = discover.with_ports(custom_ports);
    }

    let records: Vec<DiscoveryRecord> = discover.discover();
    let final_records: Vec<DiscoveryRecord> = if args.all {
        records
    } else {
        records
            .into_iter()
            .filter(|r| r.mac.is_some() || r.port.is_some() || r.banner.is_some())
            .collect()
    };

    eprintln!("[discovery-cli] Discovered {} host record(s)", final_records.len());

    io::write_canonical_csv_file(&args.out, &final_records)
        .map_err(|e| format!("[discovery-cli] Error writing CSV to {}: {}", args.out.display(), e))?;
    println!("[discovery-cli] Wrote CSV: {}", args.out.display());

    let method_tag = if args.probe { "arp_probe" } else { "arp_passive" };
    write_json_artifacts(&args, &final_records, method_tag);
    Ok(())
}

fn write_json_artifacts(args: &Args, final_records: &[DiscoveryRecord], method_tag: &str) {
    if args.json {
        let json_path = args.out.with_extension("json");
        let target_path = args.out.with_extension("target.json");
        let legacy_path = args.out.with_extension("legacy.json");

        if let Ok(mut f) = File::create(&json_path) {
            if let Ok(s) = serde_json::to_string_pretty(final_records) {
                let _ = f.write_all(s.as_bytes());
                println!("[discovery-cli] Wrote JSON: {}", json_path.display());
            }
        }

        if let Err(e) = io::write_target_json_file(target_path.display().to_string(), final_records, method_tag) {
            eprintln!("[discovery-cli] Warning: failed writing target JSON: {}", e);
        } else {
            println!("[discovery-cli] Wrote Target JSON: {}", target_path.display());
        }

        if let Err(e) = io::write_legacy_json_file(legacy_path.display().to_string(), final_records, method_tag) {
            eprintln!("[discovery-cli] Warning: failed writing legacy JSON: {}", e);
        } else {
            println!("[discovery-cli] Wrote Legacy JSON: {}", legacy_path.display());
        }
    }

    if let Some(ref target_file) = args.out_target {
        if let Err(e) = io::write_target_json_file(target_file.display().to_string(), final_records, method_tag) {
            eprintln!("[discovery-cli] Error writing target JSON to {}: {}", target_file.display(), e);
        } else {
            println!("[discovery-cli] Wrote Target JSON: {}", target_file.display());
        }
    }

    if let Some(ref legacy_file) = args.out_legacy {
        if let Err(e) = io::write_legacy_json_file(legacy_file.display().to_string(), final_records, method_tag) {
            eprintln!("[discovery-cli] Error writing legacy JSON to {}: {}", legacy_file.display(), e);
        } else {
            println!("[discovery-cli] Wrote Legacy JSON: {}", legacy_file.display());
        }
    }
}
