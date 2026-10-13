use crate::arp;
use ipnetwork::Ipv4Network;
use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Expand an IPv4 network into usable host addresses (skip network and broadcast when applicable).
fn hosts_from_network(net: Ipv4Network) -> Vec<Ipv4Addr> {
    let prefix = net.prefix();
    let octets = net.ip().octets();
    let base = u32::from_be_bytes(octets);
    if prefix == 32 {
        return vec![net.ip()];
    }
    if prefix == 31 {
        // RFC 3021: Point-to-point links (both base and base + 1 are usable)
        return vec![Ipv4Addr::from(base), Ipv4Addr::from(base + 1)];
    }
    let host_count = 1u32.wrapping_shl(32 - prefix as u32);
    if host_count <= 2 {
        return vec![net.ip()];
    }
    // iterate over addresses excluding network (base) and broadcast (base + host_count - 1)
    let first = base + 1;
    let last = base + host_count - 2; // inclusive
    let mut hosts = Vec::with_capacity((last - first + 1) as usize);
    for addr in first..=last {
        hosts.push(Ipv4Addr::from(addr));
    }
    hosts
}

/// Scan a CIDR and attempt to resolve MAC addresses using ARP.
/// - `cidr` like "192.168.1.0/24"
/// - `workers` number of concurrent worker threads (>=1)
/// - `perform_probe` if true will actively probe (opt-in)
/// - `timeout` per-lookup timeout
/// Returns vector of (ip, Option<mac>) in no particular order.
pub fn scan_cidr(
    cidr: &str,
    workers: usize,
    perform_probe: bool,
    timeout: Duration,
) -> Result<Vec<(Ipv4Addr, Option<[u8; 6]>)>, String> {
    let net: Ipv4Network = cidr.parse().map_err(|e| format!("invalid cidr: {}", e))?;
    if net.prefix() < 16 {
        return Err(format!(
            "CIDR /{} exceeds maximum supported size (maximum is /16 for safe memory allocation)",
            net.prefix()
        ));
    }
    let hosts = hosts_from_network(net);
    if hosts.is_empty() {
        return Ok(Vec::new());
    }

    // High-speed passive lookup: read the kernel ARP table once in microsecond time
    if !perform_probe {
        let mut arp_map = std::collections::HashMap::new();
        if let Ok(entries) = arp::read_proc_net_arp() {
            for (ip, mac_str, _) in entries {
                if let Some(mac) = arp::parse_mac(&mac_str) {
                    if mac != [0, 0, 0, 0, 0, 0] {
                        arp_map.insert(ip, mac);
                    }
                }
            }
        }
        if arp_map.is_empty() {
            if let Ok(output) = std::process::Command::new("ip").args(["neigh"]).output() {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for (ip, mac_str, _) in arp::parse_ip_neigh(&stdout) {
                        if let Some(mac) = arp::parse_mac(&mac_str) {
                            if mac != [0, 0, 0, 0, 0, 0] {
                                arp_map.insert(ip, mac);
                            }
                        }
                    }
                }
            }
        }

        let mut results = Vec::with_capacity(hosts.len());
        for ip in hosts {
            let mac = arp_map.get(&ip).cloned();
            results.push((ip, mac));
        }
        return Ok(results);
    }

    let workers = std::cmp::max(1, workers);
    let (res_tx, res_rx) = mpsc::channel();

    // Partition hosts into chunks for each worker to avoid channel contention.
    let chunk_size = (hosts.len() + workers - 1) / workers;
    let mut handles = Vec::new();
    for chunk in hosts.chunks(chunk_size) {
        let chunk_vec = chunk.to_vec();
        let res_tx = res_tx.clone();
        let timeout = timeout.clone();
        let chunk_perform = perform_probe;
        let handle = thread::spawn(move || {
            for ip in chunk_vec {
                match arp::ensure_mac(ip, None, timeout, chunk_perform) {
                    Ok(Some(mac)) => {
                        let _ = res_tx.send((ip, Some(mac)));
                    }
                    Ok(None) => {
                        let _ = res_tx.send((ip, None));
                    }
                    Err(_) => {
                        let _ = res_tx.send((ip, None));
                    }
                }
            }
        });
        handles.push(handle);
    }

    drop(res_tx);

    let mut results = Vec::new();
    for _ in 0..hosts.len() {
        if let Ok(r) = res_rx.recv() {
            results.push(r);
        }
    }

    for h in handles {
        let _ = h.join();
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn hosts_from_small_cidr() {
        let net: Ipv4Network = "192.168.0.0/30".parse().unwrap();
        let hosts = hosts_from_network(net);
        // /30 has 2 usable hosts
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].to_string(), "192.168.0.1");
        assert_eq!(hosts[1].to_string(), "192.168.0.2");
    }

    #[test]
    fn scan_cidr_no_probe_returns_all_hosts() {
        let res = scan_cidr("192.168.254.0/30", 2, false, Duration::from_secs(1)).unwrap();
        // should return 2 hosts for /30
        assert_eq!(res.len(), 2);
    }
}
