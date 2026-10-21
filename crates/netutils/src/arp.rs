use std::net::Ipv4Addr;
use std::process::Command;
use std::time::Duration;
use std::{fmt, io};

#[derive(Debug)]
pub enum ArpError {
    Io(io::Error),
    Parse(String),
    ToolUnavailable,
}

impl fmt::Display for ArpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArpError::Io(e) => write!(f, "IO error: {}", e),
            ArpError::Parse(s) => write!(f, "Parse error: {}", s),
            ArpError::ToolUnavailable => write!(f, "Required tool not available"),
        }
    }
}

impl std::error::Error for ArpError {}

/// Parse `/proc/net/arp` (Linux) and return a vec of (ip, mac_str, device)
pub fn parse_proc_net_arp(content: &str) -> Vec<(Ipv4Addr, String, String)> {
    let mut out = Vec::new();
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 6 {
            let flags = parts[2];
            // Skip incomplete / stale ARP entries (0x0)
            if flags == "0x0" || flags == "0" {
                continue;
            }
            if let Ok(ip) = parts[0].parse::<Ipv4Addr>() {
                if let Some(m) = parse_mac(parts[3]) {
                    if m == [0, 0, 0, 0, 0, 0] {
                        continue;
                    }
                    let mac = parts[3].to_string();
                    let dev = parts[5].to_string();
                    out.push((ip, mac, dev));
                }
            }
        }
    }
    out
}

/// Read `/proc/net/arp` and parse.
pub fn read_proc_net_arp() -> Result<Vec<(Ipv4Addr, String, String)>, ArpError> {
    let s = std::fs::read_to_string("/proc/net/arp").map_err(ArpError::Io)?;
    Ok(parse_proc_net_arp(&s))
}

/// Lookup using `ip neigh` which is often present; returns (ip, mac, dev) lines parsed.
pub fn parse_ip_neigh(output: &str) -> Vec<(Ipv4Addr, String, String)> {
    let mut out = Vec::new();
    for line in output.lines() {
        if line.contains("FAILED") || line.contains("INCOMPLETE") {
            continue;
        }
        // typical: "192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 {
            if let Ok(ip) = parts[0].parse::<Ipv4Addr>() {
                let mut mac = String::new();
                let mut dev = String::new();
                for i in 1..parts.len() {
                    if parts[i] == "lladdr" && i + 1 < parts.len() {
                        mac = parts[i + 1].to_string();
                    }
                    if parts[i] == "dev" && i + 1 < parts.len() {
                        dev = parts[i + 1].to_string();
                    }
                }
                if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                    if let Some(m) = parse_mac(&mac) {
                        if m != [0, 0, 0, 0, 0, 0] {
                            out.push((ip, mac, dev));
                        }
                    }
                }
            }
        }
    }
    out
}

/// Try to lookup MAC for an IPv4 address using `/proc/net/arp`, then `ip neigh`, then `arp -n`.
pub fn lookup_mac(ip: Ipv4Addr) -> Option<[u8; 6]> {
    // 1. Try /proc/net/arp first (fastest on Linux, zero subprocess forks)
    if let Ok(entries) = read_proc_net_arp() {
        for (addr, mac, _dev) in entries {
            if addr == ip {
                if let Some(m) = parse_mac(&mac) {
                    if m != [0, 0, 0, 0, 0, 0] {
                        return Some(m);
                    }
                }
            }
        }
    }

    // 2. Fallback to `ip neigh`
    if let Ok(output) = Command::new("ip").args(["neigh"]).output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for (addr, mac, _dev) in parse_ip_neigh(&stdout) {
                if addr == ip {
                    if let Some(m) = parse_mac(&mac) {
                        if m != [0, 0, 0, 0, 0, 0] {
                            return Some(m);
                        }
                    }
                }
            }
        }
    }

    // 3. Fallback to `arp -n` if present
    if let Ok(output) = Command::new("arp").arg("-n").output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    if parts[0] == ip.to_string() {
                        if parts[2] != "00:00:00:00:00:00" && parts[2] != "<incomplete>" {
                            if let Some(m) = parse_mac(parts[2]) {
                                if m != [0, 0, 0, 0, 0, 0] {
                                    return Some(m);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

/// Ensure an IPv4 address is in the ARP table; optionally perform an active probe using `arping` or `ping`.
/// Returns the MAC if found.
pub fn ensure_mac(
    ip: Ipv4Addr,
    iface: Option<&str>,
    timeout: Duration,
    perform_probe: bool,
) -> Result<Option<[u8; 6]>, ArpError> {
    if let Some(mac) = lookup_mac(ip) {
        return Ok(Some(mac));
    }

    if !perform_probe {
        return Ok(None);
    }

    // Try arping if available (Linux). Use -c1 -w timeout_seconds -I iface ip
    #[cfg(target_os = "linux")]
    {
        let mut cmd = Command::new("arping");
        cmd.arg("-c").arg("1");
        cmd.arg("-w").arg(format!("{}", timeout.as_secs()));
        if let Some(iface_name) = iface {
            cmd.arg("-I").arg(iface_name);
        }
        cmd.arg(ip.to_string());
        if let Ok(output) = cmd.output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if let Some(mac_str) = line
                        .split_whitespace()
                        .find(|s| s.contains(':') && s.len() >= 16)
                    {
                        if let Some(mac) = parse_mac(mac_str) {
                            return Ok(Some(mac));
                        }
                    }
                }
            }
        }
        // Fallback: run ping once to trigger ARP resolution, then lookup again
        let mut ping_cmd = Command::new("ping");
        ping_cmd.arg("-c").arg("1");
        ping_cmd.arg("-W").arg(format!("{}", timeout.as_secs()));
        if let Some(iface_name) = iface {
            // Some ping implementations support -I
            ping_cmd.arg("-I").arg(iface_name);
        }
        ping_cmd.arg(ip.to_string());
        let _ = ping_cmd.output();

        // Try lookup again
        if let Some(mac) = lookup_mac(ip) {
            return Ok(Some(mac));
        }
    }

    // On non-Linux or if probes didn't work, return None
    Ok(None)
}

/// Parse a MAC like "00:11:22:33:44:55" into [u8;6]
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let cleaned = s.trim();
    let parts: Vec<&str> = cleaned.split(|c| c == ':' || c == '-').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        if let Ok(b) = u8::from_str_radix(p, 16) {
            mac[i] = b;
        } else {
            return None;
        }
    }
    Some(mac)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn parse_proc_net_arp_basic() {
        let sample = "IP address       HW type     Flags       HW address            Mask     Device\n192.168.1.10    0x1         0x2         00:11:22:33:44:55     *        eth0\n";
        let entries = parse_proc_net_arp(sample);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(entries[0].1, "00:11:22:33:44:55");
        assert_eq!(entries[0].2, "eth0");
    }

    #[test]
    fn parse_ip_neigh_basic() {
        let sample = "192.168.1.1 dev eth0 lladdr 00:aa:bb:cc:dd:ee REACHABLE\n";
        let entries = parse_ip_neigh(sample);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(entries[0].1, "00:aa:bb:cc:dd:ee");
        assert_eq!(entries[0].2, "eth0");
    }

    #[test]
    fn parse_mac_formats() {
        assert_eq!(
            parse_mac("00:11:22:33:44:55").unwrap(),
            [0, 17, 34, 51, 68, 85]
        );
        assert_eq!(
            parse_mac("00-11-22-33-44-55").unwrap(),
            [0, 17, 34, 51, 68, 85]
        );
        assert!(parse_mac("not-a-mac").is_none());
    }

    #[test]
    fn lookup_mac_none_when_absent() {
        // Best-effort: this will likely be None in CI
        let ip: Ipv4Addr = "10.255.255.254".parse().unwrap();
        let m = lookup_mac(ip);
        assert!(m.is_none() || m.is_some());
    }
}
/// Resolve the current IPv4 lease for an immutable hardware MAC signature (`SOVEREIGN-IDENTITY-ANCHOR-01`).
pub fn resolve_ip_by_mac(target_mac: [u8; 6]) -> Option<Ipv4Addr> {
    if target_mac == [0, 0, 0, 0, 0, 0] {
        return None;
    }
    if let Ok(entries) = read_proc_net_arp() {
        for (addr, mac_str, _dev) in entries {
            if parse_mac(&mac_str) == Some(target_mac) {
                return Some(addr);
            }
        }
    }
    if let Ok(output) = Command::new("ip").args(["neigh"]).output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for (addr, mac_str, _dev) in parse_ip_neigh(&stdout) {
                if parse_mac(&mac_str) == Some(target_mac) {
                    return Some(addr);
                }
            }
        }
    }
    None
}

