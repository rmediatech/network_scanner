//! Lightweight discovery trait + LiveArpDiscover & HardwareIdentityRegistry
//!
//! Provides a deterministic, bounded discovery contract that produces canonical
//! `formats::DiscoveryRecord` objects and anchors hardware MAC identities across IP drift.

use formats::DiscoveryRecord;

pub mod anchor;
pub mod ports;
pub mod sim;

pub use anchor::{AnchoredAsset, HardwareIdentityRegistry, LeaseDriftEvent};
pub use sim::{ArpSimDiscover, SimpleDiscover};

/// A minimal discovery trait.
///
/// Inputs: list of candidate IPs or source artifacts.
/// Output: list of canonical DiscoveryRecord objects.
pub trait Discover {
    /// Perform discovery and return canonical records.
    fn discover(&self) -> Vec<DiscoveryRecord>;
}

/// Live ARP-based discoverer. Uses `netutils::cidrsniffer::scan_cidr` internally.
pub struct LiveArpDiscover {
    pub cidr: String,
    pub workers: usize,
    pub perform_probe: bool,
    /// per-lookup timeout
    pub timeout_secs: u64,
    /// enable port scanning (opt-in, off by default)
    pub portscan: bool,
    /// optional explicit port list; when None the builtin 1..=1024 is used
    pub ports: Option<Vec<u16>>,
    /// concurrency for port scanning
    pub port_concurrency: usize,
    /// per-port timeout
    pub port_timeout_secs: u64,
}

impl LiveArpDiscover {
    pub fn new<S: Into<String>>(cidr: S) -> Self {
        Self {
            cidr: cidr.into(),
            workers: 64,
            perform_probe: false,
            timeout_secs: 1,
            portscan: false,
            ports: None,
            port_concurrency: 64,
            port_timeout_secs: 1,
        }
    }

    pub fn with_workers(mut self, w: usize) -> Self {
        self.workers = w;
        self
    }

    pub fn with_probe(mut self, probe: bool) -> Self {
        self.perform_probe = probe;
        self
    }

    pub fn with_timeout_secs(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    pub fn with_portscan(mut self, enabled: bool) -> Self {
        self.portscan = enabled;
        self
    }

    pub fn with_ports(mut self, ports: Option<Vec<u16>>) -> Self {
        self.ports = ports;
        self
    }

    pub fn with_port_concurrency(mut self, c: usize) -> Self {
        self.port_concurrency = c;
        self
    }

    pub fn with_port_timeout_secs(mut self, secs: u64) -> Self {
        self.port_timeout_secs = secs;
        self
    }
}

impl Discover for LiveArpDiscover {
    fn discover(&self) -> Vec<DiscoveryRecord> {
        let timeout = std::time::Duration::from_secs(self.timeout_secs);
        match netutils::cidrsniffer::scan_cidr(
            &self.cidr,
            self.workers,
            self.perform_probe,
            timeout,
        ) {
            Ok(results) => results
                .into_iter()
                .map(|(ip, mac)| {
                    let mac_str = mac.map(|m| {
                        format!(
                            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                            m[0], m[1], m[2], m[3], m[4], m[5]
                        )
                    });
                    let vendor = mac_str.as_deref().and_then(io::lookup_vendor_from_oui);
                    DiscoveryRecord::new(
                        &ip.to_string(),
                        None,
                        None,
                        mac_str.as_deref(),
                        vendor.as_deref(),
                        None,
                    )
                })
                .collect::<Vec<_>>()
                .into_iter()
                .flat_map(|r| {
                    if !self.portscan || (r.mac.is_none() && !self.perform_probe) {
                        return vec![r].into_iter();
                    }

                    let ip_addr = match r.ip.parse::<std::net::Ipv4Addr>() {
                        Ok(a) => a,
                        Err(_) => return vec![r].into_iter(),
                    };

                    let ports_vec = match &self.ports {
                        Some(v) => v.clone(),
                        None => ports::builtin_ports(),
                    };

                    let timeout = std::time::Duration::from_secs(self.port_timeout_secs);
                    let port_results = netutils::portscan::scan_host_ports(
                        ip_addr,
                        ports_vec,
                        timeout,
                        self.port_concurrency,
                    );

                    let mut out = Vec::new();
                    let mut any_open = false;
                    for p in port_results {
                        if p.open {
                            any_open = true;
                            let mut rec = r.clone();
                            rec.port = Some(p.port);
                            rec.banner = p.banner.clone();
                            out.push(rec);
                        }
                    }

                    if any_open {
                        out.into_iter()
                    } else {
                        vec![r].into_iter()
                    }
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_discover_returns_expected_records() {
        let items = vec![
            (
                "192.0.2.10".to_string(),
                Some(22),
                Some("ssh-1.0".to_string()),
                Some("aa:bb:cc:dd:ee:ff".to_string()),
                Some("ACME".to_string()),
                Some("2025-11-02T12:00:00Z".to_string()),
            ),
            ("198.51.100.5".to_string(), None, None, None, None, None),
        ];
        let s = SimpleDiscover::new(items);
        let recs = s.discover();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].ip, "192.0.2.10");
        assert_eq!(recs[0].port, Some(22));
        assert_eq!(recs[0].mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(recs[1].ip, "198.51.100.5");
        assert_eq!(recs[1].port, None);
    }
}
