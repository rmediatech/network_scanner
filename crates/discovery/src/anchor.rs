//! Hardware Identity Anchoring (`SOVEREIGN-IDENTITY-ANCHOR-01`)
//!
//! Anchors discovered assets to immutable Layer-2 MAC signatures across transient
//! Layer-3 IPv4 DHCP lease drift, preserving custom labels, vendor context, and
//! historic service banners across roaming events.

use formats::DiscoveryRecord;
use std::collections::HashMap;

/// Event emitted when a hardware-anchored asset migrates to a new IPv4 lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseDriftEvent {
    pub mac: String,
    pub previous_ip: String,
    pub current_ip: String,
    pub vendor: Option<String>,
}

/// Canonical hardware-anchored asset state (`SOVEREIGN-IDENTITY-ANCHOR-01`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchoredAsset {
    pub mac: String,
    pub current_ip: String,
    pub ip_history: Vec<String>,
    pub vendor: Option<String>,
    pub banner: Option<String>,
    pub open_ports: Vec<u16>,
    pub last_seen: Option<String>,
}

/// Registry that reconciles transient `DiscoveryRecord` observations against
/// persistent hardware MAC identities.
#[derive(Debug, Default, Clone)]
pub struct HardwareIdentityRegistry {
    by_mac: HashMap<String, AnchoredAsset>,
}

impl HardwareIdentityRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Normalize a MAC string (`00-11-22-AA-BB-CC` -> `00:11:22:aa:bb:cc`).
    pub fn normalize_mac(mac: &str) -> Option<String> {
        let bytes = netutils::arp::parse_mac(mac)?;
        if bytes == [0, 0, 0, 0, 0, 0] {
            return None;
        }
        Some(format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        ))
    }

    /// Ingest a batch of discovery records, re-anchoring assets across IP lease drift
    /// and returning any detected `LeaseDriftEvent`s.
    pub fn ingest_records(&mut self, records: &[DiscoveryRecord]) -> Vec<LeaseDriftEvent> {
        let mut drift_events = Vec::new();
        for rec in records {
            let Some(raw_mac) = rec.mac.as_deref() else {
                continue;
            };
            let Some(mac_key) = Self::normalize_mac(raw_mac) else {
                continue;
            };

            match self.by_mac.get_mut(&mac_key) {
                Some(asset) => {
                    if asset.current_ip != rec.ip {
                        drift_events.push(LeaseDriftEvent {
                            mac: mac_key.clone(),
                            previous_ip: asset.current_ip.clone(),
                            current_ip: rec.ip.clone(),
                            vendor: asset.vendor.clone().or_else(|| rec.vendor.clone()),
                        });
                        if !asset.ip_history.contains(&asset.current_ip) {
                            asset.ip_history.push(asset.current_ip.clone());
                        }
                        asset.current_ip = rec.ip.clone();
                    }
                    if asset.vendor.is_none() && rec.vendor.is_some() {
                        asset.vendor = rec.vendor.clone();
                    }
                    if rec.banner.is_some() {
                        asset.banner = rec.banner.clone();
                    }
                    if let Some(p) = rec.port {
                        if !asset.open_ports.contains(&p) {
                            asset.open_ports.push(p);
                            asset.open_ports.sort_unstable();
                        }
                    }
                    if rec.timestamp.is_some() {
                        asset.last_seen = rec.timestamp.clone();
                    }
                }
                None => {
                    let mut open_ports = Vec::new();
                    if let Some(p) = rec.port {
                        open_ports.push(p);
                    }
                    self.by_mac.insert(
                        mac_key.clone(),
                        AnchoredAsset {
                            mac: mac_key,
                            current_ip: rec.ip.clone(),
                            ip_history: Vec::new(),
                            vendor: rec.vendor.clone(),
                            banner: rec.banner.clone(),
                            open_ports,
                            last_seen: rec.timestamp.clone(),
                        },
                    );
                }
            }
        }
        drift_events
    }

    /// Lookup an anchored asset by its hardware MAC address.
    pub fn get_by_mac(&self, mac: &str) -> Option<&AnchoredAsset> {
        let key = Self::normalize_mac(mac)?;
        self.by_mac.get(&key)
    }

    /// Return the total count of unique hardware-anchored assets.
    pub fn len(&self) -> usize {
        self.by_mac.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_mac.is_empty()
    }
}
