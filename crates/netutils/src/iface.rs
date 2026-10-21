use ipnetwork::{IpNetwork, Ipv4Network};
use std::fmt;
use std::fs;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::process::Command;

pub use crate::iface_lookup::{
    get_interface_by_index, get_interface_by_ipv4, get_interface_by_mac,
    get_interface_by_mac_or_ipv4, get_interface_by_name,
    get_interface_by_name_index_mac_ipv4, get_interface_by_name_or_index,
};

/// Represents a network interface on the system.
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub index: u32,
    pub mac: Option<[u8; 6]>,
    pub ipv4: Option<Ipv4Addr>,
    pub up: bool,
}

#[derive(Debug)]
pub enum IfaceError {
    NotFound,
    NoUpInterface,
    Io(std::io::Error),
    Platform(String),
    PermissionDenied(String),
    InvalidInterface(String),
    Other(String),
}

impl fmt::Display for IfaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IfaceError::NotFound => write!(f, "Interface not found"),
            IfaceError::NoUpInterface => write!(f, "No up interface with IPv4"),
            IfaceError::Io(e) => write!(f, "IO error: {}", e),
            IfaceError::Platform(s) => write!(f, "Platform error: {}", s),
            IfaceError::PermissionDenied(s) => write!(f, "Permission denied: {}", s),
            IfaceError::InvalidInterface(s) => write!(f, "Invalid interface: {}", s),
            IfaceError::Other(s) => write!(f, "Other error: {}", s),
        }
    }
}

impl std::error::Error for IfaceError {}

/// Returns the default network's CIDR (IPv4Network) for the primary interface.
/// Falls back to /24 if we can't determine a mask.
pub fn get_default_cidr() -> Result<Ipv4Network, IfaceError> {
    let iface = get_default_interface()?;
    let ipv4 = iface.ipv4.ok_or(IfaceError::NoUpInterface)?;
    let interfaces = pnet_datalink::interfaces();
    for i in interfaces {
        if i.name == iface.name {
            for ip in i.ips {
                if let IpNetwork::V4(net) = ip {
                    if net.ip() == ipv4 {
                        return Ok(net);
                    }
                }
            }
        }
    }
    Ipv4Network::new(ipv4, 24).map_err(|_| IfaceError::NoUpInterface)
}

/// Returns the default gateway IPv4 address by parsing /proc/net/route (Linux only).
pub fn get_default_gateway_ipv4() -> Option<Ipv4Addr> {
    let file = fs::File::open("/proc/net/route").ok()?;
    let reader = BufReader::new(file);
    for line in reader.lines().skip(1).flatten() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 && fields[1] == "00000000" {
            if let Ok(gw_hex) = u32::from_str_radix(fields[2], 16) {
                let gw_bytes = gw_hex.to_le_bytes();
                return Some(Ipv4Addr::new(
                    gw_bytes[0],
                    gw_bytes[1],
                    gw_bytes[2],
                    gw_bytes[3],
                ));
            }
        }
    }
    None
}

/// Returns the MAC address for a given IPv4 address from the ARP table (Linux only).
pub fn get_mac_for_ipv4(ip: Ipv4Addr) -> Option<[u8; 6]> {
    if let Ok(output) = Command::new("ip").args(["neigh"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains(&ip.to_string()) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(idx) = parts.iter().position(|&s| s == "lladdr") {
                    if let Some(mac_str) = parts.get(idx + 1) {
                        let mac_bytes: Vec<u8> = mac_str
                            .split(':')
                            .filter_map(|b| u8::from_str_radix(b, 16).ok())
                            .collect();
                        if mac_bytes.len() == 6 {
                            let mut mac = [0u8; 6];
                            mac.copy_from_slice(&mac_bytes);
                            return Some(mac);
                        }
                    }
                }
            }
        }
    }
    None
}

/// Returns a list of all network interfaces on the system.
pub fn list_interfaces() -> Result<Vec<NetworkInterface>, IfaceError> {
    let ifaces = pnet_datalink::interfaces();
    let result = ifaces
        .into_iter()
        .map(|iface| NetworkInterface {
            name: iface.name.clone(),
            index: iface.index,
            mac: iface.mac.map(|m| m.octets()),
            ipv4: iface.ips.iter().find_map(|ip| match ip {
                IpNetwork::V4(ipv4) => Some(ipv4.ip()),
                _ => None,
            }),
            up: iface.is_up(),
        })
        .collect();
    Ok(result)
}

/// Attempts to find the system's default (primary) network interface that is up and has an IPv4 address.
pub fn get_default_interface() -> Result<NetworkInterface, IfaceError> {
    let interfaces = list_interfaces()?;
    interfaces
        .into_iter()
        .find(|iface| iface.up && iface.ipv4.is_some() && !iface.name.starts_with("lo"))
        .ok_or(IfaceError::NoUpInterface)
}

/// Returns true if the interface is NOT managed by a DHCP client (Linux heuristics).
pub fn is_interface_unmanaged(interface: &str) -> Result<bool, IfaceError> {
    #[cfg(target_os = "linux")]
    {
        let lease_paths = [
            format!("/run/systemd/netif/leases/{}", interface),
            format!("/var/lib/dhcp/dhclient.{}.leases", interface),
            format!("/var/lib/NetworkManager/dhclient-{}.lease", interface),
        ];
        for path in &lease_paths {
            if fs::metadata(path).is_ok() {
                return Ok(false);
            }
        }
        if let Ok(output) = Command::new("nmcli")
            .args(["device", "show", interface])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("DHCP4") {
                return Ok(false);
            }
        }
        Ok(true)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(true)
    }
}

pub fn resolve_iface_name(interface: &Option<String>) -> String {
    match interface.as_deref() {
        Some(name) => name.to_string(),
        None => get_default_interface()
            .expect("No default interface found")
            .name,
    }
}
