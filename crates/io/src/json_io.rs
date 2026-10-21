use formats::DiscoveryRecord;
use serde::Serialize;
use std::error::Error;
use std::fs::File;
use std::io::Read;

/// Read a netscan-style JSON file and map to canonical DiscoveryRecord list.
pub fn read_netscan_json<P: AsRef<str>>(path: P) -> Result<Vec<DiscoveryRecord>, Box<dyn Error>> {
    let path = path.as_ref();
    let mut s = String::new();
    File::open(path)?.read_to_string(&mut s)?;
    let v: serde_json::Value = serde_json::from_str(&s)?;
    let arr = v
        .as_array()
        .ok_or_else(|| "expected top-level array in netscan json")?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let ip = item
            .get("IP")
            .and_then(|x| x.as_str())
            .or_else(|| item.get("ip").and_then(|x| x.as_str()))
            .ok_or("missing IP")?;
        let port = item
            .get("ports")
            .and_then(|p| p.as_array())
            .and_then(|a| a.first())
            .and_then(|n| n.as_u64())
            .map(|n| n as u16);
        let banner = item
            .get("Hostname")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                item.get("banners")
                    .and_then(|b| b.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            });
        let mac = item
            .get("MAC")
            .and_then(|x| x.as_str())
            .or_else(|| item.get("mac").and_then(|x| x.as_str()));
        let vendor = item
            .get("Vendor")
            .and_then(|x| x.as_str())
            .or_else(|| item.get("vendor").and_then(|x| x.as_str()));
        let timestamp = item
            .get("Timestamp")
            .and_then(|x| x.as_str())
            .or_else(|| item.get("timestamp").and_then(|x| x.as_str()))
            .or_else(|| item.get("time").and_then(|x| x.as_str()));

        out.push(DiscoveryRecord::new(
            ip,
            port,
            banner.as_deref(),
            mac,
            vendor,
            timestamp,
        ));
    }
    Ok(out)
}

#[derive(Serialize)]
struct GoDevice<'a> {
    ip: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    mac: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vendor: Option<&'a str>,
    method: &'a str,
    ports: Vec<u16>,
    is_up: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<&'a str>,
}

/// Export a list of `DiscoveryRecord` as a JSON array compatible with the
/// Target-compatible JSON exporter.
pub fn to_target_json(
    records: &[DiscoveryRecord],
    default_method: &str,
) -> Result<String, Box<dyn Error>> {
    let mut out = Vec::with_capacity(records.len());
    for r in records {
        let ports = r.port.map(|p| vec![p]).unwrap_or_default();
        let hostname = r.banner.as_deref();
        let dev = GoDevice {
            ip: &r.ip,
            mac: r.mac.as_deref(),
            hostname,
            vendor: r.vendor.as_deref(),
            method: default_method,
            ports,
            is_up: true,
            timestamp: r.timestamp.as_deref(),
        };
        out.push(dev);
    }

    Ok(serde_json::to_string_pretty(&out)?)
}

/// Convenience: write target-compatible JSON to a file path.
pub fn write_target_json_file<P: AsRef<str>>(
    path: P,
    records: &[DiscoveryRecord],
    default_method: &str,
) -> Result<(), Box<dyn Error>> {
    let s = to_target_json(records, default_method)?;
    std::fs::write(path.as_ref(), s)?;
    Ok(())
}

#[derive(Serialize)]
struct LegacyDevice<'a> {
    #[serde(rename = "IP")]
    ip: &'a str,
    #[serde(rename = "MAC", skip_serializing_if = "Option::is_none")]
    mac: Option<&'a str>,
    #[serde(rename = "Hostname", skip_serializing_if = "Option::is_none")]
    hostname: Option<&'a str>,
    #[serde(rename = "Vendor", skip_serializing_if = "Option::is_none")]
    vendor: Option<&'a str>,
    #[serde(rename = "Timestamp", skip_serializing_if = "Option::is_none")]
    timestamp: Option<&'a str>,
    ports: Vec<u16>,
    banners: Vec<&'a str>,
    #[serde(rename = "is_up")]
    is_up: bool,
    #[serde(rename = "Method")]
    method: &'a str,
}

/// Export a list of `DiscoveryRecord` in a legacy netscan-shaped JSON format.
pub fn to_legacy_json(
    records: &[DiscoveryRecord],
    default_method: &str,
) -> Result<String, Box<dyn Error>> {
    let mut out = Vec::with_capacity(records.len());
    for r in records {
        let ports = r.port.map(|p| vec![p]).unwrap_or_default();
        let mut banners = Vec::new();
        if let Some(b) = r.banner.as_deref() {
            if !b.is_empty() {
                banners.push(b);
            }
        }

        let dev = LegacyDevice {
            ip: &r.ip,
            mac: r.mac.as_deref(),
            hostname: r.banner.as_deref(),
            vendor: r.vendor.as_deref(),
            timestamp: r.timestamp.as_deref(),
            ports,
            banners,
            is_up: true,
            method: default_method,
        };
        out.push(dev);
    }

    Ok(serde_json::to_string_pretty(&out)?)
}

/// Convenience: write legacy-shaped JSON to a file path.
pub fn write_legacy_json_file<P: AsRef<str>>(
    path: P,
    records: &[DiscoveryRecord],
    default_method: &str,
) -> Result<(), Box<dyn Error>> {
    let s = to_legacy_json(records, default_method)?;
    std::fs::write(path.as_ref(), s)?;
    Ok(())
}
