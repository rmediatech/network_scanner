use formats::DiscoveryRecord;
use std::error::Error;

/// Scrub raw ANSI CSI/OSC escape sequences and unprintable control characters.
pub fn scrub_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            match chars.peek().copied() {
                Some('[') => {
                    chars.next();
                    while let Some(&nc) = chars.peek() {
                        chars.next();
                        if ('\x40'..='\x7e').contains(&nc) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    chars.next();
                    while let Some(nc) = chars.next() {
                        if nc == '\x07' {
                            break;
                        }
                        if nc == '\x1b' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                _ => {}
            }
            continue;
        }
        if c == '\t' || c == '\r' || (!c.is_control() && c != '\x7f') {
            out.push(c);
        }
    }
    out
}

/// Sanitize CSV fields against formula injection / DDE attacks and ANSI log poisoning.
/// If a field starts with '=', '+', '-', '@', tab, or carriage return, it is prepended with a single quote.
pub fn sanitize_csv_field(s: &str) -> String {
    let scrubbed = scrub_ansi(s);
    if scrubbed.starts_with('\t') || scrubbed.starts_with('\r') {
        return format!("'{}", scrubbed.trim());
    }
    let trimmed = scrubbed.trim();
    if trimmed.starts_with('=')
        || trimmed.starts_with('+')
        || trimmed.starts_with('-')
        || trimmed.starts_with('@')
        || trimmed.starts_with('\t')
        || trimmed.starts_with('\r')
    {
        format!("'{}", trimmed)
    } else {
        trimmed.to_string()
    }
}

/// Read a netscan-style CSV file and map to canonical DiscoveryRecord list.
/// Expected CSV headers (common netscan): Timestamp,IP,MAC,Hostname,Vendor,OS
pub fn read_netscan_csv<P: AsRef<str>>(path: P) -> Result<Vec<DiscoveryRecord>, Box<dyn Error>> {
    let path = path.as_ref();
    let mut rdr = csv::Reader::from_path(path)?;
    let mut out = Vec::new();

    let headers = rdr.headers()?.clone();
    let find = |names: &[&str]| {
        names
            .iter()
            .filter_map(|n| headers.iter().position(|h| h.eq_ignore_ascii_case(n)))
            .next()
    };

    let ip_idx_default = find(&["ip", "IP"]).or(Some(1)).unwrap_or(1);
    let mac_idx_default = find(&["mac", "MAC"]);
    let ts_idx_default = find(&["timestamp", "time", "Timestamp"]);
    let host_idx_default = find(&["hostname", "host", "Host"]);
    let vendor_idx_default = find(&["vendor", "Vendor"]);

    for result in rdr.records() {
        let rec = result?;

        let ip = rec
            .get(ip_idx_default)
            .ok_or("missing IP column")?
            .trim()
            .to_string();

        let hostname = host_idx_default.and_then(|i| rec.get(i)).and_then(|s| {
            let t = s.trim();
            if t.is_empty() { None } else { Some(t) }
        });

        let mac = mac_idx_default.and_then(|i| rec.get(i)).and_then(|s| {
            let t = s.trim();
            if t.is_empty() { None } else { Some(t) }
        });

        let vendor = vendor_idx_default.and_then(|i| rec.get(i)).and_then(|s| {
            let t = s.trim();
            if t.is_empty() { None } else { Some(t) }
        });

        let timestamp = ts_idx_default.and_then(|i| rec.get(i)).and_then(|s| {
            let t = s.trim();
            if t.is_empty() { None } else { Some(t) }
        });

        out.push(DiscoveryRecord::new(
            &ip, None, hostname, mac, vendor, timestamp,
        ));
    }

    Ok(out)
}

/// Write canonical discovery records to a CSV formatted string.
/// Always produces the uniform 6-column header: ip,port,banner,mac,vendor,timestamp
pub fn to_canonical_csv(records: &[DiscoveryRecord]) -> Result<String, Box<dyn Error>> {
    let mut wtr = csv::WriterBuilder::new()
        .has_headers(false)
        .from_writer(Vec::new());
    wtr.write_record(&["ip", "port", "banner", "mac", "vendor", "timestamp"])?;
    for r in records {
        let port_str = r.port.map(|p| p.to_string()).unwrap_or_default();
        let ip_clean = sanitize_csv_field(&r.ip);
        let banner_clean = sanitize_csv_field(r.banner.as_deref().unwrap_or(""));
        let mac_clean = sanitize_csv_field(r.mac.as_deref().unwrap_or(""));
        let vendor_clean = sanitize_csv_field(r.vendor.as_deref().unwrap_or(""));
        let ts_clean = sanitize_csv_field(r.timestamp.as_deref().unwrap_or(""));
        wtr.write_record(&[
            &ip_clean,
            &port_str,
            &banner_clean,
            &mac_clean,
            &vendor_clean,
            &ts_clean,
        ])?;
    }
    wtr.flush()?;
    let bytes = wtr.into_inner().map_err(|e| e.into_error())?;
    Ok(String::from_utf8(bytes)?)
}

/// Convenience: write canonical CSV formatted records directly to a file path.
pub fn write_canonical_csv_file<P: AsRef<std::path::Path>>(
    path: P,
    records: &[DiscoveryRecord],
) -> Result<(), Box<dyn Error>> {
    let s = to_canonical_csv(records)?;
    std::fs::write(path.as_ref(), s)?;
    Ok(())
}
