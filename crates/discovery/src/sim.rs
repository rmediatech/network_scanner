use crate::Discover;
#[cfg(feature = "enrich")]
use enrich::vendor_from_hostname;
use formats::DiscoveryRecord;
use io::{read_netscan_csv, read_netscan_json};
use std::error::Error;
use std::path::Path;

/// A simple, deterministic discoverer built from an explicit list of
/// tuples (ip, port, banner, mac, vendor, timestamp). Useful for unit tests.
pub struct SimpleDiscover {
    items: Vec<(
        String,
        Option<u16>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    )>,
}

impl SimpleDiscover {
    /// Create a new SimpleDiscover from an iterator of tuples.
    pub fn new<I>(items: I) -> Self
    where
        I: Into<
            Vec<(
                String,
                Option<u16>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
            )>,
        >,
    {
        Self {
            items: items.into(),
        }
    }
}

impl Discover for SimpleDiscover {
    fn discover(&self) -> Vec<DiscoveryRecord> {
        self.items
            .iter()
            .map(|(ip, port, banner, mac, vendor, timestamp)| {
                DiscoveryRecord::new(
                    ip,
                    *port,
                    banner.as_deref(),
                    mac.as_deref(),
                    vendor.as_deref(),
                    timestamp.as_deref(),
                )
            })
            .collect()
    }
}

/// ArpSimDiscover: load legacy netscan outputs (CSV/JSON) and map them into canonical DiscoveryRecord
pub struct ArpSimDiscover {}

impl ArpSimDiscover {
    /// Load from a CSV file path (netscan-style) and return canonical DiscoveryRecord list.
    pub fn from_csv<P: AsRef<Path>>(p: P) -> Result<Vec<DiscoveryRecord>, Box<dyn Error>> {
        let mut recs = read_netscan_csv(p.as_ref().to_str().ok_or("invalid path")?)?;
        #[cfg(feature = "enrich")]
        {
            for r in recs.iter_mut() {
                if r.vendor.is_none() {
                    if let Some(b) = r.banner.as_deref() {
                        if let Some(v) = vendor_from_hostname(b) {
                            r.vendor = Some(v);
                        }
                    }
                }
            }
        }
        Ok(recs)
    }

    /// Load from a JSON file path (netscan-style) and return canonical DiscoveryRecord list.
    pub fn from_json<P: AsRef<Path>>(p: P) -> Result<Vec<DiscoveryRecord>, Box<dyn Error>> {
        let mut recs = read_netscan_json(p.as_ref().to_str().ok_or("invalid path")?)?;
        #[cfg(feature = "enrich")]
        {
            for r in recs.iter_mut() {
                if r.vendor.is_none() {
                    if let Some(b) = r.banner.as_deref() {
                        if let Some(v) = vendor_from_hostname(b) {
                            r.vendor = Some(v);
                        }
                    }
                }
            }
        }
        Ok(recs)
    }
}
