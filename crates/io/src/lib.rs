//! IO adapters for legacy netscan JSON/CSV into canonical `formats::DiscoveryRecord`

mod csv_io;
mod json_io;
mod oui;

pub use csv_io::{
    read_netscan_csv, sanitize_csv_field, scrub_ansi, to_canonical_csv, write_canonical_csv_file,
};
pub use json_io::{
    read_netscan_json, to_legacy_json, to_target_json, write_legacy_json_file,
    write_target_json_file,
};
pub use oui::default_cache_path;
pub use oui::load_from_str;
pub use oui::lookup_vendor;
pub use oui::lookup_vendor as lookup_vendor_from_oui;
pub use oui::update_oui_cache;
