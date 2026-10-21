use discovery::{ports, Discover, HardwareIdentityRegistry, LeaseDriftEvent, SimpleDiscover};
use formats::DiscoveryRecord;
use std::net::{Ipv4Addr, TcpListener};
use std::thread;
use std::time::Duration;

#[test]
fn parity_nmap_port_range_and_preset_semantics() {
    // Nmap -p "22,80,443,8000-8003" equivalent port spec parsing
    let parsed = ports::parse_port_list("22,80,443,8000-8003,80");
    assert_eq!(parsed, vec![22, 80, 443, 8000, 8001, 8002, 8003]);

    // Nmap -F (fast top ports) equivalent preset
    let fast = ports::fast_ports();
    assert!(fast.contains(&22));
    assert!(fast.contains(&80));
    assert!(fast.contains(&443));
    assert!(fast.len() >= 50);
}

#[test]
fn parity_nmap_tcp_connect_and_banner_scrubbing() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind ephemeral port");
    let addr = listener.local_addr().unwrap();

    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            use std::io::Write;
            // Send a banner containing both OSC and CSI ANSI sequences
            let _ = stream.write_all(b"\x1b]0;PwnedTitle\x07\x1b[31mSSH-2.0-OpenSSH_9.6\x1b[0m\r\n");
            thread::sleep(Duration::from_millis(50));
        }
    });

    let results = netutils::portscan::scan_host_ports(
        Ipv4Addr::LOCALHOST,
        vec![addr.port()],
        Duration::from_secs(1),
        4,
    );
    assert_eq!(results.len(), 1);
    assert!(results[0].open);
    assert_eq!(results[0].banner.as_deref(), Some("SSH-2.0-OpenSSH_9.6"));
}

#[test]
fn sovereign_identity_anchor_tracks_mac_across_ip_lease_drift() {
    let mut registry = HardwareIdentityRegistry::new();

    // T0: Initial discovery at 192.0.2.10
    let t0_records = SimpleDiscover::new(vec![(
        "192.0.2.10".to_string(),
        Some(22),
        Some("SSH-2.0-SovereignNode".to_string()),
        Some("00-11-22-AA-BB-CC".to_string()),
        Some("Sovereign Hardware Inc.".to_string()),
        Some("2026-10-18T00:00:00Z".to_string()),
    )])
    .discover();

    let drift_t0 = registry.ingest_records(&t0_records);
    assert!(drift_t0.is_empty(), "No drift on initial anchor");
    assert_eq!(registry.len(), 1);

    // T1: Device roams to 192.0.2.55 via DHCP renewal and opens port 443
    let t1_records = vec![DiscoveryRecord::new(
        "192.0.2.55",
        Some(443),
        None,
        Some("00:11:22:aa:bb:cc"),
        None,
        Some("2026-10-18T00:05:00Z"),
    )];

    let drift_t1 = registry.ingest_records(&t1_records);
    assert_eq!(
        drift_t1,
        vec![LeaseDriftEvent {
            mac: "00:11:22:aa:bb:cc".to_string(),
            previous_ip: "192.0.2.10".to_string(),
            current_ip: "192.0.2.55".to_string(),
            vendor: Some("Sovereign Hardware Inc.".to_string()),
        }]
    );

    let anchored = registry
        .get_by_mac("00-11-22-AA-BB-CC")
        .expect("anchored asset must resolve regardless of MAC separator case");
    assert_eq!(anchored.current_ip, "192.0.2.55");
    assert_eq!(anchored.ip_history, vec!["192.0.2.10".to_string()]);
    assert_eq!(anchored.open_ports, vec![22, 443]);
    assert_eq!(
        anchored.vendor.as_deref(),
        Some("Sovereign Hardware Inc."),
        "Vendor identity preserved across DHCP lease drift"
    );
    assert_eq!(
        anchored.banner.as_deref(),
        Some("SSH-2.0-SovereignNode"),
        "Historic service banner preserved across lease drift"
    );
}

#[test]
fn adversarial_ansi_and_formula_evasion_neutralized_in_csv() {
    let records = vec![DiscoveryRecord::new(
        "192.0.2.99",
        Some(80),
        Some("\x1b]0;EvilTitle\x07\x1b[31m=cmd|' /C calc'!A0"),
        Some("00:11:22:33:44:55"),
        Some("\t@SUM(1+1)"),
        Some("\r-2+3"),
    )];

    let csv_out = io::to_canonical_csv(&records).expect("canonical csv export");
    assert!(
        !csv_out.contains('\x1b'),
        "Raw ANSI escape sequences must never leak into CSV export"
    );
    assert!(
        csv_out.contains("'=cmd|' /C calc'!A0"),
        "ANSI-prefixed formula injection must still be neutralized with leading single quote: {}",
        csv_out
    );
    assert!(
        csv_out.contains("'@SUM(1+1)"),
        "Tab-prefixed formula payload must be neutralized: {}",
        csv_out
    );
}
