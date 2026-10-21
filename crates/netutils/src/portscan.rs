use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use std::sync::Arc;

/// Result of a TCP probe: optional banner string (trimmed) when available.
pub type TcpProbeResult = (Ipv4Addr, Option<String>);

/// Structured port scan result for a single port.
#[derive(Debug, Clone)]
pub struct PortResult {
    pub port: u16,
    pub proto: &'static str,
    pub open: bool,
    pub banner: Option<String>,
    pub rtt_ms: Option<u128>,
}

/// Async TCP scanner over a list of IPv4 addresses on a single port.
/// - `timeout` is per-connection timeout
/// - `concurrency` limits number of simultaneous connection attempts
pub async fn scan_tcp_async(
    ips: Vec<Ipv4Addr>,
    port: u16,
    timeout: Duration,
    concurrency: usize,
) -> Vec<TcpProbeResult> {
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut handles = Vec::with_capacity(ips.len());

    for ip in ips {
    let sem_cloned = sem.clone();
    let permit = sem_cloned.acquire_owned().await.unwrap();
        let addr = SocketAddrV4::new(ip, port);
        let timeout = timeout.clone();
        let h = tokio::spawn(async move {
            // Drop permit when finished
            let _p = permit;
            let res = tokio::time::timeout(timeout, TcpStream::connect(addr)).await;
            match res {
                Ok(Ok(mut stream)) => {
                    // Try to read a small banner with a short timeout
                    let mut buf = vec![0u8; 512];
                    let read_res = tokio::time::timeout(Duration::from_millis(300), stream.read(&mut buf)).await;
                    let banner = match read_res {
                        Ok(Ok(n)) if n > 0 => Some(normalize_banner(&String::from_utf8_lossy(&buf[..n]))),
                        _ => None,
                    };
                    // Attempt to close gracefully
                    let _ = stream.shutdown().await;
                    (ip, banner)
                }
                _ => (ip, None),
            }
        });
        handles.push(h);
    }

    let mut out = Vec::new();
    for h in handles {
        if let Ok(item) = h.await {
            out.push(item);
        }
    }
    out
}

/// Blocking wrapper for `scan_tcp_async` using a runtime created locally.
pub fn scan_tcp(
    ips: Vec<Ipv4Addr>,
    port: u16,
    timeout: Duration,
    concurrency: usize,
) -> Vec<TcpProbeResult> {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(scan_tcp_async(ips, port, timeout, concurrency))
}

/// Normalize a banner string: strip CSI/OSC ANSI escapes, trim, keep printable ascii, collapse whitespace, limit length.
pub fn normalize_banner(s: &str) -> String {
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
                _ => {
                    while let Some(&nc) = chars.peek() {
                        chars.next();
                        if nc.is_ascii_alphabetic() {
                            break;
                        }
                    }
                }
            }
            continue;
        }
        if c == '\t' || c == '\n' || c == '\r' {
            out.push(' ');
        } else if c.is_ascii() && !c.is_control() {
            out.push(c);
        }
    }
    let collapsed = out.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.len() > 200 {
        collapsed[..200].to_string()
    } else {
        collapsed
    }
}

/// Scan multiple ports on a single host (TCP). Returns a Vec<PortResult>.
pub async fn scan_host_ports_async(
    ip: Ipv4Addr,
    ports: Vec<u16>,
    timeout: Duration,
    concurrency: usize,
) -> Vec<PortResult> {
    use tokio::time::Instant;
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut handles = Vec::with_capacity(ports.len());
    for port in ports {
        let sem_cloned = sem.clone();
        let timeout = timeout.clone();
        let handle = tokio::spawn(async move {
            let permit = sem_cloned.acquire_owned().await.unwrap();
            let addr = SocketAddrV4::new(ip, port);
            let start = Instant::now();
            let res = tokio::time::timeout(timeout, TcpStream::connect(addr)).await;
            let rtt = start.elapsed().as_millis();
            match res {
                Ok(Ok(mut stream)) => {
                    let mut buf = vec![0u8; 512];
                    let read_res = tokio::time::timeout(Duration::from_millis(300), stream.read(&mut buf)).await;
                    let banner = match read_res {
                        Ok(Ok(n)) if n > 0 => Some(normalize_banner(&String::from_utf8_lossy(&buf[..n]))),
                        _ => None,
                    };
                    let _ = stream.shutdown().await;
                    drop(permit);
                    PortResult { port, proto: "tcp", open: true, banner, rtt_ms: Some(rtt) }
                }
                _ => {
                    drop(permit);
                    PortResult { port, proto: "tcp", open: false, banner: None, rtt_ms: None }
                }
            }
        });
        handles.push(handle);
    }
    let mut out = Vec::new();
    for h in handles {
        if let Ok(item) = h.await {
            out.push(item);
        }
    }
    out
}

/// Blocking wrapper for scan_host_ports_async.
pub fn scan_host_ports(
    ip: Ipv4Addr,
    ports: Vec<u16>,
    timeout: Duration,
    concurrency: usize,
) -> Vec<PortResult> {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(scan_host_ports_async(ip, ports, timeout, concurrency))
}

/// UDP probe: send an empty datagram and wait for a response for `timeout`.
/// Returns (ip, Option<Vec<u8>>) where Vec<u8> is any response bytes received.
pub async fn probe_udp_async(
    ip: Ipv4Addr,
    port: u16,
    timeout: Duration,
) -> (Ipv4Addr, Option<Vec<u8>>) {
    // Bind to ephemeral address on local system
    match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await {
        Ok(socket) => {
            let target = SocketAddrV4::new(ip, port);
            let _ = socket.send_to(&[], target).await;
            let mut buf = vec![0u8; 1500];
            let res = tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await;
            match res {
                Ok(Ok((n, _src))) if n > 0 => (ip, Some(buf[..n].to_vec())),
                _ => (ip, None),
            }
        }
        Err(_) => (ip, None),
    }
}

/// Blocking wrapper for UDP probe.
pub fn probe_udp(ip: Ipv4Addr, port: u16, timeout: Duration) -> (Ipv4Addr, Option<Vec<u8>>) {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(probe_udp_async(ip, port, timeout))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};
    use std::time::Duration;
    use std::thread;

    #[test]
    fn scan_tcp_empty_ips_returns_empty() {
        let res = scan_tcp(vec![], 80, Duration::from_secs(1), 10);
        assert!(res.is_empty());
    }

    #[test]
    fn scan_tcp_local_banner() {
        // Start a TCP listener that writes a small banner then sleeps
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                use std::io::Write;
                let _ = s.write_all(b"HELLO\n");
                // keep connection briefly
                thread::sleep(Duration::from_millis(200));
            }
        });

        let ips = vec![addr.ip().to_string().parse().unwrap()];
        let res = scan_tcp(ips, addr.port(), Duration::from_secs(2), 2);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].1.as_deref(), Some("HELLO"));
    }
}
