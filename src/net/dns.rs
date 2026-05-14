//! DNS resolver — interogare A records via UDP
//!
//! Protocol DNS (RFC 1035):
//!   Query: [ID:2][Flags:2][QDCOUNT:2][...][ANCOUNT:2][...][ARCOUNT:2]
//!   Question: [QNAME][QTYPE:2][QCLASS:2]
//!   Answer:   [NAME][TYPE:2][CLASS:2][TTL:4][RDLEN:2][RDATA]
//!
//! Implementare: trimite query UDP pe port 53, parseazăr răspunsul
//! Folosește smoltcp UDP socket intern

use alloc::{vec::Vec, string::String};

use alloc::collections::BTreeMap;
use spin::{Lazy, Mutex};

static DNS_CACHE: Lazy<Mutex<BTreeMap<String, [u8; 4]>>> = Lazy::new(|| {
    let mut m = BTreeMap::new();
    m.insert("localhost".into(), [127,0,0,1]);
    Mutex::new(m)
});

const DNS_PORT:    u16   = 53;
const DNS_TIMEOUT: u64   = 3000; // ms

/// Rezolvă un hostname la IPv4 — returnează prima adresă A din răspuns
pub fn resolve(hostname: &str) -> Option<[u8; 4]> {
    if let Some(ip) = DNS_CACHE.lock().get(hostname).copied() { return Some(ip); }

    // Hardcoded fallback pentru hosturi comune
    if hostname == "localhost" || hostname == "127.0.0.1" {
        return Some([127, 0, 0, 1]);
    }

    // Try to parse as direct IP
    if let Some(ip) = parse_ipv4(hostname) {
        return Some(ip);
    }

    // Use system DNS server (8.8.8.8 as default, overridden by DHCP)
    let dns_server = get_dns_server();

    // Build DNS query
    let tx_id: u16 = (crate::arch::x86_64::timer::uptime_ms() & 0xFFFF) as u16;
    let query = build_query(hostname, tx_id);

    // Send via UDP and wait for response
    let fd = crate::net::udp_bind([0,0,0,0], 0)?; // bind to ephemeral port
    crate::net::udp_sendto(fd, &query, dns_server, DNS_PORT);

    // Poll for response with retry (up to 3 attempts)
    const MAX_RETRIES: usize = 3;
    let mut attempt = 0;
    while attempt < MAX_RETRIES {
        let deadline = crate::arch::x86_64::timer::uptime_ms() + DNS_TIMEOUT / MAX_RETRIES as u64;
        let mut buf = alloc::vec![0u8; 512];
        loop {
            let (n, _src_ip, _src_port) = crate::net::udp_recvfrom(fd, &mut buf);
            if n >= 12 {
                let resp_id = u16::from_be_bytes([buf[0], buf[1]]);
                if resp_id == tx_id {
                    if let Some(ip) = parse_response(&buf[..n]) {
                        DNS_CACHE.lock().insert(hostname.into(), ip);
                        crate::net::udp_close(fd);
                        return Some(ip);
                    }
                    // Got a response for our ID but no A record (NXDOMAIN etc.)
                    crate::net::udp_close(fd);
                    return None;
                }
            }
            if crate::arch::x86_64::timer::uptime_ms() > deadline { break; }
            crate::arch::x86_64::timer::sleep_ms(10);
        }
        // Retry: re-send query
        attempt += 1;
        if attempt < MAX_RETRIES {
            crate::serial_println!("[DNS] timeout attempt {}/{}, retrying...", attempt, MAX_RETRIES);
            crate::net::udp_sendto(fd, &query, dns_server, DNS_PORT);
        }
    }
    crate::net::udp_close(fd);
    None
}

fn get_dns_server() -> [u8; 4] {
    // Try to read from DHCP-configured DNS, fallback to 8.8.8.8
    if let Some(data) = crate::fs::ionafs::read("/etc/resolv.conf") {
        for line in data.split(|&b| b == b'\n') {
            if line.starts_with(b"nameserver ") {
                let s = core::str::from_utf8(&line[11..]).unwrap_or("");
                if let Some(ip) = parse_ipv4(s.trim()) {
                    return ip;
                }
            }
        }
    }
    [8, 8, 8, 8] // Google Public DNS fallback
}

fn build_query(name: &str, tx_id: u16) -> Vec<u8> {
    let mut q = Vec::new();
    // Header
    q.extend_from_slice(&tx_id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // Flags: QR=0 Opcode=0 RD=1
    q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    q.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
    q.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    q.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0
    // Question: encode name as labels
    for part in name.split('.') {
        q.push(part.len() as u8);
        q.extend_from_slice(part.as_bytes());
    }
    q.push(0); // root label
    q.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
    q.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
    q
}

fn parse_response(data: &[u8]) -> Option<[u8; 4]> {
    if data.len() < 12 { return None; }

    let flags   = u16::from_be_bytes([data[2], data[3]]);
    let rcode   = flags & 0x000F;  // Response code
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;

    // Must be a response (QR=1)
    if flags & 0x8000 == 0 { return None; }

    // NXDOMAIN (rcode=3) or SERVFAIL (rcode=2) — no answer
    if rcode == 3 {
        crate::serial_println!("[DNS] NXDOMAIN");
        return None;
    }
    if rcode != 0 {
        crate::serial_println!("[DNS] server error rcode={}", rcode);
        return None;
    }

    if ancount == 0 { return None; }

    // TC bit (truncated) — in real impl: retry with TCP
    if flags & 0x0200 != 0 {
        crate::serial_println!("[DNS] WARN: truncated response (TC=1), trying anyway");
    }

    // Skip question section(s)
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(data, pos)?;
        pos = pos.checked_add(4)?; // QTYPE + QCLASS
    }

    // Parse answer records — return first A record found
    for _ in 0..ancount {
        if pos >= data.len() { return None; }
        pos = skip_name(data, pos)?;
        if pos + 10 > data.len() { return None; }
        let rtype  = u16::from_be_bytes([data[pos],   data[pos+1]]);
        // let rclass = u16::from_be_bytes([data[pos+2], data[pos+3]]);
        // let ttl    = u32::from_be_bytes([data[pos+4], data[pos+5], data[pos+6], data[pos+7]]);
        let rdlen  = u16::from_be_bytes([data[pos+8], data[pos+9]]) as usize;
        pos += 10;
        if pos + rdlen > data.len() { return None; }

        if rtype == 1 && rdlen == 4 {
            // Type A — IPv4 address
            return Some([data[pos], data[pos+1], data[pos+2], data[pos+3]]);
        }
        // Skip other record types (CNAME=5, AAAA=28, etc.)
        pos = pos.checked_add(rdlen)?;
    }
    None
}

fn skip_name(data: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= data.len() { return None; }
        let len = data[pos] as usize;
        if len == 0 { return Some(pos + 1); }
        if len & 0xC0 == 0xC0 { return Some(pos + 2); } // pointer
        pos += 1 + len;
    }
}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 { return None; }
    let mut ip = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        ip[i] = part.parse::<u8>().ok()?;
    }
    Some(ip)
}


pub fn cache_insert(name: &str, ip: [u8; 4]) {
    DNS_CACHE.lock().insert(name.into(), ip);
}

/// Build DNS A record query packet
fn build_dns_query(id: u16, hostname: &str) -> alloc::vec::Vec<u8> {
    let mut pkt = alloc::vec![0u8; 512];
    // Header: ID, flags (recursion desired), QDCOUNT=1
    pkt[0] = (id >> 8) as u8; pkt[1] = id as u8;
    pkt[2] = 0x01; pkt[3] = 0x00; // RD bit
    pkt[4] = 0x00; pkt[5] = 0x01; // QDCOUNT = 1
    // Question: QNAME (labels), QTYPE=A(1), QCLASS=IN(1)
    let mut pos = 12usize;
    for label in hostname.split('.') {
        if label.is_empty() { continue; }
        pkt[pos] = label.len() as u8; pos += 1;
        for b in label.bytes() { pkt[pos] = b; pos += 1; }
    }
    pkt[pos] = 0; pos += 1; // root
    pkt[pos] = 0; pkt[pos+1] = 1; pos += 2; // QTYPE A
    pkt[pos] = 0; pkt[pos+1] = 1; pos += 2; // QCLASS IN
    pkt.truncate(pos);
    pkt
}

/// Parse DNS response — extract first A record
fn parse_dns_response(pkt: &[u8]) -> Option<[u8; 4]> {
    if pkt.len() < 12 { return None; }
    let ancount = u16::from_be_bytes([pkt[6], pkt[7]]) as usize;
    if ancount == 0 { return None; }
    // Skip question section — find answer section
    let mut pos = 12usize;
    // Skip QNAME
    while pos < pkt.len() {
        let len = pkt[pos] as usize; pos += 1;
        if len == 0 { break; }
        if len & 0xC0 == 0xC0 { pos += 1; break; } // pointer
        pos += len;
    }
    pos += 4; // skip QTYPE + QCLASS
    // Parse first answer
    while pos < pkt.len() {
        // Skip NAME
        if pos >= pkt.len() { break; }
        if pkt[pos] & 0xC0 == 0xC0 { pos += 2; }
        else { while pos < pkt.len() && pkt[pos] != 0 { pos += 1; } pos += 1; }
        if pos + 10 > pkt.len() { break; }
        let rtype  = u16::from_be_bytes([pkt[pos], pkt[pos+1]]); pos += 2;
        pos += 2; // CLASS
        pos += 4; // TTL
        let rdlen  = u16::from_be_bytes([pkt[pos], pkt[pos+1]]) as usize; pos += 2;
        if rtype == 1 && rdlen == 4 && pos + 4 <= pkt.len() {
            return Some([pkt[pos], pkt[pos+1], pkt[pos+2], pkt[pos+3]]);
        }
        pos += rdlen;
    }
    None
}

/// Send DNS query and wait for response
fn send_dns_query(hostname: &str) -> Option<[u8; 4]> {
    // Get DNS server from DHCP lease or default
    let dns_ip = {
        let lease = crate::net::dhcp::get_lease();
        if lease.obtained { lease.dns } else { [8, 8, 8, 8] }
    };

    let query_id: u16 = (crate::arch::x86_64::timer::uptime_ms() & 0xFFFF) as u16;
    let pkt = build_dns_query(query_id, hostname);

    // Bind ephemeral port and send to DNS server port 53
    let local_port = 10000 + (query_id % 10000);
    let dns_fd = crate::net::udp::udp_bind(local_port);
    crate::net::udp::udp_sendto(dns_fd, &pkt, dns_ip, 53);

    // Wait for response (up to 3s)
    let deadline = crate::arch::x86_64::timer::uptime_ms() + 3000;
    while crate::arch::x86_64::timer::uptime_ms() < deadline {
        {
            let mut resp_buf = [0u8; 1024];
            let (rn, _rip, _rport) = crate::net::udp::udp_recvfrom(dns_fd, &mut resp_buf);
            if rn >= 2 {
                let resp = &resp_buf[..rn];
                let resp_id = u16::from_be_bytes([resp[0], resp[1]]);
                if resp_id == query_id {
                    if let Some(ip) = parse_dns_response(resp) {
                        crate::serial_println!("[DNS] {} → {}.{}.{}.{}", hostname, ip[0],ip[1],ip[2],ip[3]);
                        return Some(ip);
                    }
                }
            }
        }
        crate::arch::x86_64::timer::sleep_ms(10);
    }
    crate::serial_println!("[DNS] timeout for {}", hostname);
    None
}

/// Resolve hostname — cache hit or real UDP query
pub fn resolve_full(hostname: &str) -> Option<[u8; 4]> {
    // Check cache first
    if let Some(ip) = DNS_CACHE.lock().get(hostname).copied() { return Some(ip); }
    // Send real UDP query
    if let Some(ip) = send_dns_query(hostname) {
        DNS_CACHE.lock().insert(hostname.into(), ip);
        return Some(ip);
    }
    // Hardcoded fallbacks
    parse_ipv4(hostname)
}
