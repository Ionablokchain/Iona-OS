//! DNS resolver — interogare A records via UDP
//!
//! Implementare conform RFC 1035, cu suport pentru:
//! - Cache local (BTreeMap + Mutex)
//! - Fallback la /etc/resolv.conf sau DHCP
//! - Rezolvare directă IP literală
//! - Retry logic (3 încercări) cu timeout progresiv
//! - Parsare robustă a răspunsurilor, inclusiv compresie pointeri
//! - Logare serială pentru depanare

use alloc::{vec::Vec, string::String, collections::BTreeMap};
use spin::{Lazy, Mutex};

/// Cache DNS persistent pe durata rulării.
/// În viitor se poate adăuga TTL și o limită de capacitate.
static DNS_CACHE: Lazy<Mutex<BTreeMap<String, [u8; 4]>>> = Lazy::new(|| {
    let mut m = BTreeMap::new();
    m.insert("localhost".into(), [127, 0, 0, 1]);
    Mutex::new(m)
});

const DNS_PORT: u16 = 53;
const DNS_TIMEOUT_MS: u64 = 3000;      // timeout total per interogare
const DNS_MAX_RETRIES: usize = 3;      // reîncercări după timeout parțial

/// Rezolvă un hostname la o adresă IPv4.
///
/// Ordinea de căutare:
/// 1. Cache local
/// 2. Parsare IP literal (ex: "10.0.0.1")
/// 3. Interogare DNS reală (UDP) cu retry
///
/// Returnează `None` doar dacă niciuna dintre metode nu a produs un rezultat.
pub fn resolve(hostname: &str) -> Option<[u8; 4]> {
    // 1. Cache hit
    {
        let cache = DNS_CACHE.lock();
        if let Some(&ip) = cache.get(hostname) {
            return Some(ip);
        }
    }

    // 2. Adresă IP literală (evităm interogări DNS inutile)
    if let Some(ip) = parse_ipv4(hostname) {
        return Some(ip);
    }

    // 3. DNS real
    let dns_server = get_dns_server();
    let result = dns_query(hostname, dns_server);
    
    // 4. Dacă am primit un răspuns valid, actualizăm cache-ul
    if let Some(ip) = result {
        DNS_CACHE.lock().insert(hostname.into(), ip);
    }
    result
}

/// Construiește un pachet de interogare DNS (A record, recursive).
fn build_query(name: &str, tx_id: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(64);
    // Header (12 octeți)
    q.extend_from_slice(&tx_id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // Flags: RD=1 (recursion desired)
    q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    q.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
    q.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    q.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0

    // QNAME: codificare în etichete
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        // Limităm eticheta la 63 de octeți conform RFC
        let len = label.len().min(63);
        q.push(len as u8);
        q.extend_from_slice(&label.as_bytes()[..len]);
    }
    q.push(0x00); // terminare QNAME (root label)
    // QTYPE=A (1), QCLASS=IN (1)
    q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    q
}

/// Trimite interogarea și așteaptă răspunsul, cu reîncercări.
fn dns_query(hostname: &str, dns_server: [u8; 4]) -> Option<[u8; 4]> {
    // ID de tranzacție aleator (derivat din timp)
    let tx_id = (crate::arch::x86_64::timer::uptime_ms() & 0xFFFF) as u16;
    let query = build_query(hostname, tx_id);

    // Alocăm un socket UDP efemer
    let fd = crate::net::udp::udp_bind([0, 0, 0, 0], 0)?;

    let timeout_per_attempt = DNS_TIMEOUT_MS / DNS_MAX_RETRIES as u64;
    let mut attempt = 0;

    while attempt < DNS_MAX_RETRIES {
        // Trimitem interogarea
        crate::net::udp::udp_sendto(fd, &query, dns_server, DNS_PORT);

        let deadline = crate::arch::x86_64::timer::uptime_ms() + timeout_per_attempt;
        let mut buf = [0u8; 512];  // buffer suficient pentru răspunsurile obișnuite

        loop {
            if crate::arch::x86_64::timer::uptime_ms() > deadline {
                break; // timeout pentru această încercare
            }

            // Încercăm să citim fără a bloca prea mult
            let (n, _src, _sport) = crate::net::udp::udp_recvfrom(fd, &mut buf);
            if n >= 12 {
                let resp_id = u16::from_be_bytes([buf[0], buf[1]]);
                if resp_id == tx_id {
                    // Răspunsul corespunde interogării noastre
                    match parse_response(&buf[..n]) {
                        Ok(ip) => {
                            crate::net::udp::udp_close(fd);
                            return Some(ip);
                        }
                        Err(e) => {
                            // Eroare permanentă (NXDOMAIN, SERVFAIL, etc.)
                            crate::serial_println!("[DNS] {}: {}", hostname, e);
                            crate::net::udp::udp_close(fd);
                            return None;
                        }
                    }
                }
                // altfel, pachet străin, continuăm să așteptăm
            }
            crate::arch::x86_64::timer::sleep_ms(5); // evităm polling-ul intens
        }

        attempt += 1;
        if attempt < DNS_MAX_RETRIES {
            crate::serial_println!(
                "[DNS] timeout attempt {}/{}, retrying...",
                attempt, DNS_MAX_RETRIES
            );
        }
    }

    crate::net::udp::udp_close(fd);
    crate::serial_println!("[DNS] all attempts failed for {}", hostname);
    None
}

/// Parsează răspunsul DNS și extrage primul A record valid.
/// Returnează `Ok(ip)` sau `Err("mesaj")` în caz de eroare definitivă.
fn parse_response(data: &[u8]) -> Result<[u8; 4], &'static str> {
    if data.len() < 12 {
        return Err("response too short");
    }

    let flags   = u16::from_be_bytes([data[2], data[3]]);
    let rcode   = flags & 0x000F;
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

    // Verificăm bitul QR (trebuie să fie răspuns)
    if flags & 0x8000 == 0 {
        return Err("not a response");
    }

    // Trunchiere: în producție s-ar putea reîncerca cu TCP,
    // dar pentru un resolver simplu considerăm eroare temporară.
    // (Atenție: în implementarea curentă, dacă TC=1, ignorăm și încercăm totuși să parsăm)
    if flags & 0x0200 != 0 {
        crate::serial_println!("[DNS] warning: truncated response (TC=1)");
    }

    // Coduri de răspuns definitive
    match rcode {
        0 => (), // NoError
        3 => return Err("NXDOMAIN"),
        2 => return Err("SERVFAIL"),
        _ => return Err("server error"),
    }

    if ancount == 0 {
        // Răspuns valid, dar fără răspunsuri (posibil CNAME fără A asociat)
        return Err("no answer records");
    }

    // Sar peste secțiunea de întrebări
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(data, pos).ok_or("invalid question name")?;
        pos = pos.checked_add(4).ok_or("question overflow")?; // QTYPE + QCLASS
    }

    // Parcurgem răspunsurile
    for _ in 0..ancount {
        pos = skip_name(data, pos).ok_or("invalid answer name")?;
        if pos + 10 > data.len() {
            return Err("answer header truncated");
        }

        let rtype = u16::from_be_bytes([data[pos], data[pos+1]]);
        let rdlen = u16::from_be_bytes([data[pos+8], data[pos+9]]) as usize;
        pos += 10;

        if pos + rdlen > data.len() {
            return Err("answer data truncated");
        }

        if rtype == 1 && rdlen == 4 {
            // Am găsit un A record valid
            let ip = [data[pos], data[pos+1], data[pos+2], data[pos+3]];
            return Ok(ip);
        }
        // Alt tip de înregistrare (CNAME, AAAA, etc.), îl sărim
        pos += rdlen;
    }

    Err("no A record found")
}

/// Decodifică un nume DNS comprimat (suportă pointeri).
/// Returnează poziția imediat după numele decodificat.
fn skip_name(data: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= data.len() {
            return None;
        }
        let len = data[pos] as usize;
        if len == 0 {
            return Some(pos + 1); // etichetă de terminare
        }
        if len & 0xC0 == 0xC0 {
            // Pointer comprimat: doi octeți, următorul offset este imediat după
            return pos.checked_add(2);
        }
        // Etichetă normală: lungime + conținut
        pos = pos.checked_add(1 + len)?;
    }
}

/// Determină serverul DNS configurat.
/// Ordine de prioritate:
/// 1. /etc/resolv.conf (dacă există)
/// 2. DHCP (lease-ul curent)
/// 3. Fallback 8.8.8.8
fn get_dns_server() -> [u8; 4] {
    // Încercăm fișierul de configurare static
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

    // Încercăm informațiile de la DHCP
    if let Some(lease) = crate::net::dhcp::get_lease() {
        if lease.obtained && !lease.dns.iter().all(|&b| b == 0) {
            return lease.dns;
        }
    }

    // Fallback
    [8, 8, 8, 8]
}

/// Convertește un string IPv4 în array de 4 octeți.
fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut parts = s.split('.');
    let a = parts.next()?.parse::<u8>().ok()?;
    let b = parts.next()?.parse::<u8>().ok()?;
    let c = parts.next()?.parse::<u8>().ok()?;
    let d = parts.next()?.parse::<u8>().ok()?;
    if parts.next().is_some() {
        return None; // prea multe componente
    }
    Some([a, b, c, d])
}

/// Inserează manual o intrare în cache-ul DNS (utilă pentru configurări statice).
pub fn cache_insert(name: &str, ip: [u8; 4]) {
    DNS_CACHE.lock().insert(name.into(), ip);
}
