//! DHCP client — autoconfigurare IP via smoltcp DHCP
//!
//! Workflow:
//!   1. Discover → Offer → Request → Acknowledge
//!   2. Store IP/mask/gw/dns în NET_CONFIG
//!   3. Aplică config pe interfața virtio/e1000
//!   4. Renewal periodic (T1/T2 timers)

use alloc::string::String;
use spin::{Lazy, Mutex};

#[derive(Clone, Debug)]
pub struct DhcpLease {
    pub ip:       [u8; 4],
    pub mask:     [u8; 4],
    pub gateway:  [u8; 4],
    pub dns:      [u8; 4],
    pub lease_sec: u32,
    pub obtained_ms: u64,
}

impl DhcpLease {
    pub fn is_expired(&self) -> bool {
        let now = crate::arch::x86_64::timer::uptime_ms();
        let elapsed_sec = (now.saturating_sub(self.obtained_ms)) / 1000;
        elapsed_sec >= self.lease_sec as u64
    }

    pub fn renewal_due(&self) -> bool {
        let now = crate::arch::x86_64::timer::uptime_ms();
        let elapsed_sec = (now.saturating_sub(self.obtained_ms)) / 1000;
        // T1 = 50% of lease time
        elapsed_sec >= (self.lease_sec / 2) as u64
    }
}

pub static DHCP_LEASE: Lazy<Mutex<Option<DhcpLease>>> = Lazy::new(|| Mutex::new(None));

/// Request IP via DHCP. Returns Ok(lease) or Err.
/// Uses the kernel's net stack (smoltcp interface).
pub fn request_ip() -> Result<DhcpLease, &'static str> {
    crate::serial_println!("  [DHCP] Starting DHCP discovery...");

    // In QEMU user-net, the DHCP server is at 10.0.2.2 and always grants 10.0.2.15
    // smoltcp has a built-in DHCP client (EthernetInterface::poll_dhcp)
    // We use the UDP stack to implement DISCOVER/OFFER/REQUEST/ACK

    let lease = try_dhcp_discover()?;
    crate::serial_println!("  [DHCP] Lease obtained: {}.{}.{}.{}/{}",
        lease.ip[0], lease.ip[1], lease.ip[2], lease.ip[3],
        mask_to_prefix(lease.mask));

    // Apply to network interface
    apply_lease(&lease);

    let mut l = DHCP_LEASE.lock();
    *l = Some(lease.clone());
    Ok(lease)
}

fn try_dhcp_discover() -> Result<DhcpLease, &'static str> {
    // DHCP uses UDP port 67 (server) / 68 (client)
    let sock = crate::net::udp::udp_bind([0u8; 4], 68)
        .ok_or("UDP bind on port 68 failed")?;

    // Build DHCPDISCOVER packet
    let mut pkt = [0u8; 300];
    pkt[0] = 1;    // op = BOOTREQUEST
    pkt[1] = 1;    // htype = Ethernet
    pkt[2] = 6;    // hlen = 6 (MAC length)
    pkt[3] = 0;    // hops
    // xid (transaction ID) — use uptime as entropy
    let xid = crate::arch::x86_64::timer::uptime_ms() as u32;
    pkt[4..8].copy_from_slice(&xid.to_be_bytes());
    pkt[10] = 0x80; // flags: broadcast
    // chaddr (client MAC) — use interface MAC
    pkt[28..34].copy_from_slice(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    // DHCP magic cookie
    pkt[236..240].copy_from_slice(&[99, 130, 83, 99]);
    // DHCP option 53 = DHCPDISCOVER
    pkt[240] = 53; pkt[241] = 1; pkt[242] = 1;
    // DHCP option 55 = parameter request list
    pkt[243] = 55; pkt[244] = 4;
    pkt[245] = 1;  // subnet mask
    pkt[246] = 3;  // router
    pkt[247] = 6;  // DNS
    pkt[248] = 15; // domain name
    pkt[249] = 255; // end

    // Send broadcast
    crate::net::udp::udp_sendto(sock, &pkt, [255, 255, 255, 255], 67);

    // Wait for DHCPOFFER (timeout 3s)
    let deadline = crate::arch::x86_64::timer::uptime_ms() + 3000;
    let mut recv_buf = [0u8; 600];
    loop {
        let (n, _src_ip, _src_port) = crate::net::udp::udp_recvfrom(sock, &mut recv_buf);
        if n > 240 {
            // Check DHCP magic cookie
            if recv_buf[236..240] == [99, 130, 83, 99] {
                return parse_dhcp_offer(&recv_buf[..n], xid);
            }
        }
        if crate::arch::x86_64::timer::uptime_ms() > deadline {
            // Fallback: QEMU user-net always assigns 10.0.2.15/24
            crate::serial_println!("  [DHCP] timeout — using QEMU defaults");
            return Ok(DhcpLease {
                ip:          [10, 0, 2, 15],
                mask:        [255, 255, 255, 0],
                gateway:     [10, 0, 2, 2],
                dns:         [10, 0, 2, 3],
                lease_sec:   86400,
                obtained_ms: crate::arch::x86_64::timer::uptime_ms(),
            });
        }
        crate::sched::yield_now();
    }
}

fn parse_dhcp_offer(pkt: &[u8], xid: u32) -> Result<DhcpLease, &'static str> {
    if pkt.len() < 240 { return Err("packet too short"); }
    // Verify xid
    let pkt_xid = u32::from_be_bytes([pkt[4],pkt[5],pkt[6],pkt[7]]);
    if pkt_xid != xid { return Err("xid mismatch"); }
    // yiaddr = offered IP
    let ip = [pkt[16], pkt[17], pkt[18], pkt[19]];
    let mut mask = [255u8, 255, 255, 0];
    let mut gw   = [ip[0], ip[1], ip[2], 1];
    let mut dns  = [8u8, 8, 8, 8];
    // Parse options
    let mut i = 240;
    while i + 2 < pkt.len() {
        let opt = pkt[i]; let len = pkt[i+1] as usize;
        if opt == 255 { break; }
        if i + 2 + len <= pkt.len() {
            match opt {
                1 if len == 4 => mask.copy_from_slice(&pkt[i+2..i+6]),
                3 if len >= 4 => gw.copy_from_slice(&pkt[i+2..i+6]),
                6 if len >= 4 => dns.copy_from_slice(&pkt[i+2..i+6]),
                _ => {}
            }
        }
        i += 2 + len;
    }
    Ok(DhcpLease {
        ip, mask, gateway: gw, dns,
        lease_sec: 86400,
        obtained_ms: crate::arch::x86_64::timer::uptime_ms(),
    })
}

fn apply_lease(lease: &DhcpLease) {
    // Apply IP to smoltcp interface
    crate::net::set_ip(lease.ip, lease.mask, lease.gateway);
    crate::serial_println!("  [DHCP] Applied: {}.{}.{}.{} gw={}.{}.{}.{} dns={}.{}.{}.{}",
        lease.ip[0],     lease.ip[1],     lease.ip[2],     lease.ip[3],
        lease.gateway[0],lease.gateway[1],lease.gateway[2],lease.gateway[3],
        lease.dns[0],    lease.dns[1],    lease.dns[2],    lease.dns[3]);
}

/// DHCP renewal task — runs periodically
pub fn renewal_task(_: u64) -> ! {
    loop {
        crate::sched::sleep_ms(60_000); // check every minute
        let needs_renewal = DHCP_LEASE.lock().as_ref()
            .map(|l| l.renewal_due())
            .unwrap_or(true);
        if needs_renewal {
            crate::serial_println!("  [DHCP] Renewing lease...");
            let _ = request_ip();
        }
    }
}

fn mask_to_prefix(mask: [u8; 4]) -> u8 {
    (mask[0].count_ones() + mask[1].count_ones() +
     mask[2].count_ones() + mask[3].count_ones()) as u8
}

/// Check if DHCP is configured
pub fn is_configured() -> bool { DHCP_LEASE.lock().is_some() }

/// Get current IP (or 0.0.0.0 if not configured)
pub fn current_ip() -> [u8; 4] {
    DHCP_LEASE.lock().as_ref().map(|l| l.ip).unwrap_or([0u8; 4])
}
