//! Network epoll integration — proper async I/O model
//!
//! Bridges smoltcp poll events with epoll notifications.
//! When a TCP socket becomes readable/writable, wakes tasks
//! waiting in epoll_wait().
//!
//! Also provides peer discovery via UDP broadcast/multicast.

use core::str::FromStr;

/// Constants for send buffer backpressure.
const TCP_MIN_SEND_BUFFER_FREE: usize = 512; // bytes

/// Default multicast group for peer discovery (IANA assigned).
const DISCOVERY_MULTICAST_ADDR: [u8; 4] = [239, 192, 0, 1];
/// Beacon message identifier.
const DISCOVERY_BEACON: &[u8] = b"IONA_DISCOVERY_BEACON_v1\n";

/// Trigger wakeups for tasks blocked in epoll_wait.
///
/// This should be called periodically (e.g., from the network poll task)
/// after checking socket readiness. It notifies the epoll subsystem
/// that some file descriptors may have become ready, allowing blocked
/// tasks to resume.
pub fn notify_epoll_watchers() {
    // Wake tasks that are waiting in epoll_wait.
    // tick_wakeups() is assumed to unblock any pending epoll waiters
    // whose sockets have become ready.
    crate::wait::tick_wakeups();
}

/// Check if the TCP send buffer has insufficient space to send more data.
///
/// Returns `true` if the available buffer space is less than
/// `TCP_MIN_SEND_BUFFER_FREE` bytes, indicating backpressure.
/// The caller should suspend sending until space becomes available.
pub fn tcp_send_backpressure(fd: u64) -> bool {
    let available = crate::net::tcp_send_available(fd) as usize;
    available < TCP_MIN_SEND_BUFFER_FREE
}

/// Broadcast a peer discovery beacon to the local network via UDP.
///
/// Sends to both the limited broadcast address (255.255.255.255)
/// and the configured multicast group (`DISCOVERY_MULTICAST_ADDR`).
/// The `fd` must be a UDP socket bound to an appropriate local port.
/// Errors during send are logged but do not panic.
pub fn discover_peers(fd: u64, port: u16) {
    // Broadcast to 255.255.255.255
    if let Err(e) = crate::net::udp::udp_sendto(fd, DISCOVERY_BEACON, [255, 255, 255, 255], port) {
        crate::serial_println!("[DISCOVERY] broadcast send failed: {:?}", e);
    }
    // Multicast to group
    if let Err(e) = crate::net::udp::udp_sendto(fd, DISCOVERY_BEACON, DISCOVERY_MULTICAST_ADDR, port) {
        crate::serial_println!("[DISCOVERY] multicast send failed: {:?}", e);
    }
}

/// Parse a peer discovery response and extract the IP address and port.
///
/// Expected response format (case‑sensitive):
/// `IONA_DISCOVERY_BEACON_v1\nip=A.B.C.D port=NNNNN\n`
///
/// Returns `None` if the beacon header is missing or the IP/port cannot be parsed.
pub fn parse_discovery(data: &[u8]) -> Option<([u8; 4], u16)> {
    // Must start with beacon identifier
    if !data.starts_with(DISCOVERY_BEACON) {
        return None;
    }

    let body = data.get(DISCOVERY_BEACON.len()..)?;
    // Convert to string for easier parsing, allow lossy (non‑UTF‑8 ignored)
    let body_str = core::str::from_utf8(body).ok()?;

    // Extract key=value pairs separated by whitespace/newline
    let mut ip_str: Option<&str> = None;
    let mut port_str: Option<&str> = None;

    for token in body_str.split_whitespace() {
        if let Some(val) = token.strip_prefix("ip=") {
            ip_str = Some(val);
        } else if let Some(val) = token.strip_prefix("port=") {
            port_str = Some(val);
        }
    }

    let ip_str = ip_str?;
    let port_str = port_str?;

    // Parse IPv4 address
    let mut parts = ip_str.split('.');
    let a = parts.next()?.parse::<u8>().ok()?;
    let b = parts.next()?.parse::<u8>().ok()?;
    let c = parts.next()?.parse::<u8>().ok()?;
    let d = parts.next()?.parse::<u8>().ok()?;
    if parts.next().is_some() {
        return None; // too many octets
    }
    let ip = [a, b, c, d];

    // Parse port number (allow whitespace before/after)
    let port: u16 = port_str.trim().parse().ok()?;
    Some((ip, port))
}
