//! Network epoll integration — proper async I/O model
//!
//! Bridges smoltcp poll events with epoll notifications.
//! When a TCP socket becomes readable/writable, wakes tasks
//! waiting in epoll_wait().


/// Check all sockets and wake waiting epoll tasks
pub fn notify_epoll_watchers() {
    // Called from net-poll task every 5ms
    // For each socket that became readable → wake epoll waiters
    // (Epoll already checks socket_has_data in check_ready_fds)
    // This function triggers any pending wakeups

    // Wake tasks blocked in epoll_wait that have readable sockets
    crate::wait::tick_wakeups();
}

/// TCP backpressure — check if send buffer is full
pub fn tcp_send_backpressure(fd: u64) -> bool {
    let available = crate::net::tcp_send_available(fd);
    available < 512  // less than 512 bytes free → backpressure
}

/// Peer discovery via UDP broadcast
pub fn discover_peers(fd: u64, port: u16) {
    // Send discovery beacon to broadcast address
    let beacon = b"IONA_DISCOVERY_BEACON_v1\n";
    let broadcast_ip = [255u8, 255, 255, 255];
    crate::net::udp::udp_sendto(fd, beacon, broadcast_ip, port);

    // Also try multicast group 239.192.0.1 (IANA-assigned for application use)
    let multicast_ip = [239u8, 192, 0, 1];
    crate::net::udp::udp_sendto(fd, beacon, multicast_ip, port);
}

/// Parse peer discovery response
pub fn parse_discovery(data: &[u8]) -> Option<([u8; 4], u16)> {
    if data.starts_with(b"IONA_DISCOVERY_BEACON_v1") {
        // Extract IP:port from response (appended by responder)
        // Format: IONA_DISCOVERY_BEACON_v1\nip=X.X.X.X port=XXXX\n
        let s = core::str::from_utf8(data).ok()?;
        let ip_part  = s.split("ip=").nth(1)?;
        let port_part = s.split("port=").nth(1)?;

        let mut ip = [0u8; 4];
        for (i, octet) in ip_part.splitn(4, '.').enumerate().take(4) {
            ip[i] = octet.trim().parse().ok()?;
        }
        let port: u16 = port_part.trim().parse().ok()?;
        Some((ip, port))
    } else {
        None
    }
}
