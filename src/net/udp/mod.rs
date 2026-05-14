//! UDP sockets via smoltcp
//!
//! Syscalls:
//!   sys_udp_bind(port)                    → fd
//!   sys_udp_sendto(fd, buf, ip, port)     → n_sent
//!   sys_udp_recvfrom(fd, buf, addr_out)   → n_recv

use alloc::collections::BTreeMap;
use smoltcp::{
    socket::udp::{Socket as UdpSocket, PacketBuffer, PacketMetadata},
    wire::{IpAddress, IpEndpoint, Ipv4Address},
};
use spin::{Lazy, Mutex};

static UDP_SOCKETS: Lazy<Mutex<BTreeMap<u64, smoltcp::iface::SocketHandle>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

static NEXT_UDP_FD: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(10000);

pub fn udp_bind(port: u16) -> u64 {
    let mut lock = crate::net::NETSTACK.lock();
    let stack = match lock.as_mut() { Some(s) => s, None => return u64::MAX };

    let rx_meta = alloc::vec![PacketMetadata::EMPTY; 16];
    let tx_meta = alloc::vec![PacketMetadata::EMPTY; 16];
    let rx_buf  = alloc::vec![0u8; 65536];
    let tx_buf  = alloc::vec![0u8; 65536];

    let mut socket = UdpSocket::new(
        PacketBuffer::new(rx_meta, rx_buf),
        PacketBuffer::new(tx_meta, tx_buf),
    );

    if socket.bind(port).is_err() {
        return u64::MAX;
    }

    let handle = stack.sockets.add(socket);
    let fd     = NEXT_UDP_FD.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    UDP_SOCKETS.lock().insert(fd, handle);

    crate::serial_println!("  [UDP] bound :{} fd={}", port, fd);
    fd
}

pub fn udp_sendto(fd: u64, data: &[u8], dest_ip: [u8; 4], dest_port: u16) -> usize {
    let mut lock = crate::net::NETSTACK.lock();
    let stack    = match lock.as_mut() { Some(s) => s, None => return 0 };
    let handle   = match UDP_SOCKETS.lock().get(&fd).cloned() { Some(h) => h, None => return 0 };

    let endpoint = IpEndpoint::new(
        IpAddress::Ipv4(Ipv4Address::new(dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3])),
        dest_port,
    );

    let socket = stack.sockets.get_mut::<UdpSocket>(handle);
    match socket.send_slice(data, endpoint) {
        Ok(())  => {
            let now = smoltcp::time::Instant::from_micros(
                crate::arch::x86_64::timer::uptime_ms() as i64 * 1000
            );
            stack.iface.poll(now, &mut stack.device, &mut stack.sockets);
            data.len()
        }
        Err(_) => 0,
    }
}

pub fn udp_recvfrom(fd: u64, buf: &mut [u8]) -> (usize, [u8; 4], u16) {
    let mut lock = crate::net::NETSTACK.lock();
    let stack    = match lock.as_mut() { Some(s) => s, None => return (0,[0;4],0) };
    let handle   = match UDP_SOCKETS.lock().get(&fd).cloned() { Some(h) => h, None => return (0,[0;4],0) };

    let now = smoltcp::time::Instant::from_micros(
        crate::arch::x86_64::timer::uptime_ms() as i64 * 1000
    );
    stack.iface.poll(now, &mut stack.device, &mut stack.sockets);

    let socket = stack.sockets.get_mut::<UdpSocket>(handle);
    match socket.recv_slice(buf) {
        Ok((n, meta)) => {
            let ip = match meta.endpoint.addr {
                IpAddress::Ipv4(a) => a.0,
                _                   => [0;4],
            };
            (n, ip, meta.endpoint.port)
        }
        Err(_) => (0, [0;4], 0),
    }
}

pub fn udp_close(fd: u64) {
    let mut lock = crate::net::NETSTACK.lock();
    let stack    = match lock.as_mut() { Some(s) => s, None => return };
    if let Some(handle) = UDP_SOCKETS.lock().remove(&fd) {
        stack.sockets.remove(handle);
    }
}

/// Convenience wrapper: send to IP:port without managing fd
pub fn sendto(dest_ip: [u8; 4], dest_port: u16, data: &[u8]) -> usize {
    let ep = (crate::arch::x86_64::timer::uptime_ms() & 0x3FFF) as u16 + 10000;
    let fd = udp_bind(ep);
    if fd == u64::MAX { return 0; }
    let n = udp_sendto(fd, data, dest_ip, dest_port);
    udp_close(fd);
    n
}

/// Send broadcast UDP to 255.255.255.255 — fire and forget, closes socket.
/// Returns bytes sent. Does NOT retain fd for reply — caller must bind separately.
pub fn sendto_broadcast(local_port: u16, dest_port: u16, data: &[u8]) -> usize {
    let fd = udp_bind(local_port);
    if fd == u64::MAX { return 0; }
    let n = udp_sendto(fd, data, [255,255,255,255], dest_port);
    udp_close(fd);
    n
}

/// Receive one packet on port (convenience wrapper — binds ephemeral socket)
pub fn recvfrom(port: u16) -> Option<alloc::vec::Vec<u8>> {
    let fd = udp_bind(port);
    if fd == u64::MAX { return None; }
    let mut buf = alloc::vec![0u8; 1500];
    let (n, _ip, _p) = udp_recvfrom(fd, &mut buf);
    if n == 0 { return None; }
    buf.truncate(n);
    Some(buf)
}

/// Alias used by dhcp + sync modules
pub fn udp_recvfrom_port(port: u16) -> Option<alloc::vec::Vec<u8>> {
    recvfrom(port)
}
