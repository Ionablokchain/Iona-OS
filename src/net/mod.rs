//! Network stack — smoltcp TCP/IP over virtio-net
//!
//! smoltcp este un TCP/IP stack pur Rust, no_std, matur.
//! Folosit în Redox OS, Embassy, și acum IONA OS.
//!
//! Arhitectură:
//!   virtio-net driver → frame-uri Ethernet raw
//!   smoltcp Interface  → ARP, IP routing
//!   smoltcp Sockets    → TCP, UDP connections

pub mod epoll_net;
pub mod udp;
pub mod tls;
pub mod dhcp;
pub mod dns;

use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use smoltcp::{
    iface::{Config, Interface, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp::{Socket as TcpSocket, SocketBuffer},
    time::Instant,
    wire::{EthernetAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address},
};
use spin::{Lazy, Mutex};

// Wrapper pentru virtio-net driver compatibil cu smoltcp Device trait
pub struct VirtioDevice;

impl Device for VirtioDevice {
    type RxToken<'a> = VirtioRxToken where Self: 'a;
    type TxToken<'a> = VirtioTxToken where Self: 'a;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium          = Medium::Ethernet;
        caps.max_transmission_unit = 1514;
        caps
    }

    fn receive(&mut self, _ts: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let frame = crate::drivers::virtio::net::recv_frame()?;
        Some((VirtioRxToken(frame), VirtioTxToken))
    }

    fn transmit(&mut self, _ts: Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtioTxToken)
    }
}

pub struct VirtioRxToken(Vec<u8>);
pub struct VirtioTxToken;

impl RxToken for VirtioRxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(mut self, f: F) -> R {
        f(&mut self.0)
    }
}

impl TxToken for VirtioTxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = alloc::vec![0u8; len];
        let r = f(&mut buf);
        crate::drivers::virtio::net::send_frame(&buf);
        r
    }
}

pub struct NetworkStack {
    pub iface:   Interface,
    pub sockets: SocketSet<'static>,
    device:      VirtioDevice,
}

static NETSTACK: Mutex<Option<NetworkStack>> = Mutex::new(None);

/// Inițializează stack-ul de rețea
/// IP static: 10.0.2.15/24, gateway: 10.0.2.2 (QEMU defaults)

pub fn init() {
    if !crate::drivers::virtio::net::is_present() {
        crate::serial_println!("  [NET] virtio-net not found — network disabled");
        return;
    }

    let mac = crate::drivers::virtio::net::mac().unwrap_or([0x52, 0x54, 0, 0x12, 0x34, 0x56]);
    let eth_addr = EthernetAddress(mac);
    let ip_addr  = IpCidr::new(IpAddress::v4(10, 0, 2, 15), 24);

    let mut device = VirtioDevice;
    let now = Instant::from_micros(crate::arch::x86_64::timer::uptime_ms() as i64 * 1000);

    let config = Config::new(eth_addr.into());
    let mut iface = Interface::new(config, &mut device, now);
    iface.update_ip_addrs(|addrs| {
        addrs.push(ip_addr).expect("too many IP addresses");
    });
    iface.routes_mut().add_default_ipv4_route(Ipv4Address::new(10, 0, 2, 2))
        .expect("routes full");

    let sockets = SocketSet::new(alloc::vec![]);

    crate::serial_println!("  [NET] IP=10.0.2.15/24 GW=10.0.2.2 MAC={:x?}", mac);
    *NETSTACK.lock() = Some(NetworkStack { iface, sockets, device });
}

/// Poll — procesează RX/TX (apelat periodic din main loop sau scheduler)
pub fn poll() {
    let mut lock = NETSTACK.lock();
    let stack = match lock.as_mut() { Some(s) => s, None => return };
    let now = Instant::from_micros(crate::arch::x86_64::timer::uptime_ms() as i64 * 1000);
    stack.iface.poll(now, &mut stack.device, &mut stack.sockets);
}

pub fn is_ready() -> bool { NETSTACK.lock().is_some() }

// ── Chain RPC URL (citit de syscall 322) ─────────────────────────────────────
pub static CHAIN_RPC_URL: Lazy<Mutex<alloc::string::String>> =
    Lazy::new(|| Mutex::new("http://10.0.2.2:9001".into()));

pub fn set_chain_rpc(url: &str) {
    *CHAIN_RPC_URL.lock() = url.into();
}

// ── TCP Socket table ──────────────────────────────────────────────────────────
// fd (u64) → smoltcp SocketHandle

static SOCKETS: Lazy<Mutex<BTreeMap<u64, smoltcp::iface::SocketHandle>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

static NEXT_FD: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(100);

fn next_fd() -> u64 {
    NEXT_FD.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

/// Deschide o conexiune TCP outbound. Returnează fd sau u64::MAX.
pub fn tcp_connect(ip: [u8; 4], port: u16) -> u64 {
    let mut lock = NETSTACK.lock();
    let stack = match lock.as_mut() { Some(s) => s, None => return u64::MAX };

    let rx_buf = SocketBuffer::new(alloc::vec![0u8; 4096]);
    let tx_buf = SocketBuffer::new(alloc::vec![0u8; 4096]);
    let socket = TcpSocket::new(rx_buf, tx_buf);
    let handle = stack.sockets.add(socket);

    let remote = IpEndpoint::new(
        IpAddress::Ipv4(Ipv4Address::new(ip[0], ip[1], ip[2], ip[3])),
        port,
    );
    let local_port = 49152 + (next_fd() % 16384) as u16;

    {
        let socket = stack.sockets.get_mut::<TcpSocket>(handle);
        if socket.connect(stack.iface.context(), remote, local_port).is_err() {
            return u64::MAX;
        }
    }

    // Poll pentru a stabili conexiunea (busy wait max 500ms)
    let deadline = crate::arch::x86_64::timer::uptime_ms() + 500;
    loop {
        let now = smoltcp::time::Instant::from_micros(
            crate::arch::x86_64::timer::uptime_ms() as i64 * 1000
        );
        stack.iface.poll(now, &mut stack.device, &mut stack.sockets);

        let socket = stack.sockets.get_mut::<TcpSocket>(handle);
        if socket.is_active() { break; }
        if socket.state() == smoltcp::socket::tcp::State::Closed { return u64::MAX; }
        if crate::arch::x86_64::timer::uptime_ms() > deadline { return u64::MAX; }

        core::hint::spin_loop();
    }

    let fd = next_fd();
    SOCKETS.lock().insert(fd, handle);
    fd
}

/// Trimite date pe un socket TCP
pub fn tcp_send(fd: u64, data: &[u8]) -> usize {
    let mut lock = NETSTACK.lock();
    let stack = match lock.as_mut() { Some(s) => s, None => return 0 };
    let handle = match SOCKETS.lock().get(&fd).cloned() { Some(h) => h, None => return 0 };

    let socket = stack.sockets.get_mut::<TcpSocket>(handle);
    let n = socket.send_slice(data).unwrap_or(0);

    let now = smoltcp::time::Instant::from_micros(
        crate::arch::x86_64::timer::uptime_ms() as i64 * 1000
    );
    stack.iface.poll(now, &mut stack.device, &mut stack.sockets);
    n
}

/// Primește date de pe un socket TCP (non-blocking)
pub fn tcp_recv(fd: u64, buf: &mut [u8]) -> usize {
    // Non-blocking first try
    let n = tcp_recv_nonblock(fd, buf);
    if n > 0 { return n; }
    // Yield scheduler and wait for network interrupt to wake us
    // This replaces the previous 500ms busy-wait
    let deadline = crate::arch::x86_64::timer::uptime_ms() + 5000;
    while crate::arch::x86_64::timer::uptime_ms() < deadline {
        crate::sched::wait_for_event(crate::sched::WaitEvent::Io);
        let n = tcp_recv_nonblock(fd, buf);
        if n > 0 { return n; }
        // Brief yield to avoid tight loop if wake_on_event not yet triggered
        unsafe { core::arch::asm!("hlt", options(nostack)); }
    }
    0
}

/// Închide un socket TCP
pub fn tcp_close(fd: u64) {
    let mut lock = NETSTACK.lock();
    let stack = match lock.as_mut() { Some(s) => s, None => return };
    if let Some(handle) = SOCKETS.lock().remove(&fd) {
        let socket = stack.sockets.get_mut::<TcpSocket>(handle);
        socket.close();
        let now = smoltcp::time::Instant::from_micros(
            crate::arch::x86_64::timer::uptime_ms() as i64 * 1000
        );
        stack.iface.poll(now, &mut stack.device, &mut stack.sockets);
        stack.sockets.remove(handle);
    }
}

/// Server TCP — ascultă pe un port. Returnează fd sau u64::MAX.
pub fn tcp_listen(port: u16) -> u64 {
    let mut lock = NETSTACK.lock();
    let stack = match lock.as_mut() { Some(s) => s, None => return u64::MAX };

    let rx_buf = SocketBuffer::new(alloc::vec![0u8; 8192]);
    let tx_buf = SocketBuffer::new(alloc::vec![0u8; 8192]);
    let mut socket = TcpSocket::new(rx_buf, tx_buf);
    if socket.listen(port).is_err() { return u64::MAX; }

    let handle = stack.sockets.add(socket);
    let fd = next_fd();
    SOCKETS.lock().insert(fd, handle);

    crate::serial_println!("  [NET] TCP listening on :{}", port);
    fd
}

/// Acceptă o conexiune inbound (non-blocking). Returnează fd sau u64::MAX.
pub fn tcp_accept(server_fd: u64) -> u64 {
    let mut lock = NETSTACK.lock();
    let stack = match lock.as_mut() { Some(s) => s, None => return u64::MAX };

    let now = smoltcp::time::Instant::from_micros(
        crate::arch::x86_64::timer::uptime_ms() as i64 * 1000
    );
    stack.iface.poll(now, &mut stack.device, &mut stack.sockets);

    let server_handle = match SOCKETS.lock().get(&server_fd).cloned() {
        Some(h) => h,
        None    => return u64::MAX,
    };

    let has_conn = {
        let socket = stack.sockets.get_mut::<TcpSocket>(server_handle);
        socket.is_active() && socket.may_recv()
    };

    if !has_conn { return u64::MAX; }

    // Creăm un nou socket pentru conexiunea acceptată
    // (smoltcp: socket-ul listen devine socket-ul de conexiune)
    let fd = next_fd();
    SOCKETS.lock().insert(fd, server_handle);

    // Recreăm server socket pentru a putea accepta viitoare conexiuni
    let rx_buf = SocketBuffer::new(alloc::vec![0u8; 8192]);
    let tx_buf = SocketBuffer::new(alloc::vec![0u8; 8192]);
    let mut new_server = TcpSocket::new(rx_buf, tx_buf);
    // Look up the original listen port for this server_fd
    let port = SERVER_PORTS.lock().get(&server_fd).copied().unwrap_or(7777);
    new_server.listen(port).ok();
    let new_handle = stack.sockets.add(new_server);
    SOCKETS.lock().insert(server_fd, new_handle);

    fd
}

/// Check if a socket has data available (used by wait queue)
pub fn socket_has_data(fd: u64) -> bool {
    let mut lock = NETSTACK.lock();
    let stack = match lock.as_mut() { Some(s) => s, None => return false };
    let handle = match SOCKETS.lock().get(&fd).cloned() { Some(h) => h, None => return false };
    let socket = stack.sockets.get_mut::<smoltcp::socket::tcp::Socket>(handle);
    socket.can_recv()
}

// ── Server port tracking ────────────────────────────────────────────────────
/// Maps server_fd → listen port (fixes TODO in tcp_accept)
static SERVER_PORTS: Lazy<Mutex<alloc::collections::BTreeMap<u64, u16>>> =
    Lazy::new(|| Mutex::new(alloc::collections::BTreeMap::new()));

// Fix tcp_listen to store port
// Note: already stores port before; this patches the accept side above.

// ── TCP shutdown semantics ────────────────────────────────────────────────────
/// shutdown(fd, how) — how: 0=SHUT_RD, 1=SHUT_WR, 2=SHUT_RDWR
pub fn tcp_shutdown(fd: u64, how: u32) {
    let mut lock = NETSTACK.lock();
    let stack    = match lock.as_mut() { Some(s) => s, None => return };
    let handle   = match SOCKETS.lock().get(&fd).cloned() { Some(h) => h, None => return };
    let socket   = stack.sockets.get_mut::<smoltcp::socket::tcp::Socket>(handle);
    match how {
        0 | 2 => { socket.close(); } // SHUT_RD or SHUT_RDWR
        1     => { socket.close(); } // SHUT_WR (smoltcp closes both, FIN sent)
        _     => {}
    }
    let now = smoltcp::time::Instant::from_micros(
        crate::arch::x86_64::timer::uptime_ms() as i64 * 1000
    );
    stack.iface.poll(now, &mut stack.device, &mut stack.sockets);
}

/// Get number of bytes available in recv buffer (for poll/select)
pub fn tcp_recv_available(fd: u64) -> usize {
    let mut lock = NETSTACK.lock();
    let stack    = match lock.as_mut() { Some(s) => s, None => return 0 };
    let handle   = match SOCKETS.lock().get(&fd).cloned() { Some(h) => h, None => return 0 };
    let socket   = stack.sockets.get_mut::<smoltcp::socket::tcp::Socket>(handle);
    socket.recv_queue()
}

/// Get number of bytes free in send buffer
pub fn tcp_send_available(fd: u64) -> usize {
    let mut lock = NETSTACK.lock();
    let stack    = match lock.as_mut() { Some(s) => s, None => return 0 };
    let handle   = match SOCKETS.lock().get(&fd).cloned() { Some(h) => h, None => return 0 };
    let socket   = stack.sockets.get_mut::<smoltcp::socket::tcp::Socket>(handle);
    socket.send_queue()
}

// ── UDP support ───────────────────────────────────────────────────────────────
use smoltcp::socket::udp::{Socket as UdpSocket, PacketBuffer, PacketMetadata};

static UDP_SOCKETS: Lazy<Mutex<BTreeMap<u64, smoltcp::iface::SocketHandle>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

pub fn udp_bind(local_ip: [u8; 4], local_port: u16) -> Option<u64> {
    let mut lock = NETSTACK.lock();
    let stack = lock.as_mut()?;
    let rx_meta = alloc::vec![PacketMetadata::EMPTY; 16];
    let tx_meta = alloc::vec![PacketMetadata::EMPTY; 16];
    let rx_buf  = alloc::vec![0u8; 8192];
    let tx_buf  = alloc::vec![0u8; 8192];
    let socket  = UdpSocket::new(
        PacketBuffer::new(rx_meta, rx_buf),
        PacketBuffer::new(tx_meta, tx_buf),
    );
    let handle = stack.sockets.add(socket);
    let fd = next_fd();
    // Bind to local port (0 = ephemeral)
    let port = if local_port == 0 { 49152 + (fd % 16384) as u16 } else { local_port };
    {
        let sock = stack.sockets.get_mut::<UdpSocket>(handle);
        let _ = sock.bind(port);
    }
    UDP_SOCKETS.lock().insert(fd, handle);
    Some(fd)
}

pub fn udp_sendto(fd: u64, data: &[u8], dst_ip: [u8; 4], dst_port: u16) -> usize {
    let mut lock = NETSTACK.lock();
    let stack = match lock.as_mut() { Some(s) => s, None => return 0 };
    let handle = match UDP_SOCKETS.lock().get(&fd).cloned() { Some(h) => h, None => return 0 };
    let dst = IpEndpoint::new(
        smoltcp::wire::IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(dst_ip[0],dst_ip[1],dst_ip[2],dst_ip[3])),
        dst_port,
    );
    let socket = stack.sockets.get_mut::<UdpSocket>(handle);
    let _ = socket.send_slice(data, dst);
    let now = smoltcp::time::Instant::from_micros(crate::arch::x86_64::timer::uptime_ms() as i64 * 1000);
    stack.iface.poll(now, &mut stack.device, &mut stack.sockets);
    data.len()
}

pub fn udp_recvfrom(fd: u64, buf: &mut [u8]) -> (usize, [u8; 4], u16) {
    let mut lock = NETSTACK.lock();
    let stack = match lock.as_mut() { Some(s) => s, None => return (0,[0;4],0) };
    let now = smoltcp::time::Instant::from_micros(crate::arch::x86_64::timer::uptime_ms() as i64 * 1000);
    stack.iface.poll(now, &mut stack.device, &mut stack.sockets);
    let handle = match UDP_SOCKETS.lock().get(&fd).cloned() { Some(h) => h, None => return (0,[0;4],0) };
    let socket = stack.sockets.get_mut::<UdpSocket>(handle);
    match socket.recv_slice(buf) {
        Ok((n, ep)) => {
            let ip = match ep.endpoint.addr {
                smoltcp::wire::IpAddress::Ipv4(v4) => v4.0,
                _ => [0;4],
            };
            (n, ip, ep.endpoint.port)
        }
        Err(_) => (0, [0;4], 0),
    }
}

pub fn udp_close(fd: u64) {
    if let Some(handle) = UDP_SOCKETS.lock().remove(&fd) {
        if let Some(stack) = NETSTACK.lock().as_mut() {
            stack.sockets.remove(handle);
        }
    }
}

/// Non-blocking TCP recv — returns immediately with 0 if no data
pub fn tcp_recv_nonblock(fd: u64, buf: &mut [u8]) -> usize {
    let mut lock = NETSTACK.lock();
    let stack = match lock.as_mut() { Some(s) => s, None => return 0 };
    let handle = match SOCKETS.lock().get(&fd).cloned() { Some(h) => h, None => return 0 };
    let now = smoltcp::time::Instant::from_micros(
        crate::arch::x86_64::timer::uptime_ms() as i64 * 1000);
    stack.iface.poll(now, &mut stack.device, &mut stack.sockets);
    let socket = stack.sockets.get_mut::<TcpSocket>(handle);
    if socket.can_recv() { socket.recv_slice(buf).unwrap_or(0) } else { 0 }
}

/// Gossip UDP fd (bound to port 9000)
static GOSSIP_FD: spin::Lazy<core::sync::atomic::AtomicU64> =
    spin::Lazy::new(|| core::sync::atomic::AtomicU64::new(u64::MAX));

fn ensure_gossip_fd() -> u64 {
    let fd = GOSSIP_FD.load(core::sync::atomic::Ordering::Relaxed);
    if fd != u64::MAX { return fd; }
    let new_fd = udp_bind([0,0,0,0], 9000).unwrap_or(u64::MAX);
    GOSSIP_FD.store(new_fd, core::sync::atomic::Ordering::Relaxed);
    new_fd
}

/// Broadcast message to all gossip peers — returns number of peers
pub fn gossip_broadcast(data: &[u8]) -> usize {
    let fd = ensure_gossip_fd();
    if fd == u64::MAX { return 0; }
    let peers = crate::net::get_peer_list();
    let mut sent = 0;
    for peer_ip in &peers {
        if udp_sendto(fd, data, *peer_ip, 9000) > 0 { sent += 1; }
    }
    if sent == 0 && !data.is_empty() {
        udp_sendto(fd, data, [10,0,2,255], 9000);
        sent = 1;
    }
    sent
}

/// Receive one gossip message (non-blocking)
pub fn gossip_recv() -> Option<alloc::vec::Vec<u8>> {
    let fd = ensure_gossip_fd();
    if fd == u64::MAX { return None; }
    let mut buf = alloc::vec![0u8; 4096];
    let (n, _ip, _port) = udp_recvfrom(fd, &mut buf);
    if n > 0 { buf.truncate(n); Some(buf) } else { None }
}

/// Get list of known peer IPs from IONAFS config
pub fn get_peer_list() -> alloc::vec::Vec<[u8;4]> {
    let mut peers = alloc::vec::Vec::new();
    if let Some(data) = crate::fs::ionafs::read("/etc/iona-node.json") {
        let s = alloc::string::String::from_utf8_lossy(&data);
        // Parse "peers":["10.0.2.3","10.0.2.4"] 
        for part in s.split('"') {
            let ip: alloc::vec::Vec<u8> = part.split('.')
                .filter_map(|x| x.parse::<u8>().ok())
                .collect();
            if ip.len() == 4 { peers.push([ip[0],ip[1],ip[2],ip[3]]); }
        }
    }
    peers
}

// ── Network error counters ────────────────────────────────────────────────────
use core::sync::atomic::{AtomicU64, Ordering};

pub static NET_TX_ERRORS:   AtomicU64 = AtomicU64::new(0);
pub static NET_RX_ERRORS:   AtomicU64 = AtomicU64::new(0);
pub static NET_TCP_RESETS:  AtomicU64 = AtomicU64::new(0);
pub static NET_CONN_REFUSED: AtomicU64 = AtomicU64::new(0);

pub fn inc_tx_error()      { NET_TX_ERRORS.fetch_add(1, Ordering::Relaxed); }
pub fn inc_rx_error()      { NET_RX_ERRORS.fetch_add(1, Ordering::Relaxed); }
pub fn inc_tcp_reset()     { NET_TCP_RESETS.fetch_add(1, Ordering::Relaxed); }
pub fn inc_conn_refused()  { NET_CONN_REFUSED.fetch_add(1, Ordering::Relaxed); }

pub fn error_count() -> u64 {
    NET_TX_ERRORS.load(Ordering::Relaxed) + NET_RX_ERRORS.load(Ordering::Relaxed)
}

pub fn net_stats() -> (u64, u64, u64, u64) {
    (NET_TX_ERRORS.load(Ordering::Relaxed),
     NET_RX_ERRORS.load(Ordering::Relaxed),
     NET_TCP_RESETS.load(Ordering::Relaxed),
     NET_CONN_REFUSED.load(Ordering::Relaxed))
}
