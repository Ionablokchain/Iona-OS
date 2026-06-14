//! Network stack — smoltcp TCP/IP over virtio-net
//!
//! Arhitectură:
//!   virtio-net driver → frame-uri Ethernet raw
//!   smoltcp Interface  → ARP, IP routing
//!   smoltcp Sockets    → TCP, UDP connections
//!
//! Oferă API sincron, dar intern utilizează polling regulat (apelat din scheduler).

pub mod epoll_net;
pub mod udp;
pub mod tls;
pub mod dhcp;
pub mod dns;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use smoltcp::{
    iface::{Config, Interface, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp::{Socket as TcpSocket, SocketBuffer},
    socket::udp::{PacketBuffer, PacketMetadata, Socket as UdpSocket},
    time::Instant,
    wire::{EthernetAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address},
};
use spin::{Lazy, Mutex, Once};

// ── Dispozitiv virtio-net pentru smoltcp ─────────────────────────────────────

pub struct VirtioDevice;

impl Device for VirtioDevice {
    type RxToken<'a> = VirtioRxToken where Self: 'a;
    type TxToken<'a> = VirtioTxToken where Self: 'a;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
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

// ── Stare globală ────────────────────────────────────────────────────────────

/// Capacitatea maximă a setului de socketuri smoltcp.
const MAX_SOCKETS: usize = 64;

/// Structura principală a stack-ului de rețea.
pub struct NetworkStack {
    pub iface:   Interface,
    pub sockets: SocketSet<'static>,
    device:      VirtioDevice,
}

/// Stack-ul global, inițializat la `init()`.
static NETSTACK: Mutex<Option<NetworkStack>> = Mutex::new(None);

/// Pentru inițializarea unică a descriptorului de gossip.
static GOSSIP_INIT: Once = Once::new();
static GOSSIP_FD: Lazy<Mutex<u64>> = Lazy::new(|| Mutex::new(u64::MAX));

// ── Inițializare și polling ─────────────────────────────────────────────────

/// Inițializează stack-ul de rețea cu IP static (QEMU defaults).
pub fn init() {
    if !crate::drivers::virtio::net::is_present() {
        crate::serial_println!("  [NET] virtio-net not found — network disabled");
        return;
    }

    let mac = crate::drivers::virtio::net::mac().unwrap_or([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    let eth_addr = EthernetAddress(mac);
    let ip_addr = IpCidr::new(IpAddress::v4(10, 0, 2, 15), 24);

    let mut device = VirtioDevice;
    let now = smoltcp_now();

    let config = Config::new(eth_addr.into());
    let mut iface = Interface::new(config, &mut device, now);
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(ip_addr); // eroare doar dacă bufferul e plin (imposibil aici)
    });
    iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(10, 0, 2, 2))
        .expect("routes full");

    // Set inițial de socketuri cu capacitate fixă
    let sockets = SocketSet::new(vec![None; MAX_SOCKETS]);

    crate::serial_println!("  [NET] IP=10.0.2.15/24 GW=10.0.2.2 MAC={:x?}", mac);
    *NETSTACK.lock() = Some(NetworkStack { iface, sockets, device });
}

/// Poll — procesează RX/TX. Trebuie apelat periodic (ex. la fiecare tick).
pub fn poll() {
    let mut lock = NETSTACK.lock();
    if let Some(stack) = lock.as_mut() {
        let now = smoltcp_now();
        stack.iface.poll(now, &mut stack.device, &mut stack.sockets);
    }
}

pub fn is_ready() -> bool {
    NETSTACK.lock().is_some()
}

/// Returnează timestamp-ul curent smoltcp.
#[inline]
fn smoltcp_now() -> Instant {
    Instant::from_micros(crate::arch::x86_64::timer::uptime_ms() as i64 * 1000)
}

// ── Chain RPC URL (syscall 322) ──────────────────────────────────────────────
pub static CHAIN_RPC_URL: Lazy<Mutex<alloc::string::String>> =
    Lazy::new(|| Mutex::new("http://10.0.2.2:9001".into()));

pub fn set_chain_rpc(url: &str) {
    *CHAIN_RPC_URL.lock() = url.into();
}

// ── Tabelă socketuri TCP ─────────────────────────────────────────────────────
static TCP_SOCKETS: Lazy<Mutex<BTreeMap<u64, smoltcp::iface::SocketHandle>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));
static NEXT_FD: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(100);

fn next_fd() -> u64 {
    NEXT_FD.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

// ── TCP Connect ──────────────────────────────────────────────────────────────
/// Deschide o conexiune TCP outbound. Returnează fd sau `u64::MAX` pe eroare.
pub fn tcp_connect(ip: [u8; 4], port: u16) -> u64 {
    let mut stack_lock = NETSTACK.lock();
    let stack = match stack_lock.as_mut() {
        Some(s) => s,
        None => return u64::MAX,
    };

    let rx_buf = SocketBuffer::new(alloc::vec![0u8; 4096]);
    let tx_buf = SocketBuffer::new(alloc::vec![0u8; 4096]);
    let socket = TcpSocket::new(rx_buf, tx_buf);
    let handle = stack.sockets.add(socket);

    let remote = IpEndpoint::new(
        IpAddress::Ipv4(Ipv4Address::new(ip[0], ip[1], ip[2], ip[3])),
        port,
    );
    let local_port = 49152 + (next_fd() % 16384) as u16;

    // connect() poate eșua
    {
        let mut sock = stack.sockets.get_mut::<TcpSocket>(handle);
        if sock.connect(stack.iface.context(), remote, local_port).is_err() {
            stack.sockets.remove(handle); // curățare imediată
            return u64::MAX;
        }
    }

    // Poll până la stabilirea conexiunii (max 500ms)
    let deadline = crate::arch::x86_64::timer::uptime_ms() + 500;
    loop {
        let now = smoltcp_now();
        stack.iface.poll(now, &mut stack.device, &mut stack.sockets);

        let sock = stack.sockets.get_mut::<TcpSocket>(handle);
        if sock.is_active() {
            let fd = next_fd();
            TCP_SOCKETS.lock().insert(fd, handle);
            return fd;
        }
        if sock.state() == smoltcp::socket::tcp::State::Closed {
            stack.sockets.remove(handle);
            return u64::MAX;
        }
        if crate::arch::x86_64::timer::uptime_ms() > deadline {
            stack.sockets.remove(handle);
            return u64::MAX;
        }
        core::hint::spin_loop();
    }
}

// ── TCP Send / Recv ─────────────────────────────────────────────────────────
/// Trimite date pe un socket TCP. Returnează numărul de octeți trimiși (0 = eroare).
pub fn tcp_send(fd: u64, data: &[u8]) -> usize {
    let mut stack_lock = NETSTACK.lock();
    let stack = match stack_lock.as_mut() {
        Some(s) => s,
        None => return 0,
    };
    let handle = match TCP_SOCKETS.lock().get(&fd).copied() {
        Some(h) => h,
        None => return 0,
    };

    let socket = stack.sockets.get_mut::<TcpSocket>(handle);
    let n = socket.send_slice(data).unwrap_or(0);
    // Forțează un poll pentru a expedia imediat
    let now = smoltcp_now();
    stack.iface.poll(now, &mut stack.device, &mut stack.sockets);
    n
}

/// Primește date (blocant cu timeout). Preferă `tcp_recv_nonblock` pentru operații neblocante.
pub fn tcp_recv(fd: u64, buf: &mut [u8]) -> usize {
    // Încearcă non‑blocking
    if let Some(n) = tcp_recv_nonblock(fd, buf) {
        return n;
    }
    // Așteaptă până la 5 secunde, cedează CPU între încercări
    let deadline = crate::arch::x86_64::timer::uptime_ms() + 5000;
    while crate::arch::x86_64::timer::uptime_ms() < deadline {
        crate::sched::yield_now(); // cooperare cu schedulerul
        if let Some(n) = tcp_recv_nonblock(fd, buf) {
            return n;
        }
    }
    0
}

/// Închide un socket TCP.
pub fn tcp_close(fd: u64) {
    let mut stack_lock = NETSTACK.lock();
    let stack = match stack_lock.as_mut() {
        Some(s) => s,
        None => return,
    };
    if let Some(handle) = TCP_SOCKETS.lock().remove(&fd) {
        let socket = stack.sockets.get_mut::<TcpSocket>(handle);
        socket.close();
        let now = smoltcp_now();
        stack.iface.poll(now, &mut stack.device, &mut stack.sockets);
        stack.sockets.remove(handle);
    }
}

// ── TCP Listen / Accept ─────────────────────────────────────────────────────
static SERVER_PORTS: Lazy<Mutex<BTreeMap<u64, u16>>> = Lazy::new(|| Mutex::new(BTreeMap::new()));

/// Ascultă pe un port TCP. Returnează fd-ul serverului.
pub fn tcp_listen(port: u16) -> u64 {
    let mut stack_lock = NETSTACK.lock();
    let stack = match stack_lock.as_mut() {
        Some(s) => s,
        None => return u64::MAX,
    };

    let rx_buf = SocketBuffer::new(alloc::vec![0u8; 8192]);
    let tx_buf = SocketBuffer::new(alloc::vec![0u8; 8192]);
    let mut socket = TcpSocket::new(rx_buf, tx_buf);
    if socket.listen(port).is_err() {
        return u64::MAX;
    }

    let handle = stack.sockets.add(socket);
    let fd = next_fd();
    TCP_SOCKETS.lock().insert(fd, handle);
    SERVER_PORTS.lock().insert(fd, port); // memorare port pentru accept()

    crate::serial_println!("  [NET] TCP listening on :{}", port);
    fd
}

/// Acceptă o conexiune inbound. Returnează fd-ul conexiunii sau `u64::MAX`.
pub fn tcp_accept(server_fd: u64) -> u64 {
    let mut stack_lock = NETSTACK.lock();
    let stack = match stack_lock.as_mut() {
        Some(s) => s,
        None => return u64::MAX,
    };

    let now = smoltcp_now();
    stack.iface.poll(now, &mut stack.device, &mut stack.sockets);

    // Obține handle-ul serverului
    let server_handle = match TCP_SOCKETS.lock().get(&server_fd).copied() {
        Some(h) => h,
        None => return u64::MAX,
    };

    // Verifică dacă există o conexiune nouă
    let has_conn = {
        let sock = stack.sockets.get_mut::<TcpSocket>(server_handle);
        sock.is_active() && sock.may_recv()
    };

    if !has_conn {
        return u64::MAX;
    }

    // Socketul de ascultare a devenit socketul conectat.
    // Atribuim un fd nou conexiunii.
    let client_fd = next_fd();
    TCP_SOCKETS.lock().insert(client_fd, server_handle);

    // Reînnoim socketul de ascultare pe același port
    let port = SERVER_PORTS.lock().get(&server_fd).copied().unwrap_or(7777);
    let rx_buf = SocketBuffer::new(alloc::vec![0u8; 8192]);
    let tx_buf = SocketBuffer::new(alloc::vec![0u8; 8192]);
    let mut new_server = TcpSocket::new(rx_buf, tx_buf);
    if new_server.listen(port).is_ok() {
        let new_handle = stack.sockets.add(new_server);
        TCP_SOCKETS.lock().insert(server_fd, new_handle);
    } else {
        // Eroare la recrearea serverului — scoatem serverul și returnăm eroare?
        // Pentru robustețe, închidem și conexiunea acceptată.
        TCP_SOCKETS.lock().remove(&server_fd);
        TCP_SOCKETS.lock().remove(&client_fd);
        stack.sockets.remove(server_handle);
        return u64::MAX;
    }

    client_fd
}

// ── TCP shutdown & info ─────────────────────────────────────────────────────
pub fn tcp_shutdown(fd: u64, how: u32) {
    let mut stack_lock = NETSTACK.lock();
    let stack = match stack_lock.as_mut() {
        Some(s) => s,
        None => return,
    };
    let handle = match TCP_SOCKETS.lock().get(&fd).copied() {
        Some(h) => h,
        None => return,
    };
    let socket = stack.sockets.get_mut::<TcpSocket>(handle);
    // smoltcp nu diferențiază SHUT_RD/SHUT_WR, close() trimite FIN
    match how {
        0 | 1 | 2 => socket.close(),
        _ => {}
    }
    let now = smoltcp_now();
    stack.iface.poll(now, &mut stack.device, &mut stack.sockets);
}

pub fn tcp_recv_available(fd: u64) -> usize {
    with_tcp_socket(fd, |s| s.recv_queue()).unwrap_or(0)
}

pub fn tcp_send_available(fd: u64) -> usize {
    with_tcp_socket(fd, |s| s.send_queue()).unwrap_or(0)
}

/// Non-blocking recv. Returnează `None` dacă nu sunt date, altfel `Some(n)`.
pub fn tcp_recv_nonblock(fd: u64, buf: &mut [u8]) -> Option<usize> {
    let mut stack_lock = NETSTACK.lock();
    let stack = stack_lock.as_mut()?;
    let handle = TCP_SOCKETS.lock().get(&fd).copied()?;
    let now = smoltcp_now();
    stack.iface.poll(now, &mut stack.device, &mut stack.sockets);
    let socket = stack.sockets.get_mut::<TcpSocket>(handle);
    if socket.can_recv() {
        let n = socket.recv_slice(buf).unwrap_or(0);
        if n > 0 { Some(n) } else { None }
    } else {
        None
    }
}

pub fn socket_has_data(fd: u64) -> bool {
    with_tcp_socket(fd, |s| s.can_recv()).unwrap_or(false)
}

// Helper: accesează un socket TCP, returnând rezultatul unei închideri.
fn with_tcp_socket<F, R>(fd: u64, f: F) -> Option<R>
where
    F: FnOnce(&mut TcpSocket) -> R,
{
    let mut stack_lock = NETSTACK.lock();
    let stack = stack_lock.as_mut()?;
    let handle = TCP_SOCKETS.lock().get(&fd).copied()?;
    let socket = stack.sockets.get_mut::<TcpSocket>(handle);
    Some(f(socket))
}

// ── UDP support ──────────────────────────────────────────────────────────────
static UDP_SOCKETS: Lazy<Mutex<BTreeMap<u64, smoltcp::iface::SocketHandle>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

pub fn udp_bind(local_ip: [u8; 4], local_port: u16) -> Option<u64> {
    let mut stack_lock = NETSTACK.lock();
    let stack = stack_lock.as_mut()?;

    let rx_meta = alloc::vec![PacketMetadata::EMPTY; 16];
    let tx_meta = alloc::vec![PacketMetadata::EMPTY; 16];
    let rx_buf = alloc::vec![0u8; 8192];
    let tx_buf = alloc::vec![0u8; 8192];
    let socket = UdpSocket::new(
        PacketBuffer::new(rx_meta, rx_buf),
        PacketBuffer::new(tx_meta, tx_buf),
    );

    let handle = stack.sockets.add(socket);
    let fd = next_fd();
    let port = if local_port == 0 {
        49152 + (fd % 16384) as u16
    } else {
        local_port
    };

    {
        let sock = stack.sockets.get_mut::<UdpSocket>(handle);
        if sock.bind(port).is_err() {
            stack.sockets.remove(handle);
            return None;
        }
    }

    UDP_SOCKETS.lock().insert(fd, handle);
    Some(fd)
}

pub fn udp_sendto(fd: u64, data: &[u8], dst_ip: [u8; 4], dst_port: u16) -> usize {
    let mut stack_lock = NETSTACK.lock();
    let stack = match stack_lock.as_mut() {
        Some(s) => s,
        None => return 0,
    };
    let handle = match UDP_SOCKETS.lock().get(&fd).copied() {
        Some(h) => h,
        None => return 0,
    };

    let dst = IpEndpoint::new(
        IpAddress::Ipv4(Ipv4Address::new(dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3])),
        dst_port,
    );

    let socket = stack.sockets.get_mut::<UdpSocket>(handle);
    match socket.send_slice(data, dst) {
        Ok(()) => {
            let now = smoltcp_now();
            stack.iface.poll(now, &mut stack.device, &mut stack.sockets);
            data.len()
        }
        Err(_) => {
            inc_tx_error();
            0
        }
    }
}

pub fn udp_recvfrom(fd: u64, buf: &mut [u8]) -> (usize, [u8; 4], u16) {
    let mut stack_lock = NETSTACK.lock();
    let stack = match stack_lock.as_mut() {
        Some(s) => s,
        None => return (0, [0; 4], 0),
    };

    let now = smoltcp_now();
    stack.iface.poll(now, &mut stack.device, &mut stack.sockets);

    let handle = match UDP_SOCKETS.lock().get(&fd).copied() {
        Some(h) => h,
        None => return (0, [0; 4], 0),
    };

    let socket = stack.sockets.get_mut::<UdpSocket>(handle);
    match socket.recv_slice(buf) {
        Ok((n, ep)) => {
            let ip = match ep.endpoint.addr {
                IpAddress::Ipv4(v4) => v4.0,
                _ => [0; 4],
            };
            (n, ip, ep.endpoint.port)
        }
        Err(_) => (0, [0; 4], 0),
    }
}

pub fn udp_close(fd: u64) {
    if let Some(handle) = UDP_SOCKETS.lock().remove(&fd) {
        if let Some(stack) = NETSTACK.lock().as_mut() {
            stack.sockets.remove(handle);
        }
    }
}

// ── Gossip (UDP multicast) ──────────────────────────────────────────────────
fn ensure_gossip_fd() -> Option<u64> {
    GOSSIP_INIT.call_once(|| {
        let fd = udp_bind([0, 0, 0, 0], 9000).unwrap_or(u64::MAX);
        *GOSSIP_FD.lock() = fd;
    });
    let fd = *GOSSIP_FD.lock();
    if fd == u64::MAX { None } else { Some(fd) }
}

pub fn gossip_broadcast(data: &[u8]) -> usize {
    let fd = match ensure_gossip_fd() {
        Some(f) => f,
        None => return 0,
    };
    let peers = get_peer_list();
    let mut sent = 0;
    for peer_ip in &peers {
        if udp_sendto(fd, data, *peer_ip, 9000) > 0 {
            sent += 1;
        }
    }
    // Fallback broadcast dacă nu cunoaștem noduri
    if sent == 0 && !data.is_empty() {
        udp_sendto(fd, data, [10, 0, 2, 255], 9000);
        sent = 1;
    }
    sent
}

pub fn gossip_recv() -> Option<Vec<u8>> {
    let fd = ensure_gossip_fd()?;
    let mut buf = alloc::vec![0u8; 4096];
    let (n, _ip, _port) = udp_recvfrom(fd, &mut buf);
    if n > 0 {
        buf.truncate(n);
        Some(buf)
    } else {
        None
    }
}

pub fn get_peer_list() -> Vec<[u8; 4]> {
    let mut peers = Vec::new();
    if let Some(data) = crate::fs::ionafs::read("/etc/iona-node.json") {
        let s = alloc::string::String::from_utf8_lossy(&data);
        // Parsare simplă: extrage secvențe "a.b.c.d"
        for part in s.split('"') {
            let nums: Vec<u8> = part.split('.').filter_map(|x| x.parse().ok()).collect();
            if nums.len() == 4 {
                peers.push([nums[0], nums[1], nums[2], nums[3]]);
            }
        }
    }
    peers
}

// ── Contoare de erori ───────────────────────────────────────────────────────
use core::sync::atomic::{AtomicU64, Ordering};

pub static NET_TX_ERRORS: AtomicU64 = AtomicU64::new(0);
pub static NET_RX_ERRORS: AtomicU64 = AtomicU64::new(0);
pub static NET_TCP_RESETS: AtomicU64 = AtomicU64::new(0);
pub static NET_CONN_REFUSED: AtomicU64 = AtomicU64::new(0);

pub fn inc_tx_error()     { NET_TX_ERRORS.fetch_add(1, Ordering::Relaxed); }
pub fn inc_rx_error()     { NET_RX_ERRORS.fetch_add(1, Ordering::Relaxed); }
pub fn inc_tcp_reset()    { NET_TCP_RESETS.fetch_add(1, Ordering::Relaxed); }
pub fn inc_conn_refused() { NET_CONN_REFUSED.fetch_add(1, Ordering::Relaxed); }

pub fn error_count() -> u64 {
    NET_TX_ERRORS.load(Ordering::Relaxed) + NET_RX_ERRORS.load(Ordering::Relaxed)
}

pub fn net_stats() -> (u64, u64, u64, u64) {
    (
        NET_TX_ERRORS.load(Ordering::Relaxed),
        NET_RX_ERRORS.load(Ordering::Relaxed),
        NET_TCP_RESETS.load(Ordering::Relaxed),
        NET_CONN_REFUSED.load(Ordering::Relaxed),
    )
}
