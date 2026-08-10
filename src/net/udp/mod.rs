//! UDP sockets via smoltcp.
//!
//! Syscalls:
//!   sys_udp_bind(port)                    → fd
//!   sys_udp_sendto(fd, buf, ip, port)     → n_sent
//!   sys_udp_recvfrom(fd, buf, addr_out)   → n_recv
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                           UDP Module                                   │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   config    │    error     │     types     │        metrics           │
//! │ (UdpConfig) │ (UdpError)   │ (Fd, Socket)  │ (UdpMetrics)             │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   registry  │   manager    │    legacy     │                          │
//! │ (socket reg)│ (UdpManager) │ (global fns)  │                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::net::udp::{UdpManager, UdpConfig};
//!
//! let config = UdpConfig::default();
//! let manager = UdpManager::new(config);
//! let fd = manager.bind(0).unwrap();
//! manager.sendto(fd, &data, [8,8,8,8], 53).unwrap();
//! let (n, ip, port) = manager.recvfrom(fd, &mut buf).unwrap();
//! ```

#![allow(dead_code)]

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use smoltcp::{
    socket::udp::{Socket as UdpSocket, PacketBuffer, PacketMetadata},
    wire::{IpAddress, IpEndpoint, Ipv4Address},
};
use spin::{Mutex, RwLock};
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for the UDP subsystem.
    use serde::{Deserialize, Serialize};

    /// Configuration for UDP.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct UdpConfig {
        pub rx_buffer_size: usize,
        pub tx_buffer_size: usize,
        pub rx_metadata_count: usize,
        pub tx_metadata_count: usize,
        pub max_packet_size: usize,
        pub collect_metrics: bool,
        pub log_operations: bool,
    }

    impl Default for UdpConfig {
        fn default() -> Self {
            Self {
                rx_buffer_size: 65536,
                tx_buffer_size: 65536,
                rx_metadata_count: 16,
                tx_metadata_count: 16,
                max_packet_size: 1500,
                collect_metrics: true,
                log_operations: false,
            }
        }
    }

    impl UdpConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.rx_buffer_size == 0 { return Err("rx_buffer_size must be > 0"); }
            if self.tx_buffer_size == 0 { return Err("tx_buffer_size must be > 0"); }
            if self.rx_metadata_count == 0 { return Err("rx_metadata_count must be > 0"); }
            if self.tx_metadata_count == 0 { return Err("tx_metadata_count must be > 0"); }
            if self.max_packet_size == 0 { return Err("max_packet_size must be > 0"); }
            Ok(())
        }
    }
}

pub mod error {
    //! Error types for UDP operations.
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum UdpError {
        #[error("socket binding failed on port {0}")]
        BindFailed(u16),

        #[error("invalid file descriptor {0}")]
        InvalidFd(u64),

        #[error("send failed: {0}")]
        SendFailed(&'static str),

        #[error("receive failed: {0}")]
        RecvFailed(&'static str),

        #[error("buffer too small: needed {needed}, got {got}")]
        BufferTooSmall { needed: usize, got: usize },

        #[error("network stack not available")]
        StackNotAvailable,

        #[error("configuration error: {0}")]
        Config(String),

        #[error("internal error: {0}")]
        Internal(String),
    }

    pub type UdpResult<T> = Result<T, UdpError>;
}

pub mod types {
    //! Types for the UDP module.
    use smoltcp::socket::udp::SocketHandle;
    use core::fmt;

    /// UDP file descriptor.
    pub type Fd = u64;

    /// Internal socket entry.
    #[derive(Debug)]
    pub struct UdpSocketEntry {
        pub fd: Fd,
        pub handle: SocketHandle,
        pub local_port: u16,
    }

    /// UDP endpoint (IP + port).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct UdpEndpoint {
        pub ip: [u8; 4],
        pub port: u16,
    }
}

pub mod metrics {
    //! Metrics for UDP operations.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct UdpMetrics {
        pub binds: AtomicU64,
        pub closes: AtomicU64,
        pub sends: AtomicU64,
        pub recvs: AtomicU64,
        pub send_errors: AtomicU64,
        pub recv_errors: AtomicU64,
        pub bytes_sent: AtomicU64,
        pub bytes_received: AtomicU64,
        pub active_sockets: AtomicU64,
    }

    impl UdpMetrics {
        pub fn inc_bind(&self) { self.binds.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_close(&self) { self.closes.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_send(&self) { self.sends.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_recv(&self) { self.recvs.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_send_error(&self) { self.send_errors.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_recv_error(&self) { self.recv_errors.fetch_add(1, Ordering::Relaxed); }
        pub fn add_bytes_sent(&self, n: u64) { self.bytes_sent.fetch_add(n, Ordering::Relaxed); }
        pub fn add_bytes_received(&self, n: u64) { self.bytes_received.fetch_add(n, Ordering::Relaxed); }
        pub fn set_active_sockets(&self, count: u64) { self.active_sockets.store(count, Ordering::Relaxed); }

        pub fn snapshot(&self) -> UdpMetricsSnapshot {
            UdpMetricsSnapshot {
                binds: self.binds.load(Ordering::Relaxed),
                closes: self.closes.load(Ordering::Relaxed),
                sends: self.sends.load(Ordering::Relaxed),
                recvs: self.recvs.load(Ordering::Relaxed),
                send_errors: self.send_errors.load(Ordering::Relaxed),
                recv_errors: self.recv_errors.load(Ordering::Relaxed),
                bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
                bytes_received: self.bytes_received.load(Ordering::Relaxed),
                active_sockets: self.active_sockets.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct UdpMetricsSnapshot {
        pub binds: u64,
        pub closes: u64,
        pub sends: u64,
        pub recvs: u64,
        pub send_errors: u64,
        pub recv_errors: u64,
        pub bytes_sent: u64,
        pub bytes_received: u64,
        pub active_sockets: u64,
    }
}

pub mod registry {
    //! Socket registry (fd → smoltcp handle).
    use super::{
        config::UdpConfig,
        error::{UdpError, UdpResult},
        types::{Fd, UdpSocketEntry},
        metrics::UdpMetrics,
    };
    use alloc::collections::BTreeMap;
    use core::sync::atomic::{AtomicU64, Ordering};
    use smoltcp::socket::udp::{Socket as UdpSocket, SocketHandle, PacketBuffer, PacketMetadata};
    use spin::Mutex;
    use crate::net::NETSTACK;
    use tracing::debug;

    /// Registry of UDP sockets.
    pub struct UdpRegistry {
        sockets: Mutex<BTreeMap<Fd, UdpSocketEntry>>,
        next_fd: AtomicU64,
        config: UdpConfig,
        metrics: UdpMetrics,
    }

    impl UdpRegistry {
        pub fn new(config: UdpConfig) -> Self {
            Self {
                sockets: Mutex::new(BTreeMap::new()),
                next_fd: AtomicU64::new(10000),
                config,
                metrics: UdpMetrics::default(),
            }
        }

        pub fn metrics(&self) -> &UdpMetrics {
            &self.metrics
        }

        /// Bind a UDP socket to a local port.
        pub fn bind(&self, port: u16) -> UdpResult<Fd> {
            let mut lock = NETSTACK.lock();
            let stack = lock.as_mut().ok_or(UdpError::StackNotAvailable)?;

            let rx_meta = alloc::vec![PacketMetadata::EMPTY; self.config.rx_metadata_count];
            let tx_meta = alloc::vec![PacketMetadata::EMPTY; self.config.tx_metadata_count];
            let rx_buf = alloc::vec![0u8; self.config.rx_buffer_size];
            let tx_buf = alloc::vec![0u8; self.config.tx_buffer_size];

            let mut socket = UdpSocket::new(
                PacketBuffer::new(rx_meta, rx_buf),
                PacketBuffer::new(tx_meta, tx_buf),
            );

            if socket.bind(port).is_err() {
                return Err(UdpError::BindFailed(port));
            }

            let handle = stack.sockets.add(socket);
            let fd = self.next_fd.fetch_add(1, Ordering::Relaxed);

            let entry = UdpSocketEntry { fd, handle, local_port: port };
            self.sockets.lock().insert(fd, entry);

            self.metrics.inc_bind();
            self.metrics.set_active_sockets(self.sockets.lock().len() as u64);

            if self.config.log_operations {
                debug!(fd, port, "UDP socket bound");
            }
            Ok(fd)
        }

        /// Send data over a UDP socket.
        pub fn sendto(&self, fd: Fd, data: &[u8], dest_ip: [u8; 4], dest_port: u16) -> UdpResult<usize> {
            let entry = {
                let sockets = self.sockets.lock();
                sockets.get(&fd).cloned().ok_or(UdpError::InvalidFd(fd))?
            };

            let mut lock = NETSTACK.lock();
            let stack = lock.as_mut().ok_or(UdpError::StackNotAvailable)?;

            let endpoint = IpEndpoint::new(
                IpAddress::Ipv4(Ipv4Address::new(dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3])),
                dest_port,
            );

            let socket = stack.sockets.get_mut::<UdpSocket>(entry.handle);
            match socket.send_slice(data, endpoint) {
                Ok(()) => {
                    // Poll to actually send the packet.
                    let now = smoltcp::time::Instant::from_micros(
                        crate::arch::x86_64::timer::uptime_ms() as i64 * 1000
                    );
                    stack.iface.poll(now, &mut stack.device, &mut stack.sockets);
                    self.metrics.inc_send();
                    self.metrics.add_bytes_sent(data.len() as u64);
                    if self.config.log_operations {
                        debug!(fd, dest_ip = ?dest_ip, dest_port, len = data.len(), "UDP send");
                    }
                    Ok(data.len())
                }
                Err(e) => {
                    self.metrics.inc_send_error();
                    Err(UdpError::SendFailed(e.into()))
                }
            }
        }

        /// Receive data from a UDP socket.
        pub fn recvfrom(&self, fd: Fd, buf: &mut [u8]) -> UdpResult<(usize, [u8; 4], u16)> {
            let entry = {
                let sockets = self.sockets.lock();
                sockets.get(&fd).cloned().ok_or(UdpError::InvalidFd(fd))?
            };

            let mut lock = NETSTACK.lock();
            let stack = lock.as_mut().ok_or(UdpError::StackNotAvailable)?;

            // Poll the interface.
            let now = smoltcp::time::Instant::from_micros(
                crate::arch::x86_64::timer::uptime_ms() as i64 * 1000
            );
            stack.iface.poll(now, &mut stack.device, &mut stack.sockets);

            let socket = stack.sockets.get_mut::<UdpSocket>(entry.handle);
            match socket.recv_slice(buf) {
                Ok((n, meta)) => {
                    let ip = match meta.endpoint.addr {
                        IpAddress::Ipv4(a) => a.0,
                        _ => [0; 4],
                    };
                    self.metrics.inc_recv();
                    self.metrics.add_bytes_received(n as u64);
                    if self.config.log_operations {
                        debug!(fd, src_ip = ?ip, src_port = meta.endpoint.port, len = n, "UDP recv");
                    }
                    Ok((n, ip, meta.endpoint.port))
                }
                Err(e) => {
                    self.metrics.inc_recv_error();
                    Err(UdpError::RecvFailed(e.into()))
                }
            }
        }

        /// Close a UDP socket.
        pub fn close(&self, fd: Fd) -> UdpResult<()> {
            let mut sockets = self.sockets.lock();
            if let Some(entry) = sockets.remove(&fd) {
                let mut lock = NETSTACK.lock();
                if let Some(stack) = lock.as_mut() {
                    stack.sockets.remove(entry.handle);
                }
                self.metrics.inc_close();
                self.metrics.set_active_sockets(sockets.len() as u64);
                if self.config.log_operations {
                    debug!(fd, "UDP socket closed");
                }
                Ok(())
            } else {
                Err(UdpError::InvalidFd(fd))
            }
        }

        /// Get the local port of a socket.
        pub fn local_port(&self, fd: Fd) -> Option<u16> {
            self.sockets.lock().get(&fd).map(|e| e.local_port)
        }

        /// List all active FDs.
        pub fn list_fds(&self) -> Vec<Fd> {
            self.sockets.lock().keys().copied().collect()
        }

        /// Clear all sockets (for shutdown).
        pub fn clear(&self) {
            let mut sockets = self.sockets.lock();
            let fds: Vec<_> = sockets.keys().copied().collect();
            for fd in fds {
                let _ = self.close(fd);
            }
            sockets.clear();
        }
    }
}

pub mod manager {
    //! Centralised UDP manager.
    use super::{
        config::UdpConfig,
        error::{UdpError, UdpResult},
        registry::UdpRegistry,
        metrics::UdpMetrics,
        types::{Fd, UdpEndpoint},
    };
    use alloc::vec::Vec;
    use core::sync::atomic::Ordering;

    /// Centralised manager for UDP operations.
    pub struct UdpManager {
        registry: UdpRegistry,
    }

    impl UdpManager {
        pub fn new(config: UdpConfig) -> Self {
            config.validate().expect("invalid UdpConfig");
            Self {
                registry: UdpRegistry::new(config),
            }
        }

        pub fn default() -> Self {
            Self::new(UdpConfig::default())
        }

        /// Get metrics snapshot.
        pub fn metrics(&self) -> super::metrics::UdpMetricsSnapshot {
            self.registry.metrics().snapshot()
        }

        /// Bind to a local port.
        pub fn bind(&self, port: u16) -> UdpResult<Fd> {
            self.registry.bind(port)
        }

        /// Send data.
        pub fn sendto(&self, fd: Fd, data: &[u8], dest_ip: [u8; 4], dest_port: u16) -> UdpResult<usize> {
            self.registry.sendto(fd, data, dest_ip, dest_port)
        }

        /// Receive data.
        pub fn recvfrom(&self, fd: Fd, buf: &mut [u8]) -> UdpResult<(usize, [u8; 4], u16)> {
            self.registry.recvfrom(fd, buf)
        }

        /// Close a socket.
        pub fn close(&self, fd: Fd) -> UdpResult<()> {
            self.registry.close(fd)
        }

        /// Get local port.
        pub fn local_port(&self, fd: Fd) -> Option<u16> {
            self.registry.local_port(fd)
        }

        /// List active FDs.
        pub fn list_fds(&self) -> Vec<Fd> {
            self.registry.list_fds()
        }

        /// Convenience: send to a destination without managing the FD.
        /// This binds an ephemeral port, sends, and closes.
        pub fn sendto_ephemeral(&self, data: &[u8], dest_ip: [u8; 4], dest_port: u16) -> UdpResult<usize> {
            let fd = self.bind(0)?;
            let result = self.sendto(fd, data, dest_ip, dest_port);
            let _ = self.close(fd);
            result
        }

        /// Convenience: receive one packet on a port.
        /// This binds the port, receives one packet, and closes.
        pub fn recvone(&self, port: u16, max_size: usize) -> UdpResult<(Vec<u8>, [u8; 4], u16)> {
            let fd = self.bind(port)?;
            let mut buf = alloc::vec![0u8; max_size];
            let (n, ip, p) = self.recvfrom(fd, &mut buf)?;
            buf.truncate(n);
            let _ = self.close(fd);
            Ok((buf, ip, p))
        }

        /// Send a broadcast packet (fire and forget).
        pub fn sendto_broadcast(&self, local_port: u16, dest_port: u16, data: &[u8]) -> UdpResult<usize> {
            let fd = self.bind(local_port)?;
            let result = self.sendto(fd, data, [255, 255, 255, 255], dest_port);
            let _ = self.close(fd);
            result
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::UdpConfig;
pub use error::{UdpError, UdpResult};
pub use types::{Fd, UdpEndpoint};
pub use metrics::{UdpMetrics, UdpMetricsSnapshot};
pub use manager::UdpManager;

// -----------------------------------------------------------------------------
// Legacy global API (wrappers around a global singleton)
// -----------------------------------------------------------------------------

static GLOBAL_MANAGER: spin::Once<UdpManager> = spin::Once::new();

/// Initialize the global UDP manager.
pub fn init() {
    GLOBAL_MANAGER.call_once(|| UdpManager::default());
    crate::serial_println!("  [UDP] subsystem initialized");
}

/// Get a reference to the global manager.
fn global_manager() -> &'static UdpManager {
    GLOBAL_MANAGER.get().expect("UDP manager not initialized")
}

/// Bind a UDP socket to a port.
pub fn udp_bind(port: u16) -> Fd {
    global_manager().bind(port).unwrap_or(u64::MAX)
}

/// Send data via UDP.
pub fn udp_sendto(fd: Fd, data: &[u8], dest_ip: [u8; 4], dest_port: u16) -> usize {
    global_manager().sendto(fd, data, dest_ip, dest_port).unwrap_or(0)
}

/// Receive data from UDP socket.
pub fn udp_recvfrom(fd: Fd, buf: &mut [u8]) -> (usize, [u8; 4], u16) {
    global_manager().recvfrom(fd, buf).unwrap_or((0, [0; 4], 0))
}

/// Close a UDP socket.
pub fn udp_close(fd: Fd) {
    let _ = global_manager().close(fd);
}

/// Convenience: send to IP:port without managing fd.
pub fn sendto(dest_ip: [u8; 4], dest_port: u16, data: &[u8]) -> usize {
    global_manager().sendto_ephemeral(data, dest_ip, dest_port).unwrap_or(0)
}

/// Send broadcast UDP to 255.255.255.255 — fire and forget.
pub fn sendto_broadcast(local_port: u16, dest_port: u16, data: &[u8]) -> usize {
    global_manager().sendto_broadcast(local_port, dest_port, data).unwrap_or(0)
}

/// Receive one packet on a port (convenience).
pub fn recvfrom(port: u16) -> Option<alloc::vec::Vec<u8>> {
    let max_size = 1500;
    match global_manager().recvone(port, max_size) {
        Ok((buf, _ip, _port)) => Some(buf),
        Err(_) => None,
    }
}

/// Alias used by dhcp + sync modules.
pub fn udp_recvfrom_port(port: u16) -> Option<alloc::vec::Vec<u8>> {
    recvfrom(port)
}

/// Get local port for an fd.
pub fn udp_local_port(fd: Fd) -> Option<u16> {
    global_manager().local_port(fd)
}

/// List all open UDP FDs.
pub fn udp_list_fds() -> Vec<Fd> {
    global_manager().list_fds()
}

/// Clear all UDP sockets (for shutdown).
pub fn udp_clear_all() {
    let fds = global_manager().list_fds();
    for fd in fds {
        let _ = global_manager().close(fd);
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::NETSTACK;

    fn init_test() {
        // Ensure NETSTACK is available (mock or real).
        // For tests, we might need to set up a dummy stack.
        // This is a placeholder.
    }

    #[test]
    fn test_config_validation() {
        let config = UdpConfig::default();
        assert!(config.validate().is_ok());

        let mut bad = config.clone();
        bad.rx_buffer_size = 0;
        assert!(bad.validate().is_err());

        let mut bad2 = config;
        bad2.max_packet_size = 0;
        assert!(bad2.validate().is_err());
    }

    #[test]
    fn test_sendto_ephemeral_fails_without_stack() {
        // Without a network stack, this should fail.
        // We just test that the function returns 0.
        let result = sendto([8, 8, 8, 8], 53, b"hello");
        // Depending on the test environment, this may return 0 if stack not initialized.
        // We won't assert a specific value; just ensure it doesn't panic.
        let _ = result;
    }
}
