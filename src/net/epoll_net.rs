//! Network epoll integration — proper async I/O model.
//!
//! Bridges smoltcp poll events with epoll notifications.
//! When a TCP socket becomes readable/writable, wakes tasks
//! waiting in epoll_wait().
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                           Epoll Module                                 │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   config    │    error     │     types     │        metrics           │
//! │ (EpollCfg)  │ (EpollError) │ (Fd, Event)   │ (EpollMetrics)          │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   notify    │  backpressure│   discovery   │        manager           │
//! │ (wake task) │ (send buffer)│ (UDP beacon)  │ (EpollManager)           │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::net::epoll::{EpollManager, EpollConfig};
//!
//! let config = EpollConfig::default();
//! let manager = EpollManager::new(config);
//! manager.tick(); // called periodically
//! let backpressure = manager.tcp_send_backpressure(fd);
//! manager.discover_peers(fd, 7001);
//! ```

#![allow(dead_code)]

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for epoll integration.
    use serde::{Deserialize, Serialize};

    /// Configuration for epoll.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct EpollConfig {
        pub tick_interval_ms: u64,
        pub backpressure_threshold_bytes: usize,
        pub discovery_port: u16,
        pub discovery_beacon: String,
        pub enable_discovery: bool,
        pub collect_metrics: bool,
        pub log_events: bool,
    }

    impl Default for EpollConfig {
        fn default() -> Self {
            Self {
                tick_interval_ms: 5,
                backpressure_threshold_bytes: 512,
                discovery_port: 7001,
                discovery_beacon: "IONA_DISCOVERY_BEACON_v1".into(),
                enable_discovery: true,
                collect_metrics: true,
                log_events: false,
            }
        }
    }

    impl EpollConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.tick_interval_ms == 0 { return Err("tick_interval_ms must be > 0"); }
            if self.backpressure_threshold_bytes == 0 { return Err("backpressure_threshold_bytes must be > 0"); }
            if self.discovery_port == 0 { return Err("discovery_port must be > 0"); }
            Ok(())
        }
    }
}

pub mod error {
    //! Error types for epoll operations.
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum EpollError {
        #[error("invalid file descriptor")]
        InvalidFd,

        #[error("socket not found")]
        SocketNotFound,

        #[error("I/O error: {0}")]
        Io(String),

        #[error("configuration error: {0}")]
        Config(String),

        #[error("internal error: {0}")]
        Internal(String),
    }

    pub type EpollResult<T> = Result<T, EpollError>;
}

pub mod types {
    //! Types for epoll integration.
    use core::fmt;

    /// Network file descriptor.
    pub type Fd = u64;

    /// Epoll event kind.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum EventKind {
        Readable,
        Writable,
        Error,
        HangUp,
    }

    /// Epoll event.
    #[derive(Debug, Clone)]
    pub struct EpollEvent {
        pub fd: Fd,
        pub kind: EventKind,
        pub data: u64,
    }
}

pub mod metrics {
    //! Metrics for epoll operations.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct EpollMetrics {
        pub ticks: AtomicU64,
        pub wakeups: AtomicU64,
        pub backpressure_events: AtomicU64,
        pub discovery_beacons_sent: AtomicU64,
        pub discovery_responses_received: AtomicU64,
    }

    impl EpollMetrics {
        pub fn inc_tick(&self) { self.ticks.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_wakeup(&self) { self.wakeups.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_backpressure(&self) { self.backpressure_events.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_beacon_sent(&self) { self.discovery_beacons_sent.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_discovery_response(&self) { self.discovery_responses_received.fetch_add(1, Ordering::Relaxed); }

        pub fn snapshot(&self) -> EpollMetricsSnapshot {
            EpollMetricsSnapshot {
                ticks: self.ticks.load(Ordering::Relaxed),
                wakeups: self.wakeups.load(Ordering::Relaxed),
                backpressure_events: self.backpressure_events.load(Ordering::Relaxed),
                discovery_beacons_sent: self.discovery_beacons_sent.load(Ordering::Relaxed),
                discovery_responses_received: self.discovery_responses_received.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct EpollMetricsSnapshot {
        pub ticks: u64,
        pub wakeups: u64,
        pub backpressure_events: u64,
        pub discovery_beacons_sent: u64,
        pub discovery_responses_received: u64,
    }
}

pub mod notify {
    //! Notification of epoll watchers.
    use super::{
        config::EpollConfig,
        metrics::EpollMetrics,
        types::Fd,
    };
    use tracing::debug;

    /// Called periodically to wake tasks blocked in epoll_wait.
    pub fn notify_epoll_watchers(config: &EpollConfig, metrics: &EpollMetrics) {
        // In the real implementation, this would check all registered sockets
        // and wake tasks that have events ready.
        // For this stub, we just call the wait subsystem's tick.
        crate::wait::tick_wakeups();
        metrics.inc_wakeup();
        if config.log_events {
            debug!("epoll watchers notified");
        }
    }
}

pub mod backpressure {
    //! TCP backpressure detection.
    use super::{
        config::EpollConfig,
        metrics::EpollMetrics,
        types::Fd,
    };

    /// Check if the TCP send buffer is under backpressure.
    pub fn tcp_send_backpressure(fd: Fd, config: &EpollConfig, metrics: &EpollMetrics) -> bool {
        let available = crate::net::tcp_send_available(fd);
        let under_pressure = available < config.backpressure_threshold_bytes as u64;
        if under_pressure {
            metrics.inc_backpressure();
            if config.log_events {
                tracing::debug!(fd, available, threshold = config.backpressure_threshold_bytes, "TCP backpressure");
            }
        }
        under_pressure
    }
}

pub mod discovery {
    //! Peer discovery via UDP broadcast and multicast.
    use super::{
        config::EpollConfig,
        metrics::EpollMetrics,
        types::Fd,
        error::{EpollError, EpollResult},
    };
    use alloc::vec::Vec;
    use tracing::{debug, warn};

    /// Send a discovery beacon to broadcast and multicast addresses.
    pub fn discover_peers(fd: Fd, port: u16, config: &EpollConfig, metrics: &EpollMetrics) -> EpollResult<()> {
        if !config.enable_discovery {
            return Ok(());
        }

        let beacon = config.discovery_beacon.as_bytes();
        let broadcast_ip = [255u8, 255, 255, 255];
        let multicast_ip = [239u8, 192, 0, 1];

        // Send to broadcast.
        crate::net::udp::udp_sendto(fd, beacon, broadcast_ip, port);
        metrics.inc_beacon_sent();

        // Send to multicast.
        crate::net::udp::udp_sendto(fd, beacon, multicast_ip, port);
        metrics.inc_beacon_sent();

        if config.log_events {
            debug!("discovery beacons sent to {}:{} and {}:{}",
                broadcast_ip[0], broadcast_ip[1], broadcast_ip[2], broadcast_ip[3], port,
                multicast_ip[0], multicast_ip[1], multicast_ip[2], multicast_ip[3], port);
        }
        Ok(())
    }

    /// Parse a discovery response.
    /// Expected format: "IONA_DISCOVERY_BEACON_v1\nip=X.X.X.X port=XXXX\n"
    pub fn parse_discovery(data: &[u8]) -> Option<([u8; 4], u16)> {
        if !data.starts_with(b"IONA_DISCOVERY_BEACON_v1") {
            return None;
        }
        let s = core::str::from_utf8(data).ok()?;
        let ip_part = s.split("ip=").nth(1)?;
        let port_part = s.split("port=").nth(1)?;

        let mut ip = [0u8; 4];
        for (i, octet) in ip_part.splitn(4, '.').enumerate().take(4) {
            ip[i] = octet.trim().parse().ok()?;
        }
        let port: u16 = port_part.trim().parse().ok()?;
        Some((ip, port))
    }
}

pub mod manager {
    //! Centralised epoll manager.
    use super::{
        config::EpollConfig,
        error::{EpollError, EpollResult},
        metrics::EpollMetrics,
        notify,
        backpressure,
        discovery,
    };
    use tracing::debug;

    /// Centralised manager for epoll integration.
    pub struct EpollManager {
        config: EpollConfig,
        metrics: EpollMetrics,
    }

    impl EpollManager {
        pub fn new(config: EpollConfig) -> Self {
            config.validate().expect("invalid EpollConfig");
            Self {
                config,
                metrics: EpollMetrics::default(),
            }
        }

        pub fn default() -> Self {
            Self::new(EpollConfig::default())
        }

        /// Get metrics snapshot.
        pub fn metrics(&self) -> super::metrics::EpollMetricsSnapshot {
            self.metrics.snapshot()
        }

        /// Get configuration.
        pub fn config(&self) -> &EpollConfig {
            &self.config
        }

        /// Periodic tick – called by scheduler or timer.
        pub fn tick(&self) {
            self.metrics.inc_tick();
            // Notify epoll watchers.
            notify::notify_epoll_watchers(&self.config, &self.metrics);
        }

        /// Check TCP send buffer backpressure.
        pub fn tcp_send_backpressure(&self, fd: super::types::Fd) -> bool {
            backpressure::tcp_send_backpressure(fd, &self.config, &self.metrics)
        }

        /// Send discovery beacons.
        pub fn discover_peers(&self, fd: super::types::Fd, port: u16) -> EpollResult<()> {
            discovery::discover_peers(fd, port, &self.config, &self.metrics)
        }

        /// Parse a discovery response.
        pub fn parse_discovery(&self, data: &[u8]) -> Option<([u8; 4], u16)> {
            let result = discovery::parse_discovery(data);
            if result.is_some() {
                self.metrics.inc_discovery_response();
            }
            result
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::EpollConfig;
pub use error::{EpollError, EpollResult};
pub use types::{Fd, EventKind, EpollEvent};
pub use metrics::{EpollMetrics, EpollMetricsSnapshot};
pub use manager::EpollManager;

// -----------------------------------------------------------------------------
// Legacy global API (wrappers around a global singleton)
// -----------------------------------------------------------------------------

static GLOBAL_MANAGER: spin::Once<EpollManager> = spin::Once::new();

/// Initialize the global epoll manager.
pub fn init() {
    GLOBAL_MANAGER.call_once(|| EpollManager::default());
    crate::serial_println!("  [EPOLL] integration initialized");
}

/// Get a reference to the global manager.
fn global_manager() -> &'static EpollManager {
    GLOBAL_MANAGER.get().expect("epoll manager not initialized")
}

/// Tick the epoll system.
pub fn notify_epoll_watchers() {
    global_manager().tick();
}

/// Check TCP send backpressure.
pub fn tcp_send_backpressure(fd: Fd) -> bool {
    global_manager().tcp_send_backpressure(fd)
}

/// Send discovery beacons.
pub fn discover_peers(fd: Fd, port: u16) {
    let _ = global_manager().discover_peers(fd, port);
}

/// Parse a discovery response.
pub fn parse_discovery(data: &[u8]) -> Option<([u8; 4], u16)> {
    global_manager().parse_discovery(data)
}

/// Get metrics snapshot.
pub fn metrics() -> EpollMetricsSnapshot {
    global_manager().metrics()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let config = EpollConfig::default();
        assert!(config.validate().is_ok());

        let mut bad = config.clone();
        bad.tick_interval_ms = 0;
        assert!(bad.validate().is_err());

        let mut bad2 = config;
        bad2.backpressure_threshold_bytes = 0;
        assert!(bad2.validate().is_err());
    }

    #[test]
    fn test_discovery_parse() {
        let data = b"IONA_DISCOVERY_BEACON_v1\nip=10.0.0.1 port=7001\n";
        let result = parse_discovery(data);
        assert_eq!(result, Some(([10, 0, 0, 1], 7001)));

        let bad = b"BLAH\n";
        assert_eq!(parse_discovery(bad), None);
    }
}
