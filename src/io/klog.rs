//! Kernel structured logging — log levels + ring buffer.
//!
//! Usage:
//!   kinfo!("message");
//!   kwarn!("message");
//!   kerr!("message");
//!   kdebug!("message"); // only in debug builds
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                           Logging Module                               │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   Config    │    Error     │    Metrics    │         Types            │
//! │ (LogCfg)    │ (LogError)   │ (LogMetrics)  │ (Level, Entry, Stats)    │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │    Ring     │   Writer     │   Manager     │        Legacy            │
//! │ (buffer)    │ (serial, fs) │ (LogManager)  │ (global fns, macros)     │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::io::klog::{LogManager, LogConfig};
//!
//! let config = LogConfig::default();
//! let manager = LogManager::new(config);
//! manager.init();
//! manager.log(LogLevel::Info, "Hello, kernel!");
//! let dump = manager.dump(4096);
//! ```

#![allow(dead_code)]

use alloc::{
    collections::VecDeque,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Mutex, RwLock};
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for the logging subsystem.
    use serde::{Deserialize, Serialize};
    use super::types::LogLevel;

    /// Configuration for logging.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct LogConfig {
        pub min_level: LogLevel,
        pub ring_capacity: usize,
        pub persist_errors: bool,
        pub persist_path: String,
        pub log_timestamps: bool,
        pub collect_metrics: bool,
        pub log_serial: bool,
    }

    impl Default for LogConfig {
        fn default() -> Self {
            Self {
                min_level: LogLevel::Info,
                ring_capacity: 1024,
                persist_errors: true,
                persist_path: "/var/log/kernel.log".to_string(),
                log_timestamps: true,
                collect_metrics: true,
                log_serial: true,
            }
        }
    }

    impl LogConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.ring_capacity == 0 {
                return Err("ring_capacity must be > 0");
            }
            if self.persist_path.is_empty() {
                return Err("persist_path must not be empty");
            }
            Ok(())
        }

        pub fn with_metrics(mut self) -> Self {
            self.collect_metrics = true;
            self
        }
    }
}

pub mod error {
    //! Error types for logging.
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum LogError {
        #[error("ring buffer full")]
        RingFull,

        #[error("persistence error: {0}")]
        Persistence(String),

        #[error("configuration error: {0}")]
        Config(String),
    }

    pub type LogResult<T> = Result<T, LogError>;
}

pub mod types {
    //! Core types for logging.
    use core::fmt;

    /// Log level.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum LogLevel {
        Debug = 0,
        Info = 1,
        Warn = 2,
        Error = 3,
    }

    impl LogLevel {
        pub fn as_str(self) -> &'static str {
            match self {
                Self::Debug => "DBG",
                Self::Info => "INF",
                Self::Warn => "WRN",
                Self::Error => "ERR",
            }
        }

        pub fn prefix(self) -> &'static str {
            match self {
                Self::Debug => "[DBG] ",
                Self::Info => "[INF] ",
                Self::Warn => "[WRN] ",
                Self::Error => "[ERR] ",
            }
        }

        pub fn from_str(s: &str) -> Option<Self> {
            match s {
                "debug" => Some(Self::Debug),
                "info" => Some(Self::Info),
                "warn" => Some(Self::Warn),
                "error" => Some(Self::Error),
                _ => None,
            }
        }
    }

    impl fmt::Display for LogLevel {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.as_str())
        }
    }

    /// A single log entry.
    #[derive(Clone, Debug)]
    pub struct LogEntry {
        pub level: LogLevel,
        pub ts_ms: u64,
        pub msg: String,
    }

    /// Statistics about the logging subsystem.
    #[derive(Debug, Clone, Default)]
    pub struct LogStats {
        pub total_entries: u64,
        pub debug_count: u64,
        pub info_count: u64,
        pub warn_count: u64,
        pub error_count: u64,
        pub dropped_count: u64,
        pub ring_usage: usize,
    }
}

pub mod metrics {
    //! Metrics for the logging subsystem.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};
    use super::types::LogLevel;

    #[derive(Debug, Default)]
    pub struct LogMetrics {
        pub total_entries: AtomicU64,
        pub debug_count: AtomicU64,
        pub info_count: AtomicU64,
        pub warn_count: AtomicU64,
        pub error_count: AtomicU64,
        pub dropped_count: AtomicU64,
        pub persist_failures: AtomicU64,
    }

    impl LogMetrics {
        pub fn inc_level(&self, level: LogLevel) {
            self.total_entries.fetch_add(1, Ordering::Relaxed);
            match level {
                LogLevel::Debug => self.debug_count.fetch_add(1, Ordering::Relaxed),
                LogLevel::Info => self.info_count.fetch_add(1, Ordering::Relaxed),
                LogLevel::Warn => self.warn_count.fetch_add(1, Ordering::Relaxed),
                LogLevel::Error => self.error_count.fetch_add(1, Ordering::Relaxed),
            };
        }

        pub fn inc_dropped(&self) {
            self.dropped_count.fetch_add(1, Ordering::Relaxed);
        }

        pub fn inc_persist_failure(&self) {
            self.persist_failures.fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> LogMetricsSnapshot {
            LogMetricsSnapshot {
                total_entries: self.total_entries.load(Ordering::Relaxed),
                debug_count: self.debug_count.load(Ordering::Relaxed),
                info_count: self.info_count.load(Ordering::Relaxed),
                warn_count: self.warn_count.load(Ordering::Relaxed),
                error_count: self.error_count.load(Ordering::Relaxed),
                dropped_count: self.dropped_count.load(Ordering::Relaxed),
                persist_failures: self.persist_failures.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct LogMetricsSnapshot {
        pub total_entries: u64,
        pub debug_count: u64,
        pub info_count: u64,
        pub warn_count: u64,
        pub error_count: u64,
        pub dropped_count: u64,
        pub persist_failures: u64,
    }
}

pub mod ring {
    //! Ring buffer for log entries.
    use super::{
        config::LogConfig,
        error::{LogError, LogResult},
        types::LogEntry,
        metrics::LogMetrics,
    };
    use alloc::collections::VecDeque;
    use spin::Mutex;

    /// Ring buffer for log entries.
    pub struct LogRing {
        inner: Mutex<VecDeque<LogEntry>>,
        capacity: usize,
    }

    impl LogRing {
        pub fn new(config: &LogConfig) -> Self {
            Self {
                inner: Mutex::new(VecDeque::with_capacity(config.ring_capacity)),
                capacity: config.ring_capacity,
            }
        }

        /// Push an entry, dropping oldest if full.
        pub fn push(&self, entry: LogEntry, metrics: &LogMetrics) -> LogResult<()> {
            let mut ring = self.inner.lock();
            if ring.len() >= self.capacity {
                ring.pop_front();
                metrics.inc_dropped();
            }
            ring.push_back(entry);
            Ok(())
        }

        /// Dump all entries as a string.
        pub fn dump(&self, max_bytes: usize, timestamps: bool) -> String {
            let ring = self.inner.lock();
            let mut out = String::new();
            for entry in ring.iter() {
                let line = if timestamps {
                    format!("[{:>8}ms]{}{}\n", entry.ts_ms, entry.level.prefix(), entry.msg)
                } else {
                    format!("{}{}\n", entry.level.prefix(), entry.msg)
                };
                if out.len() + line.len() > max_bytes {
                    break;
                }
                out.push_str(&line);
            }
            out
        }

        /// Get the number of entries.
        pub fn len(&self) -> usize {
            self.inner.lock().len()
        }

        /// Check if the ring is empty.
        pub fn is_empty(&self) -> bool {
            self.inner.lock().is_empty()
        }

        /// Clear the ring.
        pub fn clear(&self) {
            self.inner.lock().clear();
        }

        /// Get statistics.
        pub fn stats(&self) -> super::types::LogStats {
            let ring = self.inner.lock();
            let mut stats = super::types::LogStats::default();
            stats.ring_usage = ring.len();
            for entry in ring.iter() {
                stats.total_entries += 1;
                match entry.level {
                    super::types::LogLevel::Debug => stats.debug_count += 1,
                    super::types::LogLevel::Info => stats.info_count += 1,
                    super::types::LogLevel::Warn => stats.warn_count += 1,
                    super::types::LogLevel::Error => stats.error_count += 1,
                }
            }
            stats
        }
    }
}

pub mod writer {
    //! Output writers: serial and filesystem.
    use super::{
        config::LogConfig,
        types::LogEntry,
        metrics::LogMetrics,
    };
    use crate::serial_println;
    use core::fmt::Write;

    /// Writer for serial output.
    pub struct SerialWriter;

    impl SerialWriter {
        pub fn write(entry: &LogEntry, config: &LogConfig) {
            if !config.log_serial {
                return;
            }
            if config.log_timestamps {
                serial_println!("[{:>8}ms]{}{}", entry.ts_ms, entry.level.prefix(), entry.msg);
            } else {
                serial_println!("{}{}", entry.level.prefix(), entry.msg);
            }
        }
    }

    /// Writer for persistent filesystem storage.
    pub struct FsWriter;

    impl FsWriter {
        pub fn write(entry: &LogEntry, config: &LogConfig, metrics: &LogMetrics) {
            if !config.persist_errors || entry.level != super::types::LogLevel::Error {
                return;
            }
            let line = if config.log_timestamps {
                format!("[{:>8}ms]{}{}\n", entry.ts_ms, entry.level.prefix(), entry.msg)
            } else {
                format!("{}{}\n", entry.level.prefix(), entry.msg)
            };
            if let Err(e) = crate::fs::ionafs::append(&config.persist_path, line.as_bytes()) {
                // Use a counter to avoid log spam.
                metrics.inc_persist_failure();
                // Fallback: try to write once more; if still fails, ignore.
                let _ = crate::fs::ionafs::append(&config.persist_path, line.as_bytes());
            }
        }
    }
}

pub mod manager {
    //! Centralised log manager.
    use super::{
        config::LogConfig,
        error::{LogError, LogResult},
        types::{LogLevel, LogEntry, LogStats},
        metrics::LogMetrics,
        ring::LogRing,
        writer::{SerialWriter, FsWriter},
    };
    use spin::RwLock;
    use core::sync::atomic::Ordering;

    /// Manager for the logging subsystem.
    pub struct LogManager {
        config: LogConfig,
        ring: LogRing,
        metrics: LogMetrics,
        min_level: RwLock<LogLevel>,
        initialised: bool,
    }

    impl LogManager {
        pub fn new(config: LogConfig) -> Self {
            config.validate().expect("invalid LogConfig");
            let ring = LogRing::new(&config);
            Self {
                config,
                ring,
                metrics: LogMetrics::default(),
                min_level: RwLock::new(config.min_level),
                initialised: false,
            }
        }

        pub fn default() -> Self {
            Self::new(LogConfig::default())
        }

        pub fn init(&mut self) {
            self.initialised = true;
            info!("logging subsystem initialised");
        }

        pub fn config(&self) -> &LogConfig {
            &self.config
        }

        pub fn metrics(&self) -> &LogMetrics {
            &self.metrics
        }

        /// Set the minimum log level.
        pub fn set_min_level(&self, level: LogLevel) {
            *self.min_level.write() = level;
        }

        /// Get the minimum log level.
        pub fn min_level(&self) -> LogLevel {
            *self.min_level.read()
        }

        /// Log a message at a given level.
        pub fn log(&self, level: LogLevel, msg: &str) -> LogResult<()> {
            if level < self.min_level() {
                return Ok(());
            }
            let ts = crate::arch::x86_64::timer::uptime_ms();
            let entry = LogEntry {
                level,
                ts_ms: ts,
                msg: msg.to_string(),
            };

            // Write to serial.
            SerialWriter::write(&entry, &self.config);

            // Store in ring buffer.
            self.ring.push(entry.clone(), &self.metrics)?;

            // Persist errors to filesystem.
            FsWriter::write(&entry, &self.config, &self.metrics);

            self.metrics.inc_level(level);
            Ok(())
        }

        /// Dump the ring buffer as a string.
        pub fn dump(&self, max_bytes: usize) -> String {
            self.ring.dump(max_bytes, self.config.log_timestamps)
        }

        /// Get the number of entries in the ring.
        pub fn entry_count(&self) -> usize {
            self.ring.len()
        }

        /// Clear the ring buffer.
        pub fn clear(&self) {
            self.ring.clear();
        }

        /// Get statistics.
        pub fn stats(&self) -> LogStats {
            self.ring.stats()
        }

        /// Get metrics snapshot.
        pub fn metrics_snapshot(&self) -> super::metrics::LogMetricsSnapshot {
            self.metrics.snapshot()
        }

        /// Reset metrics.
        pub fn reset_metrics(&self) {
            *self.metrics = LogMetrics::default();
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::LogConfig;
pub use error::{LogError, LogResult};
pub use types::{LogLevel, LogEntry, LogStats};
pub use metrics::{LogMetrics, LogMetricsSnapshot};
pub use manager::LogManager;

// -----------------------------------------------------------------------------
// Legacy global API (backward compatibility)
// -----------------------------------------------------------------------------

use spin::Once;

static GLOBAL_MANAGER: Once<LogManager> = Once::new();

/// Get the global manager (initialises with defaults if not yet set).
fn global_manager() -> &'static LogManager {
    GLOBAL_MANAGER.get_or_init(|| {
        let mut mgr = LogManager::new(LogConfig::default());
        mgr.init();
        mgr
    })
}

/// Set the minimum log level (legacy).
pub fn set_level(level: LogLevel) {
    global_manager().set_min_level(level);
}

/// Log a message at a given level (legacy).
pub fn klog(level: LogLevel, msg: &str) {
    let _ = global_manager().log(level, msg);
}

/// Dump the ring buffer to a string (legacy).
pub fn drain_to_string(max_bytes: usize) -> String {
    global_manager().dump(max_bytes)
}

/// Get the number of entries in the ring (legacy).
pub fn entry_count() -> usize {
    global_manager().entry_count()
}

/// Clear the ring buffer (legacy).
pub fn clear_logs() {
    global_manager().clear();
}

/// Get statistics (legacy).
pub fn log_stats() -> LogStats {
    global_manager().stats()
}

/// Get metrics snapshot (legacy).
pub fn log_metrics() -> LogMetricsSnapshot {
    global_manager().metrics_snapshot()
}

// -----------------------------------------------------------------------------
// Macros (backward compatible)
// -----------------------------------------------------------------------------

#[macro_export]
macro_rules! kinfo {
    ($($arg:tt)*) => {
        $crate::io::klog::klog($crate::io::klog::LogLevel::Info, &alloc::format!($($arg)*));
    };
}

#[macro_export]
macro_rules! kwarn {
    ($($arg:tt)*) => {
        $crate::io::klog::klog($crate::io::klog::LogLevel::Warn, &alloc::format!($($arg)*));
    };
}

#[macro_export]
macro_rules! kerr {
    ($($arg:tt)*) => {
        $crate::io::klog::klog($crate::io::klog::LogLevel::Error, &alloc::format!($($arg)*));
    };
}

#[macro_export]
macro_rules! kdebug {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        $crate::io::klog::klog($crate::io::klog::LogLevel::Debug, &alloc::format!($($arg)*));
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn reset_manager() {
        // Force reinitialisation for tests.
        // Since Once doesn't allow reinit, we just use the manager directly in tests.
        // We'll create a fresh manager.
    }

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
    }

    #[test]
    fn test_log_level_prefix() {
        assert_eq!(LogLevel::Debug.prefix(), "[DBG] ");
        assert_eq!(LogLevel::Error.prefix(), "[ERR] ");
    }

    #[test]
    fn test_ring_basic() {
        let config = LogConfig {
            ring_capacity: 3,
            ..Default::default()
        };
        let manager = LogManager::new(config);
        manager.init();

        manager.log(LogLevel::Info, "msg1").unwrap();
        manager.log(LogLevel::Info, "msg2").unwrap();
        manager.log(LogLevel::Info, "msg3").unwrap();

        assert_eq!(manager.entry_count(), 3);
        let dump = manager.dump(1024);
        assert!(dump.contains("msg1"));
        assert!(dump.contains("msg2"));
        assert!(dump.contains("msg3"));

        // Overflow: oldest dropped.
        manager.log(LogLevel::Info, "msg4").unwrap();
        assert_eq!(manager.entry_count(), 3);
        let dump2 = manager.dump(1024);
        assert!(!dump2.contains("msg1"));
        assert!(dump2.contains("msg2"));
        assert!(dump2.contains("msg3"));
        assert!(dump2.contains("msg4"));
    }

    #[test]
    fn test_min_level_filtering() {
        let config = LogConfig {
            min_level: LogLevel::Warn,
            ..Default::default()
        };
        let manager = LogManager::new(config);
        manager.init();

        manager.log(LogLevel::Info, "info").unwrap();
        manager.log(LogLevel::Warn, "warn").unwrap();
        manager.log(LogLevel::Error, "error").unwrap();

        let dump = manager.dump(1024);
        assert!(!dump.contains("info"));
        assert!(dump.contains("warn"));
        assert!(dump.contains("error"));
    }

    #[test]
    fn test_metrics() {
        let config = LogConfig::default();
        let manager = LogManager::new(config);
        manager.init();

        manager.log(LogLevel::Info, "test").unwrap();
        manager.log(LogLevel::Error, "err").unwrap();

        let snap = manager.metrics_snapshot();
        assert_eq!(snap.total_entries, 2);
        assert_eq!(snap.info_count, 1);
        assert_eq!(snap.error_count, 1);
    }

    #[test]
    fn test_config_validation() {
        let config = LogConfig::default();
        assert!(config.validate().is_ok());

        let mut bad = config.clone();
        bad.ring_capacity = 0;
        assert!(bad.validate().is_err());

        let mut bad2 = config;
        bad2.persist_path = "";
        assert!(bad2.validate().is_err());
    }
}
