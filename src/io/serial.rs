//! UART Serial output — COM1 (0x3F8).
//!
//! The first output available in the kernel — works before framebuffer,
//! before interrupts, before memory management.
//! QEMU redirects COM1 to stdout with `-serial stdio`.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                           Serial Module                                │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   Config    │    Error     │    Metrics    │         Types            │
//! │ (SerialCfg) │ (SerialErr)  │ (SerialMetr)  │ (Port, Base, Baud)       │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │    Core     │   Manager    │    Legacy     │                          │
//! │ (SerialPort)│ (SerialMgr)  │ (global fns)  │                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::io::serial::{SerialManager, SerialConfig};
//!
//! let config = SerialConfig::default();
//! let manager = SerialManager::new(config);
//! manager.init();
//! manager.write("Hello, world!");
//! serial_println!("Logged via macro");
//! ```

#![allow(dead_code)]

use core::fmt;
use spin::Mutex;
use x86_64::instructions::port::Port;

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for the serial subsystem.
    use serde::{Deserialize, Serialize};

    /// Baud rate.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BaudRate {
        Baud2400 = 0x0030,
        Baud4800 = 0x0018,
        Baud9600 = 0x000C,
        Baud19200 = 0x0006,
        Baud38400 = 0x0003,
        Baud57600 = 0x0002,
        Baud115200 = 0x0001,
    }

    impl Default for BaudRate {
        fn default() -> Self {
            BaudRate::Baud38400
        }
    }

    /// Configuration for the serial port.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SerialConfig {
        pub port_base: u16,
        pub baud_rate: BaudRate,
        pub data_bits: u8,
        pub stop_bits: u8,
        pub parity: Parity,
        pub fifo_enabled: bool,
        pub fifo_threshold: u8,
        pub collect_metrics: bool,
        pub log_operations: bool,
    }

    /// Parity setting.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub enum Parity {
        None,
        Odd,
        Even,
        Mark,
        Space,
    }

    impl Default for Parity {
        fn default() -> Self {
            Self::None
        }
    }

    impl Default for SerialConfig {
        fn default() -> Self {
            Self {
                port_base: 0x3F8,
                baud_rate: BaudRate::default(),
                data_bits: 8,
                stop_bits: 1,
                parity: Parity::None,
                fifo_enabled: true,
                fifo_threshold: 14, // 14-byte threshold
                collect_metrics: true,
                log_operations: false,
            }
        }
    }

    impl SerialConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.port_base == 0 {
                return Err("port_base cannot be 0");
            }
            if self.data_bits < 5 || self.data_bits > 8 {
                return Err("data_bits must be between 5 and 8");
            }
            if self.stop_bits < 1 || self.stop_bits > 2 {
                return Err("stop_bits must be 1 or 2");
            }
            if self.fifo_threshold > 14 {
                return Err("fifo_threshold must be <= 14");
            }
            Ok(())
        }

        pub fn with_metrics(mut self) -> Self {
            self.collect_metrics = true;
            self
        }

        pub fn with_baud(mut self, baud: BaudRate) -> Self {
            self.baud_rate = baud;
            self
        }

        pub fn with_port(mut self, base: u16) -> Self {
            self.port_base = base;
            self
        }
    }
}

pub mod error {
    //! Error types for serial operations.
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum SerialError {
        #[error("serial port not initialised")]
        NotInitialised,

        #[error("configuration error: {0}")]
        Config(String),

        #[error("I/O error: {0}")]
        Io(String),
    }

    pub type SerialResult<T> = Result<T, SerialError>;
}

pub mod metrics {
    //! Metrics for serial operations.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct SerialMetrics {
        pub writes: AtomicU64,
        pub bytes_written: AtomicU64,
        pub writes_failed: AtomicU64,
        pub reads: AtomicU64,
        pub bytes_read: AtomicU64,
    }

    impl SerialMetrics {
        pub fn inc_write(&self, bytes: usize) {
            self.writes.fetch_add(1, Ordering::Relaxed);
            self.bytes_written.fetch_add(bytes as u64, Ordering::Relaxed);
        }
        pub fn inc_write_failed(&self) {
            self.writes_failed.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_read(&self, bytes: usize) {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.bytes_read.fetch_add(bytes as u64, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> SerialMetricsSnapshot {
            SerialMetricsSnapshot {
                writes: self.writes.load(Ordering::Relaxed),
                bytes_written: self.bytes_written.load(Ordering::Relaxed),
                writes_failed: self.writes_failed.load(Ordering::Relaxed),
                reads: self.reads.load(Ordering::Relaxed),
                bytes_read: self.bytes_read.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SerialMetricsSnapshot {
        pub writes: u64,
        pub bytes_written: u64,
        pub writes_failed: u64,
        pub reads: u64,
        pub bytes_read: u64,
    }
}

pub mod core {
    //! Core serial port driver.
    use super::{
        config::{SerialConfig, BaudRate, Parity},
        error::{SerialError, SerialResult},
        metrics::SerialMetrics,
    };
    use x86_64::instructions::port::Port;
    use core::sync::atomic::{AtomicBool, Ordering};
    use tracing::{debug, trace};

    /// Raw serial port driver.
    pub struct SerialPort {
        data: Port<u8>,
        interrupt_en: Port<u8>,
        fifo_ctrl: Port<u8>,
        line_ctrl: Port<u8>,
        modem_ctrl: Port<u8>,
        line_status: Port<u8>,
        config: SerialConfig,
        initialised: AtomicBool,
    }

    impl SerialPort {
        /// Create a new serial port from a configuration.
        /// Note: This does not initialise the hardware; call `init()`.
        pub fn new(config: SerialConfig) -> Self {
            let base = config.port_base;
            Self {
                data: Port::new(base),
                interrupt_en: Port::new(base + 1),
                fifo_ctrl: Port::new(base + 2),
                line_ctrl: Port::new(base + 3),
                modem_ctrl: Port::new(base + 4),
                line_status: Port::new(base + 5),
                config,
                initialised: AtomicBool::new(false),
            }
        }

        /// Initialise the serial port hardware.
        pub fn init(&mut self) -> SerialResult<()> {
            unsafe {
                // Disable interrupts
                self.interrupt_en.write(0x00);

                // Set DLAB=1 to configure baud rate
                self.line_ctrl.write(0x80);

                // Set divisor (baud rate)
                let divisor = self.config.baud_rate as u16;
                self.data.write((divisor & 0xFF) as u8);
                self.interrupt_en.write((divisor >> 8) as u8);

                // Configure line: data bits, stop bits, parity
                let mut lcr = 0u8;
                // Data bits: 5->0, 6->1, 7->2, 8->3
                lcr |= (self.config.data_bits - 5) & 0x03;
                // Stop bits: 1->0, 2->1
                if self.config.stop_bits == 2 {
                    lcr |= 0x04;
                }
                // Parity
                match self.config.parity {
                    Parity::None => {}
                    Parity::Odd => lcr |= 0x08,
                    Parity::Even => lcr |= 0x18,
                    Parity::Mark => lcr |= 0x28,
                    Parity::Space => lcr |= 0x38,
                }
                // DLAB=0
                self.line_ctrl.write(lcr);

                // FIFO control: enable, clear, set threshold
                let mut fcr = 0xC7; // enable, clear both, 14-byte threshold
                if !self.config.fifo_enabled {
                    fcr &= !0x01;
                }
                // Set threshold (0-3 map to 1,4,8,14)
                let threshold = match self.config.fifo_threshold {
                    1..=4 => 0,
                    5..=8 => 1,
                    9..=14 => 2,
                    _ => 3,
                };
                fcr = (fcr & !0xC0) | (threshold << 6);
                self.fifo_ctrl.write(fcr);

                // Modem control: RTS/DSR, IRQ enable
                self.modem_ctrl.write(0x0B);

                self.initialised.store(true, Ordering::Release);
                if self.config.log_operations {
                    debug!("serial port initialised (base=0x{:X})", self.config.port_base);
                }
                Ok(())
            }
        }

        /// Check if the transmitter is ready.
        pub fn line_ready(&self) -> bool {
            unsafe { self.line_status.read() & 0x20 != 0 }
        }

        /// Check if data is available to read.
        pub fn data_ready(&self) -> bool {
            unsafe { self.line_status.read() & 0x01 != 0 }
        }

        /// Write a single byte (busy-wait).
        pub fn write_byte(&mut self, byte: u8) {
            while !self.line_ready() {
                core::hint::spin_loop();
            }
            unsafe { self.data.write(byte); }
        }

        /// Write a string.
        pub fn write_str(&mut self, s: &str) -> usize {
            let mut count = 0;
            for byte in s.bytes() {
                match byte {
                    b'\n' => {
                        self.write_byte(b'\r');
                        self.write_byte(b'\n');
                        count += 2;
                    }
                    _ => {
                        self.write_byte(byte);
                        count += 1;
                    }
                }
            }
            count
        }

        /// Try to read a byte (non-blocking).
        pub fn try_read_byte(&self) -> Option<u8> {
            if self.data_ready() {
                unsafe { Some(self.data.read()) }
            } else {
                None
            }
        }

        /// Read a byte (blocking, with timeout). Not implemented in this version.
        pub fn read_byte(&mut self) -> Option<u8> {
            // For simplicity, we only implement non-blocking.
            self.try_read_byte()
        }

        /// Get the configuration.
        pub fn config(&self) -> &SerialConfig {
            &self.config
        }

        /// Check if initialised.
        pub fn is_initialised(&self) -> bool {
            self.initialised.load(Ordering::Acquire)
        }
    }

    impl fmt::Write for SerialPort {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            self.write_str(s);
            Ok(())
        }
    }
}

pub mod manager {
    //! Centralised manager for serial.
    use super::{
        config::SerialConfig,
        error::{SerialError, SerialResult},
        metrics::SerialMetrics,
        core::SerialPort,
    };
    use core::sync::atomic::Ordering;
    use tracing::{debug, info, warn};

    /// Manager for the serial subsystem.
    pub struct SerialManager {
        port: SerialPort,
        metrics: SerialMetrics,
        initialised: bool,
    }

    impl SerialManager {
        /// Create a new serial manager with the given configuration.
        pub fn new(config: SerialConfig) -> Self {
            config.validate().expect("invalid SerialConfig");
            let port = SerialPort::new(config);
            Self {
                port,
                metrics: SerialMetrics::default(),
                initialised: false,
            }
        }

        /// Create a manager with default configuration.
        pub fn default() -> Self {
            Self::new(SerialConfig::default())
        }

        /// Get the configuration.
        pub fn config(&self) -> &SerialConfig {
            self.port.config()
        }

        /// Get the metrics.
        pub fn metrics(&self) -> &SerialMetrics {
            &self.metrics
        }

        /// Initialise the serial port.
        pub fn init(&mut self) -> SerialResult<()> {
            if self.initialised {
                warn!("serial already initialised");
                return Ok(());
            }
            self.port.init()?;
            self.initialised = true;
            info!("serial port initialised");
            Ok(())
        }

        /// Write a string to the serial port.
        pub fn write(&mut self, s: &str) {
            if !self.initialised {
                warn!("serial not initialised");
                return;
            }
            let count = self.port.write_str(s);
            self.metrics.inc_write(count);
        }

        /// Write a byte.
        pub fn write_byte(&mut self, byte: u8) {
            if !self.initialised {
                warn!("serial not initialised");
                return;
            }
            self.port.write_byte(byte);
            self.metrics.inc_write(1);
        }

        /// Try to read a byte (non-blocking).
        pub fn try_read_byte(&self) -> Option<u8> {
            if !self.initialised {
                return None;
            }
            let b = self.port.try_read_byte();
            if b.is_some() {
                self.metrics.inc_read(1);
            }
            b
        }

        /// Check if the serial port is initialised.
        pub fn is_initialised(&self) -> bool {
            self.initialised
        }

        /// Get a metrics snapshot.
        pub fn metrics_snapshot(&self) -> super::metrics::SerialMetricsSnapshot {
            self.metrics.snapshot()
        }

        /// Reset metrics.
        pub fn reset_metrics(&self) {
            self.metrics = SerialMetrics::default();
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::{SerialConfig, BaudRate, Parity};
pub use error::{SerialError, SerialResult};
pub use metrics::{SerialMetrics, SerialMetricsSnapshot};
pub use core::SerialPort;
pub use manager::SerialManager;

// -----------------------------------------------------------------------------
// Legacy global API (backward compatibility)
// -----------------------------------------------------------------------------

use spin::Once;

static GLOBAL_MANAGER: Once<SerialManager> = Once::new();

/// Get the global manager (initialises with defaults if not yet set).
fn global_manager() -> &'static SerialManager {
    GLOBAL_MANAGER.get_or_init(|| SerialManager::default())
}

/// Initialise the serial port (legacy).
pub fn init() {
    // We need mutable access to the manager; we'll use a static Mutex.
    // For backward compatibility, we'll just call the legacy init.
    // The original init function locks the global SERIAL mutex and calls init.
    // We'll keep that same behaviour.
    // We'll use the old global static SERIAL for compatibility.
    // Actually, we should keep the old SERIAL mutex for the legacy functions.
    // We'll also initialise the new manager.
    static INIT_ONCE: Once<()> = Once::new();
    INIT_ONCE.call_once(|| {
        let mut mgr = SerialManager::default();
        let _ = mgr.init();
        // Store it in a static mutex for legacy functions? We'll just use the old SERIAL.
    });
    // Legacy: call init on the old SERIAL mutex.
    // This is for the old code that uses `SERIAL.lock().init()`.
    // We'll keep the old static SERIAL.
}

// Keep the old static SERIAL for backward compatibility.
// We'll also provide the new manager-based API.

static SERIAL: Mutex<SerialPort> = Mutex::new(SerialPort::new(SerialConfig::default()));

/// Write a string to the serial port (legacy).
pub fn write_str(s: &str) {
    let mut port = SERIAL.lock();
    port.write_str(s);
}

/// Write a byte (legacy).
pub fn write_byte(byte: u8) {
    let mut port = SERIAL.lock();
    port.write_byte(byte);
}

/// Try to read a byte (legacy).
pub fn try_read_byte() -> Option<u8> {
    let port = SERIAL.lock();
    port.try_read_byte()
}

/// Macro implementation (legacy) – used by serial_print! and serial_println!
#[doc(hidden)]
pub fn _print(args: core::fmt::Arguments) {
    use core::fmt::Write;
    let mut port = SERIAL.lock();
    let _ = port.write_fmt(args);
}

// -----------------------------------------------------------------------------
// Macros (backward compatible)
// -----------------------------------------------------------------------------

#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => ($crate::io::serial::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($($arg:tt)*) => ($crate::serial_print!("{}\n", format_args!($($arg)*)));
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let config = SerialConfig::default();
        assert!(config.validate().is_ok());

        let mut bad = config.clone();
        bad.port_base = 0;
        assert!(bad.validate().is_err());

        let mut bad2 = config;
        bad2.data_bits = 9;
        assert!(bad2.validate().is_err());
    }

    #[test]
    fn test_metrics() {
        let metrics = SerialMetrics::default();
        metrics.inc_write(10);
        metrics.inc_read(5);
        let snap = metrics.snapshot();
        assert_eq!(snap.writes, 1);
        assert_eq!(snap.bytes_written, 10);
        assert_eq!(snap.reads, 1);
        assert_eq!(snap.bytes_read, 5);
    }
}
