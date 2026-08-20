//! I/O subsystem — serial, framebuffer, font, console.
//!
//! This module provides the core I/O facilities for the kernel:
//! - **Serial**: early boot logging and debug output.
//! - **Framebuffer**: double-buffered display with dirty-rect optimisation.
//! - **Font**: bitmap font rendering for the framebuffer.
//! - **Console**: text console on top of the framebuffer.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                           I/O Manager                                  │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   Config    │    Error     │    Metrics    │         Types            │
//! │ (IoConfig)  │ (IoError)    │ (IoMetrics)   │ (Stats, Level)           │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   Serial    │  Framebuffer │     Font      │         Console          │
//! │ (serial)    │ (framebuffer)│ (font)        │ (console)                │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   Manager   │    Legacy    │               │                          │
//! │ (IoManager) │ (global fns) │               │                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::io::{IoManager, IoConfig};
//!
//! let config = IoConfig::default();
//! let manager = IoManager::new(config);
//! manager.init(fb);
//! manager.serial().write("Hello, world!");
//! ```

#![allow(dead_code)]

// -----------------------------------------------------------------------------
// Submodule declarations
// -----------------------------------------------------------------------------

pub mod serial;
pub mod framebuffer;
pub mod font;
pub mod console;

// -----------------------------------------------------------------------------
// Re‑exports of all important types and functions from submodules
// -----------------------------------------------------------------------------

pub use serial::{SerialPort, COM1};
pub use framebuffer::{
    init as fb_init, present, present_full, mark_dirty, mark_all_dirty,
    set_pixel, fill_rect, clear, draw_text_col, draw_rect,
    hline, vline, blit_mask, blit_pixels, draw_cursor, erase_cursor,
    draw_boot_splash, draw_logo,
    width, height, size,
    CURSOR_W, CURSOR_H,
};
pub use font::{
    FONT_WIDTH, FONT_HEIGHT, get_glyph, render_char, render_string,
    CURSOR_MASK, CURSOR_OUTLINE,
};
pub use console::{
    Console, init_console, clear_screen, putchar, puts, print,
    set_color, set_cursor_pos, get_cursor_pos,
};

// -----------------------------------------------------------------------------
// Inline submodules for the manager
// -----------------------------------------------------------------------------

mod config {
    //! Configuration for the I/O subsystem.
    use serde::{Deserialize, Serialize};

    /// Configuration for the I/O subsystem.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct IoConfig {
        pub serial_enabled: bool,
        pub framebuffer_enabled: bool,
        pub console_enabled: bool,
        pub collect_metrics: bool,
        pub log_operations: bool,
        pub default_console_color: u32,
    }

    impl Default for IoConfig {
        fn default() -> Self {
            Self {
                serial_enabled: true,
                framebuffer_enabled: true,
                console_enabled: true,
                collect_metrics: true,
                log_operations: false,
                default_console_color: 0xFFFFFF,
            }
        }
    }

    impl IoConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            Ok(())
        }

        pub fn with_metrics(mut self) -> Self {
            self.collect_metrics = true;
            self
        }
    }
}

mod error {
    //! Error types for I/O operations.
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum IoError {
        #[error("serial port error: {0}")]
        Serial(String),

        #[error("framebuffer error: {0}")]
        Framebuffer(String),

        #[error("console error: {0}")]
        Console(String),

        #[error("configuration error: {0}")]
        Config(String),
    }

    pub type IoResult<T> = Result<T, IoError>;
}

mod metrics {
    //! Metrics for the I/O subsystem.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct IoMetrics {
        pub serial_writes: AtomicU64,
        pub framebuffer_presents: AtomicU64,
        pub console_chars: AtomicU64,
        pub console_lines: AtomicU64,
        pub draw_calls: AtomicU64,
    }

    impl IoMetrics {
        pub fn inc_serial_write(&self) {
            self.serial_writes.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_fb_present(&self) {
            self.framebuffer_presents.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_console_char(&self) {
            self.console_chars.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_console_line(&self) {
            self.console_lines.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_draw_call(&self) {
            self.draw_calls.fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> IoMetricsSnapshot {
            IoMetricsSnapshot {
                serial_writes: self.serial_writes.load(Ordering::Relaxed),
                framebuffer_presents: self.framebuffer_presents.load(Ordering::Relaxed),
                console_chars: self.console_chars.load(Ordering::Relaxed),
                console_lines: self.console_lines.load(Ordering::Relaxed),
                draw_calls: self.draw_calls.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct IoMetricsSnapshot {
        pub serial_writes: u64,
        pub framebuffer_presents: u64,
        pub console_chars: u64,
        pub console_lines: u64,
        pub draw_calls: u64,
    }
}

mod manager {
    //! Centralised manager for the I/O subsystem.
    use super::{
        config::IoConfig,
        error::{IoError, IoResult},
        metrics::IoMetrics,
        serial, framebuffer, console,
    };
    use bootloader_api::info::FrameBuffer;
    use core::sync::atomic::Ordering;
    use tracing::{debug, info, warn};

    /// Manager for the I/O subsystem.
    pub struct IoManager {
        config: IoConfig,
        metrics: IoMetrics,
        initialised: bool,
    }

    impl IoManager {
        /// Create a new I/O manager with the given configuration.
        pub fn new(config: IoConfig) -> Self {
            config.validate().expect("invalid IoConfig");
            Self {
                config,
                metrics: IoMetrics::default(),
                initialised: false,
            }
        }

        /// Create a manager with default configuration.
        pub fn default() -> Self {
            Self::new(IoConfig::default())
        }

        /// Get the configuration.
        pub fn config(&self) -> &IoConfig {
            &self.config
        }

        /// Get the metrics.
        pub fn metrics(&self) -> &IoMetrics {
            &self.metrics
        }

        /// Initialise the I/O subsystem.
        ///
        /// # Arguments
        /// * `fb` – Optional framebuffer from the bootloader.
        pub fn init(&mut self, fb: Option<&'static mut FrameBuffer>) -> IoResult<()> {
            if self.initialised {
                warn!("I/O subsystem already initialised");
                return Ok(());
            }

            if self.config.serial_enabled {
                // Serial is already initialised by the bootloader; we just log.
                info!("serial output enabled");
            }

            if let Some(fb) = fb {
                if self.config.framebuffer_enabled {
                    framebuffer::init(fb);
                    info!("framebuffer initialised ({}x{})", framebuffer::width(), framebuffer::height());
                }
                if self.config.console_enabled {
                    console::init_console();
                    info!("console initialised");
                }
            } else {
                info!("no framebuffer provided; console disabled");
            }

            self.initialised = true;
            info!("I/O subsystem initialised");
            Ok(())
        }

        /// Check if the I/O subsystem is initialised.
        pub fn is_initialised(&self) -> bool {
            self.initialised
        }

        /// Get a metrics snapshot.
        pub fn metrics_snapshot(&self) -> super::metrics::IoMetricsSnapshot {
            self.metrics.snapshot()
        }

        /// Reset metrics.
        pub fn reset_metrics(&self) {
            self.metrics = IoMetrics::default();
        }

        /// Write to serial (if enabled).
        pub fn serial_write(&self, s: &str) {
            if self.config.serial_enabled {
                serial::COM1.write(s);
                self.metrics.inc_serial_write();
            }
        }

        /// Present the framebuffer (if enabled).
        pub fn present(&self) {
            if self.config.framebuffer_enabled {
                framebuffer::present();
                self.metrics.inc_fb_present();
            }
        }

        /// Present full (force full blit).
        pub fn present_full(&self) {
            if self.config.framebuffer_enabled {
                framebuffer::present_full();
                self.metrics.inc_fb_present();
            }
        }

        /// Print a character to the console (if enabled).
        pub fn putchar(&self, c: char) {
            if self.config.console_enabled {
                console::putchar(c);
                self.metrics.inc_console_char();
            }
        }

        /// Print a string to the console (if enabled).
        pub fn puts(&self, s: &str) {
            for c in s.chars() {
                self.putchar(c);
            }
        }

        /// Print to the console with formatting (if enabled).
        pub fn print(&self, args: core::fmt::Arguments<'_>) {
            if self.config.console_enabled {
                // We need to format to a string; we'll use alloc::format!.
                // But we want to avoid allocation if possible; we'll use a simple loop.
                // For simplicity, we'll use the console's print function which already handles formatting.
                // The console module already provides `print!` macro; we'll just call that.
                // However, we're inside a method; we can't use the macro directly.
                // We'll forward to the console's print function.
                console::print_args(args);
            }
        }

        /// Clear the console (if enabled).
        pub fn clear_console(&self) {
            if self.config.console_enabled {
                console::clear_screen();
            }
        }

        /// Reset the I/O subsystem (for testing).
        #[cfg(test)]
        pub fn reset(&mut self) {
            self.initialised = false;
            self.metrics = IoMetrics::default();
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::IoConfig;
pub use error::{IoError, IoResult};
pub use metrics::{IoMetrics, IoMetricsSnapshot};
pub use manager::IoManager;

// -----------------------------------------------------------------------------
// Legacy global API (backward compatibility)
// -----------------------------------------------------------------------------

use spin::Once;

static GLOBAL_MANAGER: Once<IoManager> = Once::new();

/// Get the global manager (initialises with defaults if not yet set).
fn global_manager() -> &'static IoManager {
    GLOBAL_MANAGER.get_or_init(|| IoManager::default())
}

/// Initialise the global I/O manager (legacy).
pub fn init(fb: Option<&'static mut FrameBuffer>) {
    let manager = global_manager();
    // We need mutable access to call init; we'll use a workaround with a static Mutex.
    // For simplicity, we'll just call the legacy init functions directly.
    // The original init function in mod.rs called submodule inits.
    // We'll keep the original init behavior.
    // Since the original init wasn't defined in this file, we'll assume the user
    // calls fb_init and console_init separately.
    // We'll just set up the manager with default config.
    // The manager is already initialised with default config.
    // We'll just log.
    if let Some(fb) = fb {
        framebuffer::init(fb);
        console::init_console();
    }
    crate::serial_println!("[IO] I/O subsystem initialised");
}

/// Write to serial (legacy).
pub fn serial_write(s: &str) {
    global_manager().serial_write(s);
}

/// Present framebuffer (legacy).
pub fn fb_present() {
    global_manager().present();
}

/// Present full (legacy).
pub fn fb_present_full() {
    global_manager().present_full();
}

/// Put a character on the console (legacy).
pub fn console_putchar(c: char) {
    global_manager().putchar(c);
}

/// Put a string on the console (legacy).
pub fn console_puts(s: &str) {
    global_manager().puts(s);
}

/// Print formatted arguments to the console (legacy).
pub fn console_print(args: core::fmt::Arguments<'_>) {
    global_manager().print(args);
}

/// Clear the console (legacy).
pub fn console_clear() {
    global_manager().clear_console();
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let config = IoConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_metrics() {
        let metrics = IoMetrics::default();
        metrics.inc_serial_write();
        metrics.inc_fb_present();
        let snap = metrics.snapshot();
        assert_eq!(snap.serial_writes, 1);
        assert_eq!(snap.framebuffer_presents, 1);
    }

    #[test]
    fn test_manager_creation() {
        let config = IoConfig::default();
        let manager = IoManager::new(config);
        assert!(!manager.is_initialised());
        // We can't easily init without a framebuffer, but we can test the config.
        assert_eq!(manager.config().serial_enabled, true);
    }
}
