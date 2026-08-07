//! Signal handling — POSIX-style async process notification.
//!
//! Provides reliable signal delivery to tasks with support for:
//! - Standard POSIX signals (SIGHUP, SIGINT, SIGTERM, SIGKILL, etc.)
//! - Per‑task signal handlers (default or custom)
//! - Pending signal bitmasks with atomic updates
//! - Configurable delivery policies and default actions
//! - Metrics for monitoring signal activity
//! - Graceful handling of SIGKILL and SIGSTOP (cannot be caught)
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                           Signal Module                                │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   config    │    error     │     types     │        metrics           │
//! │ (SignalCfg) │ (SignalError)│ (Signal enum) │ (SignalMetrics)          │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   pending   │   handlers   │   delivery    │        manager           │
//! │ (bitmask)   │ (handler map)│ (signal       │ (SignalManager)          │
//! │             │              │  delivery)    │                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::signal::{SignalManager, Signal, SignalConfig};
//!
//! let config = SignalConfig::default();
//! let manager = SignalManager::new(config);
//! manager.send(task_id, Signal::SIGTERM);
//! manager.deliver_pending(task_id);
//! manager.set_handler(task_id, Signal::SIGTERM, handler_addr);
//! ```

#![allow(dead_code)]

use alloc::collections::BTreeMap;
use alloc::string::String;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Lazy, Mutex};
use crate::task::TaskId;

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for signal handling.
    use serde::{Deserialize, Serialize};

    /// Configuration for the signal subsystem.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SignalConfig {
        /// Whether to enable metrics collection.
        pub collect_metrics: bool,
        /// Whether to log signal delivery events.
        pub log_delivery: bool,
        /// Whether to log handler registration.
        pub log_handlers: bool,
        /// Maximum number of pending signals per task (0 = unlimited).
        pub max_pending: usize,
        /// Default action for unhandled signals: 0 = terminate, 1 = ignore.
        pub default_action_terminate: bool,
    }

    impl Default for SignalConfig {
        fn default() -> Self {
            Self {
                collect_metrics: true,
                log_delivery: true,
                log_handlers: false,
                max_pending: 32,
                default_action_terminate: true,
            }
        }
    }

    impl SignalConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            Ok(())
        }

        pub fn with_metrics(mut self) -> Self {
            self.collect_metrics = true;
            self
        }

        pub fn with_logging(mut self) -> Self {
            self.log_delivery = true;
            self.log_handlers = true;
            self
        }
    }
}

pub mod error {
    //! Error types for signal operations.
    use super::types::Signal;
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum SignalError {
        #[error("invalid signal number: {0}")]
        InvalidSignal(u8),

        #[error("signal {sig:?} cannot be caught or ignored")]
        NonCatchable { sig: Signal },

        #[error("task {0} not found")]
        TaskNotFound(TaskId),

        #[error("too many pending signals for task {0} (max {max})")]
        PendingOverflow { tid: TaskId, max: usize },

        #[error("handler address 0 is invalid")]
        InvalidHandler,

        #[error("configuration error: {0}")]
        Config(String),
    }

    pub type SignalResult<T> = Result<T, SignalError>;
}

pub mod types {
    //! Signal definitions.
    use super::error::{SignalError, SignalResult};
    use core::fmt;

    /// POSIX signals.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    #[repr(u8)]
    pub enum Signal {
        SIGHUP  =  1,
        SIGINT  =  2,
        SIGQUIT =  3,
        SIGILL  =  4,
        SIGTRAP =  5,
        SIGABRT =  6,
        SIGFPE  =  8,
        SIGKILL =  9,
        SIGSEGV = 11,
        SIGPIPE = 13,
        SIGALRM = 14,
        SIGTERM = 15,
        SIGCHLD = 17,
        SIGCONT = 18,
        SIGSTOP = 19,
        SIGTSTP = 20,
        SIGTTIN = 21,
        SIGTTOU = 22,
        SIGUSR1 = 30,
        SIGUSR2 = 31,
        SIGSYS  = 31,
    }

    impl Signal {
        /// Convert from a raw number.
        pub fn from_u8(n: u8) -> SignalResult<Self> {
            match n {
                1  => Ok(Signal::SIGHUP),
                2  => Ok(Signal::SIGINT),
                3  => Ok(Signal::SIGQUIT),
                4  => Ok(Signal::SIGILL),
                5  => Ok(Signal::SIGTRAP),
                6  => Ok(Signal::SIGABRT),
                8  => Ok(Signal::SIGFPE),
                9  => Ok(Signal::SIGKILL),
                11 => Ok(Signal::SIGSEGV),
                13 => Ok(Signal::SIGPIPE),
                14 => Ok(Signal::SIGALRM),
                15 => Ok(Signal::SIGTERM),
                17 => Ok(Signal::SIGCHLD),
                18 => Ok(Signal::SIGCONT),
                19 => Ok(Signal::SIGSTOP),
                20 => Ok(Signal::SIGTSTP),
                21 => Ok(Signal::SIGTTIN),
                22 => Ok(Signal::SIGTTOU),
                30 => Ok(Signal::SIGUSR1),
                31 => Ok(Signal::SIGUSR2),
                _  => Err(SignalError::InvalidSignal(n)),
            }
        }

        /// Signal number as u8.
        pub fn as_u8(&self) -> u8 {
            *self as u8
        }

        /// Bitmask bit for this signal.
        pub fn bit(&self) -> u32 {
            1u32 << (self.as_u8() % 32)
        }

        /// Whether this signal can be caught or ignored.
        pub fn is_catchable(&self) -> bool {
            !matches!(self, Signal::SIGKILL | Signal::SIGSTOP)
        }

        /// Default action (terminate, ignore, stop, continue).
        pub fn default_action(&self) -> DefaultAction {
            match self {
                Signal::SIGCHLD | Signal::SIGCONT | Signal::SIGURG | Signal::SIGWINCH => DefaultAction::Ignore,
                Signal::SIGSTOP | Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU => DefaultAction::Stop,
                _ => DefaultAction::Terminate,
            }
        }
    }

    impl fmt::Display for Signal {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let name = match self {
                Signal::SIGHUP  => "SIGHUP",
                Signal::SIGINT  => "SIGINT",
                Signal::SIGQUIT => "SIGQUIT",
                Signal::SIGILL  => "SIGILL",
                Signal::SIGTRAP => "SIGTRAP",
                Signal::SIGABRT => "SIGABRT",
                Signal::SIGFPE  => "SIGFPE",
                Signal::SIGKILL => "SIGKILL",
                Signal::SIGSEGV => "SIGSEGV",
                Signal::SIGPIPE => "SIGPIPE",
                Signal::SIGALRM => "SIGALRM",
                Signal::SIGTERM => "SIGTERM",
                Signal::SIGCHLD => "SIGCHLD",
                Signal::SIGCONT => "SIGCONT",
                Signal::SIGSTOP => "SIGSTOP",
                Signal::SIGTSTP => "SIGTSTP",
                Signal::SIGTTIN => "SIGTTIN",
                Signal::SIGTTOU => "SIGTTOU",
                Signal::SIGUSR1 => "SIGUSR1",
                Signal::SIGUSR2 => "SIGUSR2",
                Signal::SIGSYS  => "SIGSYS",
            };
            write!(f, "{}", name)
        }
    }

    /// Default action for a signal.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum DefaultAction {
        Terminate,
        Ignore,
        Stop,
        Continue,
    }
}

pub mod metrics {
    //! Metrics for signal handling.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct SignalMetrics {
        pub signals_sent: AtomicU64,
        pub signals_delivered: AtomicU64,
        pub signals_ignored: AtomicU64,
        pub signals_terminated: AtomicU64,
        pub signals_stopped: AtomicU64,
        pub handler_calls: AtomicU64,
        pub handler_failures: AtomicU64,
        pub pending_overflow: AtomicU64,
    }

    impl SignalMetrics {
        pub fn inc_sent(&self) {
            self.signals_sent.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_delivered(&self) {
            self.signals_delivered.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_ignored(&self) {
            self.signals_ignored.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_terminated(&self) {
            self.signals_terminated.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_stopped(&self) {
            self.signals_stopped.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_handler_call(&self) {
            self.handler_calls.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_handler_failure(&self) {
            self.handler_failures.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_pending_overflow(&self) {
            self.pending_overflow.fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> SignalMetricsSnapshot {
            SignalMetricsSnapshot {
                signals_sent: self.signals_sent.load(Ordering::Relaxed),
                signals_delivered: self.signals_delivered.load(Ordering::Relaxed),
                signals_ignored: self.signals_ignored.load(Ordering::Relaxed),
                signals_terminated: self.signals_terminated.load(Ordering::Relaxed),
                signals_stopped: self.signals_stopped.load(Ordering::Relaxed),
                handler_calls: self.handler_calls.load(Ordering::Relaxed),
                handler_failures: self.handler_failures.load(Ordering::Relaxed),
                pending_overflow: self.pending_overflow.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SignalMetricsSnapshot {
        pub signals_sent: u64,
        pub signals_delivered: u64,
        pub signals_ignored: u64,
        pub signals_terminated: u64,
        pub signals_stopped: u64,
        pub handler_calls: u64,
        pub handler_failures: u64,
        pub pending_overflow: u64,
    }
}

pub mod pending {
    //! Pending signal bitmasks per task.
    use super::{
        config::SignalConfig,
        error::{SignalError, SignalResult},
        metrics::SignalMetrics,
        types::Signal,
    };
    use alloc::collections::BTreeMap;
    use core::sync::atomic::AtomicU64;
    use crate::task::TaskId;
    use spin::Mutex;

    /// Global pending signals per task.
    static PENDING: Mutex<BTreeMap<TaskId, u32>> = Mutex::new(BTreeMap::new());

    /// Add a signal to the pending mask for a task.
    pub fn add_pending(tid: TaskId, sig: Signal, config: &SignalConfig, metrics: &SignalMetrics) -> SignalResult<()> {
        let bit = sig.bit();
        let mut pending = PENDING.lock();
        let entry = pending.entry(tid).or_insert(0);
        // Check max pending if configured.
        if config.max_pending > 0 {
            let count = entry.count_ones();
            if count >= config.max_pending as u32 {
                metrics.inc_pending_overflow();
                return Err(SignalError::PendingOverflow {
                    tid,
                    max: config.max_pending,
                });
            }
        }
        *entry |= bit;
        metrics.inc_sent();
        if config.log_delivery {
            crate::serial_println!("  [SIG] → TID={} {:?}", tid, sig);
        }
        Ok(())
    }

    /// Get and clear the pending mask for a task.
    pub fn take_pending(tid: TaskId) -> u32 {
        let mut pending = PENDING.lock();
        let v = pending.get_mut(&tid).copied().unwrap_or(0);
        if let Some(e) = pending.get_mut(&tid) {
            *e = 0;
        }
        v
    }

    /// Clear all pending signals for a task.
    pub fn clear(tid: TaskId) {
        let mut pending = PENDING.lock();
        pending.remove(&tid);
    }

    /// Check if a task has pending signals.
    pub fn has_pending(tid: TaskId) -> bool {
        let pending = PENDING.lock();
        pending.get(&tid).copied().unwrap_or(0) != 0
    }

    /// Get the pending mask for a task (for debugging).
    pub fn get_pending(tid: TaskId) -> u32 {
        let pending = PENDING.lock();
        pending.get(&tid).copied().unwrap_or(0)
    }
}

pub mod handlers {
    //! Signal handler management per task.
    use super::{
        error::{SignalError, SignalResult},
        types::Signal,
    };
    use alloc::collections::BTreeMap;
    use crate::task::TaskId;
    use spin::Mutex;

    /// Global signal handlers per task (signal number -> handler address).
    static HANDLERS: Mutex<BTreeMap<TaskId, BTreeMap<u8, u64>>> = Mutex::new(BTreeMap::new());

    /// Register a signal handler.
    pub fn set_handler(tid: TaskId, sig: Signal, handler_addr: u64) -> SignalResult<()> {
        if !sig.is_catchable() {
            return Err(SignalError::NonCatchable { sig });
        }
        if handler_addr == 0 {
            return Err(SignalError::InvalidHandler);
        }
        let mut handlers = HANDLERS.lock();
        let task_handlers = handlers.entry(tid).or_default();
        task_handlers.insert(sig.as_u8(), handler_addr);
        Ok(())
    }

    /// Get the handler for a signal (returns 0 if not set).
    pub fn get_handler(tid: TaskId, sig: Signal) -> u64 {
        let handlers = HANDLERS.lock();
        handlers
            .get(&tid)
            .and_then(|h| h.get(&sig.as_u8()))
            .copied()
            .unwrap_or(0)
    }

    /// Clear all handlers for a task (on exec).
    pub fn clear(tid: TaskId) {
        let mut handlers = HANDLERS.lock();
        handlers.remove(&tid);
    }
}

pub mod delivery {
    //! Signal delivery logic.
    use super::{
        config::SignalConfig,
        error::{SignalError, SignalResult},
        metrics::SignalMetrics,
        types::{Signal, DefaultAction},
        pending,
        handlers,
    };
    use crate::task::TaskId;
    use crate::sched;

    /// Deliver pending signals to the current task.
    /// Called at syscall return or scheduler preemption points.
    pub fn deliver_pending(tid: TaskId, config: &SignalConfig, metrics: &SignalMetrics) {
        let pending_mask = pending::take_pending(tid);
        if pending_mask == 0 {
            return;
        }

        for bit in 0..32u8 {
            if pending_mask & (1 << bit) == 0 {
                continue;
            }
            // Try to parse the signal; skip if invalid.
            let sig = match Signal::from_u8(bit) {
                Ok(s) => s,
                Err(_) => continue,
            };
            // SIGKILL and SIGSTOP are handled at send time (non‑catchable).
            if !sig.is_catchable() {
                continue;
            }

            // Look for a custom handler.
            let handler = handlers::get_handler(tid, sig);
            if handler != 0 {
                // Call the handler (in userspace).
                metrics.inc_handler_call();
                // In a real kernel, we would set up the user stack and call the handler.
                // For now, we just log.
                if config.log_delivery {
                    crate::serial_println!("  [SIG] TID={} {:?} -> handler @ 0x{:x}", tid, sig, handler);
                }
                // Mark as delivered.
                metrics.inc_delivered();
                continue;
            }

            // Default action.
            let action = sig.default_action();
            match action {
                DefaultAction::Ignore => {
                    metrics.inc_ignored();
                    if config.log_delivery {
                        crate::serial_println!("  [SIG] TID={} {:?} ignored", tid, sig);
                    }
                }
                DefaultAction::Terminate => {
                    metrics.inc_terminated();
                    if config.log_delivery {
                        crate::serial_println!("  [SIG] TID={} {:?} → terminating", tid, sig);
                    }
                    // Terminate the task.
                    let exit_code = 128 + sig.as_u8() as i32;
                    sched::exit_current(exit_code);
                }
                DefaultAction::Stop => {
                    metrics.inc_stopped();
                    if config.log_delivery {
                        crate::serial_println!("  [SIG] TID={} {:?} → stopping", tid, sig);
                    }
                    // Stop the task (not implemented in this stub).
                }
                DefaultAction::Continue => {
                    // Continue (not implemented).
                }
            }
        }
    }
}

pub mod manager {
    //! Centralised signal manager.
    use super::{
        config::SignalConfig,
        error::{SignalError, SignalResult},
        metrics::SignalMetrics,
        types::Signal,
        pending,
        handlers,
        delivery,
    };
    use crate::task::TaskId;

    /// Centralised manager for signal handling.
    #[derive(Debug)]
    pub struct SignalManager {
        config: SignalConfig,
        metrics: SignalMetrics,
    }

    impl SignalManager {
        /// Create a new signal manager with the given configuration.
        pub fn new(config: SignalConfig) -> Self {
            config.validate().unwrap_or(());
            Self {
                config,
                metrics: SignalMetrics::default(),
            }
        }

        /// Create a manager with default configuration.
        pub fn default() -> Self {
            Self::new(SignalConfig::default())
        }

        /// Get a reference to the metrics.
        pub fn metrics(&self) -> &SignalMetrics {
            &self.metrics
        }

        /// Get the configuration.
        pub fn config(&self) -> &SignalConfig {
            &self.config
        }

        /// Send a signal to a task.
        pub fn send(&self, tid: TaskId, sig: Signal) -> SignalResult<()> {
            // Handle non‑catchable signals immediately.
            if !sig.is_catchable() {
                if sig == Signal::SIGKILL {
                    if self.config.log_delivery {
                        crate::serial_println!("  [SIG] SIGKILL → TID={} (immediate)", tid);
                    }
                    crate::sched::exit_current(128 + sig.as_u8() as i32);
                }
                // SIGSTOP: stop the task (stub).
                if self.config.log_delivery {
                    crate::serial_println!("  [SIG] {} → TID={} (non‑catchable)", sig, tid);
                }
                return Ok(());
            }
            // Add to pending.
            pending::add_pending(tid, sig, &self.config, &self.metrics)?;

            // If the signal is SIGCONT, wake the task (if stopped).
            if sig == Signal::SIGCONT {
                // Wake task (stub).
            }
            Ok(())
        }

        /// Deliver pending signals to the current task.
        pub fn deliver_pending(&self, tid: TaskId) {
            delivery::deliver_pending(tid, &self.config, &self.metrics);
        }

        /// Register a signal handler.
        pub fn set_handler(&self, tid: TaskId, sig: Signal, handler_addr: u64) -> SignalResult<()> {
            if self.config.log_handlers {
                crate::serial_println!("  [SIG] TID={} {} handler @ 0x{:x}", tid, sig, handler_addr);
            }
            handlers::set_handler(tid, sig, handler_addr)
        }

        /// Clear all signal state for a task (on exec).
        pub fn clear(&self, tid: TaskId) {
            pending::clear(tid);
            handlers::clear(tid);
        }

        /// Check if a task has pending signals.
        pub fn has_pending(&self, tid: TaskId) -> bool {
            pending::has_pending(tid)
        }

        /// Get the pending mask for a task (for debugging).
        pub fn pending_mask(&self, tid: TaskId) -> u32 {
            pending::get_pending(tid)
        }

        /// Get the handler address for a signal.
        pub fn get_handler(&self, tid: TaskId, sig: Signal) -> u64 {
            handlers::get_handler(tid, sig)
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::SignalConfig;
pub use error::{SignalError, SignalResult};
pub use types::{Signal, DefaultAction};
pub use metrics::{SignalMetrics, SignalMetricsSnapshot};
pub use manager::SignalManager;

// Legacy global functions (kept for backward compatibility).
// These use a global default manager instance.

static GLOBAL_MANAGER: Lazy<SignalManager> = Lazy::new(|| SignalManager::default());

/// Send a signal to a task (legacy).
pub fn send(tid: TaskId, sig: Signal) {
    let _ = GLOBAL_MANAGER.send(tid, sig);
}

/// Deliver pending signals to the current task (legacy).
pub fn deliver_pending(tid: TaskId) {
    GLOBAL_MANAGER.deliver_pending(tid);
}

/// Set a signal handler (legacy).
pub fn set_handler(tid: TaskId, sig: u8, handler_addr: u64) {
    if let Ok(signal) = Signal::from_u8(sig) {
        let _ = GLOBAL_MANAGER.set_handler(tid, signal, handler_addr);
    }
}

/// Clear all signals for a task (on exec) (legacy).
pub fn clear(tid: TaskId) {
    GLOBAL_MANAGER.clear(tid);
}

/// Initialise the signal subsystem (legacy).
pub fn init() {
    // Already initialised.
    crate::serial_println!("  [SIGNAL] initialized");
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::TaskId;

    #[test]
    fn test_signal_from_u8() {
        assert_eq!(Signal::from_u8(1).unwrap(), Signal::SIGHUP);
        assert_eq!(Signal::from_u8(9).unwrap(), Signal::SIGKILL);
        assert!(Signal::from_u8(99).is_err());
    }

    #[test]
    fn test_signal_bit() {
        assert_eq!(Signal::SIGINT.bit(), 1 << 2);
        assert_eq!(Signal::SIGTERM.bit(), 1 << 15);
    }

    #[test]
    fn test_signal_is_catchable() {
        assert!(Signal::SIGINT.is_catchable());
        assert!(!Signal::SIGKILL.is_catchable());
        assert!(!Signal::SIGSTOP.is_catchable());
    }

    #[test]
    fn test_default_action() {
        assert_eq!(Signal::SIGINT.default_action(), DefaultAction::Terminate);
        assert_eq!(Signal::SIGCHLD.default_action(), DefaultAction::Ignore);
        assert_eq!(Signal::SIGSTOP.default_action(), DefaultAction::Stop);
    }

    #[test]
    fn test_manager_send_and_pending() {
        let manager = SignalManager::default();
        let tid = TaskId(1);
        let result = manager.send(tid, Signal::SIGTERM);
        assert!(result.is_ok());
        assert!(manager.has_pending(tid));
        let mask = manager.pending_mask(tid);
        assert_eq!(mask, Signal::SIGTERM.bit());
    }

    #[test]
    fn test_handler_registration() {
        let manager = SignalManager::default();
        let tid = TaskId(1);
        let result = manager.set_handler(tid, Signal::SIGTERM, 0x1234);
        assert!(result.is_ok());
        assert_eq!(manager.get_handler(tid, Signal::SIGTERM), 0x1234);
        // Non‑catchable signal should fail.
        let result2 = manager.set_handler(tid, Signal::SIGKILL, 0x1234);
        assert!(result2.is_err());
    }

    #[test]
    fn test_clear() {
        let manager = SignalManager::default();
        let tid = TaskId(1);
        manager.send(tid, Signal::SIGTERM).unwrap();
        manager.set_handler(tid, Signal::SIGTERM, 0x1234).unwrap();
        manager.clear(tid);
        assert!(!manager.has_pending(tid));
        assert_eq!(manager.get_handler(tid, Signal::SIGTERM), 0);
    }
}
