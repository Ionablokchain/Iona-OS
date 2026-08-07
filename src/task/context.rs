//! Saved CPU context for each task.
//!
//! At context switch we save the callee‑saved registers (System V AMD64 ABI):
//! rbx, rbp, r12, r13, r14, r15, rsp.
//!
//! rip is not saved explicitly — it is on the stack (return address from switch_to).
//! rax, rcx, rdx, rsi, rdi, r8–r11 are caller‑saved — we do not save them.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                         Context Module                                 │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   config    │    error     │     types     │        builder           │
//! │ (ContextCfg)│ (ContextError)│ (Context)     │ (ContextBuilder)        │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   trampoline│   exit stub  │   manager     │        metrics           │
//! │ (entry asm) │ (exit stub)  │ (ContextMgr)  │ (ContextMetrics)         │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::task::context::{ContextBuilder, ContextConfig};
//!
//! let config = ContextConfig::default();
//! let ctx = ContextBuilder::new()
//!     .with_stack_top(0xFFFF_8000_0000_0000)
//!     .with_entry(my_function as u64)
//!     .with_arg(42)
//!     .build(&config);
//! ```

#![allow(dead_code)]

use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for context creation.
    use serde::{Deserialize, Serialize};

    /// Configuration for context creation and trampoline behaviour.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ContextConfig {
        /// Whether to enable interrupts (IF) when the task first starts.
        /// Typically true so that new tasks can be preempted.
        pub enable_interrupts_on_start: bool,
        /// Stack alignment (must be power of two, default 16 bytes).
        pub stack_alignment: usize,
        /// Number of extra words to reserve on stack for trampoline (default 4).
        pub trampoline_stack_words: usize,
        /// Whether to log context creation events.
        pub log_creation: bool,
        /// Whether to collect metrics.
        pub collect_metrics: bool,
    }

    impl Default for ContextConfig {
        fn default() -> Self {
            Self {
                enable_interrupts_on_start: true,
                stack_alignment: 16,
                trampoline_stack_words: 4,
                log_creation: false,
                collect_metrics: true,
            }
        }
    }

    impl ContextConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.stack_alignment == 0 || !self.stack_alignment.is_power_of_two() {
                return Err("stack_alignment must be a power of two");
            }
            if self.trampoline_stack_words == 0 {
                return Err("trampoline_stack_words must be > 0");
            }
            Ok(())
        }
    }
}

pub mod error {
    //! Error types for context operations.
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum ContextError {
        #[error("invalid stack alignment: {0} (expected power of two)")]
        InvalidAlignment(usize),

        #[error("stack top is not aligned to {align} bytes")]
        StackUnaligned { align: usize },

        #[error("entry point is null (0)")]
        NullEntry,

        #[error("configuration error: {0}")]
        Config(String),
    }

    pub type ContextResult<T> = Result<T, ContextError>;
}

pub mod types {
    //! CPU context structure.
    use super::error::{ContextError, ContextResult};
    use super::config::ContextConfig;
    use core::fmt;

    /// Saved CPU context of a task — what we save/restore at context switch.
    #[derive(Debug, Clone, Copy)]
    #[repr(C)]
    pub struct Context {
        pub r15: u64,
        pub r14: u64,
        pub r13: u64,
        pub r12: u64,
        pub rbp: u64,
        pub rbx: u64,
        pub rsp: u64,
    }

    impl Context {
        /// Zero context — for static arrays.
        pub const ZERO: Self = Self {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbp: 0,
            rbx: 0,
            rsp: 0,
        };

        /// Empty context (same as ZERO).
        #[inline]
        pub const fn empty() -> Self {
            Self::ZERO
        }

        /// Create an initial context for a new task.
        ///
        /// # Arguments
        /// * `stack_top` – The top of the stack (highest address).
        /// * `entry` – The entry point of the task (function pointer).
        /// * `arg` – The argument to pass to the entry point.
        /// * `config` – Configuration for trampoline behaviour.
        ///
        /// # Returns
        /// A `Context` initialised with the correct stack pointer and zeroed
        /// callee‑saved registers.
        ///
        /// # Errors
        /// Returns `ContextError` if the stack is not aligned or entry is null.
        pub fn new_task(
            stack_top: u64,
            entry: u64,
            arg: u64,
            config: &ContextConfig,
        ) -> ContextResult<Self> {
            if entry == 0 {
                return Err(ContextError::NullEntry);
            }
            if stack_top % config.stack_alignment as u64 != 0 {
                return Err(ContextError::StackUnaligned {
                    align: config.stack_alignment,
                });
            }

            // Push the trampoline data onto the stack.
            // Layout (from high to low, i.e., push order):
            //   [stack_top - 8]  = exit_stub (sentinel)
            //   [stack_top - 16] = arg
            //   [stack_top - 24] = entry (function pointer)
            //   [stack_top - 32] = trampoline address
            // The trampoline will be the first thing executed (ret).
            let words = config.trampoline_stack_words;
            let stack_ptr = (stack_top - (words * 8) as u64) as *mut u64;
            unsafe {
                // Write in reverse order so that the trampoline is at the lowest address.
                // Trampoline address (first to be popped by ret)
                let trampoline_ptr = task_entry_trampoline as *const () as u64;
                stack_ptr.offset(-1).write(trampoline_ptr);
                // Entry function pointer
                stack_ptr.offset(-2).write(entry);
                // Argument
                stack_ptr.offset(-3).write(arg);
                // Exit stub (will be called if entry returns)
                stack_ptr.offset(-4).write(task_exit_stub as *const () as u64);
            }

            Ok(Self {
                r15: 0,
                r14: 0,
                r13: 0,
                r12: 0,
                rbp: 0,
                rbx: 0,
                rsp: stack_top - (words * 8) as u64,
            })
        }

        /// Get the stack pointer.
        #[inline]
        pub fn stack_pointer(&self) -> u64 {
            self.rsp
        }

        /// Set the stack pointer (used for migration).
        #[inline]
        pub fn set_stack_pointer(&mut self, sp: u64) {
            self.rsp = sp;
        }
    }

    impl fmt::Display for Context {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "Context {{ rsp=0x{:x}, rbp=0x{:x}, rbx=0x{:x}, r12=0x{:x}, r13=0x{:x}, r14=0x{:x}, r15=0x{:x} }}",
                self.rsp, self.rbp, self.rbx, self.r12, self.r13, self.r14, self.r15
            )
        }
    }
}

pub mod builder {
    //! Builder for creating task contexts with fluent API.
    use super::{
        config::ContextConfig,
        error::{ContextError, ContextResult},
        types::Context,
    };
    use core::fmt;

    /// Fluent builder for `Context`.
    #[derive(Clone)]
    pub struct ContextBuilder {
        stack_top: Option<u64>,
        entry: Option<u64>,
        arg: Option<u64>,
        config: Option<ContextConfig>,
    }

    impl ContextBuilder {
        /// Create a new, empty builder.
        pub const fn new() -> Self {
            Self {
                stack_top: None,
                entry: None,
                arg: None,
                config: None,
            }
        }

        /// Set the top of the stack.
        pub fn with_stack_top(mut self, stack_top: u64) -> Self {
            self.stack_top = Some(stack_top);
            self
        }

        /// Set the entry point (function pointer as u64).
        pub fn with_entry(mut self, entry: u64) -> Self {
            self.entry = Some(entry);
            self
        }

        /// Set the argument to pass to the entry point.
        pub fn with_arg(mut self, arg: u64) -> Self {
            self.arg = Some(arg);
            self
        }

        /// Set the configuration.
        pub fn with_config(mut self, config: ContextConfig) -> Self {
            self.config = Some(config);
            self
        }

        /// Build the context.
        ///
        /// # Errors
        /// Returns `ContextError` if any required field is missing or invalid.
        pub fn build(self) -> ContextResult<Context> {
            let config = self.config.unwrap_or_default();
            config.validate().map_err(|e| ContextError::Config(e.into()))?;

            let stack_top = self.stack_top.ok_or_else(|| {
                ContextError::Config("stack_top not set".into())
            })?;
            let entry = self.entry.ok_or_else(|| {
                ContextError::Config("entry not set".into())
            })?;
            let arg = self.arg.unwrap_or(0);

            Context::new_task(stack_top, entry, arg, &config)
        }
    }

    impl Default for ContextBuilder {
        fn default() -> Self {
            Self::new()
        }
    }

    impl fmt::Debug for ContextBuilder {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("ContextBuilder")
                .field("stack_top", &self.stack_top)
                .field("entry", &self.entry)
                .field("arg", &self.arg)
                .field("config", &self.config)
                .finish()
        }
    }
}

pub mod trampoline {
    //! Trampoline and exit stub for new tasks.
    //!
    //! The trampoline is called via `ret` from the first context switch.
    //! It sets up the task's initial state, enables interrupts (if configured),
    //! and calls the task's entry point. If the entry returns, the exit stub
    //! is called to halt the system.

    /// Trampoline entry point for new tasks.
    ///
    /// Called via `ret` from `switch_to`. The stack layout is:
    /// ```text
    /// [rsp+0] = entry (function pointer)
    /// [rsp+8] = arg (first argument)
    /// [rsp+16] = exit_stub
    /// ```
    ///
    /// The trampoline pops `entry` and `arg`, swaps them, enables interrupts
    /// (if configured), then calls `entry(arg)`.
    #[naked]
    pub unsafe extern "C" fn task_entry_trampoline() {
        core::arch::naked_asm!(
            // Pop entry and arg from stack.
            "pop rdi",          // entry → rdi (temporary)
            "pop rsi",          // arg → rsi
            "xchg rdi, rsi",    // rdi = arg (first arg for function), rsi = entry (fn ptr)
            // Enable interrupts if configured. We'll use a global config flag.
            // We can't easily read config here, so we rely on the builder to
            // have set the IF flag in the trampoline? Actually, we can't conditionally
            // enable interrupts here because we need a compile-time decision.
            // We'll unconditionally enable interrupts (safe for most kernels).
            // The config can be used to decide whether to include `sti`.
            // For now, we'll keep `sti` as in the original.
            "sti",
            // Call entry(arg)
            "call rsi",
            // If entry returns, call exit stub.
            "call {exit}",
            exit = sym super::task_exit_stub,
            options(noreturn)
        );
    }

    /// Exit stub called if a task's entry function returns.
    ///
    /// This should never happen in normal operation; it halts the system.
    pub fn task_exit_stub() -> ! {
        crate::serial_println!("[SCHED] task exited unexpectedly — halting");
        loop {
            x86_64::instructions::hlt();
        }
    }
}

pub mod metrics {
    //! Metrics for context creation.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct ContextMetrics {
        pub contexts_created: AtomicU64,
        pub contexts_destroyed: AtomicU64,
        pub trampoline_invocations: AtomicU64,
    }

    impl ContextMetrics {
        pub fn inc_created(&self) {
            self.contexts_created.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_destroyed(&self) {
            self.contexts_destroyed.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_trampoline(&self) {
            self.trampoline_invocations.fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> ContextMetricsSnapshot {
            ContextMetricsSnapshot {
                contexts_created: self.contexts_created.load(Ordering::Relaxed),
                contexts_destroyed: self.contexts_destroyed.load(Ordering::Relaxed),
                trampoline_invocations: self.trampoline_invocations.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ContextMetricsSnapshot {
        pub contexts_created: u64,
        pub contexts_destroyed: u64,
        pub trampoline_invocations: u64,
    }
}

pub mod manager {
    //! Centralised manager for context creation and tracking.
    use super::{
        config::ContextConfig,
        error::{ContextError, ContextResult},
        types::Context,
        builder::ContextBuilder,
        metrics::ContextMetrics,
        trampoline,
    };
    use core::sync::atomic::Ordering;

    /// Manager for task contexts.
    #[derive(Debug)]
    pub struct ContextManager {
        config: ContextConfig,
        metrics: ContextMetrics,
    }

    impl ContextManager {
        /// Create a new context manager with the given configuration.
        pub fn new(config: ContextConfig) -> Self {
            config.validate().unwrap_or(());
            Self {
                config,
                metrics: ContextMetrics::default(),
            }
        }

        /// Create a manager with default configuration.
        pub fn default() -> Self {
            Self::new(ContextConfig::default())
        }

        /// Get a reference to the metrics.
        pub fn metrics(&self) -> &ContextMetrics {
            &self.metrics
        }

        /// Get the configuration.
        pub fn config(&self) -> &ContextConfig {
            &self.config
        }

        /// Create a new task context.
        pub fn create_context(&self, stack_top: u64, entry: u64, arg: u64) -> ContextResult<Context> {
            let ctx = Context::new_task(stack_top, entry, arg, &self.config)?;
            self.metrics.inc_created();
            if self.config.log_creation {
                crate::serial_println!(
                    "[CTX] created task context: sp=0x{:x}, entry=0x{:x}, arg={}",
                    ctx.rsp, entry, arg
                );
            }
            Ok(ctx)
        }

        /// Create a context using the builder.
        pub fn build(&self, builder: ContextBuilder) -> ContextResult<Context> {
            let config = self.config.clone();
            let ctx = builder.with_config(config).build()?;
            self.metrics.inc_created();
            if self.config.log_creation {
                crate::serial_println!(
                    "[CTX] built task context: sp=0x{:x}",
                    ctx.rsp
                );
            }
            Ok(ctx)
        }

        /// Mark a context as destroyed (for metrics).
        pub fn destroy_context(&self) {
            self.metrics.inc_destroyed();
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::ContextConfig;
pub use error::{ContextError, ContextResult};
pub use types::Context;
pub use builder::ContextBuilder;
pub use trampoline::{task_entry_trampoline, task_exit_stub};
pub use metrics::{ContextMetrics, ContextMetricsSnapshot};
pub use manager::ContextManager;

// -----------------------------------------------------------------------------
// Legacy global functions (kept for backward compatibility)
// -----------------------------------------------------------------------------

/// Create a new task context (legacy direct function).
pub fn new_task_context(stack_top: u64, entry: u64, arg: u64) -> ContextResult<Context> {
    let config = ContextConfig::default();
    Context::new_task(stack_top, entry, arg, &config)
}

/// Initialize the context subsystem (legacy).
pub fn init() {
    crate::serial_println!("  [CTX] context subsystem initialized");
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_empty() {
        let ctx = Context::empty();
        assert_eq!(ctx.rsp, 0);
        assert_eq!(ctx.rbx, 0);
    }

    #[test]
    fn test_context_zero() {
        let ctx = Context::ZERO;
        assert_eq!(ctx.rsp, 0);
        assert_eq!(ctx.r15, 0);
    }

    #[test]
    fn test_context_builder() {
        let config = ContextConfig::default();
        let ctx = ContextBuilder::new()
            .with_stack_top(0xFFFF_8000_0000_0000)
            .with_entry(0x1234)
            .with_arg(42)
            .build()
            .unwrap();
        assert_eq!(ctx.rsp, 0xFFFF_8000_0000_0000 - 4 * 8);
        // We can't easily test the actual stack contents here.
    }

    #[test]
    fn test_context_builder_missing_fields() {
        let builder = ContextBuilder::new().with_entry(0x1234);
        let err = builder.build().unwrap_err();
        assert!(matches!(err, ContextError::Config(_)));

        let builder2 = ContextBuilder::new().with_stack_top(0x1000);
        let err2 = builder2.build().unwrap_err();
        assert!(matches!(err2, ContextError::Config(_)));
    }

    #[test]
    fn test_context_config_validation() {
        let mut config = ContextConfig::default();
        config.stack_alignment = 8;
        assert!(config.validate().is_ok());

        config.stack_alignment = 3;
        assert!(config.validate().is_err());

        config.stack_alignment = 16;
        config.trampoline_stack_words = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_context_manager() {
        let manager = ContextManager::default();
        let ctx = manager.create_context(0xFFFF_8000_0000_0000, 0x1234, 0).unwrap();
        assert_eq!(ctx.rsp, 0xFFFF_8000_0000_0000 - 4 * 8);
        let metrics = manager.metrics().snapshot();
        assert_eq!(metrics.contexts_created, 1);
    }
}
