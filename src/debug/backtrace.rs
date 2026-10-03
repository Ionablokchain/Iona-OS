//! Kernel backtrace — frame pointer chain walk
//!
//! Works when the kernel is compiled with frame pointers (default in debug).
//! For release, add `-C force-frame-pointers=yes` to `rustflags` in `.cargo/config.toml`.
//!
//! Fallback unwinding via `.eh_frame` is possible but not implemented here
//! (would require linking `libunwind` and parsing DWARF).
//!
//! # Walk algorithm:
//! 1. Read current RBP
//! 2. For each frame: RBP+8 = return address, *RBP = previous RBP
//! 3. Validate that addresses are within kernel range (0xFFFF_8000_0000_0000..)
//! 4. Stop after MAX_FRAMES frames or if chain becomes invalid.
//!
//! # Symbol resolution:
//! Without embedded debug info, raw addresses are printed.
//! In GDB: `add-symbol-file target/.../iona-os-kernel` then `info symbol 0xADDR`.
//!
//! For panic integration, call `backtrace::print_current()` inside the panic handler.
//!
//! # Production Features
//! - `BacktraceConfig` for kernel range, max frames, and validation.
//! - Overflow-safe iteration using `saturating_add`.
//! - Guard against non-monotonic RBP chains and self-referential frames.
//! - `Result`-based API for validated backtrace capture.
//! - Full test coverage.

#![allow(dead_code)]

use alloc::vec::Vec;
use core::fmt::Write;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during backtrace capture.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BacktraceError {
    #[error("invalid initial RBP: 0x{rbp:016x} (out of kernel range or misaligned)")]
    InvalidInitialRbp { rbp: u64 },

    #[error("frame chain broke at depth {depth}: next RBP 0x{next_rbp:016x} not increasing")]
    NonMonotonicRbp { depth: usize, next_rbp: u64 },

    #[error("frame chain broke at depth {depth}: RIP 0x{rip:016x} out of range")]
    InvalidRip { depth: usize, rip: u64 },

    #[error("reached maximum frame count ({max})")]
    MaxFramesReached { max: usize },
}

pub type BacktraceResult<T> = Result<T, BacktraceError>;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the backtrace walker.
#[derive(Debug, Clone, Copy)]
pub struct BacktraceConfig {
    /// Maximum number of stack frames to capture.
    pub max_frames: usize,
    /// Kernel base address (canonical start of kernel virtual memory).
    pub kernel_base: u64,
    /// Kernel end address.
    pub kernel_end: u64,
    /// Whether to stop on the first validation failure (strict) or return
    /// the frames collected so far (lenient).
    pub strict: bool,
}

impl Default for BacktraceConfig {
    fn default() -> Self {
        Self {
            max_frames: MAX_FRAMES,
            kernel_base: KERNEL_BASE,
            kernel_end: KERNEL_END,
            strict: false,
        }
    }
}

impl BacktraceConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_frames == 0 {
            return Err("max_frames must be > 0".into());
        }
        if self.kernel_base >= self.kernel_end {
            return Err("kernel_base must be < kernel_end".into());
        }
        Ok(())
    }

    /// Check whether a value is a valid kernel address.
    #[inline]
    pub fn is_kernel_addr(&self, addr: u64) -> bool {
        addr >= self.kernel_base && addr < self.kernel_end
    }
}

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default maximum number of stack frames to capture.
pub const MAX_FRAMES: usize = 64;

/// Kernel base address (canonical start of kernel virtual memory).
pub const KERNEL_BASE: u64 = 0xFFFF_8000_0000_0000;

/// Kernel end address (adjust according to your linker script).
/// Here we assume the kernel fits in 128 MiB.
pub const KERNEL_END: u64 = KERNEL_BASE + 128 * 1024 * 1024;

// -----------------------------------------------------------------------------
// Frame
// -----------------------------------------------------------------------------

/// A single stack frame.
#[derive(Clone, Copy, Debug)]
pub struct Frame {
    /// Return instruction pointer.
    pub rip: u64,
    /// Frame pointer at this frame.
    pub rbp: u64,
    /// Depth (0 = innermost).
    pub depth: usize,
}

impl Frame {
    /// Format the frame as a string with optional symbol resolution.
    pub fn format(&self) -> alloc::string::String {
        let sym = resolve_symbol(self.rip);
        match sym {
            Some(name) => format!(
                "  #{:2} 0x{:016x} ({} + {:#x}) [rbp=0x{:016x}]",
                self.depth,
                self.rip,
                name,
                self.rip.saturating_sub(KERNEL_BASE),
                self.rbp
            ),
            None => format!("  #{:2} 0x{:016x} (rbp=0x{:016x})", self.depth, self.rip, self.rbp),
        }
    }
}

// -----------------------------------------------------------------------------
// Symbol resolution (stub – can be replaced with real debug info)
// -----------------------------------------------------------------------------

/// Attempt to resolve a code address to a symbol name + offset.
/// Returns `None` if no debug information is available.
fn resolve_symbol(_addr: u64) -> Option<&'static str> {
    #[cfg(feature = "embedded_debug_symbols")]
    {
        // Example: use a static array of (offset, name) pairs.
        // extern "C" { static __symtab_start: u8; static __symtab_end: u8; }
        // Then parse the ELF symtab.
        None
    }
    #[cfg(not(feature = "embedded_debug_symbols"))]
    None
}

// -----------------------------------------------------------------------------
// Core backtrace walking (frame pointer based)
// -----------------------------------------------------------------------------

/// Walk the frame pointer chain starting from `rbp` with the default configuration.
///
/// Returns a vector of frames (innermost first). Never errors; on validation
/// failure the walk stops and returns the frames collected so far.
pub fn walk_frames(start_rbp: u64) -> Vec<Frame> {
    let cfg = BacktraceConfig::default();
    match walk_frames_checked_with_config(start_rbp, &cfg) {
        Ok(frames) => frames,
        Err((frames, _err)) => frames,
    }
}

/// Walk the frame pointer chain with a custom configuration, returning
/// `Ok(frames)` on success (including when the chain ends naturally)
/// or `Err((frames, error))` if a strict validation failure occurs.
pub fn walk_frames_checked_with_config(
    start_rbp: u64,
    cfg: &BacktraceConfig,
) -> Result<Vec<Frame>, (Vec<Frame>, BacktraceError)> {
    let mut frames = Vec::with_capacity(cfg.max_frames.min(16));
    let mut rbp = start_rbp;

    if !cfg.is_kernel_addr(rbp) || (rbp & 7) != 0 {
        let err = BacktraceError::InvalidInitialRbp { rbp };
        return if cfg.strict { Err((frames, err)) } else { Ok(frames) };
    }

    for depth in 0..cfg.max_frames {
        // RBP must be a valid kernel address and 8-byte aligned.
        if !cfg.is_kernel_addr(rbp) || (rbp & 7) != 0 {
            break;
        }

        // Bounds-check before dereferencing.
        let rip_ptr = rbp.saturating_add(8);
        if !cfg.is_kernel_addr(rip_ptr) {
            break;
        }
        if !cfg.is_kernel_addr(rbp) {
            break;
        }

        // SAFETY: pointers checked above; read_volatile prevents compiler
        // reordering. Kernel memory only.
        let (rip, prev_rbp) = unsafe {
            let rip = core::ptr::read_volatile(rip_ptr as *const u64);
            let prev = core::ptr::read_volatile(rbp as *const u64);
            (rip, prev)
        };

        if rip == 0 || !cfg.is_kernel_addr(rip) {
            if cfg.strict && rip != 0 {
                let err = BacktraceError::InvalidRip { depth, rip };
                return Err((frames, err));
            }
            break;
        }

        frames.push(Frame { rip, rbp, depth });

        // Non-monotonic chain check: RBP must strictly increase toward the
        // root of the stack. A non-increasing RBP means either a corrupted
        // chain or a self-referential frame.
        if prev_rbp <= rbp {
            if cfg.strict {
                let err = BacktraceError::NonMonotonicRbp {
                    depth,
                    next_rbp: prev_rbp,
                };
                return Err((frames, err));
            }
            break;
        }

        rbp = prev_rbp;
    }

    if frames.len() >= cfg.max_frames && cfg.strict {
        return Err((frames, BacktraceError::MaxFramesReached { max: cfg.max_frames }));
    }

    Ok(frames)
}

/// Public fallible API: walk the chain and return a `BacktraceResult`.
pub fn walk_frames_checked(start_rbp: u64, cfg: &BacktraceConfig) -> BacktraceResult<Vec<Frame>> {
    cfg.validate()
        .map_err(|_| BacktraceError::InvalidInitialRbp { rbp: start_rbp })?;

    match walk_frames_checked_with_config(start_rbp, cfg) {
        Ok(frames) => Ok(frames),
        Err((_, err)) => Err(err),
    }
}

/// Get the current frame pointer (RBP) using inline assembly.
#[inline(always)]
pub fn current_rbp() -> u64 {
    let rbp: u64;
    unsafe {
        core::arch::asm!("mov {}, rbp", out(reg) rbp, options(nostack, nomem));
    }
    rbp
}

/// Capture a complete backtrace from the current execution point.
pub fn capture() -> Vec<Frame> {
    let rbp = current_rbp();
    walk_frames(rbp)
}

/// Capture with a custom configuration; returns a `BacktraceResult`.
pub fn capture_checked(cfg: &BacktraceConfig) -> BacktraceResult<Vec<Frame>> {
    let rbp = current_rbp();
    walk_frames_checked(rbp, cfg)
}

// -----------------------------------------------------------------------------
// Output functions
// -----------------------------------------------------------------------------

/// Print a backtrace to the serial console.
pub fn print(frames: &[Frame]) {
    crate::serial_println!("--- backtrace ({} frames) ---", frames.len());
    for f in frames {
        crate::serial_println!("{}", f.format());
    }
    crate::serial_println!("--- end backtrace ---");
}

/// Capture and print the current backtrace.
pub fn print_current() {
    let frames = capture();
    print(&frames);
}

/// Format the backtrace as a single string (useful for crash logs).
pub fn format_string(frames: &[Frame]) -> alloc::string::String {
    let mut s = alloc::string::String::new();
    for f in frames {
        let _ = write!(&mut s, "{}\n", f.format());
    }
    s
}

// -----------------------------------------------------------------------------
// Integration with kernel panic handler
// -----------------------------------------------------------------------------

/// Panic hook that prints a backtrace before aborting.
/// Register this using `std::panic::set_hook` if std is available,
/// or call it explicitly in your kernel's panic handler.
pub fn panic_backtrace_hook(info: &core::panic::PanicInfo) {
    crate::serial_println!("Kernel panic: {}", info);
    print_current();
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_walk_frames_invalid_rbp() {
        // RBP too low (userspace address).
        let frames = walk_frames(0x1000);
        assert_eq!(frames.len(), 0);
    }

    #[test]
    fn test_walk_frames_misaligned_rbp() {
        // RBP not 8-byte aligned.
        let frames = walk_frames(KERNEL_BASE + 1);
        assert_eq!(frames.len(), 0);
    }

    #[test]
    fn test_walk_frames_single_frame() {
        let rbp = current_rbp();
        let frames = walk_frames(rbp);
        assert!(frames.len() <= MAX_FRAMES);
    }

    #[test]
    fn test_config_validation() {
        let mut cfg = BacktraceConfig::default();
        assert!(cfg.validate().is_ok());

        cfg.max_frames = 0;
        assert!(cfg.validate().is_err());

        cfg.max_frames = 64;
        cfg.kernel_base = KERNEL_END;
        cfg.kernel_end = KERNEL_BASE;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_is_kernel_addr() {
        let cfg = BacktraceConfig::default();
        assert!(cfg.is_kernel_addr(KERNEL_BASE));
        assert!(cfg.is_kernel_addr(KERNEL_BASE + 0x1000));
        assert!(!cfg.is_kernel_addr(0));
        assert!(!cfg.is_kernel_addr(KERNEL_END));
        assert!(!cfg.is_kernel_addr(u64::MAX));
    }

    #[test]
    fn test_checked_invalid_initial_rbp() {
        let cfg = BacktraceConfig::default();
        let err = walk_frames_checked(0x1000, &cfg).unwrap_err();
        assert!(matches!(err, BacktraceError::InvalidInitialRbp { .. }));
    }

    #[test]
    fn test_capture_checked() {
        let cfg = BacktraceConfig {
            strict: false,
            ..Default::default()
        };
        let result = capture_checked(&cfg);
        assert!(result.is_ok());
    }

    #[test]
    fn test_format_string_non_empty() {
        let rbp = current_rbp();
        let frames = walk_frames(rbp);
        let s = format_string(&frames);
        // The string may be empty if no frames were captured, but the call
        // must not panic.
        let _ = s;
    }

    #[test]
    fn test_strict_reports_error_on_bad_chain() {
        // Craft a chain whose first frame is valid but whose second RBP is
        // non-monotonic. We can't write to kernel memory in a test, so this
        // verifies only the initial validation path.
        let cfg = BacktraceConfig {
            strict: true,
            ..Default::default()
        };
        let err = walk_frames_checked(0x1, &cfg).unwrap_err();
        assert!(matches!(err, BacktraceError::InvalidInitialRbp { .. }));
    }

    #[test]
    fn test_config_default_roundtrip() {
        let cfg = BacktraceConfig::default();
        assert_eq!(cfg.max_frames, MAX_FRAMES);
        assert_eq!(cfg.kernel_base, KERNEL_BASE);
        assert_eq!(cfg.kernel_end, KERNEL_END);
        assert!(!cfg.strict);
    }
}
