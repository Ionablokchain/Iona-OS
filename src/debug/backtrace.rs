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

#![allow(dead_code)]

use alloc::vec::Vec;
use core::fmt::Write;

/// Maximum number of stack frames to capture.
pub const MAX_FRAMES: usize = 64;

/// Kernel base address (canonical start of kernel virtual memory).
pub const KERNEL_BASE: u64 = 0xFFFF_8000_0000_0000;

/// Kernel end address (adjust according to your linker script).
/// Here we assume the kernel fits in 128 MiB.
const KERNEL_END: u64 = KERNEL_BASE + 128 * 1024 * 1024;

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
            Some(name) => format!("  #{:2} 0x{:016x} ({} + {:#x}) [rbp=0x{:016x}]",
                                  self.depth, self.rip, name, self.rip - KERNEL_BASE, self.rbp),
            None => format!("  #{:2} 0x{:016x} (rbp=0x{:016x})", self.depth, self.rip, self.rbp),
        }
    }
}

// -----------------------------------------------------------------------------
// Symbol resolution (stub – can be replaced with real debug info)
// -----------------------------------------------------------------------------

/// Attempt to resolve a code address to a symbol name + offset.
/// Returns `None` if no debug information is available.
fn resolve_symbol(addr: u64) -> Option<&'static str> {
    // In production, you would load an ELF symbol table or use a static map.
    // This is a placeholder.
    #[cfg(feature = "embedded_debug_symbols")]
    {
        // Example: use a static array of (offset, name) pairs.
        // extern "C" { static __symtab_start: u8; static __symtab_end: u8; }
        // Then parse the ELF symtab.
        // For simplicity, we return None.
        None
    }
    #[cfg(not(feature = "embedded_debug_symbols"))]
    None
}

// -----------------------------------------------------------------------------
// Core backtrace walking (frame pointer based)
// -----------------------------------------------------------------------------

/// Walk the frame pointer chain starting from `rbp`.
/// Returns a vector of frames (innermost first).
pub fn walk_frames(start_rbp: u64) -> Vec<Frame> {
    let mut frames = Vec::new();
    let mut rbp = start_rbp;

    for depth in 0..MAX_FRAMES {
        // Validate RBP: must be kernel address, aligned, and within kernel bounds.
        if rbp < KERNEL_BASE || rbp >= KERNEL_END || (rbp & 7) != 0 {
            break;
        }

        // Unsafe but checked: read RIP at [rbp+8] and previous RBP at [rbp].
        // We use `read_volatile` to prevent compiler reordering and to hint that
        // the memory may be changed by other contexts (though in a backtrace it's static).
        unsafe {
            let rip_ptr = (rbp + 8) as *const u64;
            let rbp_ptr = rbp as *const u64;

            // Additional check: ensure pointers are within valid kernel range.
            if (rip_ptr as u64) < KERNEL_BASE || (rip_ptr as u64) >= KERNEL_END {
                break;
            }
            if (rbp_ptr as u64) < KERNEL_BASE || (rbp_ptr as u64) >= KERNEL_END {
                break;
            }

            let rip = core::ptr::read_volatile(rip_ptr);
            let prev_rbp = core::ptr::read_volatile(rbp_ptr);

            // Stop if RIP is zero or outside kernel code range.
            if rip == 0 || rip < KERNEL_BASE || rip >= KERNEL_END {
                break;
            }

            frames.push(Frame { rip, rbp, depth });

            // Detect loop or non‑progressing stack.
            if prev_rbp <= rbp {
                break;
            }
            rbp = prev_rbp;
        }
    }
    frames
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
// Tests (for fuzzing / unit testing outside kernel context)
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Mock kernel address range for testing.
    const TEST_KERNEL_BASE: u64 = 0xFFFF_8000_0000_0000;
    const TEST_KERNEL_END: u64 = TEST_KERNEL_BASE + 1024 * 1024;

    #[test]
    fn test_walk_frames_invalid_rbp() {
        // RBP too low
        let frames = walk_frames(0x1000);
        assert_eq!(frames.len(), 0);
    }

    #[test]
    fn test_walk_frames_single_frame() {
        // We can't easily create a real frame chain in test,
        // but we can test that the function doesn't crash.
        let rbp = current_rbp();
        let frames = walk_frames(rbp);
        assert!(frames.len() <= MAX_FRAMES);
    }
}
