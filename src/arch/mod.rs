//! Architecture‑specific code for IONA OS.
//!
//! This module abstracts platform‑dependent functionality.
//! Currently only x86_64 is supported.
//!
//! # Example
//!
//! ```
//! use iona::arch::{gdt, idt, timer};
//!
//! unsafe {
//!     gdt::init();
//!     idt::init();
//!     timer::init();
//! }
//! ```

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::{
    gdt,
    idt,
    timer,
    // Re‑export commonly used items from submodules
    interrupts::enable as enable_interrupts,
    interrupts::disable as disable_interrupts,
    interrupts::halt as halt_cpu,
};

/// Architecture detection (compile‑time).
#[inline]
pub const fn arch_name() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else {
        "unknown"
    }
}

/// Check if the current architecture is supported.
#[inline]
pub const fn is_supported() -> bool {
    cfg!(target_arch = "x86_64")
}

// Provide a compile‑error for unsupported architectures.
#[cfg(not(target_arch = "x86_64"))]
compile_error!("IONA OS currently only supports x86_64 architecture");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arch_name() {
        assert_eq!(arch_name(), "x86_64");
        assert!(is_supported());
    }
}
