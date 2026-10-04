//! Architecture‑specific code for IONA OS.
//!
//! This module abstracts platform‑dependent functionality. Currently only
//! x86_64 is supported; the crate root is expected to `#[cfg]`‑gate this
//! module so that a build on any other target fails with a clear message
//! rather than a wall of missing‑symbol errors.
//!
//! # Structure
//!
//! ```text
//! arch/
//!   mod.rs           — this file: re-exports + top-level init()
//!   x86_64/
//!     mod.rs         — submodule tree + ordered init()
//!     gdt/ idt/ interrupt/ timer/ apic/ smp/ percpu/ memory/ context/ ring3/
//! ```
//!
//! Callers should prefer the re-exports from this module
//! (`crate::arch::sti`, `crate::arch::uptime_ms`, …) instead of reaching
//! into `crate::arch::x86_64::…` directly. This keeps the call sites
//! target‑agnostic: adding a new backend later only requires editing
//! `mod.rs`.
//!
//! # Example
//!
//! ```ignore
//! // In `kmain`, after the physical memory map is available:
//! crate::arch::init().expect("arch init failed");
//!
//! // Elsewhere, target-agnostic:
//! let _guard = crate::arch::InterruptGuard::new();
//! let t0 = crate::arch::uptime_ms();
//! crate::arch::sleep_ms(10);
//! assert!(crate::arch::uptime_ms() >= t0);
//! ```

// -----------------------------------------------------------------------------
// Backend selection
// -----------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

// On any other target we deliberately emit a single compile error so that
// downstream users get a clear diagnostic instead of dozens of
// "module not found" errors from each subsystem.
#[cfg(not(target_arch = "x86_64"))]
compile_error!(
    "IONA OS currently only supports x86_64; see crate::arch for the backend \
     selection logic"
);

// -----------------------------------------------------------------------------
// Re-exports
// -----------------------------------------------------------------------------

// The x86_64 backend exposes the full subsystem tree. Re-export the whole
// tree here so `crate::arch::gdt::init()` works, and also re-export the
// most common individual items for ergonomic call sites.
#[cfg(target_arch = "x86_64")]
pub use x86_64::{
    // Submodule trees
    gdt,
    idt,
    interrupt,
    timer,
    memory,
    context,
    apic,
    smp,
    percpu,
    ring3,

    // Top-level init + metadata
    init,
    prelude,
    ARCH_NAME,
    GPR_COUNT,
    PAGE_SIZE,
    IdtConfig,
    IdtMetrics,
    IdtMetricsSnapshot,

    // Frequently used individual items
    interrupt::{
        disable as disable_interrupts,
        enable  as enable_interrupts,
        are_enabled as interrupts_enabled,
        InterruptGuard,
    },
    percpu::{current_cpu_id, current_tid, cpu_count},
    timer::{tick as timer_tick, uptime_ms, uptime_ns, uptime_us, sleep_ms},
};

// -----------------------------------------------------------------------------
// Compile-time architecture detection
// -----------------------------------------------------------------------------

/// Name of the architecture this binary was compiled for.
///
/// Unlike the previous implementation, this is a `const` driven by `cfg!`
/// so the value is baked in at compile time and can be used in `const`
/// contexts (e.g. `static` initialisers).
#[inline]
pub const fn arch_name() -> &'static str {
    if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else {
        "unsupported"
    }
}

/// Whether the current build target is supported by this crate.
#[inline]
pub const fn is_supported() -> bool {
    cfg!(target_arch = "x86_64")
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arch_name() {
        #[cfg(target_arch = "x86_64")]
        assert_eq!(arch_name(), "x86_64");
    }

    #[test]
    fn test_is_supported() {
        assert!(is_supported());
    }

    #[test]
    fn test_reexports_compile() {
        // Ensure the commonly used re-exports are actually reachable from
        // `crate::arch::...`. This test is a compile-time check; if it
        // builds, the re-exports are correct.
        let _: fn() -> u64 = uptime_ms;
        let _: fn() -> u64 = uptime_ns;
        let _: fn() -> u64 = uptime_us;
        let _: fn(u64)     = sleep_ms;
        let _: fn()        = timer_tick;
        let _: fn()        = enable_interrupts;
        let _: fn()        = disable_interrupts;
        let _: fn() -> bool = interrupts_enabled;
        let _: fn() -> u32 = current_cpu_id;
        let _: fn() -> u64 = current_tid;
        let _: fn() -> usize = cpu_count;
    }

    #[test]
    fn test_constants() {
        // These are re-exported from the backend; verify they have sane values.
        assert_eq!(ARCH_NAME, "x86_64");
        assert_eq!(GPR_COUNT, 16);
        assert_eq!(PAGE_SIZE, 4096);
    }
}
