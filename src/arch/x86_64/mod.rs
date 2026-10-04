//! x86_64 architecture support for IONA.
//!
//! This module groups all low‑level hardware‑specific functionality required
//! to boot and run the kernel on x86_64 CPUs. It is the single entry point
//! for architecture‑dependent code; every other module should depend on the
//! abstractions exposed here rather than poking at hardware registers
//! directly.
//!
//! # Subsystems
//!
//! | Module       | Responsibility                                              |
//! |--------------|-------------------------------------------------------------|
//! | [`gdt`]      | Global Descriptor Table + TSS + IST stacks                  |
//! | [`idt`]      | Interrupt Descriptor Table + exception/IRQ handlers         |
//! | [`interrupt`]| `sti`/`cli`/`int3`, IRQ masking, interrupt guard          |
//! | [`timer`]    | PIT + uptime clock, `SCHED_READY` signal                    |
//! | [`apic`]     | Local APIC + IOAPIC, IPIs, TLB shootdown                    |
//! | [`smp`]      | Boot strap of secondary CPUs, CPU topology                  |
//! | [`percpu`]   | Per‑CPU data (current CPU id, current TID, safe‑copy flag)  |
//! | [`memory`]   | Paging, page tables, frame allocator                        |
//! | [`context`]  | Task context switch (register save/restore)                 |
//! | [`ring3`]    | Userspace entry/exit helpers (`iretq`, `sysret`)            |
//!
//! # Initialization order
//!
//! `init()` runs the required initialization steps in the correct order:
//! 1. GDT + TSS (must be first — all segment registers are set here).
//! 2. Per‑CPU data (needed by IDT handlers and the scheduler).
//! 3. Memory (paging must be active before any heap use).
//! 4. IDT (safe once a valid GDT and per‑CPU area exist).
//! 5. Timer + APIC + SMP (start the clock and bring up secondary CPUs).
//!
//! Calling `init()` more than once is a no‑op (the individual subsystems
//! already short‑circuit on re‑init), but the intent is that it is called
//! exactly once, from `kmain`, before any interrupts are enabled.
//!
//! # Conditional compilation
//!
//! The whole module is only meaningful on x86_64. On other targets the
//! parent crate should not include it; see `lib.rs` / `main.rs` for the
//! `#[cfg(target_arch = "x86_64")]` gate.

// -----------------------------------------------------------------------------
// Submodules
// -----------------------------------------------------------------------------

pub mod gdt;
pub mod idt;
pub mod timer;
pub mod interrupt;
pub mod memory;
pub mod context;
pub mod apic;
pub mod smp;
pub mod percpu;

pub mod ring3;

// -----------------------------------------------------------------------------
// Re‑exports
// -----------------------------------------------------------------------------

// Frequently used items are re‑exported here so callers can write
// `use crate::arch::x86_64::InterruptGuard;` instead of digging into the
// submodule paths.

pub use gdt::{DOUBLE_FAULT_IST_INDEX, SYSCALL_IST_INDEX, TIMER_IST_INDEX};
pub use idt::{IdtConfig, IdtMetricsSnapshot, IdtMetrics};
pub use interrupt::{disable as cli, enable as sti, are_enabled, InterruptGuard};
pub use percpu::{current_cpu_id, current_tid, cpu_count};
pub use timer::{tick, uptime_ms, uptime_ns};

// -----------------------------------------------------------------------------
// Architecture identification
// -----------------------------------------------------------------------------

/// A short identifier for the current architecture.
pub const ARCH_NAME: &str = "x86_64";

/// Number of general‑purpose registers on x86_64.
pub const GPR_COUNT: usize = 16;

/// Page size in bytes (4 KiB; huge pages handled elsewhere).
pub const PAGE_SIZE: usize = 4096;

// -----------------------------------------------------------------------------
// Init
// -----------------------------------------------------------------------------

/// Run the full architecture initialization sequence.
///
/// Must be called exactly once, from `kmain`, before enabling interrupts.
/// See the module‑level docs for the ordering rationale.
///
/// Returns `Err` on the first subsystem that rejects its configuration; a
/// failure here is fatal and the caller should panic.
pub fn init() -> Result<(), &'static str> {
    // 1. GDT + TSS. Must come first so the CPU has valid code/data segments.
    gdt::init();
    if !gdt::is_initialized() {
        return Err("GDT failed to initialize");
    }

    // 2. Per‑CPU data. Needed by every IDT handler (current_cpu_id/current_tid).
    percpu::init();

    // 3. Memory. Paging + heap must be ready before we allocate anything
    //    inside a later init step.
    memory::init();

    // 4. IDT. Safe now that GDT and per‑CPU areas exist.
    idt::init();
    if !idt::is_initialized() {
        return Err("IDT failed to initialize");
    }

    // 5. Timer + APIC + SMP. Enable the clock, then bring up secondaries.
    timer::init();
    apic::init();
    smp::init();

    crate::klog_info!("x86_64 architecture initialized");
    Ok(())
}

// -----------------------------------------------------------------------------
// Prelude
// -----------------------------------------------------------------------------

/// Convenience prelude for arch‑specific call sites.
///
/// ```ignore
/// use crate::arch::x86_64::prelude::*;
///
/// let _guard = InterruptGuard::new();   // disables interrupts until drop
/// let cpu = current_cpu_id();
/// ```
pub mod prelude {
    pub use super::{
        cli, sti, are_enabled, InterruptGuard,
        current_cpu_id, current_tid, cpu_count,
        tick, uptime_ms, uptime_ns,
        ARCH_NAME, PAGE_SIZE,
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arch_name() {
        assert_eq!(ARCH_NAME, "x86_64");
    }

    #[test]
    fn test_gpr_count() {
        // x86_64 exposes 16 general‑purpose registers (rax..r15).
        assert_eq!(GPR_COUNT, 16);
    }

    #[test]
    fn test_page_size() {
        assert_eq!(PAGE_SIZE, 4096);
    }

    #[test]
    fn test_ist_indices_are_in_range() {
        // The TSS IST table has 7 slots on x86_64; all of ours must fit.
        assert!((DOUBLE_FAULT_IST_INDEX as usize) < 7);
        assert!((SYSCALL_IST_INDEX as usize) < 7);
        assert!((TIMER_IST_INDEX as usize) < 7);
    }

    #[test]
    fn test_pic_constants_via_idt() {
        // Just make sure the IDT module exposes a stable public surface.
        // (No hardware access from a unit test.)
        let _ = std::mem::size_of::<IdtMetricsSnapshot>();
    }
}
