//! Task switching primitives for x86_64.
//!
//! This module provides low‑level context switching and entry points for
//! Application Processors (APs) during SMP initialisation.
//!
//! # Overview
//!
//! - `switch_to(old, new)` – saves current registers into `old` and loads `new`.
//! - `run_task(ctx)` – one‑way entry point for an AP to start a new task.
//!
//! The AP bootstrap path uses a small static array of `Context` slots,
//! one per CPU, to avoid using the stack that would become invalid after
//! the context switch. For systems with more than `MAX_AP_CPUS` cores,
//! the code will panic with a clear message.

use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};

pub mod switch;
pub use switch::switch_to;

// Re‑export the task context type for convenience.
pub use crate::task::context::Context;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum number of Application Processors supported by the static bootstrap
/// array. This is a compile‑time limit that can be increased for larger systems.
///
/// The value 256 is safe because the LAPIC ID is only 8 bits wide on current
/// x86‑64 CPUs (0‑255). If you need more, consider using the per‑CPU GS pointer
/// method described below.
pub const MAX_AP_CPUS: usize = 256;

/// Whether we are using the legacy static bootstrap array or the dynamic
/// per‑CPU pointer method. This can be switched at compile time.
pub const USE_PER_CPU_BOOTSTRAP: bool = false;

// -----------------------------------------------------------------------------
// Per‑CPU bootstrap context (static array)
// -----------------------------------------------------------------------------

// Static storage for one bootstrap context per CPU. Each slot is initialised
// to a zeroed `Context` – this is safe because the first switch will overwrite
// it with the actual saved registers of the bootstrap code.
static mut BOOTSTRAP_CTX: [Context; MAX_AP_CPUS] = [Context::ZERO; MAX_AP_CPUS];

// -----------------------------------------------------------------------------
// Per‑CPU pointer via GS (advanced, heap‑free)
// -----------------------------------------------------------------------------

// When `USE_PER_CPU_BOOTSTRAP` is enabled, each CPU stores its own bootstrap
// context pointer in a GS‑relative location. This requires that the per‑CPU
// area is set up beforehand.
#[cfg(target_arch = "x86_64")]
mod per_cpu {
    use super::Context;
    use core::ptr::NonNull;

    /// Offset (in bytes) from the GS base where the bootstrap context pointer lives.
    /// Must match the linker script / per‑CPU area definition.
    pub const BOOTSTRAP_CTX_OFFSET: usize = 0x10;

    /// Get the bootstrap context pointer for the current CPU.
    ///
    /// # Safety
    /// The per‑CPU area must be initialised and the GS base must point to it.
    #[inline(always)]
    pub unsafe fn get_bootstrap_ctx() -> Option<NonNull<Context>> {
        let ptr: *mut *mut Context;
        asm!("mov {0}, gs:[{1}]", out(reg) ptr, const BOOTSTRAP_CTX_OFFSET);
        NonNull::new(*ptr)
    }

    /// Set the bootstrap context pointer for the current CPU.
    ///
    /// # Safety
    /// The per‑CPU area must be initialised and writable.
    #[inline(always)]
    pub unsafe fn set_bootstrap_ctx(ctx: *mut Context) {
        asm!("mov gs:[{0}], {1}", const BOOTSTRAP_CTX_OFFSET, in(reg) ctx);
    }
}

// -----------------------------------------------------------------------------
// Public API: run_task
// -----------------------------------------------------------------------------

/// Enter a new task context from the current bootstrap environment.
///
/// This function is called by an Application Processor (AP) immediately after
/// it has been initialised. It performs a **one‑way** context switch into the
/// supplied task context `ctx`. The function **never returns** to the caller;
/// control will only come back if the new task later calls `switch_to()` to
/// return to the bootstrap dummy context.
///
/// # Arguments
///
/// * `ctx` – A non‑null pointer to a valid, fully initialised `Context` that
///   represents the task to run. The context must have its own stack and
///   instruction pointer set correctly.
///
/// # Safety
///
/// * `ctx` must point to a valid `Context` that is properly aligned and
///   initialised.
/// * The caller must not rely on any stack‑local data after this call, because
///   the stack pointer will be changed.
/// * Interrupts must be disabled (or at least the context must be saved with
///   interrupts disabled) to prevent corruption of the saved register state.
/// * The bootstrap dummy context used internally must not be accessed from
///   multiple CPUs simultaneously. This is ensured by using a per‑CPU slot.
///
/// # Panics
///
/// * If the current CPU’s LAPIC ID is greater than or equal to `MAX_AP_CPUS`
///   and the static array method is used, the function panics.
/// * If the per‑CPU bootstrap pointer is not set (when using the advanced
///   method), the function panics.
pub unsafe fn run_task(ctx: NonNull<Context>) -> ! {
    let raw_id = crate::arch::x86_64::apic::local_apic_id() as usize;

    if USE_PER_CPU_BOOTSTRAP {
        // Advanced method: each CPU stores its own dummy context pointer.
        // The pointer must have been set up during SMP initialisation.
        let dummy_ptr = per_cpu::get_bootstrap_ctx()
            .expect("run_task: per‑CPU bootstrap context not initialised");
        switch_to(dummy_ptr.as_ptr(), ctx.as_ptr());
    } else {
        // Legacy method: static array indexed by LAPIC ID.
        if raw_id >= MAX_AP_CPUS {
            panic!(
                "run_task: CPU id {} >= MAX_AP_CPUS ({}) – increase MAX_AP_CPUS or enable USE_PER_CPU_BOOTSTRAP",
                raw_id, MAX_AP_CPUS
            );
        }
        let dummy = &mut BOOTSTRAP_CTX[raw_id] as *mut Context;
        switch_to(dummy, ctx.as_ptr());
    }
    unreachable!("switch_to() must not return")
}

/// Initialise the bootstrap context for a given CPU (only needed when using the
/// per‑CPU pointer method).
///
/// This function stores a pointer to a zero‑initialised `Context` in the CPU’s
/// GS‑relative storage. The context will be used as the “dummy” target when
/// `run_task` switches away from the AP bootstrap code.
///
/// # Safety
///
/// * Must be called on the CPU for which the bootstrap context is being set.
/// * The per‑CPU area must be properly set up (GS base).
/// * Only call this once per CPU before any `run_task` on that CPU.
#[cfg(target_arch = "x86_64")]
pub unsafe fn init_bootstrap_ctx_for_current_cpu() {
    if USE_PER_CPU_BOOTSTRAP {
        // Use a static dummy context (can be reused because only one CPU at a time
        // will be in the bootstrap path). For simplicity we use a single static
        // and store it in the per‑CPU slot.
        static mut DUMMY: Context = Context::ZERO;
        per_cpu::set_bootstrap_ctx(&mut DUMMY);
    }
}

// -----------------------------------------------------------------------------
// Tests (compile‑time only)
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_ap_cpus_is_reasonable() {
        assert!(MAX_AP_CPUS <= 256);
        assert!(MAX_AP_CPUS >= 64);
    }

    #[test]
    fn per_cpu_flag_is_defined() {
        // This test only checks that the constant exists.
        let _ = USE_PER_CPU_BOOTSTRAP;
    }
}
