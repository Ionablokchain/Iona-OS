pub mod switch;
pub use switch::switch_to;
// Context is defined in crate::task::context — re-export for convenience
pub use crate::task::context::Context;

/// Run a task context — ONE-WAY entry into a stolen task for AP execution.
///
/// This creates a throw-away "dummy" context for the current (bootstrap) state.
/// The dummy is never restored — this function does NOT return to the caller
/// unless the stolen task itself eventually calls switch_to() back.
///
/// Safety: ctx must point to a valid, fully initialized Task context.
/// The caller must not access any stack-local state after this call.
/// Maximum supported AP count for BOOTSTRAP_CTX static array.
///
/// Constraint: this is a compile-time fixed array. To support more CPUs,
/// increase MAX_AP_CPUS and rebuild. Dynamic allocation is not used here
/// because run_task() is called during AP bootstrap before the heap is
/// fully operational on that core.
///
/// Production path: allocate BOOTSTRAP_CTX per-CPU during SMP init,
/// store pointer in per-CPU GS data, read it here via GS-relative access.
/// That eliminates the fixed limit entirely.
pub const MAX_AP_CPUS: usize = 64;
// BOOTSTRAP_CTX: fixed-size static array of Context slots, one per AP.
//
// Limitation: MAX_AP_CPUS = 64 is a compile-time constant.
// Clamp to MAX_AP_CPUS-1 is safe; a warning is logged if exceeded.
//
// Production path (IONA-OS#47): allocate Context per-CPU during SMP init,
// store pointer in PerCpu struct, read via GS. Eliminates the fixed limit.
// Until then: increase MAX_AP_CPUS for systems with >64 cores.
// TODO: for systems with >64 CPUs, allocate BOOTSTRAP_CTX per-CPU during
// SMP init and store the pointer in PerCpu::bootstrap_ctx (GS-relative).
// That removes the fixed-size array entirely. Tracked as IONA-OS#47.

pub unsafe fn run_task(ctx: *const Context) {
    // Per-CPU bootstrap context — stored statically so it's not on a stack
    // that shrinks after the switch.
    static mut BOOTSTRAP_CTX: [Context; MAX_AP_CPUS] = [Context::ZERO; MAX_AP_CPUS];
    let raw_id = crate::arch::x86_64::apic::local_apic_id() as usize;
    // Saturate at MAX_AP_CPUS-1 instead of silent wraparound with %
    // A system with >64 CPUs would need a larger array — log a warning.
    if raw_id >= MAX_AP_CPUS {
        crate::serial_println!(
            "[SMP] WARNING: CPU id {} >= MAX_AP_CPUS ({}) — clamping bootstrap ctx",
            raw_id, MAX_AP_CPUS);
    }
    let cpu_id = raw_id.min(MAX_AP_CPUS - 1);
    let dummy  = &mut BOOTSTRAP_CTX[cpu_id] as *mut Context;
    switch_to(dummy, ctx);
}

