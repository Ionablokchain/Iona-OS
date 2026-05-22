//! Per‑CPU data — each core has its own structure.
//!
//! Access is via MSRs `IA32_GS_BASE` (kernel GS) and `IA32_KERNEL_GS_BASE`
//! (user GS). On syscall entry, `swapgs` makes GS point to the current
//! core’s `PerCpu` structure.
//!
//! # Memory layout (offsets from GS:0)
//! ```text
//! GS:0   = kernel_rsp  (kernel stack top on syscall entry)
//! GS:8   = user_rsp    (saved user stack on syscall)
//! GS:16  = current_tid (TID of the running task)
//! GS:24  = cpu_id      (APIC ID of this core)
//! GS:32  = sched_ptr   (pointer to the core’s `LocalScheduler`)
//! ```
//!
//! # Safety
//!
//! - The GS base must be correctly set before using any `gs`‑relative access.
//! - The `PerCpu` structure must be allocated and pinned (never moved).
//! - Access from assembly is safe only after `init_for_cpu` has been called
//!   on that CPU.

use core::sync::atomic::{AtomicU32, Ordering};
use x86_64::registers::model_specific::Msr;
use alloc::boxed::Box;

// -----------------------------------------------------------------------------
// MSR constants
// -----------------------------------------------------------------------------

/// MSR for the kernel GS base (used after `swapgs` in syscall entry).
const IA32_GS_BASE: u32 = 0xC000_0101;
/// MSR for the user GS base (saved by `swapgs`).
const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;

// -----------------------------------------------------------------------------
// Per‑CPU structure layout
// -----------------------------------------------------------------------------

/// Per‑CPU data — one instance per physical core.
///
/// The layout must match the offsets expected by assembly code
/// (syscall entry, interrupt handlers). Fields are 64‑bit aligned
/// where necessary.
#[repr(C)]
pub struct PerCpu {
    /// Kernel RSP for syscall entry (GS:0)
    pub kernel_rsp: u64,
    /// Saved user RSP on syscall (GS:8)
    pub user_rsp: u64,
    /// TID of the currently running task (GS:16)
    pub current_tid: u64,
    /// APIC ID of this core (GS:24)
    pub cpu_id: u32,
    /// Padding for alignment
    _pad: u32,
    /// Pointer to the top of the kernel stack for this core (GS:32)
    pub kstack_top: u64,
    /// APIC ticks per millisecond (calibrated at boot)
    pub apic_ticks_per_ms: u64,
    /// Safe‑copy window flag: 1 = kernel is in `copy_from/to_user`,
    /// 0 = idle. Used by the page fault handler to distinguish
    /// `EFAULT` from kernel bugs. Per‑CPU so concurrent syscalls on
    /// different cores do not interfere.
    pub in_safe_copy: u8,
    _pad2: [u8; 7],
}

impl PerCpu {
    /// Create a new `PerCpu` structure for a given CPU ID and kernel stack top.
    pub fn new(cpu_id: u32, kstack_top: u64) -> Box<Self> {
        Box::new(PerCpu {
            kernel_rsp: kstack_top,
            user_rsp: 0,
            current_tid: 0,
            cpu_id,
            _pad: 0,
            kstack_top,
            apic_ticks_per_ms: 0,
            in_safe_copy: 0,
            _pad2: [0u8; 7],
        })
    }
}

// -----------------------------------------------------------------------------
// Global per‑CPU storage
// -----------------------------------------------------------------------------

/// Global array of pointers to `PerCpu` structures, indexed by CPU ID.
/// Maximum 256 cores (fits within 8‑bit LAPIC ID).
static mut PER_CPU: [*mut PerCpu; 256] = [core::ptr::null_mut(); 256];

/// Number of CPUs that have been initialised.
static CPU_COUNT_REAL: AtomicU32 = AtomicU32::new(0);

/// Set to `true` once `init_for_cpu` has been called on the BSP (CPU 0).
/// Guards `GS`‑based reads (e.g., `current_tid`) against page faults
/// when the GS base is still zero.
pub static GS_READY: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

// -----------------------------------------------------------------------------
// Kernel stacks (static allocation for simplicity)
// -----------------------------------------------------------------------------

/// Size of each per‑CPU kernel stack (16 KiB).
const KSTACK_SIZE: usize = 16 * 1024;

/// A simple stack type with 16‑byte alignment.
#[repr(align(16))]
struct KernelStack([u8; KSTACK_SIZE]);

/// Static array of kernel stacks, one per core (max 64 cores in static mode).
/// For more cores, increase the array size or allocate dynamically.
static mut KSTACKS: [KernelStack; 64] = [const { KernelStack([0u8; KSTACK_SIZE]) }; 64];

// -----------------------------------------------------------------------------
// Initialisation
// -----------------------------------------------------------------------------

/// Initialise per‑CPU data for the current core and configure the GS base.
/// Called by the BSP (CPU 0) and by each AP after startup.
///
/// # Arguments
/// * `cpu_id` – The APIC ID of the current core (0–255).
pub fn init_for_cpu(cpu_id: u32) {
    // Obtain the top of the kernel stack for this core (aligned).
    let kstack = unsafe {
        let idx = cpu_id as usize % KSTACKS.len();
        let ptr = KSTACKS[idx].0.as_ptr() as u64;
        (ptr + KSTACK_SIZE as u64) & !0xF  // top, 16‑byte aligned
    };

    let percpu = PerCpu::new(cpu_id, kstack);
    let ptr = Box::into_raw(percpu);

    unsafe {
        PER_CPU[cpu_id as usize % PER_CPU.len()] = ptr;
    }

    // Set the GS base to the address of the `PerCpu` structure.
    unsafe {
        Msr::new(IA32_GS_BASE).write(ptr as u64);
        // Kernel GS base is zero initially (user GS not yet set).
        Msr::new(IA32_KERNEL_GS_BASE).write(0);
    }

    let _ = CPU_COUNT_REAL.fetch_add(1, Ordering::SeqCst);
    GS_READY.store(true, core::sync::atomic::Ordering::SeqCst);

    crate::serial_println!(
        "  [PERCPU] CPU#{} initialised, kstack=0x{:x}",
        cpu_id, kstack
    );
}

/// Initialise per‑CPU data for an Application Processor (AP).
/// Called from the AP entry point before entering the scheduler.
pub fn init_for_ap(cpu_id: u8) {
    init_for_cpu(cpu_id as u32);
}

// -----------------------------------------------------------------------------
// Accessor functions (using `gs`‑relative addressing)
// -----------------------------------------------------------------------------

/// Read the current TID from the GS of the current CPU.
/// Returns `0` if the GS base is not yet initialised.
#[inline]
pub fn current_tid() -> u64 {
    if !GS_READY.load(core::sync::atomic::Ordering::Relaxed) {
        return 0;
    }
    let tid: u64;
    unsafe { core::arch::asm!("mov {}, gs:16", out(reg) tid, options(nostack, nomem)); }
    tid
}

/// Set the current TID in the GS of the current CPU.
#[inline]
pub fn set_current_tid(tid: u64) {
    unsafe { core::arch::asm!("mov gs:16, {}", in(reg) tid, options(nostack, nomem)); }
}

/// Read the CPU ID from the GS of the current CPU.
#[inline]
pub fn current_cpu_id() -> u32 {
    if !GS_READY.load(core::sync::atomic::Ordering::Relaxed) {
        return 0;
    }
    let id: u32;
    unsafe { core::arch::asm!("mov {:e}, gs:24", out(reg) id, options(nostack, nomem)); }
    id
}

/// Read the kernel RSP from the GS of the current CPU.
#[inline]
pub fn kernel_rsp() -> u64 {
    if !GS_READY.load(core::sync::atomic::Ordering::Relaxed) {
        return 0;
    }
    let rsp: u64;
    unsafe { core::arch::asm!("mov {}, gs:0", out(reg) rsp, options(nostack, nomem)); }
    rsp
}

/// Set the kernel RSP in the GS of the current CPU.
#[inline]
pub fn set_kernel_rsp(rsp: u64) {
    if !GS_READY.load(core::sync::atomic::Ordering::Relaxed) {
        return;
    }
    unsafe { core::arch::asm!("mov gs:0, {}", in(reg) rsp, options(nostack, nomem)); }
}

/// Set the per‑CPU safe‑copy flag.
/// This indicates that the kernel is currently copying to/from user memory.
/// The page fault handler uses this to decide whether to return `EFAULT`.
#[inline]
pub fn set_safe_copy(val: bool) {
    let ptr = current_percpu_ptr();
    if !ptr.is_null() {
        unsafe { (*ptr).in_safe_copy = val as u8; }
    } else {
        // Fallback to a global variable if GS not initialised.
        crate::syscall::user_access::IS_SAFE_COPY.store(val, core::sync::atomic::Ordering::SeqCst);
    }
}

/// Check the per‑CPU safe‑copy flag.
#[inline]
pub fn is_safe_copy() -> bool {
    let ptr = current_percpu_ptr();
    if !ptr.is_null() {
        unsafe { (*ptr).in_safe_copy != 0 }
    } else {
        crate::syscall::user_access::IS_SAFE_COPY.load(core::sync::atomic::Ordering::SeqCst)
    }
}

/// Return the raw pointer to the current CPU’s `PerCpu` structure.
/// Returns `null()` if the GS base is not yet initialised or if the
/// pointer is zero.
#[inline]
fn current_percpu_ptr() -> *mut PerCpu {
    if !GS_READY.load(core::sync::atomic::Ordering::Relaxed) {
        return core::ptr::null_mut();
    }
    unsafe {
        let val: u64;
        core::arch::asm!(
            "mov {}, gs:[0]",
            out(reg) val,
            options(nostack, nomem, preserves_flags)
        );
        // GS:0 is the `kernel_rsp` field. If GS not set, it will be 0.
        if val == 0 {
            return core::ptr::null_mut();
        }
        let id = current_cpu_id() as usize % PER_CPU.len();
        PER_CPU[id]
    }
}

/// Return the number of CPUs that have been initialised.
pub fn cpu_count() -> u32 {
    CPU_COUNT_REAL.load(Ordering::Relaxed)
}

// -----------------------------------------------------------------------------
// Tests (compile‑time only)
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percpu_size_is_correct() {
        assert_eq!(core::mem::size_of::<PerCpu>(), 48);
        assert_eq!(core::mem::align_of::<PerCpu>(), 8);
    }
}
