//! Per-CPU data — fiecare core are structura lui proprie
//!
//! Accesat via MSR IA32_GS_BASE (kernel GS) și IA32_KERNEL_GS_BASE (user GS).
//! La syscall entry: swapgs → GS pointează la PerCpu al core-ului curent.
//!
//! Layout în memorie (offset de la GS:0):
//!   GS:0   = kernel_rsp  (stack kernel la syscall entry)
//!   GS:8   = user_rsp    (stack user salvat la syscall)
//!   GS:16  = current_tid (TID task care rulează)
//!   GS:24  = cpu_id      (APIC ID al acestui core)
//!   GS:32  = sched_ptr   (pointer la LocalScheduler al acestui core)

use core::sync::atomic::{AtomicU32, Ordering};
use x86_64::registers::model_specific::Msr;
use alloc::boxed::Box;

const IA32_GS_BASE:        u32 = 0xC000_0101;
const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;

/// Per-CPU data structure — unul per core fizic
#[repr(C)]
pub struct PerCpu {
    /// Kernel RSP pentru syscall entry (GS:0)
    pub kernel_rsp:  u64,
    /// User RSP salvat la syscall (GS:8)
    pub user_rsp:    u64,
    /// TID task curent (GS:16)
    pub current_tid: u64,
    /// APIC ID al acestui core (GS:24)
    pub cpu_id:      u32,
    _pad:            u32,
    /// Pointer la kernel stack top pentru acest core (GS:32)
    pub kstack_top:  u64,
    /// Ticks APIC per ms (calibrat la boot)
    pub apic_ticks_per_ms: u64,
    /// Safe-copy window: 1 = kernel is in copy_from/to_user, 0 = idle
    /// Used by IDT page_fault_handler to distinguish EFAULT from kernel bug.
    /// Per-CPU so concurrent syscalls on different cores don't interfere.
    pub in_safe_copy: u8,
    _pad2: [u8; 7],
}

impl PerCpu {
    pub fn new(cpu_id: u32, kstack_top: u64) -> Box<Self> {
        // in_safe_copy: 0 = not in safe-copy window
        Box::new(PerCpu {
            kernel_rsp:        kstack_top,
            user_rsp:          0,
            current_tid:       0,
            cpu_id,
            _pad:              0,
            kstack_top,
            apic_ticks_per_ms: 0,
            in_safe_copy:      0,
            _pad2:             [0u8; 7],
        })
    }
}

/// Per-CPU storage — max 256 cores
static mut PER_CPU: [*mut PerCpu; 256] = [core::ptr::null_mut(); 256];
static CPU_COUNT_REAL: AtomicU32 = AtomicU32::new(0);

/// Set to true once init_for_cpu(0) has been called on BSP.
/// Guards GS-based reads (current_tid, etc.) against #PF when GS base is 0.
pub static GS_READY: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Kernel stack pentru fiecare core (16KB per core)
const KSTACK_SIZE: usize = 16 * 1024;

#[repr(align(16))]
struct KernelStack([u8; KSTACK_SIZE]);
static mut KSTACKS: [KernelStack; 64] = [const { KernelStack([0u8; KSTACK_SIZE]) }; 64];

/// Inițializează per-CPU data pentru core-ul curent și configurează GS.
/// Apelat de BSP (cpu_id=0) și de fiecare AP după startup.
pub fn init_for_cpu(cpu_id: u32) {
    let kstack = unsafe {
        let idx = cpu_id as usize % 64;
        let ptr = KSTACKS[idx].0.as_ptr() as u64;
        (ptr + KSTACK_SIZE as u64) & !0xF  // top, aliniat 16 bytes
    };

    let percpu = PerCpu::new(cpu_id, kstack);
    let ptr = Box::into_raw(percpu);

    unsafe {
        PER_CPU[cpu_id as usize % 256] = ptr;
    }

    // Setăm GS base la adresa structurii PerCpu
    unsafe {
        Msr::new(IA32_GS_BASE).write(ptr as u64);
        // KERNEL_GS_BASE = 0 (user GS e zero inițial)
        Msr::new(IA32_KERNEL_GS_BASE).write(0);
    }

    let _n = CPU_COUNT_REAL.fetch_add(1, Ordering::SeqCst) + 1;
    GS_READY.store(true, core::sync::atomic::Ordering::SeqCst);
    crate::serial_println!("  [PERCPU] CPU#{} initialized, kstack=0x{:x}", cpu_id, kstack);
}

/// Citește câmpul current_tid din GS al core-ului curent.
/// Returns 0 if GS base is not yet initialized (before init_for_cpu).
#[inline]
pub fn current_tid() -> u64 {
    if !GS_READY.load(core::sync::atomic::Ordering::Relaxed) {
        return 0;
    }
    let tid: u64;
    unsafe { core::arch::asm!("mov {}, gs:16", out(reg) tid, options(nostack, nomem)); }
    tid
}

/// Setează current_tid în GS al core-ului curent
#[inline]
pub fn set_current_tid(tid: u64) {
    unsafe { core::arch::asm!("mov gs:16, {}", in(reg) tid, options(nostack, nomem)); }
}

/// Citește cpu_id din GS
#[inline]
pub fn current_cpu_id() -> u32 {
    if !GS_READY.load(core::sync::atomic::Ordering::Relaxed) {
        return 0;
    }
    let id: u32;
    unsafe { core::arch::asm!("mov {:e}, gs:24", out(reg) id, options(nostack, nomem)); }
    id
}

/// Citește kernel_rsp din GS
#[inline]
pub fn kernel_rsp() -> u64 {
    if !GS_READY.load(core::sync::atomic::Ordering::Relaxed) {
        return 0;
    }
    let rsp: u64;
    unsafe { core::arch::asm!("mov {}, gs:0", out(reg) rsp, options(nostack, nomem)); }
    rsp
}

/// Setează kernel_rsp în GS (la context switch kernel task)
#[inline]
/// Per-CPU safe-copy flag — set when kernel is copying to/from user memory
#[inline]
pub fn set_safe_copy(val: bool) {
    // Write to current CPU's PerCpu struct via GS
    // Falls back to global IS_SAFE_COPY if GS not initialized
    let ptr = current_percpu_ptr();
    if !ptr.is_null() {
        unsafe { (*ptr).in_safe_copy = val as u8; }
    } else {
        crate::syscall::user_access::IS_SAFE_COPY
            .store(val, core::sync::atomic::Ordering::SeqCst);
    }
}

/// Check safe-copy flag on current CPU
#[inline]
pub fn is_safe_copy() -> bool {
    let ptr = current_percpu_ptr();
    if !ptr.is_null() {
        unsafe { (*ptr).in_safe_copy != 0 }
    } else {
        crate::syscall::user_access::IS_SAFE_COPY
            .load(core::sync::atomic::Ordering::SeqCst)
    }
}

/// Get raw pointer to current CPU's PerCpu (null if GS not set up)
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
        // GS:0 = kernel_rsp field. If GS not set up → value 0
        if val == 0 { return core::ptr::null_mut(); }
        let percpu_ptr = PER_CPU[current_cpu_id() as usize % 256];
        percpu_ptr
    }
}

pub fn set_kernel_rsp(rsp: u64) {
    if !GS_READY.load(core::sync::atomic::Ordering::Relaxed) { return; }
    unsafe { core::arch::asm!("mov gs:0, {}", in(reg) rsp, options(nostack, nomem)); }
}

/// Returnează numărul de core-uri inițializate
pub fn cpu_count() -> u32 {
    CPU_COUNT_REAL.load(Ordering::Relaxed)
}

/// Initialize per-CPU data for an Application Processor
/// Called from AP entry point before entering scheduler
pub fn init_for_ap(cpu_id: u8) {
    init_for_cpu(cpu_id as u32);
}
