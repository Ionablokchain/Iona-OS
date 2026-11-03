//! SMP — Symmetric Multi-Processing.
//!
//! Brings the BSP and every Application Processor (AP) into a state where
//! they are all running the local per-CPU scheduler with interrupts
//! enabled and a real GDT/IDT/LAPIC.
//!
//! # Architecture
//!
//! This module is **x86_64-only**. On aarch64 the equivalent bringup
//! lives in `crate::arch::aarch64::smp`. Callers that are
//! architecture-neutral should call `crate::arch::smp::init()` (which
//! cfg-dispatches) rather than `crate::smp::init()` directly.
//!
//! # Boot sequence
//!
//! 1. `detect_cpu_count` reads the CPUID topology.
//! 2. `init`:
//!    - initialises the BSP's local scheduler,
//!    - sends a SIPI to every AP **in a single burst**,
//!    - waits up to [`AP_BOOT_TIMEOUT_MS`] for all of them to come
//!      online,
//!    - logs a warning for any AP that does not report in.
//! 3. `ap_main(id)` runs on each AP: GDT, IDT, LAPIC, per-CPU data,
//!    local scheduler, then idle.
//!
//! # Idempotency
//!
//! `init` is idempotent: a second call returns immediately without
//! re-sending SIPIs. This matters because some boot paths call `init`
//! from both early init and from a later stage.
//!
//! # BSP vs AP vs self
//!
//! `tlb_shootdown` and `broadcast_ipi` compute the local CPU's ID from
//! the LAPIC and **skip it** — a caller on CPU 3 does not send an IPI to
//! CPU 0 as a side effect.

pub mod scheduler;
pub use scheduler::*;

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::arch::x86_64::apic::{
    self, local_apic_id, send_startup_ipi, APS_ONLINE, CPU_COUNT,
};
use crate::arch::x86_64::timer::uptime_ms;

// ── Limits and constants ──────────────────────────────────────────────────

/// Hard cap on supported logical CPUs.
///
/// Enforced by the local scheduler (`LOCAL_SCHEDS` is sized to this), by
/// `CPU_COUNT`, and by the iteration in `init`. Callers that report more
/// than this through CPUID are clamped with a warning.
pub const MAX_CPUS: u8 = 64;

/// SIPI vector pointing at the AP trampoline (physical address
/// `SIPI_VECTOR << 12`).
const SIPI_VECTOR: u8 = 0x08;

/// Inter-processor interrupt vector used for TLB shootdown.
const IPI_TLB_SHOOTDOWN: u8 = 0xF0;

/// Maximum time to wait for APs to report online after the SIPI burst.
const AP_BOOT_TIMEOUT_MS: u64 = 2_000;

/// Local APIC ICR (Interrupt Command Register) MMIO addresses.
///
/// The addresses are physical; they must be mapped through the direct
/// map or the LAPIC window before use.
const LAPIC_ICR_LO: usize = 0xFEE0_0300;
const LAPIC_ICR_HI: usize = 0xFEE0_0310;

/// ICR low: delivery-status bit (0 = idle, 1 = pending).
const ICR_DELIVERY_STATUS: u32 = 1 << 12;
/// ICR low: level (1 = assert).
const ICR_LEVEL_ASSERT: u32 = 1 << 14;

/// Maximum spin iterations while waiting for a single IPI delivery.
///
/// Used instead of a millisecond deadline because the timer is not
/// guaranteed to be running during early boot.
const ICR_DELIVERY_SPIN_LIMIT: u32 = 1_000_000;

/// Number of CPUID topology levels to scan before giving up.
const MAX_CPUID_TOPOLOGY_LEVELS: u32 = 8;

// ── Global state ──────────────────────────────────────────────────────────

/// Set to `true` once `init()` has finished bringing APs online.
pub static SMP_READY: AtomicBool = AtomicBool::new(false);

/// Number of APs that have reported online. Equivalent to
/// [`APS_ONLINE`] but kept here so callers don't need to reach into the
/// APIC module.
static APS_REPORTED: AtomicU32 = AtomicU32::new(0);

// ── CPUID helpers ─────────────────────────────────────────────────────────

/// Highest basic CPUID leaf supported by the CPU.
#[inline]
fn cpuid_max_leaf() -> u32 {
    let eax: u32;
    // SAFETY: CPUID is available on every x86_64 CPU. RBX is preserved
    // via the push/pop dance (LLVM reserves rbx on the SysV ABI).
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            inlateout("eax") 0u32 => eax,
            out("ecx") _,
            out("edx") _,
            options(preserves_flags),
        );
    }
    eax
}

/// Full CPUID result for a given (leaf, subleaf).
#[inline]
fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let (eax, ebx, ecx, edx);
    // SAFETY: see `cpuid_max_leaf`. Every output register is declared.
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            ebx_out = out(reg) ebx,
            inlateout("eax") leaf => eax,
            inlateout("ecx") subleaf => ecx,
            out("edx") edx,
            options(preserves_flags),
        );
    }
    (eax, ebx, ecx, edx)
}

/// Number of logical CPUs, clamped to `[1, MAX_CPUS]`.
///
/// Uses CPUID leaf 0xB when available (modern topology), falling back to
/// leaf 1 EBX[23:16] on older CPUs.
pub fn detect_cpu_count() -> usize {
    let max_leaf = cpuid_max_leaf();
    let raw = if max_leaf >= 0x0B {
        // Enumerate topology levels. ECX[15:8] == 0 means "invalid level"
        // (end of enumeration); EBX is the number of logical processors
        // at that level. The maximum over all levels is the total.
        let mut total: u32 = 0;
        for level in 0..MAX_CPUID_TOPOLOGY_LEVELS {
            let (_, ebx, ecx, _) = cpuid(0x0B, level);
            if ((ecx >> 8) & 0xFF) == 0 {
                break;
            }
            if ebx > total {
                total = ebx;
            }
        }
        if total == 0 {
            // Leaf 0xB present but reported nothing; fall back.
            let (_, ebx, _, _) = cpuid(1, 0);
            (ebx >> 16) & 0xFF
        } else {
            total
        }
    } else {
        // Legacy: leaf 1 EBX[23:16] = logical processors per package.
        let (_, ebx, _, _) = cpuid(1, 0);
        (ebx >> 16) & 0xFF
    };

    let n = raw.max(1) as usize;
    let capped = n.min(MAX_CPUS as usize);
    if capped < n {
        crate::serial_println!(
            "  [SMP] WARNING: CPUID reported {} CPUs, clamped to {}",
            n,
            MAX_CPUS
        );
    }
    capped
}

// ── Bringup ───────────────────────────────────────────────────────────────

/// Bring every AP online and start the BSP's local scheduler.
///
/// Idempotent: a second call returns immediately.
pub fn init() {
    if SMP_READY.load(Ordering::Acquire) {
        crate::serial_println!("  [SMP] already initialised, skipping");
        return;
    }

    let count = detect_cpu_count();
    crate::serial_println!("  [SMP] {} logical CPU(s)", count);
    CPU_COUNT.store(count as u64, Ordering::Release);

    // Local scheduler for the BSP.
    scheduler::init_local(0);

    if count > 1 {
        bring_up_aps(count);
    }

    SMP_READY.store(true, Ordering::Release);
    crate::serial_println!(
        "  [SMP] {} AP(s) online, local schedulers ready",
        APS_REPORTED.load(Ordering::Acquire)
    );
}

/// Send one SIPI to every AP, then wait for the whole batch.
///
/// Batching the SIPIs and waiting once is strictly better than the
/// previous per-AP `send + wait` loop: it lets APs boot in parallel and
/// turns `N × per-AP-timeout` into a single `total-timeout`.
fn bring_up_aps(count: usize) {
    let ap_count = count.saturating_sub(1).min(MAX_CPUS as usize - 1);
    crate::serial_println!("  [SMP] sending SIPI to {} AP(s)", ap_count);

    for id in 1..=ap_count {
        // SAFETY: `id ∈ [1, MAX_CPUS)`. The trampoline was prepared by
        // the BSP before `smp::init` was called. Interrupts are
        // disabled at this point in boot.
        unsafe {
            send_startup_ipi(id as u8, SIPI_VECTOR);
        }
    }

    let deadline = uptime_ms().saturating_add(AP_BOOT_TIMEOUT_MS);
    while uptime_ms() < deadline {
        if APS_REPORTED.load(Ordering::Acquire) >= ap_count as u32 {
            return;
        }
        core::hint::spin_loop();
    }

    let online = APS_REPORTED.load(Ordering::Acquire);
    if (online as usize) < ap_count {
        crate::serial_println!(
            "  [SMP] WARNING: only {}/{} APs online after {} ms",
            online,
            ap_count,
            AP_BOOT_TIMEOUT_MS
        );
    }
}

// ── AP entry point ────────────────────────────────────────────────────────

/// Canonical AP entry point. Called by the trampoline with the SIPI
/// destination (the LAPIC ID).
///
/// # Safety (of the caller's contract)
///
/// The trampoline must ensure:
///
/// 1. The CPU is in long mode with a stack large enough for the boot code.
/// 2. `id` is the LAPIC ID of **this** CPU (matching the SIPI destination).
/// 3. Interrupts are disabled.
#[no_mangle]
pub extern "C" fn ap_main(id: u32) -> ! {
    // Defence in depth: the trampoline is the single source of truth for
    // the CPU ID, but a mismatch is almost always a bug worth surfacing.
    let lapic_id = local_apic_id() as u32;
    if lapic_id != id {
        crate::serial_println!(
            "  [SMP] WARNING: ap_main(id={}) vs lapic_id={} mismatch",
            id,
            lapic_id
        );
    }

    if id == 0 || id >= MAX_CPUS as u32 {
        crate::serial_println!("  [SMP] FATAL: ap_main with invalid id {}", id);
        idle_forever();
    }

    // Per-CPU early state.
    crate::arch::gdt::init();
    crate::arch::idt::init();
    apic::init_lapic();
    crate::arch::x86_64::percpu::init_for_cpu(id);

    // Local scheduler. Without this, any task dispatched to this CPU by
    // `schedule_local` would find an empty slot and be dropped.
    scheduler::init_local(id);

    // Report online before enabling interrupts so the BSP's wait loop
    // sees us before we start executing scheduler code.
    APS_REPORTED.fetch_add(1, Ordering::AcqRel);
    APS_ONLINE.fetch_add(1, Ordering::AcqRel);

    crate::serial_println!("  [SMP] AP#{} ready", id);

    // Enable interrupts; the timer will drive scheduling from here.
    enable_interrupts();

    // Idle loop. Each wakeup from `hlt` is either a timer interrupt
    // (which will context-switch to a task if one is ready) or an IPI
    // (reschedule, TLB shootdown, etc.). Calling `schedule_local` on
    // each iteration opportunistically tops up the local queue via work
    // stealing; the actual context switch happens in the timer handler.
    loop {
        scheduler::schedule_local(id);
        idle_once();
    }
}

/// Compatibility shim. Some older code paths referenced
/// `ap_scheduler_entry`; the canonical entry is now [`ap_main`].
///
/// Delegates to `ap_main` with the LAPIC ID, so the two paths cannot
/// diverge.
#[no_mangle]
pub extern "C" fn ap_scheduler_entry() -> ! {
    let cpu_id = local_apic_id() as u32;
    crate::serial_println!(
        "[SMP] ap_scheduler_entry: delegating to ap_main({})",
        cpu_id
    );
    ap_main(cpu_id)
}

// ── IPIs ──────────────────────────────────────────────────────────────────

/// Send a fixed-delivery IPI to `cpu_id`.
///
/// `cpu_id` is the LAPIC ID of the destination. Out-of-range IDs are
/// logged and ignored — writing a bogus APIC ID into the ICR would send
/// the interrupt to a completely different CPU.
pub fn send_ipi(cpu_id: u8, vector: u8) {
    if cpu_id >= MAX_CPUS {
        crate::serial_println!("  [SMP] WARNING: send_ipi to out-of-range CPU {}", cpu_id);
        return;
    }

    // SAFETY: the LAPIC MMIO region is mapped and accessible from ring 0
    // after `apic::init_lapic`. The addresses are the architectural ICR
    // registers defined in the Intel SDM (Vol 3A, §10.6).
    unsafe {
        let icr_lo = LAPIC_ICR_LO as *mut u32;
        let icr_hi = LAPIC_ICR_HI as *mut u32;

        // Destination APIC ID in bits 24..31 (physical mode).
        icr_hi.write_volatile((cpu_id as u32) << 24);

        // Fixed delivery (bits 8..10 = 0), physical destination (bit 11 = 0),
        // assert level (bit 14 = 1), edge trigger (bit 15 = 0).
        icr_lo.write_volatile((vector as u32) | ICR_LEVEL_ASSERT);

        // Bounded spin on delivery status. A spin counter is used
        // instead of `uptime_ms` because the timer is not guaranteed to
        // advance during early boot.
        let mut spins: u32 = 0;
        while icr_lo.read_volatile() & ICR_DELIVERY_STATUS != 0 {
            if spins >= ICR_DELIVERY_SPIN_LIMIT {
                break;
            }
            core::hint::spin_loop();
            spins = spins.wrapping_add(1);
        }
    }
}

/// Invalidate `vaddr` on every CPU.
///
/// The local TLB is invalidated first, then every peer is notified. On
/// return, no CPU should have a stale translation for `vaddr` after it
/// processes the IPI.
pub fn tlb_shootdown(vaddr: u64) {
    // Local invalidation first. This is cheaper than an IPI and, if a
    // peer IPI is lost, the local CPU is at least consistent.
    // SAFETY: `invlpg` is a privileged instruction valid in ring 0.
    unsafe {
        asm!("invlpg [{addr}]", addr = in(reg) vaddr, options(nostack, preserves_flags));
    }

    let ncpus = CPU_COUNT.load(Ordering::Acquire).min(MAX_CPUS as u64) as u8;
    let self_id = local_apic_id();
    for cpu in 0..ncpus {
        if cpu == self_id {
            continue;
        }
        send_ipi(cpu, IPI_TLB_SHOOTDOWN);
    }
}

/// Send `vector` to every CPU except the caller.
pub fn broadcast_ipi(vector: u8) {
    let ncpus = CPU_COUNT.load(Ordering::Acquire).min(MAX_CPUS as u64) as u8;
    let self_id = local_apic_id();
    for cpu in 0..ncpus {
        if cpu == self_id {
            continue;
        }
        send_ipi(cpu, vector);
    }
}

// ── Queries ───────────────────────────────────────────────────────────────

/// Whether SMP bringup has completed.
#[inline]
#[must_use]
pub fn is_active() -> bool {
    SMP_READY.load(Ordering::Acquire)
}

/// Number of APs that have reported online.
#[inline]
#[must_use]
pub fn aps_online() -> u32 {
    APS_REPORTED.load(Ordering::Acquire)
}

// ── Arch primitives ───────────────────────────────────────────────────────

#[inline]
fn enable_interrupts() {
    // SAFETY: `sti` enables maskable interrupts. The IDT must already be
    // loaded (`idt::init` above).
    unsafe {
        asm!("sti", options(nostack, preserves_flags));
    }
}

/// Halt the local CPU until the next interrupt.
#[inline]
fn idle_once() {
    // SAFETY: `hlt` is privileged, valid in ring 0, and returns when an
    // enabled interrupt is delivered. Interrupts must be enabled.
    unsafe {
        asm!("hlt", options(nostack, preserves_flags));
    }
}

/// Disable interrupts and halt forever. Used for unrecoverable states
/// during AP bringup.
fn idle_forever() -> ! {
    // SAFETY: `cli` disables maskable interrupts; `hlt` stops the CPU.
    unsafe {
        asm!("cli", options(nostack, preserves_flags));
        loop {
            asm!("hlt", options(nostack, preserves_flags));
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_count_is_in_range() {
        let n = detect_cpu_count();
        assert!((1..=MAX_CPUS as usize).contains(&n), "count = {n}");
    }

    #[test]
    fn max_cpus_is_a_power_of_two() {
        // LAPIC IDs are allocated in power-of-two ranges on modern
        // hardware; this sanity-checks the array sizing assumption used
        // by the local scheduler.
        assert!(MAX_CPUS.is_power_of_two());
    }

    #[test]
    fn constants_are_within_lapic_limits() {
        // LAPIC destination IDs are 8 bits on xAPIC; MAX_CPUS must fit.
        assert!(MAX_CPUS as u32 <= 0xFF);
        // 0xF0 is a valid vector (>= 0x20, not reserved for exceptions).
        assert!(IPI_TLB_SHOOTDOWN >= 0x20);
        // SIPI vector 0x08 targets physical address 0x8000.
        assert_eq!(SIPI_VECTOR, 0x08);
    }
}
