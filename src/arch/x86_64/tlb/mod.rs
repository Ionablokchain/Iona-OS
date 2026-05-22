//! TLB shootdown — cross‑core TLB invalidation via IPI
//!
//! When one CPU modifies the page tables (CoW fault, `munmap`, `mprotect`),
//! other cores may still have stale TLB entries for those pages. Without a
//! shootdown, those cores would continue using the old mapping, leading to
//! memory corruption.
//!
//! # Protocol
//! 1. Core X modifies the page table and performs a local `invlpg`.
//! 2. Core X sends an IPI (vector `0x40`) to all other cores.
//! 3. Each receiving core runs the IPI handler, which executes `invlpg` on
//!    the given virtual address.
//! 4. Core X waits for all acknowledgements and continues.
//!
//! # IPI vector
//! The dedicated TLB shootdown vector is `0x40` → IDT entry 64.
//! The address to invalidate is stored in the global atomic
//! `TLB_SHOOTDOWN_ADDR`.

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use core::hint::spin_loop;
use crate::arch::x86_64::apic::{
    lapic_write, lapic_read, CPU_COUNT, LAPIC_ICR_LO, LAPIC_ICR_HI
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// IPI vector used for TLB shootdown (IDT[64]).
pub const TLB_SHOOTDOWN_VECTOR: u8 = 0x40;

/// Destination shorthand in ICR: All Excluding Self (11b)
const ICR_SHORTHAND_ALL_EXCLUDING_SELF: u32 = 0x000C_0000;
/// Delivery mode: Fixed (000b)
const ICR_DELIVERY_FIXED: u32 = 0x0000_0000;

// -----------------------------------------------------------------------------
// Global state
// -----------------------------------------------------------------------------

/// Virtual address to invalidate – written by the initiator, read by all cores.
pub static TLB_SHOOTDOWN_ADDR: AtomicU64 = AtomicU64::new(0);
/// Number of cores that have acknowledged the shootdown.
pub static TLB_ACK_COUNT: AtomicU64 = AtomicU64::new(0);
/// Serialisation lock – only one shootdown at a time.
static TLB_LOCK: AtomicBool = AtomicBool::new(false);

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Invalidate a single page on all cores (full TLB shootdown).
///
/// Must be called after:
/// - Copy‑on‑write fault → page remapped
/// - `munmap()` → pages unmapped
/// - `mprotect()` → protection flags changed
///
/// If there is only one core, only a local `invlpg` is performed.
///
/// # Panics
/// This function may spin indefinitely if an AP never responds. A timeout
/// is enforced (10 ms) after which the function gives up and logs a warning.
pub fn shootdown(virt_addr: u64) {
    let cpu_count = CPU_COUNT.load(Ordering::Relaxed) as u64;
    if cpu_count <= 1 {
        // Single core: local invalidation is enough.
        local_invlpg(virt_addr);
        return;
    }

    // Acquire exclusive lock for this shootdown.
    while TLB_LOCK.compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed).is_err() {
        spin_loop();
    }

    // Write the address to invalidate.
    TLB_SHOOTDOWN_ADDR.store(virt_addr, Ordering::SeqCst);
    TLB_ACK_COUNT.store(0, Ordering::SeqCst);

    // Invalidate locally first.
    local_invlpg(virt_addr);

    // Send IPI to all other cores (broadcast, excluding self).
    // ICR low: vector = 0x40, delivery = Fixed, shorthand = All Excluding Self.
    unsafe {
        lapic_write(LAPIC_ICR_HI, 0);
        lapic_write(
            LAPIC_ICR_LO,
            ICR_SHORTHAND_ALL_EXCLUDING_SELF
                | ICR_DELIVERY_FIXED
                | (TLB_SHOOTDOWN_VECTOR as u32)
        );
    }

    // Wait for acknowledgements from all APs.
    let expected = cpu_count - 1;
    let deadline = crate::arch::x86_64::timer::uptime_ms() + 10; // 10 ms timeout
    while TLB_ACK_COUNT.load(Ordering::SeqCst) < expected {
        if crate::arch::x86_64::timer::uptime_ms() > deadline {
            crate::serial_println!(
                "[TLB] shootdown timeout after 10 ms (got {}/{})",
                TLB_ACK_COUNT.load(Ordering::SeqCst),
                expected
            );
            break;
        }
        spin_loop();
    }

    TLB_LOCK.store(false, Ordering::SeqCst);
}

/// Invalidate a range of pages `[start, start + size)`.
///
/// # Arguments
/// * `start` – Start virtual address (page‑aligned recommended).
/// * `size` – Size in bytes (may be unaligned; the function rounds up).
pub fn shootdown_range(start: u64, size: u64) {
    let pages = (size + 4095) / 4096;
    for i in 0..pages {
        shootdown(start + i * 4096);
    }
}

/// Handler called on each AP when it receives a TLB shootdown IPI.
/// Must be installed in the IDT at vector `TLB_SHOOTDOWN_VECTOR`.
///
/// # Safety
/// Called from an interrupt context. Must send EOI afterwards.
pub extern "x86-interrupt" fn shootdown_handler() {
    let addr = TLB_SHOOTDOWN_ADDR.load(Ordering::SeqCst);
    local_invlpg(addr);
    TLB_ACK_COUNT.fetch_add(1, Ordering::SeqCst);
    unsafe { crate::arch::x86_64::apic::lapic_eoi(); }
}

/// Invalidate a single page in the current CPU’s TLB.
#[inline(always)]
pub fn local_invlpg(virt_addr: u64) {
    unsafe {
        core::arch::asm!(
            "invlpg [{addr}]",
            addr = in(reg) virt_addr,
            options(nostack, preserves_flags),
        );
    }
}

/// Flush the entire TLB by reloading `CR3`.
#[inline(always)]
pub fn flush_all() {
    unsafe {
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, nomem));
        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, nomem));
    }
}
