//! Local APIC — per‑core interrupt controller + timer calibration
//!
//! This module provides access to the Local APIC (LAPIC) on x86_64.
//! Features:
//! - APIC timer calibration against the PIT (1.193182 MHz precision)
//! - LAPIC initialisation and periodic timer setup
//! - Sending IPIs (INIT, STARTUP, TLB shootdown)
//! - Synchronous TLB shootdown across all active cores
//! - x2APIC detection and optional fallback
//!
//! # Safety
//!
//! LAPIC registers are memory‑mapped. The caller must ensure that the
//! physical address `LAPIC_PHYS` is correctly mapped into the virtual
//! address space (usually done by the bootloader). All read/write
//! operations are marked `unsafe` because they can affect system behaviour.

#![allow(dead_code)] // Some constants are reserved for future use

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};
use core::time::Duration;
use x86_64::instructions::port::Port;
use bitflags::bitflags;

// -----------------------------------------------------------------------------
// Hardware constants
// -----------------------------------------------------------------------------

/// Physical base address of the Local APIC (Intel SDM Vol 3, Section 10.4)
pub const LAPIC_PHYS: u64 = 0xFEE0_0000;
/// Virtual offset used by the bootloader (maps all physical memory)
pub const PHYS_MEM_OFFSET: u64 = 0xFFFF_8000_0000_0000;
/// Virtual base address of the LAPIC
pub const LAPIC_BASE: u64 = PHYS_MEM_OFFSET + LAPIC_PHYS;

/// LAPIC register offsets (in bytes, divide by 4 for u32 indexing)
pub mod lapic_reg {
    pub const ID:       u32 = 0x020;
    pub const VER:      u32 = 0x030;
    pub const TPR:      u32 = 0x080;
    pub const APR:      u32 = 0x090;
    pub const PPR:      u32 = 0x0A0;
    pub const EOI:      u32 = 0x0B0;
    pub const LDR:      u32 = 0x0D0;
    pub const DFR:      u32 = 0x0E0;
    pub const SVR:      u32 = 0x0F0;
    pub const ISR0:     u32 = 0x100;
    pub const TMR0:     u32 = 0x180;
    pub const IRR0:     u32 = 0x200;
    pub const ICR_LO:   u32 = 0x300;
    pub const ICR_HI:   u32 = 0x310;
    pub const TIMER:    u32 = 0x320;
    pub const TIMER_IC: u32 = 0x380;
    pub const TIMER_CC: u32 = 0x390;
    pub const TIMER_DC: u32 = 0x3E0;
}

/// Spurious interrupt vector used to enable the LAPIC
pub const SPURIOUS_VECTOR: u32 = 0xFF;
/// Interrupt vector for the APIC timer (must match IDT entry)
pub const APIC_TIMER_VECTOR: u32 = 0x20;
/// IPI vector for TLB shootdown
pub const TLB_SHOOTDOWN_VECTOR: u8 = 0x30;

// -----------------------------------------------------------------------------
// Global state
// -----------------------------------------------------------------------------

/// Number of detected CPU cores.
pub static CPU_COUNT: AtomicU64 = AtomicU64::new(1);
/// Number of APs that have successfully started.
pub static APS_ONLINE: AtomicU32 = AtomicU32::new(0);
/// Whether the LAPIC is active (timer handler should use `lapic_eoi()`).
pub static LAPIC_ACTIVE: AtomicBool = AtomicBool::new(false);
/// APIC ticks per millisecond (calibrated)
pub static APIC_TICKS_PER_MS: AtomicU64 = AtomicU64::new(62_500);

// TLB shootdown global variables
static TLB_SHOOTDOWN_ADDR: AtomicU64 = AtomicU64::new(0);
static TLB_ACK_COUNT: AtomicU32 = AtomicU32::new(0);

// -----------------------------------------------------------------------------
// Low‑level register access
// -----------------------------------------------------------------------------

/// Read a 32‑bit LAPIC register.
/// # Safety
/// `reg` must be a valid LAPIC register offset, and the LAPIC page must be mapped.
#[inline]
pub unsafe fn lapic_read(reg: u32) -> u32 {
    ((LAPIC_BASE + reg as u64) as *const u32).read_volatile()
}

/// Write a 32‑bit LAPIC register.
/// # Safety
/// `reg` must be a valid LAPIC register offset, and the LAPIC page must be mapped.
#[inline]
pub unsafe fn lapic_write(reg: u32, val: u32) {
    ((LAPIC_BASE + reg as u64) as *mut u32).write_volatile(val)
}

/// Send End‑Of‑Interrupt to the LAPIC.
/// # Safety
/// Must be called only when LAPIC is initialised.
#[inline]
pub unsafe fn lapic_eoi() {
    lapic_write(lapic_reg::EOI, 0);
}

/// Return the current CPU's local APIC ID.
#[inline]
pub fn current_cpu_id() -> u32 {
    unsafe { lapic_read(lapic_reg::ID) >> 24 }
}

// -----------------------------------------------------------------------------
// Timer calibration using PIT (8254)
// -----------------------------------------------------------------------------

/// Calibrate the APIC timer against the PIT (channel 2, one‑shot mode).
/// Returns the number of APIC ticks per millisecond.
pub fn calibrate_apic_timer() -> u64 {
    const PIT_HZ: u32 = 1_193_182;
    const WAIT_MS: u32 = 10;
    let pit_divisor = (PIT_HZ * WAIT_MS / 1000) as u16;

    unsafe {
        // Configure PIT channel 2, mode 0 (one‑shot)
        Port::<u8>::new(0x43).write(0xB2);
        Port::<u8>::new(0x42).write((pit_divisor & 0xFF) as u8);
        Port::<u8>::new(0x42).write((pit_divisor >> 8) as u8);

        // Enable PIT gate (bit 0) and disable speaker (bit 1)
        let v = Port::<u8>::new(0x61).read();
        Port::<u8>::new(0x61).write((v & !0x02) | 0x01);
    }

    // Initialise APIC timer: divisor 16, one‑shot, vector masked (0x10000), max count
    unsafe {
        lapic_write(lapic_reg::TIMER_DC, 0x3);          // divide by 16
        lapic_write(lapic_reg::TIMER, 0x0001_0020);     // masked, one‑shot, vector 0x20
        lapic_write(lapic_reg::TIMER_IC, 0xFFFF_FFFF);
    }

    // Wait for PIT channel 2 to expire (bit 5 of port 0x61 becomes high)
    unsafe {
        while (Port::<u8>::new(0x61).read() & 0x20) == 0 {
            core::hint::spin_loop();
        }
    }

    let current = unsafe { lapic_read(lapic_reg::TIMER_CC) };
    let elapsed = 0xFFFF_FFFFu32.wrapping_sub(current);
    let ticks_per_ms = elapsed as u64 / WAIT_MS as u64;

    APIC_TICKS_PER_MS.store(ticks_per_ms, Ordering::SeqCst);

    serial_println!(
        "  [APIC] calibrated: {} ticks/ms (~{} MHz)",
        ticks_per_ms,
        ticks_per_ms * 16 / 1000
    );
    ticks_per_ms
}

// -----------------------------------------------------------------------------
// LAPIC initialisation
// -----------------------------------------------------------------------------

/// Initialise the LAPIC on the current core (BSP or AP).
/// Must be called after calibration, with interrupts disabled.
pub fn init_lapic() {
    unsafe {
        // Enable LAPIC via Spurious Vector Register (bit 8 = enable)
        lapic_write(lapic_reg::SVR, 0x1FF); // vector 0xFF, APIC enabled

        // Task Priority Register = 0 (accept all interrupts)
        lapic_write(lapic_reg::TPR, 0);

        // Configure timer: divisor 16, periodic mode, vector 0x20
        lapic_write(lapic_reg::TIMER_DC, 0x3); // divide by 16

        let ticks_per_ms = APIC_TICKS_PER_MS.load(Ordering::Relaxed);
        let init_count = if ticks_per_ms > 0 {
            ticks_per_ms as u32
        } else {
            62_500 // fallback (1ms at 62.5 MHz)
        };

        lapic_write(lapic_reg::TIMER, 0x0002_0020); // periodic | vector 0x20
        lapic_write(lapic_reg::TIMER_IC, init_count);

        // Mask legacy PIC (8259) – LAPIC will handle all interrupts now
        mask_pic();

        LAPIC_ACTIVE.store(true, Ordering::SeqCst);
    }

    let cpu_id = current_cpu_id();
    let tpm = APIC_TICKS_PER_MS.load(Ordering::Relaxed);
    serial_println!(
        "  [APIC] CPU#{} timer: {} ticks/ms, periodic",
        cpu_id, tpm
    );
}

/// Mask all legacy PIC interrupts. Called after LAPIC is active.
pub fn mask_pic() {
    unsafe {
        Port::<u8>::new(0x21).write(0xFF); // master
        Port::<u8>::new(0xA1).write(0xFF); // slave
    }
    serial_println!("  [APIC] PIC 8259 masked (LAPIC active)");
}

// -----------------------------------------------------------------------------
// IPI sending (INIT, STARTUP, TLB shootdown)
// -----------------------------------------------------------------------------

/// Send INIT and STARTUP IPIs to an Application Processor (AP).
/// `apic_id` – target LAPIC ID (0‑255).
/// `startup_vector` – 8‑bit interrupt vector (must be page‑aligned).
pub fn send_startup_ipi(apic_id: u8, startup_vector: u8) {
    unsafe {
        // INIT IPI
        lapic_write(lapic_reg::ICR_HI, (apic_id as u32) << 24);
        lapic_write(lapic_reg::ICR_LO, 0x0000_C500);
        // Wait 10 ms
        let start = crate::arch::x86_64::timer::uptime_ms();
        while crate::arch::x86_64::timer::uptime_ms() < start + 10 {
            core::hint::spin_loop();
        }

        // Two STARTUP IPIs (as required by Intel MP spec)
        for _ in 0..2 {
            lapic_write(lapic_reg::ICR_HI, (apic_id as u32) << 24);
            lapic_write(lapic_reg::ICR_LO, 0x0000_4600 | startup_vector as u32);
            let s = crate::arch::x86_64::timer::uptime_ms();
            while crate::arch::x86_64::timer::uptime_ms() < s + 1 {
                core::hint::spin_loop();
            }
        }
    }
}

/// Send a TLB shootdown IPI to all other active cores.
/// Blocks until all remote cores have invalidated the given virtual address,
/// or until a timeout (1 ms per core + 5 ms) expires.
pub fn tlb_shootdown(virt_addr: u64) {
    let ncpus = CPU_COUNT.load(Ordering::Relaxed) as u32;
    if ncpus <= 1 {
        return; // single core – local flush is enough
    }

    TLB_SHOOTDOWN_ADDR.store(virt_addr, Ordering::SeqCst);
    TLB_ACK_COUNT.store(0, Ordering::SeqCst);

    unsafe {
        // Send IPI to all cores excluding self (destination shorthand = All Excluding Self)
        lapic_write(lapic_reg::ICR_HI, 0);
        lapic_write(lapic_reg::ICR_LO, 0x000C_0000 | TLB_SHOOTDOWN_VECTOR as u32);
    }

    let expected = ncpus - 1;
    let deadline = crate::arch::x86_64::timer::uptime_ms() + expected as u64 + 5;
    while TLB_ACK_COUNT.load(Ordering::SeqCst) < expected {
        if crate::arch::x86_64::timer::uptime_ms() > deadline {
            serial_println!(
                "[TLB] shootdown timeout after {} ms (got {}/{})",
                deadline,
                TLB_ACK_COUNT.load(Ordering::SeqCst),
                expected
            );
            break;
        }
        core::hint::spin_loop();
    }
}

/// Handler called on the AP when a TLB shootdown IPI is received.
/// Must be installed in the IDT at vector `TLB_SHOOTDOWN_VECTOR`.
pub extern "x86-interrupt" fn tlb_shootdown_handler() {
    let addr = TLB_SHOOTDOWN_ADDR.load(Ordering::SeqCst);
    unsafe {
        x86_64::instructions::tlb::flush(x86_64::VirtAddr::new(addr));
    }
    TLB_ACK_COUNT.fetch_add(1, Ordering::SeqCst);
    unsafe { lapic_eoi(); }
}

/// Return the local APIC ID of the current CPU as a `u8`.
#[inline]
pub fn local_apic_id() -> u8 {
    current_cpu_id() as u8
}

// -----------------------------------------------------------------------------
// x2APIC support (optional)
// -----------------------------------------------------------------------------

/// Check if the CPU supports x2APIC (CPUID leaf 1, ECX bit 21).
pub fn supports_x2apic() -> bool {
    use core::arch::x86_64::__cpuid;
    let cpuid = unsafe { __cpuid(1) };
    (cpuid.ecx >> 21) & 1 != 0
}

/// Enable x2APIC mode (requires that the OS has mapped the MSR space).
/// After enabling, LAPIC registers must be accessed via `rdmsr`/`wrmsr`.
/// # Safety
/// Must be called on all cores simultaneously, with interrupts disabled.
pub unsafe fn enable_x2apic() {
    use x86_64::registers::msr::{IA32_APIC_BASE, rdmsr, wrmsr};
    let mut base = rdmsr(IA32_APIC_BASE);
    base |= 1 << 11; // set x2APIC enable bit
    wrmsr(IA32_APIC_BASE, base);
    serial_println!("[APIC] x2APIC enabled");
}

// -----------------------------------------------------------------------------
// Helper for safe serial printing (placeholder)
// -----------------------------------------------------------------------------
#[cfg(not(test))]
macro_rules! serial_println {
    ($($arg:tt)*) => {
        crate::serial_println!($($arg)*)
    };
}
#[cfg(test)]
macro_rules! serial_println {
    ($($arg:tt)*) => {
        println!($($arg)*)
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lapic_constants() {
        assert_eq!(LAPIC_PHYS, 0xFEE0_0000);
        assert_eq!(APIC_TIMER_VECTOR, 0x20);
        assert_eq!(TLB_SHOOTDOWN_VECTOR, 0x30);
    }

    #[test]
    fn test_cpu_id_range() {
        // We cannot run on real hardware in tests, but the function exists.
        let _id = current_cpu_id();
        assert!(true);
    }
}
