//! SMP — Application Processor startup
//!
//! This module implements the initialisation of secondary CPU cores (APs)
//! on x86_64 systems. It uses the Local APIC to send INIT and STARTUP
//! IPIs and waits for each AP to signal that it is online.
//!
//! # Overview
//!
//! 1. Detect the number of logical CPUs using the `CPUID` instruction.
//! 2. For each AP (excluding the BSP, core 0), send an INIT IPI, wait,
//!    then send two STARTUP IPIs with a 16‑byte aligned vector address.
//! 3. Wait up to 100 ms for each AP to increment `APS_ONLINE`.
//! 4. Mark SMP as ready, allowing the scheduler to use other cores.
//!
//! # Entry point
//!
//! The APs start executing at the address given by the STARTUP vector
//! (e.g., `0x8000`). That code must jump to `ap_main` after setting up
//! a minimal environment (GDT, IDT, etc.).

use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use crate::arch::x86_64::apic::{send_startup_ipi, CPU_COUNT, APS_ONLINE};

/// Set to `true` once all APs have been started and are ready.
pub static SMP_READY: AtomicBool = AtomicBool::new(false);

/// Detect the number of logical CPUs (cores + hyper‑threading) using `CPUID`.
/// Returns a value between 1 and 64 (capped for safety).
///
/// # CPUID leaf 0xB (Extended Topology Enumeration)
/// - ECX = 0, subleaf 0 returns the number of logical processors in EBX.
/// - The value in EBX is the number of cores/threads.
pub fn detect_cpu_count() -> usize {
    let result: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {0:e}, ebx",
            "pop rbx",
            out(reg) result,
            in("eax") 0xBu32,   // leaf: extended topology
            in("ecx") 0u32,     // subleaf 0
            options(nostack),
        );
    }
    let n = (result & 0xFFFF) as usize;
    if n == 0 { 1 } else { n.min(64) }
}

/// Initialise SMP: detect CPU count, start all APs, and wait for them
/// to come online. Must be called after the BSP’s LAPIC is initialised
/// and the AP startup code is placed at the startup vector address.
pub fn init() {
    let count = detect_cpu_count();
    crate::serial_println!("  [SMP] {} logical CPU(s) detected", count);
    CPU_COUNT.store(count as u64, Ordering::SeqCst);

    if count > 1 {
        // The startup vector must be 4 KiB aligned (0x8000 is typical).
        // In real hardware, the AP boot code should be copied there.
        const STARTUP_VECTOR: u8 = 0x08; // address = 0x08 * 0x1000 = 0x8000

        for ap_id in 1u8..count as u8 {
            send_startup_ipi(ap_id, STARTUP_VECTOR);

            // Wait up to 100 ms for this AP to set its online bit.
            let deadline = crate::arch::x86_64::timer::uptime_ms() + 100;
            while crate::arch::x86_64::timer::uptime_ms() < deadline {
                if APS_ONLINE.load(Ordering::SeqCst) >= ap_id as u32 {
                    break;
                }
                core::hint::spin_loop();
            }
            if APS_ONLINE.load(Ordering::SeqCst) < ap_id as u32 {
                crate::serial_println!(
                    "  [SMP] WARNING: AP#{} failed to respond within 100 ms",
                    ap_id
                );
            }
        }
    }

    SMP_READY.store(true, Ordering::SeqCst);
    crate::serial_println!(
        "  [SMP] {} APs online",
        APS_ONLINE.load(Ordering::SeqCst)
    );
}

/// Entry point for each Application Processor (AP).
/// This function is called from the AP bootstrap assembly code.
/// It initialises the CPU’s GDT, IDT, LAPIC, per‑CPU data, and local
/// scheduler, then enables interrupts and halts.
///
/// # Arguments
/// * `id` – The APIC ID of this core.
///
/// # Safety
/// This function never returns. It must be called with a valid stack,
/// and interrupts must be disabled.
#[no_mangle]
pub extern "C" fn ap_main(id: u32) -> ! {
    crate::arch::gdt::init();
    crate::arch::idt::init();
    crate::arch::x86_64::apic::init_lapic();

    // Initialise per‑CPU data (including GS base)
    crate::arch::x86_64::percpu::init_for_cpu(id);
    crate::sched::local::init_for_cpu(id);

    APS_ONLINE.fetch_add(1, Ordering::SeqCst);
    crate::serial_println!("  [SMP] AP#{} ready", id);

    // Enable interrupts on this core (timer, IPIs, etc.)
    x86_64::instructions::interrupts::enable();

    // Halt until an interrupt (e.g., scheduler IPI) wakes the core.
    loop {
        x86_64::instructions::hlt();
    }
}
