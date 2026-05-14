//! Local APIC — per-core interrupt controller + timer calibration
//!
//! Calibrare APIC timer față de PIT (precis la 1.193182 MHz):
//!   1. Setăm APIC timer cu valoare maximă (0xFFFFFFFF)
//!   2. Așteptăm exact 10ms via PIT (busy-wait precis)
//!   3. Citim valoarea curentă a APIC timer
//!   4. ticks_per_10ms = 0xFFFFFFFF - current_value
//!   5. ticks_per_ms   = ticks_per_10ms / 10

use core::sync::atomic::{AtomicU64, AtomicU32, Ordering};
use x86_64::instructions::port::Port;

/// Physical address of the Local APIC registers.
pub const LAPIC_PHYS:     u64 = 0xFEE0_0000;
/// Virtual base = phys-memory-offset + LAPIC physical address.
/// The bootloader maps all physical memory at 0xFFFF_8000_0000_0000.
pub const LAPIC_BASE:     u64 = 0xFFFF_8000_0000_0000 + LAPIC_PHYS;
pub const LAPIC_ID:       u32 = 0x020;
pub const LAPIC_VERSION:  u32 = 0x030;
pub const LAPIC_EOI:      u32 = 0x0B0;
pub const LAPIC_SVR:      u32 = 0x0F0;
pub const LAPIC_ICR_LO:   u32 = 0x300;
pub const LAPIC_ICR_HI:   u32 = 0x310;
pub const LAPIC_TIMER:    u32 = 0x320;
pub const LAPIC_TIMER_IC: u32 = 0x380;
pub const LAPIC_TIMER_CC: u32 = 0x390;
pub const LAPIC_TIMER_DC: u32 = 0x3E0;

/// Interrupt vector pentru APIC timer (= IRQ0 la PIC, dar prin LAPIC)
pub const APIC_TIMER_VECTOR: u32 = 0x20;

pub static CPU_COUNT:  AtomicU64 = AtomicU64::new(1);
pub static APS_ONLINE: AtomicU32 = AtomicU32::new(0);

/// Set to true once LAPIC is active — timer handler should use lapic_eoi only
pub static LAPIC_ACTIVE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// APIC ticks per millisecond (calibrat)
pub static APIC_TICKS_PER_MS: AtomicU64 = AtomicU64::new(62_500);

#[inline]
pub fn lapic_read(reg: u32) -> u32 {
    unsafe { ((LAPIC_BASE + reg as u64) as *const u32).read_volatile() }
}

#[inline]
pub fn lapic_write(reg: u32, val: u32) {
    unsafe { ((LAPIC_BASE + reg as u64) as *mut u32).write_volatile(val) }
}

#[inline]
pub fn lapic_eoi() { lapic_write(LAPIC_EOI, 0); }

pub fn current_cpu_id() -> u32 { lapic_read(LAPIC_ID) >> 24 }

/// Calibrează APIC timer față de PIT
/// Returnează ticks APIC per ms
pub fn calibrate_apic_timer() -> u64 {
    // Configurăm PIT channel 2 pentru one-shot 10ms
    // Port 0x61 = speaker gate + PIT gate
    // Port 0x42 = PIT channel 2 data
    // Port 0x43 = PIT command

    const PIT_HZ:      u32 = 1_193_182;
    const WAIT_MS:     u32 = 10;
    const PIT_DIVISOR: u16 = (PIT_HZ * WAIT_MS / 1000) as u16;

    unsafe {
        // Setup PIT channel 2, mode 0 (one-shot)
        Port::<u8>::new(0x43).write(0xB2); // ch2, lobyte/hibyte, mode 1, binary
        Port::<u8>::new(0x42).write((PIT_DIVISOR & 0xFF) as u8);
        Port::<u8>::new(0x42).write((PIT_DIVISOR >> 8) as u8);

        // Enable PIT gate (bit 0 of port 0x61) + disable speaker (bit 1)
        let v = Port::<u8>::new(0x61).read();
        Port::<u8>::new(0x61).write((v & !0x02) | 0x01);
    }

    // Setăm APIC timer cu valoare max, no interrupt (0x10000 = masked)
    lapic_write(LAPIC_TIMER_DC, 0x3);          // divide by 16
    lapic_write(LAPIC_TIMER,    0x0001_0020);  // masked, one-shot, vector 0x20
    lapic_write(LAPIC_TIMER_IC, 0xFFFF_FFFF);  // max initial count

    // Așteptăm ca PIT channel 2 să expire (bit 5 al portului 0x61)
    unsafe {
        loop {
            let status = Port::<u8>::new(0x61).read();
            if status & 0x20 != 0 { break; } // OUT2 high = done
        }
    }

    // Citim APIC timer curent
    let current = lapic_read(LAPIC_TIMER_CC);
    let elapsed = 0xFFFF_FFFFu32.wrapping_sub(current);

    let ticks_per_ms = elapsed as u64 / WAIT_MS as u64;
    APIC_TICKS_PER_MS.store(ticks_per_ms, Ordering::SeqCst);

    crate::serial_println!("  [APIC] calibrated: {} ticks/ms (~{}MHz)",
        ticks_per_ms, ticks_per_ms * 16 / 1000); // ×16 because divisor=16
    ticks_per_ms
}

/// Inițializează LAPIC pe core-ul curent (BSP sau AP)
pub fn init_lapic() {
    // Enable LAPIC via SVR (bit 8 = APIC enable, bits 0-7 = spurious vector 0xFF)
    lapic_write(LAPIC_SVR, 0x1FF);

    // Task Priority Register = 0 (accept all interrupts)
    lapic_write(0x080, 0);

    // Timer: periodic, vector 0x20 (= IDT[32] = timer_handler)
    lapic_write(LAPIC_TIMER_DC, 0x3); // divide by 16

    let tpm = APIC_TICKS_PER_MS.load(Ordering::Relaxed);
    let ic  = if tpm > 0 { tpm as u32 } else { 62_500 };

    lapic_write(LAPIC_TIMER, 0x0002_0020); // periodic | vector 0x20
    lapic_write(LAPIC_TIMER_IC, ic);       // initial count = 1ms worth of ticks

    // Mask legacy PIC — LAPIC handles all interrupts now
    mask_pic();

    // Mark LAPIC as active so timer handler uses lapic_eoi
    LAPIC_ACTIVE.store(true, Ordering::SeqCst);

    let cpu_id = current_cpu_id();
    crate::serial_println!("  [APIC] CPU#{} timer: {}ticks/ms, periodic",
        cpu_id, tpm);
}

/// Trimite INIT + STARTUP IPI la un AP
pub fn send_startup_ipi(apic_id: u8, vector: u8) {
    lapic_write(LAPIC_ICR_HI, (apic_id as u32) << 24);
    lapic_write(LAPIC_ICR_LO, 0x0000_C500); // INIT
    // Wait 10ms
    let start = crate::arch::x86_64::timer::uptime_ms();
    while crate::arch::x86_64::timer::uptime_ms() < start + 10 { core::hint::spin_loop(); }

    for _ in 0..2 {
        lapic_write(LAPIC_ICR_HI, (apic_id as u32) << 24);
        lapic_write(LAPIC_ICR_LO, 0x0000_4600 | vector as u32); // STARTUP
        let s = crate::arch::x86_64::timer::uptime_ms();
        while crate::arch::x86_64::timer::uptime_ms() < s + 1 { core::hint::spin_loop(); }
    }
}

/// Maskează PIC 8259 după ce APIC e activ
/// (Nu mai avem nevoie de PIC când folosim LAPIC + IO-APIC)
pub fn mask_pic() {
    unsafe {
        Port::<u8>::new(0x21).write(0xFF); // mask all master PIC
        Port::<u8>::new(0xA1).write(0xFF); // mask all slave PIC
    }
    crate::serial_println!("  [APIC] PIC 8259 masked (LAPIC active)");
}

// ── TLB shootdown ─────────────────────────────────────────────────────────────

/// IPI vector pentru TLB shootdown (vector 0x30 = 48, neutilizat de PIC)
pub const TLB_SHOOTDOWN_VECTOR: u8 = 0x30;

/// Adresa virtuală care trebuie invalidată — comunicare BSP→AP
static TLB_SHOOTDOWN_ADDR: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
/// Număr de core-uri care au confirmat invalidarea
static TLB_ACK_COUNT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Trimite IPI la toate core-urile active să invalideze `virt_addr` din TLB.
/// Blochează până toate core-urile au confirmat (max 1ms per core).
pub fn tlb_shootdown(virt_addr: u64) {
    let ncpus = CPU_COUNT.load(Ordering::Relaxed) as u32;
    if ncpus <= 1 { return; } // single-core — TLB flush local suficient

    // Setăm adresa de invalidat
    TLB_SHOOTDOWN_ADDR.store(virt_addr, Ordering::SeqCst);
    TLB_ACK_COUNT.store(0, Ordering::SeqCst);

    // Trimitem IPI broadcast la toate AP-urile (nu și la noi)
    lapic_write(LAPIC_ICR_HI, 0);
    // Destination shorthand = 11 (All Excluding Self), delivery mode = Fixed
    lapic_write(LAPIC_ICR_LO, 0x000C_0000 | TLB_SHOOTDOWN_VECTOR as u32);

    // Așteptăm ca toate AP-urile să confirme (max ncpus-1 ack-uri)
    let expected = ncpus - 1;
    let deadline = crate::arch::x86_64::timer::uptime_ms() + expected as u64 + 5;
    while TLB_ACK_COUNT.load(Ordering::SeqCst) < expected {
        if crate::arch::x86_64::timer::uptime_ms() > deadline {
            crate::serial_println!("[TLB] shootdown timeout after {}ms", expected + 5);
            break;
        }
        core::hint::spin_loop();
    }
}

/// Handler apelat pe AP la primirea IPI de shootdown.
/// Înregistrat în IDT la vectorul TLB_SHOOTDOWN_VECTOR.
pub fn tlb_shootdown_handler() {
    let addr = TLB_SHOOTDOWN_ADDR.load(Ordering::SeqCst);
    // Invalidăm TLB pentru adresa specificată
    unsafe {
        x86_64::instructions::tlb::flush(x86_64::VirtAddr::new(addr));
    }
    // Confirmăm
    TLB_ACK_COUNT.fetch_add(1, Ordering::SeqCst);
    // EOI
    lapic_eoi();
}

/// Read local APIC ID for current CPU
#[inline]
pub fn local_apic_id() -> u8 {
    current_cpu_id() as u8
}
