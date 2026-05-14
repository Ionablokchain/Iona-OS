//! PIT timer + sleep_ms via wait queues (non-busy-wait)
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use x86_64::instructions::port::Port;

static TICKS:           AtomicU64  = AtomicU64::new(0);
pub static SCHED_READY: AtomicBool = AtomicBool::new(false);

const TIMER_HZ:    u32 = 1000;
const PIT_BASE_HZ: u32 = 1_193_182;
const PIT_DIVISOR: u16 = (PIT_BASE_HZ / TIMER_HZ) as u16;

pub fn init() {
    remap_pic();
    unsafe {
        Port::<u8>::new(0x43).write(0x36);
        Port::<u8>::new(0x40).write((PIT_DIVISOR & 0xFF) as u8);
        Port::<u8>::new(0x40).write((PIT_DIVISOR >> 8) as u8);
    }
}

fn remap_pic() {
    unsafe {
        let mut mc: Port<u8> = Port::new(0x20); let mut md: Port<u8> = Port::new(0x21);
        let mut sc: Port<u8> = Port::new(0xA0); let mut sd: Port<u8> = Port::new(0xA1);
        let mm = md.read(); let sm = sd.read();
        mc.write(0x11); sc.write(0x11);
        md.write(32);   sd.write(40);
        md.write(0x04); sd.write(0x02);
        md.write(0x01); sd.write(0x01);
        md.write(mm);   sd.write(sm);
        md.write(0b1111_1000); // unmask IRQ0(timer) + IRQ1(keyboard) + IRQ2(cascade to slave)
        sd.write(0b1110_1111); // unmask IRQ12 (mouse) on slave PIC
    }
}

pub fn tick() {
    TICKS.fetch_add(1, Ordering::Relaxed);
}

pub fn uptime_ms() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

/// Sleep N milliseconds.
/// Uses hlt-based sleep: each hlt yields until the next interrupt (1ms timer),
/// so the CPU is not busy-spinning. The timer interrupt handles scheduling.
pub fn sleep_ms(ms: u64) {
    if ms == 0 { return; }
    let deadline = uptime_ms() + ms;
    while uptime_ms() < deadline {
        x86_64::instructions::hlt();
    }
}

/// Precisă busy-wait pentru calibrare APIC (fără scheduler, fără wait queue)
pub fn precise_sleep_ms(ms: u64) {
    let start = uptime_ms();
    while uptime_ms() - start < ms {
        x86_64::instructions::hlt();
    }
}
