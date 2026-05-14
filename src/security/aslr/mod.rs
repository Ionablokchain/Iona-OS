//! ASLR — Address Space Layout Randomization
//!
//! Randomizăm base address-ul ELF la fiecare exec().
//! Previne return-oriented programming (ROP) attacks.
//!
//! Entropia vine din RDTSC + uptime (suficientă pentru bare-metal fără KASLR HW).
//! Range randomizare: 0x0000_1000_0000_0000 .. 0x0000_7000_0000_0000 (user space)

use core::sync::atomic::{AtomicU64, Ordering};

/// Seed pentru pseudo-random (XorShift64)
static ASLR_SEED: AtomicU64 = AtomicU64::new(0x0BAD_CAFE_DEAD_BEEF);

fn rdrand_or_tsc() -> u64 {
    // Try RDRAND via the safe rng wrapper (checks CPUID first)
    if let Some(val) = crate::security::rng::rdrand64() {
        let tsc: u64;
        unsafe { core::arch::asm!("rdtsc", out("rax") tsc, options(nostack)); }
        return val ^ tsc.rotate_left(17);
    }
    // Fallback: XorShift64 seeded from TSC + uptime
    let tsc: u64;
    unsafe { core::arch::asm!("rdtsc", out("rax") tsc, options(nostack)); }
    let uptime = crate::arch::x86_64::timer::uptime_ms();
    tsc ^ (uptime << 32) ^ (uptime >> 32) ^ 0xDEAD_BEEF_CAFE_BABE
}

/// Inițializează ASLR seed din hardware entropy (RDTSC + uptime)
pub fn init() {
    // Try RDRAND first (hardware entropy) — fallback to TSC+uptime mix
    let seed = rdrand_or_tsc();
    ASLR_SEED.store(seed, Ordering::SeqCst);
    crate::serial_println!("  [ASLR] initialized seed=0x{:016x}", seed);
}

/// Generează un offset aleatoriu aliniat la pagini (4KB)
pub fn random_offset() -> u64 {
    // XorShift64
    let mut x = ASLR_SEED.load(Ordering::Relaxed);
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    ASLR_SEED.store(x, Ordering::SeqCst);

    // Range: 0x10_0000 .. 0x7F00_0000 (128MB range for ASLR)
    let range = 0x7F00_0000u64;
    let offset = (x % range) & !0xFFF; // align to 4KB
    offset
}

/// Aplică ASLR la un ELF entry point
/// Returnează noul entry point randomizat
pub fn randomize_entry(entry: u64) -> u64 {
    if !is_enabled() { return entry; }
    let offset = random_offset();
    let new_entry = entry.wrapping_add(offset);
    crate::serial_println!("  [ASLR] offset=0x{:x} entry=0x{:x}→0x{:x}",
        offset, entry, new_entry);
    new_entry
}

/// Randomizează stack base (stack ASLR)
pub fn randomize_stack(stack_top: u64) -> u64 {
    if !is_enabled() { return stack_top; }
    let off = random_offset() & 0xFF_F000; // max 16MB stack randomization
    stack_top.wrapping_sub(off)
}

/// Enable/disable ASLR (disablat în debug pentru reproducibilitate)
pub fn is_enabled() -> bool {
    !cfg!(debug_assertions) // disabled in debug, enabled in release
}
