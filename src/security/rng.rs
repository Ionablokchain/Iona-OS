//! Cryptographically secure RNG using RDRAND (Intel/AMD hardware instruction)
//! Fallback: RDSEED or TSC-based mixing if RDRAND unavailable
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

static ENTROPY_POOL: AtomicU64 = AtomicU64::new(0);
static POOL_MUTEX:   Mutex<()> = Mutex::new(());

/// Cached CPUID results — checked once at init, reused forever.
static HAS_RDRAND: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static HAS_RDSEED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Check if RDRAND is available via CPUID
pub fn rdrand_available() -> bool {
    let ecx: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "pop rbx",
            in("eax") 1u32,
            out("ecx") ecx,
            options(nostack),
        );
    }
    ecx & (1 << 30) != 0
}

/// Check if RDSEED is available
pub fn rdseed_available() -> bool {
    let result: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {0:e}, ebx",
            "pop rbx",
            out(reg) result,
            in("eax") 7u32,
            in("ecx") 0u32,
            options(nostack),
        );
    }
    result & (1 << 18) != 0
}

/// Get one random u64 from RDRAND (retries up to 10 times per Intel spec)
pub fn rdrand64() -> Option<u64> {
    if !HAS_RDRAND.load(core::sync::atomic::Ordering::Relaxed) { return None; }
    for _ in 0..10 {
        let val: u64;
        let ok: u8;
        unsafe {
            core::arch::asm!(
                "rdrand {val}",
                "setc {ok}",
                val = out(reg) val,
                ok  = out(reg_byte) ok,
                options(nostack),
            );
        }
        if ok != 0 { return Some(val); }
    }
    None
}

/// Get one random u64 from RDSEED
pub fn rdseed64() -> Option<u64> {
    if !HAS_RDSEED.load(core::sync::atomic::Ordering::Relaxed) { return None; }
    for _ in 0..10 {
        let val: u64;
        let ok: u8;
        unsafe {
            core::arch::asm!(
                "rdseed {val}",
                "setc {ok}",
                val = out(reg) val,
                ok  = out(reg_byte) ok,
                options(nostack),
            );
        }
        if ok != 0 { return Some(val); }
    }
    None
}

/// Get secure random bytes — tries RDRAND, RDSEED, then TSC mixing
pub fn random_u64() -> u64 {
    // Try hardware sources first
    if let Some(v) = rdrand64() { mix(v) }
    else if let Some(v) = rdseed64() { mix(v) }
    else {
        // TSC + uptime mixing (not cryptographically secure, but better than nothing)
        let tsc: u64;
        unsafe { core::arch::asm!("rdtsc", out("rax") tsc, options(nostack)); }
        let uptime = crate::arch::x86_64::timer::uptime_ms();
        let prev   = ENTROPY_POOL.load(Ordering::Relaxed);
        mix(tsc ^ uptime ^ prev.rotate_right(13) ^ 0xDEAD_C0DE_CAFE_BABE)
    }
}

/// Fill buffer with random bytes
pub fn random_bytes(buf: &mut [u8]) {
    let mut i = 0;
    while i < buf.len() {
        let r = random_u64();
        let bytes = r.to_le_bytes();
        let n = (buf.len() - i).min(8);
        buf[i..i+n].copy_from_slice(&bytes[..n]);
        i += n;
    }
}

/// SplitMix64 finalizer — avalanche effect
fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

pub fn init() {
    // Cache CPUID results BEFORE any rdrand/rdseed instruction is executed.
    // This prevents #UD on CPUs that don't support these instructions.
    let has_rdrand = rdrand_available();
    let has_rdseed = rdseed_available();
    HAS_RDRAND.store(has_rdrand, core::sync::atomic::Ordering::SeqCst);
    HAS_RDSEED.store(has_rdseed, core::sync::atomic::Ordering::SeqCst);

    let seed = rdrand64().or_else(rdseed64).unwrap_or(0xDEAD_BEEF_1234_5678);
    ENTROPY_POOL.store(seed, Ordering::SeqCst);
    crate::serial_println!("  [RNG] RDRAND={} RDSEED={} pool=0x{:016x}",
        has_rdrand, has_rdseed, seed & 0xFFFF);
}
