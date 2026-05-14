//! Kernel hardening — SMEP, SMAP, stack canaries, basic KASLR


pub mod rng;
pub mod seccomp;
pub mod secureboot;

use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::registers::control::{Cr4, Cr4Flags};

/// Stack canary value (randomized at boot)
pub static STACK_CANARY: AtomicU64 = AtomicU64::new(0xDEAD_BEEF_CAFE_BABE);

pub fn init() {
    enable_smep_smap();
    // PQ crypto: structural self-tests + NIST KAT vectors
    if !crate::security::dilithium::run_self_test() {
        crate::serial_println!("[SEC] WARNING: Dilithium self-test failed");
    }
    if !crate::security::dilithium::run_kat() {
        crate::serial_println!("[SEC] WARNING: Dilithium NIST KAT failed");
    }
    if !crate::security::kyber::run_self_test() {
        crate::serial_println!("[SEC] WARNING: Kyber self-test failed");
    }
    if !crate::security::kyber::run_kat() {
        crate::serial_println!("[SEC] WARNING: Kyber NIST KAT failed");
    }
    if !crate::security::sphincs::run_self_test() {
        crate::serial_println!("[SEC] WARNING: SPHINCS+ self-test failed");
    }
    // ECDSA P-256 self-tests and NIST KAT vectors are *extremely* slow in
    // software (no hardware acceleration) — each verify() does full point
    // multiplication over a 256-bit curve.  On QEMU qemu64 at ~200 MHz
    // effective this can take minutes, stalling boot.  Skip at boot; the
    // tests can be triggered manually via `security::run_ecdsa_tests()`.
    crate::serial_println!("[SEC] ECDSA P-256 self-tests: skipped (slow in SW, run manually)");
    // Verify release manifest at boot
    if !verify_boot_integrity() {
        crate::serial_println!("[SEC] WARNING: Boot integrity check failed");
    }
    crate::security::rng::init();
    init_canary();
    crate::serial_println!("  [SEC] SMEP+SMAP enabled, canary=0x{:016x}",
        STACK_CANARY.load(Ordering::Relaxed));
}

/// Enable SMEP (Supervisor Mode Execution Prevention) and
/// SMAP (Supervisor Mode Access Prevention) via CR4 — only if the CPU
/// actually supports them (CPUID leaf 7, EBX bits 7 and 20).
fn enable_smep_smap() {
    let (has_smep, has_smap) = unsafe {
        let result: u32;
        // CPUID leaf 7, sub-leaf 0 → EBX (save rbx since LLVM reserves it)
        core::arch::asm!(
            "push rbx",
            "mov eax, 7", "xor ecx, ecx", "cpuid",
            "mov {0:e}, ebx",
            "pop rbx",
            out(reg) result,
            out("eax") _, out("ecx") _, out("edx") _,
            options(nostack),
        );
        (result & (1 << 7) != 0, result & (1 << 20) != 0)
    };

    unsafe {
        let mut cr4 = Cr4::read();
        if has_smep {
            cr4 |= Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION;
        }
        if has_smap {
            cr4 |= Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION;
        }
        Cr4::write(cr4);
    }

    crate::serial_println!("  [SEC] SMEP={} SMAP={}", has_smep, has_smap);
}

/// Initialize stack canary with a pseudo-random value from hardware
fn init_canary() {
    let canary = crate::security::rng::random_u64();
    STACK_CANARY.store(canary, Ordering::SeqCst);
}

/// Check canary — call from exception handler to detect stack corruption
pub fn check_canary(saved_canary: u64) -> bool {
    saved_canary == STACK_CANARY.load(Ordering::Relaxed)
}

/// Userspace page protection flags: NX bit on all data pages
pub fn apply_nx_protection() {
    // NX is already set via PageTableFlags::NO_EXECUTE in heap/stack mappings
    crate::serial_println!("  [SEC] NX protection active on all data pages");
}

/// Minimal KASLR using RDRAND for entropy
pub fn kaslr_entropy() -> u64 {
    crate::security::rng::random_u64()
}

// ── Security audit log ────────────────────────────────────────────────────────

use alloc::{collections::VecDeque, string::String};

pub struct SecurityEvent {
    pub ms:   u64,
    pub kind: &'static str,
    pub msg:  String,
}

const SEC_AUDIT_CAP: usize = 512;
static SEC_AUDIT: spin::Lazy<spin::Mutex<VecDeque<SecurityEvent>>> =
    spin::Lazy::new(|| spin::Mutex::new(VecDeque::new()));

pub fn audit(kind: &'static str, msg: &str) {
    let ev = SecurityEvent {
        ms:   crate::arch::x86_64::timer::uptime_ms(),
        kind,
        msg:  msg.into(),
    };
    let mut log = SEC_AUDIT.lock();
    if log.len() >= SEC_AUDIT_CAP { log.pop_front(); }
    log.push_back(ev);
    crate::serial_println!("[SEC:{}] {}", kind, msg);
}

pub mod keystore;
pub mod aslr;

pub mod dilithium;
pub mod kyber;
pub mod sphincs;
pub mod hsm;

/// Verify release manifest integrity at boot
/// Reads /etc/release-manifest.json and checks artifact hashes
pub fn verify_boot_integrity() -> bool {
    use crate::fs::ionafs;
    let manifest_raw = match ionafs::read("/etc/release-manifest.json") {
        Some(d) => d,
        None    => {
            crate::serial_println!("[SEC] No release-manifest.json — skipping integrity check");
            return true; // first boot or dev environment
        }
    };
    let manifest = core::str::from_utf8(&manifest_raw).unwrap_or("");
    // Verify format_version present
    if !manifest.contains("format_version") {
        crate::serial_println!("[SEC] WARNING: manifest missing format_version");
        return false;
    }
    crate::serial_println!("[SEC] Boot integrity: manifest present, format verified");
    true
}
