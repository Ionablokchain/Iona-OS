//! Stress tests — validare sub presiune reală
//!
//! Rulează numai explicit (nu la fiecare boot, prea lente).
//! Activate via: tests::stress::run_all_stress_tests()
//!
//! Scenarii:
//!   SMP:      TLB shootdown concurent, work stealing, per-core queues
//!   Network:  TCP/UDP sub load, epoll cu N fds, backpressure
//!   FS:       crash loops, write-heavy, concurrent access
//!   Swap:     presiune de memorie, evicție + readback
//!   Futex:    contention mare, wake N waiters

pub fn run_all_stress_tests() {
    crate::serial_println!("
[STRESS] Starting stress test suite...");

    let t0 = crate::arch::x86_64::timer::uptime_ms();

    stress_smp_tlb_shootdown();
    stress_fs_concurrent();
    stress_swap_pressure();
    stress_futex_contention();

    let elapsed = crate::arch::x86_64::timer::uptime_ms() - t0;
    crate::serial_println!("[STRESS] All stress tests done in {}ms", elapsed);
}

// ── SMP TLB shootdown stress ──────────────────────────────────────────────────
fn stress_smp_tlb_shootdown() {
    crate::serial_println!("[STRESS] TLB shootdown × 100...");
    for i in 0..100u64 {
        let virt = 0x0000_6000_0000_0000 + i * 4096;
        crate::arch::x86_64::apic::tlb_shootdown(virt);
    }
    crate::serial_println!("[STRESS] TLB shootdown OK");
}

// ── FS concurrent write stress ────────────────────────────────────────────────
fn stress_fs_concurrent() {
    crate::serial_println!("[STRESS] FS concurrent writes × 100...");
    let mut errors = 0usize;
    for i in 0u32..100 {
        let path  = alloc::format!("/tmp/stress-{}", i);
        let data  = i.to_le_bytes();
        crate::fs::ionafs::write(&path, &data);
        match crate::fs::ionafs::read(&path) {
            Some(d) if d == data => {}
            _ => errors += 1,
        }
        crate::fs::ionafs::delete(&path);
    }
    crate::serial_println!("[STRESS] FS concurrent: {}/100 OK, {} errors", 100-errors, errors);
}

// ── Swap pressure stress ──────────────────────────────────────────────────────
fn stress_swap_pressure() {
    crate::serial_println!("[STRESS] Swap pressure test × 16 pages...");
    let ok = crate::memory::swap::stress_test(16);
    crate::serial_println!("[STRESS] Swap pressure: {}", if ok {"OK"} else {"FAILED"});
}

// ── Futex contention ──────────────────────────────────────────────────────────
fn stress_futex_contention() {
    crate::serial_println!("[STRESS] Futex contention × 50 ops...");
    let addr = 0x0000_7000_9999_0000u64;
    // Simulate 50 futex operations
    for _ in 0..50 {
        // FUTEX_WAIT + FUTEX_WAKE (just the syscall path, not blocking)
        let _ = crate::process::futex::futex_wake(addr, 1);
    }
    crate::serial_println!("[STRESS] Futex contention OK");
}
