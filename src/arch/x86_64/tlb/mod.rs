//! TLB shootdown — cross-core TLB invalidation via IPI
//!
//! Când un core modifică page tables (CoW fault, munmap, mprotect),
//! celelalte core-uri au în TLB-ul lor intrări stale pentru paginile respective.
//! Fără shootdown → alt core continuă să citească/scrie la adresa veche → memory corruption.
//!
//! Protocol:
//!   1. Core X modifică page table + face invlpg local
//!   2. Core X trimite IPI (vector 0x40) la toate celelalte core-uri
//!   3. Celelalte core-uri primesc IPI → handler face invlpg pentru adresa dată
//!   4. Core X poate continua
//!
//! Vector IPI: 0x40 (IDT[64]) — dedicat TLB shootdown
//! Adresa de invalidat: stocată în TLB_SHOOTDOWN_ADDR atomic

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use crate::arch::x86_64::apic::{lapic_write, lapic_read, CPU_COUNT,
                                   LAPIC_ICR_LO, LAPIC_ICR_HI};

pub const TLB_SHOOTDOWN_VECTOR: u8 = 0x40; // IDT[64]

/// Adresa virtuală de invalidat — scrisă de inițiator, citită de toate core-urile
pub static TLB_SHOOTDOWN_ADDR: AtomicU64 = AtomicU64::new(0);
/// Numărul de core-uri care au confirmat shootdown-ul
pub static TLB_ACK_COUNT: AtomicU64 = AtomicU64::new(0);
/// Lock pentru serializare shootdown-uri (un singur shootdown la un moment dat)
static TLB_LOCK: AtomicBool = AtomicBool::new(false);

/// Invalidează o pagină pe toate core-urile (TLB shootdown complet)
///
/// Apelat după:
/// - copy_on_write_fault() → remap pagină
/// - munmap() → unmap pagini
/// - mprotect() → modificare flags
pub fn shootdown(virt_addr: u64) {
    let cpu_count = CPU_COUNT.load(Ordering::Relaxed) as u64;
    if cpu_count <= 1 {
        // Single-core: doar invlpg local
        local_invlpg(virt_addr);
        return;
    }

    // Obținem lock exclusiv pentru shootdown
    while TLB_LOCK.compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed).is_err() {
        core::hint::spin_loop();
    }

    // Scriem adresa de invalidat
    TLB_SHOOTDOWN_ADDR.store(virt_addr, Ordering::SeqCst);
    TLB_ACK_COUNT.store(0, Ordering::SeqCst);

    // Invalidăm local
    local_invlpg(virt_addr);

    // Trimitem IPI la toate core-urile (broadcast, excluding self)
    // ICR low: vector=0x40, delivery=Fixed, shorthand=All Excluding Self (11b)
    lapic_write(LAPIC_ICR_HI, 0);
    lapic_write(LAPIC_ICR_LO, 0x000C_4000 | TLB_SHOOTDOWN_VECTOR as u32);
    //                          ^^^^ All Excl Self | Fixed delivery | vector

    // Așteptăm confirmarea de la toate AP-urile
    let expected = cpu_count - 1;
    let deadline = crate::arch::x86_64::timer::uptime_ms() + 10; // 10ms max
    while TLB_ACK_COUNT.load(Ordering::SeqCst) < expected {
        if crate::arch::x86_64::timer::uptime_ms() > deadline {
            crate::serial_println!("[TLB] shootdown timeout after 10ms");
            break;
        }
        core::hint::spin_loop();
    }

    TLB_LOCK.store(false, Ordering::SeqCst);
}

/// Shootdown pentru un range de pagini [start, start + size)
pub fn shootdown_range(start: u64, size: u64) {
    let pages = (size + 4095) / 4096;
    for i in 0..pages {
        shootdown(start + i * 4096);
    }
}

/// Handler apelat pe AP la primirea IPI TLB shootdown
/// Apelat din IDT[64] handler (extern "x86-interrupt")
pub fn shootdown_handler() {
    let addr = TLB_SHOOTDOWN_ADDR.load(Ordering::SeqCst);
    local_invlpg(addr);
    TLB_ACK_COUNT.fetch_add(1, Ordering::SeqCst);
    crate::arch::x86_64::apic::lapic_eoi();
}

/// Invalidează o singură pagină în TLB-ul core-ului curent
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

/// Flush complet TLB (reîncarcă CR3)
#[inline(always)]
pub fn flush_all() {
    unsafe {
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, nomem));
        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, nomem));
    }
}
