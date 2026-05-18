//! Swap — paginare pe disc (IONAFS swap file)
//!
//! Design:
//!   SwapSlot = un page (4KB) stocat în /swap/page-NNNN pe IONAFS
//!   SwapTable = BTreeMap<VirtAddr, SwapSlot>
//!   swap_out(frame) → scrie pagina pe disc, eliberează frame
//!   swap_in(addr)   → citește pagina de pe disc, alocă frame nou
//!   Page fault handler verifică SwapTable înaintea SIGSEGV
//!
//! Nu e un swap device real (pentru asta ai nevoie de AHCI/NVMe async I/O),
//! dar e complet funcțional pentru IONAFS cu smoltcp în memorie.

use alloc::{collections::BTreeMap, format, string::String, vec::Vec};
use spin::{Lazy, Mutex};
use x86_64::VirtAddr;

const SWAP_PAGE_SIZE: usize = 4096;
const MAX_SWAP_PAGES: usize = 16384; // 64 MB swap max

// -----------------------------------------------------------------------------
// SwapSlot
// -----------------------------------------------------------------------------

/// O pagină stocată pe disc.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapSlot {
    pub slot_id: u32,
    pub path:    String, // /swap/page-NNNN
    pub size:    usize,  // întotdeauna PAGE_SIZE
}

// -----------------------------------------------------------------------------
// SwapTable
// -----------------------------------------------------------------------------

struct SwapTable {
    /// VirtAddr (page-aligned) → SwapSlot
    entries:     BTreeMap<u64, SwapSlot>,
    /// Slot-uri libere (id-uri reciclate după `swap_in`)
    free_slots:  Vec<u32>,
    next_slot:   u32,
    total_slots: usize,
    used_slots:  usize,
}

impl SwapTable {
    fn new() -> Self {
        Self {
            entries:     BTreeMap::new(),
            free_slots:  Vec::with_capacity(64),
            next_slot:   0,
            total_slots: MAX_SWAP_PAGES,
            used_slots:  0,
        }
    }

    /// Alocă un slot nou sau unul reciclat.
    fn alloc_slot(&mut self) -> Option<SwapSlot> {
        if self.used_slots >= self.total_slots {
            return None;
        }

        let id = if let Some(recycled) = self.free_slots.pop() {
            recycled
        } else {
            let id = self.next_slot;
            self.next_slot = self.next_slot.checked_add(1)?;
            id
        };

        self.used_slots += 1;

        Some(SwapSlot {
            slot_id: id,
            path:    format!("/swap/page-{:06}", id),
            size:    SWAP_PAGE_SIZE,
        })
    }

    /// Eliberează un slot, ștergând fișierul de pe disc.
    /// Slot-ul devine disponibil pentru refolosire.
    fn free_slot(&mut self, slot: &SwapSlot) {
        // Ștergem fișierul (best-effort; logăm eroarea dar nu panicăm)
        if let Err(e) = crate::fs::ionafs::delete(&slot.path) {
            crate::serial_println!("[SWAP] warn: failed to delete {}: {:?}", slot.path, e);
        }
        self.used_slots = self.used_slots.saturating_sub(1);
        self.free_slots.push(slot.slot_id);
    }

    fn stats(&self) -> (usize, usize) {
        (self.total_slots, self.used_slots)
    }
}

// -----------------------------------------------------------------------------
// Stare globală
// -----------------------------------------------------------------------------

static SWAP: Lazy<Mutex<SwapTable>> = Lazy::new(|| Mutex::new(SwapTable::new()));

// -----------------------------------------------------------------------------
// API public
// -----------------------------------------------------------------------------

/// Swap out o pagină: scrie conținutul pe IONAFS, înregistrează maparea.
/// Returnează `true` la succes, `false` dacă swap-ul este plin sau scrierea eșuează.
pub fn swap_out(vaddr: VirtAddr, page_data: &[u8; SWAP_PAGE_SIZE]) -> bool {
    let aligned = vaddr.as_u64() & !0xFFF;
    let mut table = SWAP.lock();

    // Verificăm dacă adresa este deja swap-uită (nu duplicăm)
    if table.entries.contains_key(&aligned) {
        crate::serial_println!("[SWAP] address {:#x} already swapped", aligned);
        return false;
    }

    let slot = match table.alloc_slot() {
        Some(s) => s,
        None => {
            crate::serial_println!("[SWAP] swap full ({} pages used)", table.used_slots);
            return false;
        }
    };

    // Scriere pe disc
    if let Err(e) = crate::fs::ionafs::write(&slot.path, page_data) {
        crate::serial_println!("[SWAP] write failed for {}: {:?}", slot.path, e);
        table.free_slot(&slot);
        return false;
    }

    table.entries.insert(aligned, slot);
    crate::serial_println!("[SWAP] swapped out {:#x}", aligned);
    true
}

/// Swap in o pagină: citește de pe IONAFS în buffer, eliberează slot-ul.
/// Returnează `true` dacă adresa era swap-uită, `false` altfel.
pub fn swap_in(vaddr: VirtAddr, out: &mut [u8; SWAP_PAGE_SIZE]) -> bool {
    let aligned = vaddr.as_u64() & !0xFFF;
    let mut table = SWAP.lock();

    let slot = match table.entries.remove(&aligned) {
        Some(s) => s,
        None => return false,
    };

    // Citește datele
    match crate::fs::ionafs::read(&slot.path) {
        Some(data) => {
            let n = data.len().min(SWAP_PAGE_SIZE);
            out[..n].copy_from_slice(&data[..n]);
            table.free_slot(&slot);
            crate::serial_println!("[SWAP] swapped in {:#x}", aligned);
            true
        }
        None => {
            // Citirea a eșuat — punem slot-ul înapoi
            crate::serial_println!("[SWAP] read failed for {}", slot.path);
            table.entries.insert(aligned, slot);
            false
        }
    }
}

/// Verifică dacă o adresă este swap-uită.
pub fn is_swapped(vaddr: VirtAddr) -> bool {
    let aligned = vaddr.as_u64() & !0xFFF;
    SWAP.lock().entries.contains_key(&aligned)
}

/// Returnează statistici swap: (total_slots, used_slots).
pub fn stats() -> (usize, usize) {
    SWAP.lock().stats()
}

// -----------------------------------------------------------------------------
// Administrare
// -----------------------------------------------------------------------------

/// Inițializează subsistemul de swap (directorul /swap e creat de IONAFS la nevoie).
pub fn init() {
    let total_mb = MAX_SWAP_PAGES * SWAP_PAGE_SIZE / (1024 * 1024);
    crate::serial_println!(
        "  [SWAP] initialized: {} pages ({} MB)",
        MAX_SWAP_PAGES,
        total_mb
    );
}

/// Evacuează toate paginile swap-uite dintr-un interval de adrese virtuale.
/// Util la `munmap`.
pub fn evict_range(start: u64, end: u64) -> usize {
    let mut table = SWAP.lock();
    let addrs: Vec<u64> = table
        .entries
        .keys()
        .filter(|&&a| a >= start && a < end)
        .copied()
        .collect();

    let mut freed = 0;
    for addr in addrs {
        if let Some(slot) = table.entries.remove(&addr) {
            table.free_slot(&slot);
            freed += 1;
        }
    }
    freed
}

/// Curăță paginile swap-uite ale unui task (apelează la ieșirea procesului).
/// NOTĂ: în această implementare nu există tracking per-task; rămâne de adăugat
/// când paginarea va avea metadate de proprietar.
pub fn cleanup_task(_tid: u64) {
    // TODO: filtrează după TID și eliberează sloturile.
}

/// Hook pentru mentenanță în background. În acest backend simplu, nu există
/// reclaim proactiv; se returnează 0 păstrând API-ul stabil.
pub fn reclaim_pages(_target: usize) -> usize {
    0
}

// -----------------------------------------------------------------------------
// Teste
// -----------------------------------------------------------------------------

/// Test round-trip: swap out + swap in, verifică integritatea datelor.
pub fn stress_test(n_pages: usize) -> bool {
    // Limitează automat la MAX_SWAP_PAGES
    let n_pages = n_pages.min(MAX_SWAP_PAGES);

    let mut test_data: Vec<(VirtAddr, [u8; SWAP_PAGE_SIZE])> = Vec::with_capacity(n_pages);

    // Swap out
    for i in 0..n_pages {
        let v = VirtAddr::new(0x7000_0000_0000 + (i as u64) * 0x1000);
        let mut page = [0u8; SWAP_PAGE_SIZE];
        for (j, byte) in page.iter_mut().enumerate() {
            *byte = ((i + j) & 0xFF) as u8;
        }
        if !swap_out(v, &page) {
            crate::serial_println!("[SWAP] stress test: swap_out failed at page {}", i);
            return false;
        }
        test_data.push((v, page));
    }

    // Swap in
    for (v, expected) in &test_data {
        let mut restored = [0u8; SWAP_PAGE_SIZE];
        if !swap_in(*v, &mut restored) {
            crate::serial_println!("[SWAP] stress test: swap_in failed for {:#x}", v.as_u64());
            return false;
        }
        if restored != *expected {
            crate::serial_println!(
                "[SWAP] stress test: data mismatch for {:#x}",
                v.as_u64()
            );
            return false;
        }
    }

    true
}

// -----------------------------------------------------------------------------
// Unit tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Asigură o stare curată înaintea fiecărui test.
    fn reset_swap() {
        let mut table = SWAP.lock();
        table.entries.clear();
        table.free_slots.clear();
        table.next_slot = 0;
        table.used_slots = 0;
    }

    #[test]
    fn test_swap_out_in_basic() {
        reset_swap();
        let vaddr = VirtAddr::new(0x1000);
        let data = [0xABu8; SWAP_PAGE_SIZE];
        assert!(swap_out(vaddr, &data));
        assert!(is_swapped(vaddr));

        let mut restored = [0u8; SWAP_PAGE_SIZE];
        assert!(swap_in(vaddr, &mut restored));
        assert_eq!(restored, data);
        assert!(!is_swapped(vaddr));
    }

    #[test]
    fn test_swap_out_full() {
        reset_swap();
        // Umplem swap-ul
        for i in 0..MAX_SWAP_PAGES {
            let v = VirtAddr::new(0x1000 + (i as u64) * 0x1000);
            let data = [i as u8; SWAP_PAGE_SIZE];
            assert!(swap_out(v, &data), "swap_out failed at page {}", i);
        }
        // Următoarea alocare trebuie să eșueze
        let v = VirtAddr::new(0x1000 + (MAX_SWAP_PAGES as u64) * 0x1000);
        let data = [0xFFu8; SWAP_PAGE_SIZE];
        assert!(!swap_out(v, &data));
    }

    #[test]
    fn test_slot_recycling() {
        reset_swap();
        let v1 = VirtAddr::new(0x1000);
        let v2 = VirtAddr::new(0x2000);
        let data = [0x11u8; SWAP_PAGE_SIZE];

        swap_out(v1, &data);
        let mut buf = [0u8; SWAP_PAGE_SIZE];
        swap_in(v1, &mut buf); // eliberează slot-ul

        // Acum un nou swap ar trebui să refolosească slot-ul 0
        swap_out(v2, &data);
        assert!(is_swapped(v2));
    }

    #[test]
    fn test_evict_range() {
        reset_swap();
        let v1 = VirtAddr::new(0x1000);
        let v2 = VirtAddr::new(0x2000);
        let v3 = VirtAddr::new(0x5000);
        let data = [0x22u8; SWAP_PAGE_SIZE];

        swap_out(v1, &data);
        swap_out(v2, &data);
        swap_out(v3, &data);

        // Evacuează [0x1000, 0x3000) → trebuie să șteargă v1 și v2
        let freed = evict_range(0x1000, 0x3000);
        assert_eq!(freed, 2);
        assert!(!is_swapped(v1));
        assert!(!is_swapped(v2));
        assert!(is_swapped(v3)); // v3 e în afara intervalului
    }
}
