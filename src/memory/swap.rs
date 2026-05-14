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
const MAX_SWAP_PAGES: usize = 16384; // 64MB swap max

#[derive(Clone, Debug)]
pub struct SwapSlot {
    pub slot_id:  u32,         // unique slot index
    pub path:     String,      // IONAFS path: /swap/page-NNNN
    pub size:     usize,       // always PAGE_SIZE
}

struct SwapTable {
    /// VirtAddr (page-aligned) → SwapSlot
    entries:    BTreeMap<u64, SwapSlot>,
    next_slot:  u32,
    total_slots: usize,
    used_slots:  usize,
}

impl SwapTable {
    const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            next_slot: 0,
            total_slots: MAX_SWAP_PAGES,
            used_slots: 0,
        }
    }

    fn alloc_slot(&mut self) -> Option<SwapSlot> {
        if self.used_slots >= self.total_slots { return None; }
        let id = self.next_slot;
        self.next_slot += 1;
        self.used_slots += 1;
        Some(SwapSlot {
            slot_id: id,
            path: format!("/swap/page-{:06}", id),
            size: SWAP_PAGE_SIZE,
        })
    }

    fn free_slot(&mut self, slot: &SwapSlot) {
        if self.used_slots > 0 { self.used_slots -= 1; }
        crate::fs::ionafs::delete(&slot.path);
    }
}

static SWAP: Lazy<Mutex<SwapTable>> = Lazy::new(|| Mutex::new(SwapTable::new()));

/// Swap out a page: write contents to IONAFS, record mapping
/// Returns true on success
pub fn swap_out(vaddr: VirtAddr, page_data: &[u8; 4096]) -> bool {
    let mut table = SWAP.lock();
    let slot = match table.alloc_slot() {
        Some(s) => s,
        None    => {
            crate::serial_println!("[SWAP] swap full ({} pages used)", table.used_slots);
            return false;
        }
    };
    // Write page to IONAFS
    crate::fs::ionafs::write(&slot.path, page_data);
    table.entries.insert(vaddr.as_u64(), slot);
    crate::serial_println!("[SWAP] swapped out {:#x}", vaddr.as_u64());
    true
}

/// Swap in a page: read from IONAFS into provided buffer, remove mapping
/// Returns true if the address was in swap
pub fn swap_in(vaddr: VirtAddr, out: &mut [u8; 4096]) -> bool {
    let aligned = vaddr.as_u64() & !0xFFF;
    let mut table = SWAP.lock();
    if let Some(slot) = table.entries.remove(&aligned) {
        if let Some(data) = crate::fs::ionafs::read(&slot.path) {
            let n = data.len().min(SWAP_PAGE_SIZE);
            out[..n].copy_from_slice(&data[..n]);
            table.free_slot(&slot);
            crate::serial_println!("[SWAP] swapped in {:#x}", aligned);
            return true;
        }
        // Couldn't read — put it back
        table.entries.insert(aligned, slot);
    }
    false
}

/// Check if address is currently swapped out
pub fn is_swapped(vaddr: VirtAddr) -> bool {
    let aligned = vaddr.as_u64() & !0xFFF;
    SWAP.lock().entries.contains_key(&aligned)
}

/// Swap stats: (used_slots, total_slots)
pub fn stats() -> (usize, usize) {
    let t = SWAP.lock();
    (t.total_slots, t.used_slots)
}

pub fn init() {
    // Ensure swap directory exists
    // (IONAFS creates dirs lazily via path prefix)
    crate::serial_println!("  [SWAP] initialized: {} pages ({} MB)",
        MAX_SWAP_PAGES, MAX_SWAP_PAGES * SWAP_PAGE_SIZE / 1024 / 1024);
}

/// Clean up all swap pages owned by a task (called on process exit)
/// Prevents swap space leak when processes die without swapping pages back in
pub fn cleanup_task(_tid: crate::task::TaskId) {
    // In full impl: filter swap entries by owner tid and free them.
    // Currently: no per-slot ownership tracking, so this is a no-op.
    // Exact filtering needs page table walk with ownership metadata.
}

/// Force evict all pages for a given virtual address range (for munmap)
pub fn evict_range(start: u64, end: u64) -> usize {
    let mut table = SWAP.lock();
    let addrs: alloc::vec::Vec<u64> = table.entries.keys()
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


/// Best-effort reclaim hook used by background maintenance.
/// Current file-backed swap backend does not proactively evict pages,
/// so this returns 0 while keeping the API stable.
pub fn reclaim_pages(_target: usize) -> usize { 0 }

/// Basic swap round-trip validation used by smoke tests.
pub fn stress_test(n_pages: usize) -> bool {
    use x86_64::VirtAddr;
    let mut addrs = alloc::vec::Vec::new();
    for i in 0..n_pages {
        let v = VirtAddr::new(0x7000_0000_0000 + (i as u64) * 0x1000);
        let mut page = [0u8; 4096];
        for (j, b) in page.iter_mut().enumerate() { *b = ((i + j) & 0xFF) as u8; }
        if !swap_out(v, &page) { return false; }
        addrs.push((v, page));
    }
    for (v, expected) in addrs {
        let mut restored = [0u8; 4096];
        if !swap_in(v, &mut restored) { return false; }
        if restored != expected { return false; }
    }
    true
}
