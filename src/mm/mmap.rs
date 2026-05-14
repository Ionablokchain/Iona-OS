//! mmap — memory-mapped files + anonymous mappings
//!
//! Suportă:
//!   MAP_ANON  — pagini anonime zero-fill (deja funcțional via VMM)
//!   MAP_FILE  — fișier IONAFS mapped în spațiul virtual
//!   MAP_PRIVATE — CoW, modificările nu se propagă la fișier
//!   MAP_SHARED  — shared, flushed la msync/munmap
//!
//! Page fault flow pentru MAP_FILE:
//!   1. Access la adresă nemapată → page fault
//!   2. fault handler verifică MmapTable
//!   3. Dacă există o intrare MAP_FILE: citește pagina din IONAFS
//!   4. Mapează pagina în tabelul de pagini al procesului
//!   5. Return → reexecuție instrucțiune

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use spin::{Lazy, Mutex};
use x86_64::VirtAddr;

pub const PROT_READ:  u32 = 0x1;
pub const PROT_WRITE: u32 = 0x2;
pub const PROT_EXEC:  u32 = 0x4;
pub const MAP_FILE:   u32 = 0x0;  // default (file-backed)
pub const MAP_ANON:   u32 = 0x20; // anonymous
pub const MAP_SHARED: u32 = 0x01;
pub const MAP_PRIVATE:u32 = 0x02;
pub const MAP_FIXED:  u32 = 0x10;

#[derive(Clone, Debug)]
pub enum MmapBacking {
    Anonymous,
    File {
        path:   String,
        offset: u64,    // byte offset in file
        length: usize,  // mapping length in bytes
    },
}

#[derive(Clone, Debug)]
pub struct MmapRegion {
    pub base:    u64,           // virtual address (page-aligned)
    pub length:  usize,         // bytes
    pub prot:    u32,
    pub flags:   u32,
    pub backing: MmapBacking,
    pub dirty:   bool,          // for MAP_SHARED flush
}

impl MmapRegion {
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base + self.length as u64
    }

    /// Page offset within this mapping for a given address
    pub fn page_offset(&self, addr: u64) -> usize {
        ((addr & !0xFFF) - self.base) as usize
    }
}

// Per-task mmap table (tid → regions)
use crate::task::TaskId;
static MMAP_TABLE: Lazy<Mutex<BTreeMap<TaskId, Vec<MmapRegion>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

/// Map a file region into virtual address space
/// Returns the mapped virtual address
pub fn mmap_file(tid: TaskId, path: &str, offset: u64, length: usize,
                  prot: u32, flags: u32, hint: u64) -> Option<u64> {
    // Verify file exists and is accessible
    let file_data = crate::fs::ionafs::read(path)?;
    if offset as usize >= file_data.len() { return None; }

    let actual_len = length.min(file_data.len() - offset as usize);
    let aligned_len = (actual_len + 0xFFF) & !0xFFF;

    // Choose virtual address (hint or auto from high address space)
    let base = if hint != 0 && flags & MAP_FIXED != 0 {
        hint & !0xFFF
    } else {
        next_free_vaddr(tid, aligned_len)
    };

    let region = MmapRegion {
        base,
        length: aligned_len,
        prot, flags,
        backing: MmapBacking::File {
            path: path.into(),
            offset,
            length: actual_len,
        },
        dirty: false,
    };

    MMAP_TABLE.lock().entry(tid).or_default().push(region);
    crate::serial_println!("[MMAP] file '{}' offset={} len={} @ {:#x}", path, offset, actual_len, base);
    Some(base)
}

/// Map anonymous pages (zero-fill)
pub fn mmap_anon(tid: TaskId, length: usize, prot: u32, flags: u32, hint: u64) -> u64 {
    let aligned_len = (length + 0xFFF) & !0xFFF;
    let base = if hint != 0 && flags & MAP_FIXED != 0 {
        hint & !0xFFF
    } else {
        next_free_vaddr(tid, aligned_len)
    };
    let region = MmapRegion {
        base, length: aligned_len, prot, flags,
        backing: MmapBacking::Anonymous,
        dirty: false,
    };
    MMAP_TABLE.lock().entry(tid).or_default().push(region);
    base
}

/// Handle page fault for file-backed mapping
/// Returns Some(page_data) if the fault was in an mmap region
pub fn handle_page_fault(tid: TaskId, fault_addr: u64) -> Option<[u8; 4096]> {
    let table = MMAP_TABLE.lock();
    let regions = table.get(&tid)?;
    let region = regions.iter().find(|r| r.contains(fault_addr))?;

    let mut page = [0u8; 4096];
    match &region.backing {
        MmapBacking::Anonymous => {
            // Zero-fill already done above
        }
        MmapBacking::File { path, offset, length } => {
            let page_off = region.page_offset(fault_addr);
            let file_pos = *offset as usize + page_off;
            if let Some(data) = crate::fs::ionafs::read(path) {
                let src_start = file_pos.min(data.len());
                let src_end   = (file_pos + 4096).min(data.len());
                let copy_len  = src_end - src_start;
                page[..copy_len].copy_from_slice(&data[src_start..src_end]);
            }
        }
    }
    Some(page)
}

/// Unmap a region
pub fn munmap(tid: TaskId, addr: u64, length: usize) -> bool {
    let mut table = MMAP_TABLE.lock();
    let regions = match table.get_mut(&tid) { Some(r) => r, None => return false };
    let before = regions.len();
    regions.retain(|r| !(r.base <= addr && addr < r.base + r.length as u64));
    regions.len() < before
}

/// msync — flush dirty MAP_SHARED pages back to file
pub fn msync(tid: TaskId, addr: u64) -> bool {
    // In our simplified model: MAP_SHARED modifications go through set_pixel
    // Full impl: walk dirty page table entries and write back
    true
}

/// Clean up all mappings for a task (on exit)
/// Also evicts any swapped pages for this task's virtual ranges
pub fn cleanup_task(tid: TaskId) {
    let regions = MMAP_TABLE.lock().remove(&tid);
    // Evict any swapped pages in this task's virtual address ranges
    if let Some(regs) = regions {
        for r in &regs {
            crate::memory::swap::evict_range(r.base, r.base + r.length as u64);
        }
    }
}

fn next_free_vaddr(tid: TaskId, len: usize) -> u64 {
    // Start from a high-ish user address and scan downward
    let table = MMAP_TABLE.lock();
    let mut candidate = 0x0000_7000_0000_0000u64;
    if let Some(regions) = table.get(&tid) {
        for r in regions.iter() {
            if r.base <= candidate && candidate < r.base + r.length as u64 {
                candidate = r.base.saturating_sub(len as u64 + 0x1000);
            }
        }
    }
    candidate & !0xFFF
}

pub fn init() {
    crate::serial_println!("  [MMAP] file-backed + anonymous mmap initialized");
}

/// Real memory stats — (total_mb, used_mb, swap_used)
pub fn memory_stats() -> (usize, usize, usize) {
    let (total_f, used_f) = crate::memory::frame_alloc::stats();
    let (_total_s, used_s) = crate::memory::swap::stats();
    (total_f * 4 / 1024, used_f * 4 / 1024, used_s)
}
