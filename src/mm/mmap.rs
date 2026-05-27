//! mmap — memory‑mapped files + anonymous mappings
//!
//! Supports:
//!   - `MAP_ANON` – anonymous zero‑fill pages (already functional via VMM)
//!   - `MAP_FILE` – IONAFS file mapped into virtual space
//!   - `MAP_PRIVATE` – Copy‑on‑write, modifications do not propagate to file
//!   - `MAP_SHARED` – Shared, flushed to disk on `msync`/`munmap`
//!   - `MAP_FIXED` – Map at exact address (requires page‑aligned hint)
//!   - `MAP_POPULATE` – Pre‑fault all pages (option)
//!
//! # Page fault flow for `MAP_FILE`:
//!   1. Access to unmapped address → page fault
//!   2. Fault handler consults `MmapTable`
//!   3. If a `MAP_FILE` entry exists, reads the page from IONAFS
//!   4. Maps the page into the process page table
//!   5. Returns → instruction re‑execution
//!
//! # Security notes
//!   - MAP_FIXED without existing mapping overwrites any previous mapping
//!   - PROT_EXEC requires special handling (W^X enforcement)
//!   - MAP_SHARED writes are tracked in a dirty set for `msync`

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Lazy, Mutex};
use x86_64::VirtAddr;

// -----------------------------------------------------------------------------
// Constants (POSIX mmap flags, mirrored)
// -----------------------------------------------------------------------------

/// Page size (4 KiB).
pub const PAGE_SIZE: usize = 4096;

/// Page mask (for alignment).
pub const PAGE_MASK: u64 = !(PAGE_SIZE as u64 - 1);

/// Read permission.
pub const PROT_READ: u32 = 0x1;
/// Write permission.
pub const PROT_WRITE: u32 = 0x2;
/// Execute permission.
pub const PROT_EXEC: u32 = 0x4;
/// No access (used for guard pages).
pub const PROT_NONE: u32 = 0x0;

/// File‑backed mapping (default when `MAP_ANON` is not set).
pub const MAP_FILE: u32 = 0x0;
/// Anonymous mapping (zero‑fill).
pub const MAP_ANON: u32 = 0x20;
/// Shared mapping (writes propagate to file).
pub const MAP_SHARED: u32 = 0x01;
/// Private copy‑on‑write mapping.
pub const MAP_PRIVATE: u32 = 0x02;
/// Map at exact address (hint must be page‑aligned).
pub const MAP_FIXED: u32 = 0x10;
/// Populate (pre‑fault) all pages at map time.
pub const MAP_POPULATE: u32 = 0x8000;

/// Maximum number of mmap regions per process (sanity limit).
pub const MAX_MMAP_REGIONS: usize = 1024;

// -----------------------------------------------------------------------------
// Backing types
// -----------------------------------------------------------------------------

/// Backing storage for an mmap region.
#[derive(Clone, Debug)]
pub enum MmapBacking {
    /// Anonymous memory (zero‑filled on demand).
    Anonymous,
    /// File‑backed mapping.
    File {
        /// Path to the file in IONAFS.
        path: String,
        /// Byte offset within the file.
        offset: u64,
        /// Length of the mapping (bytes).
        length: usize,
        /// Whether the file is opened for writing (for SHARED mappings).
        writeable: bool,
    },
}

// -----------------------------------------------------------------------------
// Region tracking
// -----------------------------------------------------------------------------

/// A single mmap region.
#[derive(Clone, Debug)]
pub struct MmapRegion {
    /// Base virtual address (page‑aligned).
    pub base: u64,
    /// Length in bytes (page‑aligned).
    pub length: usize,
    /// Protection flags (PROT_READ, PROT_WRITE, PROT_EXEC).
    pub prot: u32,
    /// Mapping flags (MAP_SHARED, MAP_PRIVATE, etc.).
    pub flags: u32,
    /// Backing storage.
    pub backing: MmapBacking,
    /// Dirty pages (for MAP_SHARED). Bitmask of pages that have been written.
    pub dirty_mask: u64,
    /// Whether the mapping was populated at creation.
    pub populated: bool,
}

impl MmapRegion {
    /// Check if an address falls within this region.
    #[inline]
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base + self.length as u64
    }

    /// Get the page offset (in bytes) within this region for a given address.
    #[inline]
    pub fn page_offset(&self, addr: u64) -> usize {
        ((addr & !0xFFF) - self.base) as usize
    }

    /// Get the page index within this region.
    #[inline]
    pub fn page_index(&self, addr: u64) -> usize {
        ((addr & !0xFFF) - self.base) as usize / PAGE_SIZE
    }

    /// Mark a page as dirty (for MAP_SHARED).
    #[inline]
    pub fn mark_dirty(&mut self, addr: u64) {
        if self.flags & MAP_SHARED != 0 {
            let idx = self.page_index(addr);
            self.dirty_mask |= 1 << (idx % 64);
        }
    }

    /// Check if a page is dirty.
    #[inline]
    pub fn is_dirty(&self, idx: usize) -> bool {
        (self.dirty_mask >> (idx % 64)) & 1 != 0
    }

    /// Clear dirty flags (after flush).
    #[inline]
    pub fn clear_dirty(&mut self) {
        self.dirty_mask = 0;
    }
}

// -----------------------------------------------------------------------------
// Per‑task mmap table
// -----------------------------------------------------------------------------

use crate::task::TaskId;

/// Global mmap table: task ID → list of mmap regions.
static MMAP_TABLE: Lazy<Mutex<BTreeMap<TaskId, Vec<MmapRegion>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

/// Statistics for debugging.
#[derive(Debug, Default)]
pub struct MmapStats {
    pub total_regions: AtomicU64,
    pub anonymous_regions: AtomicU64,
    pub file_regions: AtomicU64,
    pub shared_regions: AtomicU64,
    pub private_regions: AtomicU64,
}

impl MmapStats {
    fn record_region(&self, region: &MmapRegion) {
        self.total_regions.fetch_add(1, Ordering::Relaxed);
        match region.backing {
            MmapBacking::Anonymous => self.anonymous_regions.fetch_add(1, Ordering::Relaxed),
            MmapBacking::File { .. } => self.file_regions.fetch_add(1, Ordering::Relaxed),
        };
        if region.flags & MAP_SHARED != 0 {
            self.shared_regions.fetch_add(1, Ordering::Relaxed);
        } else {
            self.private_regions.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn remove_region(&self, region: &MmapRegion) {
        self.total_regions.fetch_sub(1, Ordering::Relaxed);
        match region.backing {
            MmapBacking::Anonymous => self.anonymous_regions.fetch_sub(1, Ordering::Relaxed),
            MmapBacking::File { .. } => self.file_regions.fetch_sub(1, Ordering::Relaxed),
        };
        if region.flags & MAP_SHARED != 0 {
            self.shared_regions.fetch_sub(1, Ordering::Relaxed);
        } else {
            self.private_regions.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

static MMAP_STATS: MmapStats = MmapStats::default();

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Map a file region into virtual address space.
///
/// # Arguments
/// * `tid` – Task ID.
/// * `path` – Path to the file in IONAFS.
/// * `offset` – Byte offset within the file (must be page‑aligned).
/// * `length` – Length of the mapping in bytes.
/// * `prot` – Protection flags (PROT_READ, PROT_WRITE, PROT_EXEC).
/// * `flags` – Mapping flags (MAP_SHARED, MAP_PRIVATE, MAP_FIXED, MAP_POPULATE).
/// * `hint` – Hint address for MAP_FIXED or placement.
///
/// # Returns
/// The mapped virtual address on success, `None` on error.
pub fn mmap_file(
    tid: TaskId,
    path: &str,
    offset: u64,
    length: usize,
    prot: u32,
    flags: u32,
    hint: u64,
) -> Option<u64> {
    // Validate offset alignment (must be page‑aligned for file mappings)
    if offset & (PAGE_SIZE as u64 - 1) != 0 {
        crate::serial_println!("[MMAP] file mapping offset not page‑aligned: {}", offset);
        return None;
    }

    // Verify file exists and is readable
    let file_data = crate::fs::ionafs::read(path)?;
    if offset as usize >= file_data.len() {
        crate::serial_println!("[MMAP] file offset {} beyond file size {}", offset, file_data.len());
        return None;
    }

    let actual_len = length.min(file_data.len() - offset as usize);
    let aligned_len = (actual_len + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    // Choose virtual address
    let base = if hint != 0 && (flags & MAP_FIXED != 0) {
        hint & PAGE_MASK
    } else {
        next_free_vaddr(tid, aligned_len, hint)
    };
    if base == 0 {
        crate::serial_println!("[MMAP] no free virtual address space");
        return None;
    }

    let region = MmapRegion {
        base,
        length: aligned_len,
        prot,
        flags,
        backing: MmapBacking::File {
            path: path.into(),
            offset,
            length: actual_len,
            writeable: (prot & PROT_WRITE) != 0,
        },
        dirty_mask: 0,
        populated: false,
    };

    // Check region limit
    {
        let mut table = MMAP_TABLE.lock();
        let regions = table.entry(tid).or_default();
        if regions.len() >= MAX_MMAP_REGIONS {
            crate::serial_println!("[MMAP] too many regions for task {}", tid);
            return None;
        }

        // Check for overlapping with existing regions (unless MAP_FIXED overwrites)
        if flags & MAP_FIXED != 0 {
            // Remove any overlapping regions first
            regions.retain(|r| !(r.base <= base + aligned_len as u64 && base <= r.base + r.length as u64));
        } else {
            for r in regions.iter() {
                if r.base <= base + aligned_len as u64 && base <= r.base + r.length as u64 {
                    crate::serial_println!("[MMAP] region overlaps with existing mapping");
                    return None;
                }
            }
        }
        regions.push(region.clone());
    }

    MMAP_STATS.record_region(&region);

    // Pre‑populate if requested
    if flags & MAP_POPULATE != 0 {
        pre_populate_region(&region);
    }

    crate::serial_println!(
        "[MMAP] file '{}' offset={} len={} @ {:#x} (prot={:#x}, flags={:#x})",
        path, offset, actual_len, base, prot, flags
    );
    Some(base)
}

/// Map anonymous pages (zero‑fill).
pub fn mmap_anon(
    tid: TaskId,
    length: usize,
    prot: u32,
    flags: u32,
    hint: u64,
) -> u64 {
    let aligned_len = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let base = if hint != 0 && (flags & MAP_FIXED != 0) {
        hint & PAGE_MASK
    } else {
        next_free_vaddr(tid, aligned_len, hint)
    };
    if base == 0 {
        crate::serial_println!("[MMAP] no free virtual address space for anonymous mapping");
        return 0;
    }

    let region = MmapRegion {
        base,
        length: aligned_len,
        prot,
        flags,
        backing: MmapBacking::Anonymous,
        dirty_mask: 0,
        populated: false,
    };

    {
        let mut table = MMAP_TABLE.lock();
        let regions = table.entry(tid).or_default();
        if regions.len() >= MAX_MMAP_REGIONS {
            crate::serial_println!("[MMAP] too many regions for task {}", tid);
            return 0;
        }
        regions.push(region.clone());
    }

    MMAP_STATS.record_region(&region);

    if flags & MAP_POPULATE != 0 {
        pre_populate_region(&region);
    }

    crate::serial_println!(
        "[MMAP] anonymous len={} @ {:#x} (prot={:#x}, flags={:#x})",
        aligned_len, base, prot, flags
    );
    base
}

/// Handle a page fault for a memory‑mapped region.
///
/// Returns `Some(page_data)` if the fault belongs to an mmap region,
/// `None` otherwise.
pub fn handle_page_fault(tid: TaskId, fault_addr: u64) -> Option<[u8; PAGE_SIZE]> {
    let table = MMAP_TABLE.lock();
    let regions = table.get(&tid)?;
    let region = regions.iter().find(|r| r.contains(fault_addr))?;

    let mut page = [0u8; PAGE_SIZE];

    match &region.backing {
        MmapBacking::Anonymous => {
            // Zero‑fill (already zeroed)
        }
        MmapBacking::File { path, offset, length, .. } => {
            let page_off = region.page_offset(fault_addr);
            let file_pos = *offset as usize + page_off;

            if let Some(data) = crate::fs::ionafs::read(path) {
                let src_start = file_pos.min(data.len());
                let src_end = (file_pos + PAGE_SIZE).min(data.len());
                let copy_len = src_end - src_start;
                if copy_len > 0 {
                    page[..copy_len].copy_from_slice(&data[src_start..src_end]);
                }
            }

            // If this is a private mapping and write was attempted, we need to COW
            if region.flags & MAP_PRIVATE != 0 && (region.prot & PROT_WRITE != 0) {
                // The page should be copied in the fault handler that maps it.
                // This is handled by the VMM (copy on write).
            }
        }
    }

    Some(page)
}

/// Mark a page as dirty (for MAP_SHARED) after a write.
pub fn mark_dirty(tid: TaskId, addr: u64) {
    let mut table = MMAP_TABLE.lock();
    let regions = match table.get_mut(&tid) {
        Some(r) => r,
        None => return,
    };
    if let Some(region) = regions.iter_mut().find(|r| r.contains(addr)) {
        region.mark_dirty(addr);
    }
}

/// Unmap a memory region.
///
/// # Returns
/// `true` if a region was unmapped, `false` otherwise.
pub fn munmap(tid: TaskId, addr: u64, length: usize) -> bool {
    let mut table = MMAP_TABLE.lock();
    let regions = match table.get_mut(&tid) {
        Some(r) => r,
        None => return false,
    };

    let end = addr + length as u64;
    let before = regions.len();

    // Collect regions to remove for stats
    let to_remove: Vec<_> = regions
        .iter()
        .filter(|r| r.base >= addr && r.base + r.length as u64 <= end)
        .cloned()
        .collect();

    for r in &to_remove {
        MMAP_STATS.remove_region(r);
        // Evict from swap
        crate::memory::swap::evict_range(r.base, r.base + r.length as u64);
    }

    regions.retain(|r| !(r.base >= addr && r.base + r.length as u64 <= end));
    regions.len() < before
}

/// Synchronise a memory region to disk (for MAP_SHARED).
///
/// Flushes all dirty pages to the underlying file.
pub fn msync(tid: TaskId, addr: u64, length: usize) -> bool {
    let mut table = MMAP_TABLE.lock();
    let regions = match table.get_mut(&tid) {
        Some(r) => r,
        None => return false,
    };

    let end = addr + length as u64;
    let mut any_flushed = false;

    for region in regions.iter_mut() {
        if region.base >= addr && region.base + region.length as u64 <= end {
            if region.flags & MAP_SHARED != 0 {
                flush_region(region);
                any_flushed = true;
            }
        }
    }
    any_flushed
}

/// Clean up all mappings for a task (on exit).
/// Also evicts any swapped pages for this task's virtual ranges.
pub fn cleanup_task(tid: TaskId) {
    if let Some(regions) = MMAP_TABLE.lock().remove(&tid) {
        for region in &regions {
            MMAP_STATS.remove_region(region);
            crate::memory::swap::evict_range(region.base, region.base + region.length as u64);
        }
    }
    crate::serial_println!("[MMAP] cleaned up task {}", tid);
}

/// Get memory statistics: (total_mb, used_mb, swap_used_mb).
pub fn memory_stats() -> (usize, usize, usize) {
    let (total_f, used_f) = crate::memory::frame_alloc::stats();
    let (_total_s, used_s) = crate::memory::swap::stats();
    (total_f * 4 / 1024, used_f * 4 / 1024, used_s)
}

/// Get mmap statistics.
pub fn mmap_stats() -> &'static MmapStats {
    &MMAP_STATS
}

/// Initialise the mmap subsystem.
pub fn init() {
    crate::serial_println!("  [MMAP] file‑backed + anonymous mmap initialised");
}

// -----------------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------------

/// Find a free virtual address range for a new mapping.
fn next_free_vaddr(tid: TaskId, len: usize, hint: u64) -> u64 {
    // Start from a high user address (the usual mmap base on Linux)
    let user_start = 0x0000_7000_0000_0000u64;
    let mut candidate = if hint != 0 && hint < user_start {
        user_start
    } else if hint != 0 {
        hint & PAGE_MASK
    } else {
        user_start
    };

    let table = MMAP_TABLE.lock();
    let regions = table.get(&tid);

    if let Some(regs) = regions {
        for r in regs {
            if r.base <= candidate && candidate < r.base + r.length as u64 {
                candidate = r.base.saturating_sub(len as u64 + PAGE_SIZE as u64);
            }
        }
    }

    // Ensure we don't go below the user space limit
    if candidate < 0x0000_1000_0000_0000 {
        candidate = 0x0000_1000_0000_0000;
    }

    candidate & PAGE_MASK
}

/// Pre‑populate a region by faulting in all pages.
fn pre_populate_region(region: &MmapRegion) {
    for offset in (0..region.length).step_by(PAGE_SIZE) {
        let addr = region.base + offset as u64;
        // Touch the page to trigger a fault
        unsafe {
            core::ptr::read_volatile(addr as *const u8);
        }
    }
}

/// Flush dirty pages of a region to the underlying file.
fn flush_region(region: &MmapRegion) {
    if let MmapBacking::File { path, offset, writeable, .. } = &region.backing {
        if !writeable {
            return;
        }

        let page_count = region.length / PAGE_SIZE;
        for i in 0..page_count {
            if region.is_dirty(i) {
                let page_addr = region.base + (i * PAGE_SIZE) as u64;
                let file_offset = *offset as usize + i * PAGE_SIZE;
                let data = unsafe {
                    core::slice::from_raw_parts(page_addr as *const u8, PAGE_SIZE)
                };
                // Write the page back to the file (simplified – full IONAFS write)
                // In production: write at specific offset within the file
                let _ = crate::fs::ionafs::write_at(path, file_offset as u64, data);
            }
        }
    }
}
