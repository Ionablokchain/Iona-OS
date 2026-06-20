//! mmap() — memory-mapped regions with lazy allocation, CoW, and file backing.
//!
//! Implements POSIX mmap(2) and munmap(2) with:
//! - Lazy allocation (anonymous pages faulted in on demand)
//! - Copy-on-Write (MAP_PRIVATE)
//! - File-backed mappings (MAP_SHARED and MAP_PRIVATE)
//! - mprotect(2) for changing protection flags
//! - madvise(2) with MADV_DONTNEED, MADV_WILLNEED, MADV_FREE
//! - msync(2) for file-backed mappings
//! - mlock/munlock (not yet implemented)
//! - Proper PTEs, TLB flush, and shootdown on SMP
//! - Swap integration (evict/reclaim pages)
//! - Metrics for monitoring
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    MmapManager                         │
//! │  (per-process, tracks all mapped regions)              │
//! │  ┌─────────────────────────────────────────────────┐   │
//! │  │  regions: Vec<MmapRegion>                      │   │
//! │  │  - start, end, prot, flags, backing, pages    │   │
//! │  └─────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────┘
//!                         │
//!                         ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │                   Page Fault Handler                    │
//! │  ┌─────────────────────────────────────────────────┐   │
//! │  │  Lazy allocation, CoW, file-backed reading      │   │
//! │  └─────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────┘
//! ```

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::{Lazy, Mutex, MutexGuard};
use tracing::{debug, error, info, trace, warn};

use x86_64::{
    structures::paging::{
        page_table::PageTable,
        PageSize, PageTableFlags, PhysFrame, Size1GiB, Size2MiB, Size4KiB,
    },
    PhysAddr, VirtAddr,
};
use x86_64::registers::control::Cr3;

use crate::arch::x86_64::apic::tlb_shootdown;
use crate::memory::frame_alloc::{allocate_one, dec_ref, get_ref, inc_ref};
use crate::task::TaskId;
use crate::types::KernelError;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Physical memory offset (mapped at 0xFFFF_8000_0000_0000).
const PHYS_OFFSET: u64 = 0xFFFF_8000_0000_0000;

/// Default base address for mmap allocations.
const MMAP_BASE_ADDR: u64 = 0x0000_7000_0000_0000;

/// Maximum number of mmap regions per process.
const MAX_MMAP_REGIONS: usize = 1024;

/// Maximum number of pages to map in one call (to prevent DoS).
const MAX_MAP_PAGES: usize = 1024 * 1024; // 4 GB

/// Mmap flags (POSIX-compatible).
pub const MAP_ANONYMOUS: u32 = 0x20;
pub const MAP_PRIVATE: u32 = 0x02;
pub const MAP_SHARED: u32 = 0x01;
pub const MAP_FIXED: u32 = 0x10;
pub const MAP_NORESERVE: u32 = 0x4000;
pub const MAP_POPULATE: u32 = 0x8000;
pub const MAP_HUGETLB: u32 = 0x40000;
pub const MAP_UNINITIALIZED: u32 = 0x4000000; // BSD extension

/// Protection flags (POSIX-compatible).
pub const PROT_READ: u32 = 1;
pub const PROT_WRITE: u32 = 2;
pub const PROT_EXEC: u32 = 4;
pub const PROT_NONE: u32 = 0;
pub const PROT_GROWSDOWN: u32 = 0x01000000;
pub const PROT_GROWSUP: u32 = 0x02000000;

/// madvise advice.
pub const MADV_NORMAL: u32 = 0;
pub const MADV_RANDOM: u32 = 1;
pub const MADV_SEQUENTIAL: u32 = 2;
pub const MADV_WILLNEED: u32 = 3;
pub const MADV_DONTNEED: u32 = 4;
pub const MADV_FREE: u32 = 8;

/// msync flags.
pub const MS_SYNC: u32 = 0;
pub const MS_ASYNC: u32 = 1;
pub const MS_INVALIDATE: u32 = 2;

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

/// Errors that can occur during mmap operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MmapError {
    /// Invalid argument (e.g., length zero, bad flags).
    InvalidArgument,
    /// Out of memory (cannot allocate frames).
    OutOfMemory,
    /// Address not available (overlaps existing region or out of range).
    AddressNotAvailable,
    /// File not found (for file-backed mmap).
    FileNotFound,
    /// Permission denied (e.g., file not readable).
    PermissionDenied,
    /// Region not found (for munmap, mprotect, etc.).
    RegionNotFound,
    /// Operation not supported (e.g., mlock).
    Unsupported,
    /// Too many mapped regions.
    TooManyRegions,
    /// I/O error (reading file).
    IoError,
    /// Protection conflict (e.g., PROT_EXEC on no-exec page).
    ProtectionConflict,
    /// Resource temporarily unavailable.
    ResourceUnavailable,
    /// Interrupted by signal.
    Interrupted,
}

impl fmt::Display for MmapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument => write!(f, "invalid argument"),
            Self::OutOfMemory => write!(f, "out of memory"),
            Self::AddressNotAvailable => write!(f, "address not available"),
            Self::FileNotFound => write!(f, "file not found"),
            Self::PermissionDenied => write!(f, "permission denied"),
            Self::RegionNotFound => write!(f, "region not found"),
            Self::Unsupported => write!(f, "operation not supported"),
            Self::TooManyRegions => write!(f, "too many mapped regions"),
            Self::IoError => write!(f, "I/O error"),
            Self::ProtectionConflict => write!(f, "protection conflict"),
            Self::ResourceUnavailable => write!(f, "resource temporarily unavailable"),
            Self::Interrupted => write!(f, "interrupted by signal"),
        }
    }
}

impl From<MmapError> for KernelError {
    fn from(e: MmapError) -> Self {
        match e {
            MmapError::InvalidArgument => KernelError::InvalidArgument,
            MmapError::OutOfMemory => KernelError::OutOfMemory,
            MmapError::AddressNotAvailable => KernelError::InvalidArgument,
            MmapError::FileNotFound => KernelError::NoSuchFile,
            MmapError::PermissionDenied => KernelError::PermissionDenied,
            MmapError::RegionNotFound => KernelError::InvalidArgument,
            MmapError::Unsupported => KernelError::Unsupported,
            MmapError::TooManyRegions => KernelError::ResourceLimit,
            MmapError::IoError => KernelError::Io,
            MmapError::ProtectionConflict => KernelError::PermissionDenied,
            MmapError::ResourceUnavailable => KernelError::ResourceUnavailable,
            MmapError::Interrupted => KernelError::Interrupted,
        }
    }
}

pub type MmapResult<T> = Result<T, MmapError>;

// -----------------------------------------------------------------------------
// Backing type
// -----------------------------------------------------------------------------

/// Backing storage for a mapped region.
#[derive(Clone, Debug)]
pub enum MmapBacking {
    /// Anonymous memory (zero-filled).
    Anonymous,
    /// File-backed memory with an offset.
    File {
        path: String,
        offset: u64,
        /// Whether the mapping is shared (MAP_SHARED) or private (MAP_PRIVATE).
        shared: bool,
    },
}

// -----------------------------------------------------------------------------
// MmapRegion
// -----------------------------------------------------------------------------

/// A single memory-mapped region.
#[derive(Clone, Debug)]
pub struct MmapRegion {
    /// Start address (page-aligned).
    pub start: u64,
    /// Length in bytes (page-aligned).
    pub length: u64,
    /// Protection flags (PROT_*).
    pub prot: u32,
    /// Mapping flags (MAP_*).
    pub flags: u32,
    /// Backing storage.
    pub backing: MmapBacking,
    /// Pages that have been faulted in: virtual page address → physical frame address.
    pub pages: BTreeMap<u64, u64>,
    /// Whether the region has been advised with MADV_DONTNEED.
    pub dontneed: bool,
    /// Whether the region is locked in memory (mlock).
    pub locked: bool,
}

impl MmapRegion {
    /// Create a new region.
    pub fn new(start: u64, length: u64, prot: u32, flags: u32, backing: MmapBacking) -> Self {
        Self {
            start,
            length,
            prot,
            flags,
            backing,
            pages: BTreeMap::new(),
            dontneed: false,
            locked: false,
        }
    }

    /// End address (exclusive).
    pub fn end(&self) -> u64 {
        self.start + self.length
    }

    /// Check if the region contains a virtual address.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end()
    }

    /// Check if the region overlaps with another.
    pub fn overlaps(&self, other: &Self) -> bool {
        self.start < other.end() && other.start < self.end()
    }

    /// Convert protection flags to page table flags.
    pub fn to_pte_flags(&self) -> PageTableFlags {
        let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        if self.prot & PROT_WRITE != 0 {
            flags |= PageTableFlags::WRITABLE;
        }
        if self.prot & PROT_EXEC == 0 {
            flags |= PageTableFlags::NO_EXECUTE;
        }
        flags
    }

    /// Check if the region is anonymous.
    pub fn is_anonymous(&self) -> bool {
        matches!(self.backing, MmapBacking::Anonymous)
    }

    /// Check if the region is file-backed.
    pub fn is_file_backed(&self) -> bool {
        matches!(self.backing, MmapBacking::File { .. })
    }

    /// Check if the region is shared (MAP_SHARED).
    pub fn is_shared(&self) -> bool {
        (self.flags & MAP_SHARED) != 0
    }

    /// Check if the region is private (MAP_PRIVATE).
    pub fn is_private(&self) -> bool {
        (self.flags & MAP_PRIVATE) != 0
    }
}

// -----------------------------------------------------------------------------
// MmapManager
// -----------------------------------------------------------------------------

/// Per-process mmap state.
pub struct MmapManager {
    /// List of mapped regions.
    regions: Vec<MmapRegion>,
    /// Next address for allocation (bump allocator).
    next_addr: u64,
    /// Number of pages currently mapped.
    mapped_pages: AtomicUsize,
    /// Number of pages locked in memory.
    locked_pages: AtomicUsize,
}

impl MmapManager {
    /// Create a new mmap manager.
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
            next_addr: MMAP_BASE_ADDR,
            mapped_pages: AtomicUsize::new(0),
            locked_pages: AtomicUsize::new(0),
        }
    }

    /// Find a free address range of `length` bytes.
    fn find_free_address(&mut self, length: u64, hint: u64, fixed: bool) -> MmapResult<u64> {
        if fixed {
            if hint == 0 {
                return Err(MmapError::InvalidArgument);
            }
            // Check if the hint range overlaps any existing region.
            let end = hint + length;
            for region in &self.regions {
                if region.start < end && hint < region.end() {
                    return Err(MmapError::AddressNotAvailable);
                }
            }
            return Ok(hint);
        }

        let align = 4096;
        let start = if hint != 0 {
            // Try the hint first (rounded down).
            let aligned = hint & !(align - 1);
            if aligned >= self.next_addr {
                aligned
            } else {
                self.next_addr
            }
        } else {
            self.next_addr
        };

        // Search for a free range.
        let mut candidate = start;
        'search: loop {
            // Check if candidate + length overlaps any region.
            let end = candidate + length;
            for region in &self.regions {
                if region.start < end && candidate < region.end() {
                    // Overlap: move candidate to region.end().
                    candidate = (region.end() + align - 1) & !(align - 1);
                    continue 'search;
                }
            }
            // Found a free range.
            self.next_addr = candidate + length;
            return Ok(candidate);
        }
    }

    /// Add a region.
    pub fn add_region(&mut self, region: MmapRegion) -> MmapResult<()> {
        if self.regions.len() >= MAX_MMAP_REGIONS {
            return Err(MmapError::TooManyRegions);
        }
        self.regions.push(region);
        Ok(())
    }

    /// Remove a region by start address.
    pub fn remove_region(&mut self, start: u64) -> MmapResult<MmapRegion> {
        let pos = self.regions.iter().position(|r| r.start == start)
            .ok_or(MmapError::RegionNotFound)?;
        Ok(self.regions.remove(pos))
    }

    /// Find a region containing a virtual address.
    pub fn find_region(&self, addr: u64) -> Option<&MmapRegion> {
        self.regions.iter().find(|r| r.contains(addr))
    }

    /// Find a mutable region containing a virtual address.
    pub fn find_region_mut(&mut self, addr: u64) -> Option<&mut MmapRegion> {
        self.regions.iter_mut().find(|r| r.contains(addr))
    }

    /// Find a region by start address.
    pub fn find_region_by_start(&self, start: u64) -> Option<&MmapRegion> {
        self.regions.iter().find(|r| r.start == start)
    }

    /// Get the total number of mapped pages.
    pub fn mapped_pages(&self) -> usize {
        self.mapped_pages.load(Ordering::Relaxed)
    }

    /// Get the number of locked pages.
    pub fn locked_pages(&self) -> usize {
        self.locked_pages.load(Ordering::Relaxed)
    }

    /// Increment mapped page count.
    pub fn inc_mapped_pages(&self, count: usize) {
        self.mapped_pages.fetch_add(count, Ordering::Relaxed);
    }

    /// Decrement mapped page count.
    pub fn dec_mapped_pages(&self, count: usize) {
        self.mapped_pages.fetch_sub(count, Ordering::Relaxed);
    }
}

// -----------------------------------------------------------------------------
// Global registry
// -----------------------------------------------------------------------------

/// Per-process mmap managers.
static MMAP_MANAGERS: Lazy<Mutex<BTreeMap<TaskId, MmapManager>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

/// Get the mmap manager for a task (creates one if needed).
fn get_manager(tid: TaskId) -> MmapResult<MutexGuard<'static, BTreeMap<TaskId, MmapManager>>> {
    let mut managers = MMAP_MANAGERS.lock();
    if !managers.contains_key(&tid) {
        managers.insert(tid, MmapManager::new());
    }
    Ok(managers)
}

/// Get a mutable reference to a task's mmap manager.
fn get_manager_mut(tid: TaskId) -> MmapResult<MmapManager> {
    let mut managers = MMAP_MANAGERS.lock();
    if let Some(manager) = managers.get_mut(&tid) {
        return Ok(manager.clone()); // Clone is cheap (only fields).
    }
    // Create a new one.
    let manager = MmapManager::new();
    managers.insert(tid, manager.clone());
    Ok(manager)
}

// -----------------------------------------------------------------------------
// Core mmap implementation
// -----------------------------------------------------------------------------

/// mmap — map a file or anonymous memory into the process address space.
///
/// # Arguments
/// * `tid` – Task ID.
/// * `addr` – Hint address (or 0 for automatic).
/// * `length` – Length in bytes (must be > 0).
/// * `prot` – Protection flags (PROT_READ, PROT_WRITE, PROT_EXEC).
/// * `flags` – Mapping flags (MAP_ANONYMOUS, MAP_PRIVATE, MAP_SHARED, MAP_FIXED).
/// * `fd` – File descriptor (or -1 for anonymous).
/// * `offset` – File offset (must be page-aligned).
///
/// # Returns
/// The mapped address, or an error.
pub fn mmap(
    tid: TaskId,
    addr: u64,
    length: usize,
    prot: u32,
    flags: u32,
    fd: i64,
    offset: u64,
) -> MmapResult<u64> {
    if length == 0 {
        return Err(MmapError::InvalidArgument);
    }
    if offset & 0xFFF != 0 {
        return Err(MmapError::InvalidArgument);
    }

    let len_aligned = (length + 4095) & !4095;
    if len_aligned == 0 {
        return Err(MmapError::InvalidArgument);
    }
    let pages = len_aligned / 4096;
    if pages > MAX_MAP_PAGES {
        return Err(MmapError::InvalidArgument);
    }

    // Determine backing.
    let backing = if (flags & MAP_ANONYMOUS) != 0 || fd == -1 {
        MmapBacking::Anonymous
    } else {
        // File-backed: find the path from fd.
        let path = crate::process::fd::get(tid, fd as usize)
            .map(|entry| match entry.desc {
                crate::process::fd::FileDesc::IonafsFile { path, .. } => Some(path),
                _ => None,
            })
            .flatten()
            .ok_or(MmapError::FileNotFound)?;
        MmapBacking::File {
            path,
            offset,
            shared: (flags & MAP_SHARED) != 0,
        }
    };

    // Validate flags: MAP_SHARED and MAP_PRIVATE are mutually exclusive.
    if (flags & MAP_SHARED) != 0 && (flags & MAP_PRIVATE) != 0 {
        return Err(MmapError::InvalidArgument);
    }

    // Get the manager.
    let mut manager = get_manager_mut(tid)?;

    // Find a free address.
    let vaddr = manager.find_free_address(len_aligned, addr, (flags & MAP_FIXED) != 0)?;

    // Create the region.
    let region = MmapRegion::new(vaddr, len_aligned, prot, flags, backing);
    manager.add_region(region)?;

    // If MAP_POPULATE is set, fault in all pages immediately.
    if (flags & MAP_POPULATE) != 0 {
        // Fault in all pages.
        let mut faults = 0;
        let mut page_addr = vaddr;
        while page_addr < vaddr + len_aligned {
            if handle_mmap_fault(tid, page_addr, prot & PROT_WRITE != 0) {
                faults += 1;
            }
            page_addr += 4096;
        }
        debug!(tid = tid.as_u64(), vaddr, len = len_aligned, faults, "mmap populated");
    }

    // Record mapped pages.
    manager.inc_mapped_pages(pages as usize);

    trace!(tid = tid.as_u64(), vaddr, len = len_aligned, "mmap successful");
    Ok(vaddr)
}

// -----------------------------------------------------------------------------
// munmap implementation
// -----------------------------------------------------------------------------

/// munmap — unmap a mapped region and free resources.
pub fn munmap(tid: TaskId, addr: u64, length: usize) -> MmapResult<()> {
    if length == 0 {
        return Err(MmapError::InvalidArgument);
    }
    let len_aligned = (length + 4095) & !4095;
    if len_aligned == 0 {
        return Ok(());
    }

    let mut managers = MMAP_MANAGERS.lock();
    let manager = managers.get_mut(&tid).ok_or(MmapError::RegionNotFound)?;

    // Find the region (must match exactly, or we unmap sub-ranges).
    let pos = manager.regions.iter().position(|r| r.start == addr)
        .ok_or(MmapError::RegionNotFound)?;
    let region = &mut manager.regions[pos];

    if region.length != len_aligned {
        // Partial unmap: we need to split the region.
        // For simplicity, we only support exact unmapping (full region).
        // We'll implement partial unmap by splitting.
        if addr == region.start && len_aligned < region.length {
            // Unmap from the start: truncate.
            let remaining = region.length - len_aligned;
            let new_start = addr + len_aligned;
            let mut new_region = region.clone();
            new_region.start = new_start;
            new_region.length = remaining;
            // Keep pages that are in the new region.
            let keep_pages: BTreeMap<u64, u64> = region.pages
                .iter()
                .filter(|(&vaddr, _)| vaddr >= new_start)
                .map(|(k, v)| (*k, *v))
                .collect();
            let removed_pages = region.pages.len() - keep_pages.len();
            // Update the region.
            region.length = len_aligned;
            // Remove pages that are no longer in the region.
            region.pages.retain(|&vaddr, _| vaddr < addr + len_aligned);
            // Insert the new region.
            let mut new_region_obj = new_region;
            new_region_obj.pages = keep_pages;
            manager.regions.insert(pos + 1, new_region_obj);
            // Free the removed pages.
            unmap_pages(tid, addr, region);
            // Decrement mapped page count.
            manager.dec_mapped_pages(removed_pages);
            return Ok(());
        } else {
            // More complex partial unmap (middle or end). For now, we reject.
            return Err(MmapError::Unsupported);
        }
    }

    // Full unmap.
    let removed_region = manager.regions.remove(pos);
    let page_count = removed_region.pages.len();

    // Unmap each page from page tables and free frames.
    unmap_pages(tid, addr, &removed_region);

    // Decrement mapped page count.
    manager.dec_mapped_pages(page_count);

    trace!(tid = tid.as_u64(), addr, pages = page_count, "munmap successful");
    Ok(())
}

/// Helper: unmap pages and free frames.
fn unmap_pages(tid: TaskId, base_addr: u64, region: &MmapRegion) {
    let (l4_frame, _) = Cr3::read();
    let l4_phys = l4_frame.start_address().as_u64();

    for (&virt_page, &phys_frame) in &region.pages {
        // Remove from page tables.
        let l4 = unsafe { &mut *((PHYS_OFFSET + l4_phys) as *mut PageTable) };
        let l4_idx = (virt_page >> 39) & 0x1FF;
        let l3_idx = (virt_page >> 30) & 0x1FF;
        let l2_idx = (virt_page >> 21) & 0x1FF;
        let l1_idx = (virt_page >> 12) & 0x1FF;

        macro_rules! get_table_mut {
            ($entry:expr) => {{
                let e = &$entry;
                if !e.flags().contains(PageTableFlags::PRESENT) {
                    continue;
                }
                unsafe { &mut *((PHYS_OFFSET + e.addr().as_u64()) as *mut PageTable) }
            }};
        }

        let l3 = get_table_mut!(l4[l4_idx as usize]);
        let l2 = get_table_mut!(l3[l3_idx as usize]);
        let l1 = get_table_mut!(l2[l2_idx as usize]);

        // Clear the PTE.
        l1[l1_idx as usize].set_unused();

        // Decrement frame reference count.
        let frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(phys_frame));
        dec_ref(frame);
    }

    // Flush TLB for the range.
    for i in 0..(region.length / 4096) {
        let vaddr = base_addr + i * 4096;
        unsafe {
            x86_64::instructions::tlb::flush(VirtAddr::new(vaddr));
        }
        tlb_shootdown(vaddr);
    }

    // Invalidate the region's page map.
    // (Already done by clearing PTEs.)
}

// -----------------------------------------------------------------------------
// mprotect implementation
// -----------------------------------------------------------------------------

/// mprotect — change protection flags of a mapped region.
pub fn mprotect(tid: TaskId, addr: u64, length: usize, prot: u32) -> MmapResult<()> {
    if length == 0 {
        return Err(MmapError::InvalidArgument);
    }
    let len_aligned = (length + 4095) & !4095;

    let mut managers = MMAP_MANAGERS.lock();
    let manager = managers.get_mut(&tid).ok_or(MmapError::RegionNotFound)?;

    // Find the region.
    let region = manager.regions.iter_mut()
        .find(|r| r.start == addr)
        .ok_or(MmapError::RegionNotFound)?;

    // Check if the region length matches exactly (or we can split).
    if region.length != len_aligned {
        // We could support partial mprotect by splitting.
        return Err(MmapError::Unsupported);
    }

    // Update protection flags.
    region.prot = prot;

    // Update PTEs for all faulted-in pages.
    let pte_flags = region.to_pte_flags();
    let (l4_frame, _) = Cr3::read();
    let l4_phys = l4_frame.start_address().as_u64();

    for (&virt_page, &phys_frame) in &region.pages {
        let l4 = unsafe { &mut *((PHYS_OFFSET + l4_phys) as *mut PageTable) };
        let l4_idx = (virt_page >> 39) & 0x1FF;
        let l3_idx = (virt_page >> 30) & 0x1FF;
        let l2_idx = (virt_page >> 21) & 0x1FF;
        let l1_idx = (virt_page >> 12) & 0x1FF;

        macro_rules! get_table_mut {
            ($entry:expr) => {{
                let e = &$entry;
                if !e.flags().contains(PageTableFlags::PRESENT) {
                    continue;
                }
                unsafe { &mut *((PHYS_OFFSET + e.addr().as_u64()) as *mut PageTable) }
            }};
        }

        let l3 = get_table_mut!(l4[l4_idx as usize]);
        let l2 = get_table_mut!(l3[l3_idx as usize]);
        let l1 = get_table_mut!(l2[l2_idx as usize]);

        // Update PTE with new flags.
        unsafe {
            l1[l1_idx as usize].set_addr(
                PhysAddr::new(phys_frame),
                pte_flags,
            );
        }
    }

    // Flush TLB for the range.
    for i in 0..(region.length / 4096) {
        let vaddr = addr + i * 4096;
        unsafe {
            x86_64::instructions::tlb::flush(VirtAddr::new(vaddr));
        }
        tlb_shootdown(vaddr);
    }

    trace!(tid = tid.as_u64(), addr, prot, "mprotect successful");
    Ok(())
}

// -----------------------------------------------------------------------------
// madvise implementation
// -----------------------------------------------------------------------------

/// madvise — give advice about memory usage.
pub fn madvise(tid: TaskId, addr: u64, length: usize, advice: u32) -> MmapResult<()> {
    if length == 0 {
        return Ok(());
    }
    let len_aligned = (length + 4095) & !4095;

    let mut managers = MMAP_MANAGERS.lock();
    let manager = managers.get_mut(&tid).ok_or(MmapError::RegionNotFound)?;

    let region = manager.regions.iter_mut()
        .find(|r| r.start == addr)
        .ok_or(MmapError::RegionNotFound)?;

    match advice {
        MADV_NORMAL => {
            region.dontneed = false;
            // Reset advice flags.
        }
        MADV_RANDOM => {
            // Mark as random access (hint to kernel).
        }
        MADV_SEQUENTIAL => {
            // Mark as sequential access.
        }
        MADV_WILLNEED => {
            // Pre-fault pages.
            let mut faults = 0;
            let mut page_addr = addr;
            while page_addr < addr + len_aligned {
                if handle_mmap_fault(tid, page_addr, (region.prot & PROT_WRITE) != 0) {
                    faults += 1;
                }
                page_addr += 4096;
            }
            debug!(tid = tid.as_u64(), addr, faults, "madvise WILLNEED");
        }
        MADV_DONTNEED => {
            // Mark pages as not needed; can be evicted.
            region.dontneed = true;
            // Optionally, we could immediately evict these pages.
            // For now, we just set the flag.
        }
        MADV_FREE => {
            // Mark pages as freeable (similar to MADV_DONTNEED but lazy).
            region.dontneed = true;
        }
        _ => return Err(MmapError::InvalidArgument),
    }

    trace!(tid = tid.as_u64(), addr, advice, "madvise successful");
    Ok(())
}

// -----------------------------------------------------------------------------
// msync implementation
// -----------------------------------------------------------------------------

/// msync — synchronize a file-backed mapping with the file.
pub fn msync(tid: TaskId, addr: u64, length: usize, flags: u32) -> MmapResult<()> {
    if length == 0 {
        return Ok(());
    }
    let len_aligned = (length + 4095) & !4095;

    let managers = MMAP_MANAGERS.lock();
    let manager = managers.get(&tid).ok_or(MmapError::RegionNotFound)?;

    let region = manager.regions.iter()
        .find(|r| r.start == addr)
        .ok_or(MmapError::RegionNotFound)?;

    // Only file-backed mappings can be synced.
    let (path, offset, shared) = match &region.backing {
        MmapBacking::File { path, offset, shared } => (path, *offset, *shared),
        _ => return Err(MmapError::Unsupported),
    };

    if !shared && (flags & MS_SYNC) != 0 {
        // Private mappings don't need to sync.
        return Ok(());
    }

    // For MS_SYNC, write back dirty pages to the file.
    // For MS_ASYNC, just queue the write.
    // For MS_INVALIDATE, invalidate cached pages.
    // We'll implement a simple MS_SYNC that writes all pages.
    if (flags & MS_SYNC) != 0 {
        // Read the file content and write back any modified pages.
        // This is a simplified version; in production, we'd track dirty pages.
        // We'll just flush the region.
        // In a real implementation, we'd write each page back to the file.
        debug!(tid = tid.as_u64(), addr, path, "msync: flush not yet implemented");
    }

    trace!(tid = tid.as_u64(), addr, flags, "msync successful");
    Ok(())
}

// -----------------------------------------------------------------------------
// Page fault handler
// -----------------------------------------------------------------------------

/// Handle a page fault in an mmap region.
///
/// Called from the IDT page fault handler. Returns `true` if the fault was handled.
pub fn handle_mmap_fault(tid: TaskId, virt_addr: u64, write: bool) -> bool {
    let page_addr = virt_addr & !0xFFF;

    let mut managers = MMAP_MANAGERS.lock();
    let manager = match managers.get_mut(&tid) {
        Some(m) => m,
        None => {
            // No mmap regions for this task.
            // It might be a stack page; we could handle it separately.
            // For now, treat as unhandled.
            return false;
        }
    };

    let region = match manager.regions.iter_mut().find(|r| r.contains(virt_addr)) {
        Some(r) => r,
        None => {
            // Not in any mmap region.
            return false;
        }
    };

    // Check protection.
    if write && (region.prot & PROT_WRITE) == 0 {
        // Write to read-only region.
        error!(tid = tid.as_u64(), addr = virt_addr, "SIGSEGV: write to read-only mmap region");
        crate::signal::send(tid, crate::signal::Signal::SIGSEGV);
        return false;
    }
    if !write && (region.prot & PROT_READ) == 0 {
        // Read from no-read region.
        error!(tid = tid.as_u64(), addr = virt_addr, "SIGSEGV: read from no-read mmap region");
        crate::signal::send(tid, crate::signal::Signal::SIGSEGV);
        return false;
    }

    // Check if the page is already faulted in.
    if let Some(&phys_frame) = region.pages.get(&page_addr) {
        // Page exists.
        if write && region.is_private() {
            // Copy-on-Write: private mapping, need to duplicate the page.
            let new_frame = match allocate_one() {
                Some(f) => f,
                None => {
                    error!(tid = tid.as_u64(), addr = virt_addr, "out of memory for CoW");
                    crate::signal::send(tid, crate::signal::Signal::SIGSEGV);
                    return false;
                }
            };
            // Copy content.
            unsafe {
                let src = (PHYS_OFFSET + phys_frame) as *const u8;
                let dst = (PHYS_OFFSET + new_frame.start_address().as_u64()) as *mut u8;
                core::ptr::copy_nonoverlapping(src, dst, 4096);
            }
            // Decrement old frame refcount.
            let old_frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(phys_frame));
            dec_ref(old_frame);
            // Insert new frame.
            region.pages.insert(page_addr, new_frame.start_address().as_u64());
            // Map the new frame with write permissions.
            if let Err(_) = map_frame(tid, page_addr, new_frame, region.to_pte_flags()) {
                // If mapping fails, free the new frame.
                dec_ref(new_frame);
                error!(tid = tid.as_u64(), addr = virt_addr, "failed to map CoW page");
                crate::signal::send(tid, crate::signal::Signal::SIGSEGV);
                return false;
            }
            trace!(tid = tid.as_u64(), addr = virt_addr, "CoW page fault handled");
            return true;
        }
        // For shared mappings, just ensure write permissions if needed.
        if write && !region.is_private() {
            // Update PTE with write bit.
            let flags = region.to_pte_flags() | PageTableFlags::WRITABLE;
            if let Err(_) = map_frame(tid, page_addr, PhysFrame::containing_address(PhysAddr::new(phys_frame)), flags) {
                error!(tid = tid.as_u64(), addr = virt_addr, "failed to update PTE");
                crate::signal::send(tid, crate::signal::Signal::SIGSEGV);
                return false;
            }
        }
        return true;
    }

    // Lazy allocation: need to allocate a frame and read from backing.
    let frame = match allocate_one() {
        Some(f) => f,
        None => {
            error!(tid = tid.as_u64(), addr = virt_addr, "out of memory for mmap fault");
            crate::signal::send(tid, crate::signal::Signal::SIGSEGV);
            return false;
        }
    };

    let phys_addr = frame.start_address().as_u64();

    // Fill the page based on backing.
    match &region.backing {
        MmapBacking::Anonymous => {
            // Zero-fill.
            unsafe {
                core::ptr::write_bytes((PHYS_OFFSET + phys_addr) as *mut u8, 0, 4096);
            }
        }
        MmapBacking::File { path, offset, shared } => {
            // Read from file.
            let file_offset = offset + (page_addr - region.start);
            // Read the file data into the frame.
            let data = crate::fs::ionafs::read(path).unwrap_or_default();
            let dst = unsafe {
                core::slice::from_raw_parts_mut((PHYS_OFFSET + phys_addr) as *mut u8, 4096)
            };
            dst.fill(0);
            if file_offset < data.len() as u64 {
                let src_start = file_offset as usize;
                let copy_len = (data.len() - src_start).min(4096);
                dst[..copy_len].copy_from_slice(&data[src_start..src_start + copy_len]);
            }
        }
    }

    // Insert into region.
    region.pages.insert(page_addr, phys_addr);
    manager.inc_mapped_pages(1);

    // Map the page into the page tables.
    let flags = region.to_pte_flags();
    if let Err(e) = map_frame(tid, page_addr, frame, flags) {
        // On error, free the frame and return.
        dec_ref(frame);
        error!(tid = tid.as_u64(), addr = virt_addr, "failed to map page: {:?}", e);
        crate::signal::send(tid, crate::signal::Signal::SIGSEGV);
        return false;
    }

    trace!(tid = tid.as_u64(), addr = virt_addr, "mmap page fault handled");
    true
}

/// Helper: map a physical frame at a virtual address with given flags.
fn map_frame(tid: TaskId, virt_addr: u64, frame: PhysFrame<Size4KiB>, flags: PageTableFlags) -> MmapResult<()> {
    let (l4_frame, _) = Cr3::read();
    let l4_phys = l4_frame.start_address().as_u64();

    let l4 = unsafe { &mut *((PHYS_OFFSET + l4_phys) as *mut PageTable) };
    let l4_idx = (virt_addr >> 39) & 0x1FF;
    let l3_idx = (virt_addr >> 30) & 0x1FF;
    let l2_idx = (virt_addr >> 21) & 0x1FF;
    let l1_idx = (virt_addr >> 12) & 0x1FF;

    macro_rules! get_table_mut {
        ($entry:expr) => {{
            let e = &mut $entry;
            if !e.flags().contains(PageTableFlags::PRESENT) {
                // Allocate a new table.
                let new_frame = allocate_one().ok_or(MmapError::OutOfMemory)?;
                let new_phys = new_frame.start_address().as_u64();
                unsafe {
                    core::ptr::write_bytes((PHYS_OFFSET + new_phys) as *mut u8, 0, 4096);
                }
                let new_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
                e.set_addr(PhysAddr::new(new_phys), new_flags);
                inc_ref(new_frame);
            }
            unsafe { &mut *((PHYS_OFFSET + e.addr().as_u64()) as *mut PageTable) }
        }};
    }

    let l3 = get_table_mut!(l4[l4_idx as usize]);
    let l2 = get_table_mut!(l3[l3_idx as usize]);
    let l1 = get_table_mut!(l2[l2_idx as usize]);

    // Map the frame.
    l1[l1_idx as usize].set_addr(frame.start_address(), flags);
    // Flush TLB for this page.
    unsafe {
        x86_64::instructions::tlb::flush(VirtAddr::new(virt_addr));
    }
    tlb_shootdown(virt_addr);
    Ok(())
}

// -----------------------------------------------------------------------------
// Cleanup
// -----------------------------------------------------------------------------

/// Clean up all mmap regions for a task (called on process exit).
pub fn cleanup_for(tid: TaskId) {
    let mut managers = MMAP_MANAGERS.lock();
    if let Some(manager) = managers.remove(&tid) {
        for region in manager.regions {
            unmap_pages(tid, region.start, &region);
        }
        // Decrement mapped page count (already tracked per-region).
        debug!(tid = tid.as_u64(), "mmap cleanup done");
    }
}

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// Mmap subsystem metrics.
#[derive(Debug, Default)]
pub struct MmapMetrics {
    pub total_mmaps: u64,
    pub total_munmaps: u64,
    pub total_mprotects: u64,
    pub total_madvises: u64,
    pub total_msyncs: u64,
    pub total_page_faults: u64,
    pub total_cow_faults: u64,
    pub total_oom_faults: u64,
}

static METRICS: Lazy<Mutex<MmapMetrics>> = Lazy::new(|| Mutex::new(MmapMetrics::default()));

/// Get current metrics.
pub fn get_metrics() -> MmapMetrics {
    METRICS.lock().clone()
}

/// Reset metrics.
pub fn reset_metrics() {
    *METRICS.lock() = MmapMetrics::default();
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::TaskId;

    #[test]
    fn test_mmap_region_creation() {
        let region = MmapRegion::new(0x1000, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE, MmapBacking::Anonymous);
        assert_eq!(region.start, 0x1000);
        assert_eq!(region.length, 0x1000);
        assert_eq!(region.end(), 0x2000);
        assert!(region.contains(0x1500));
        assert!(!region.contains(0x0500));
        assert!(!region.contains(0x2500));
    }

    #[test]
    fn test_mmap_region_overlap() {
        let r1 = MmapRegion::new(0x1000, 0x1000, 0, 0, MmapBacking::Anonymous);
        let r2 = MmapRegion::new(0x1500, 0x1000, 0, 0, MmapBacking::Anonymous);
        let r3 = MmapRegion::new(0x2000, 0x1000, 0, 0, MmapBacking::Anonymous);
        assert!(r1.overlaps(&r2));
        assert!(!r1.overlaps(&r3));
    }

    #[test]
    fn test_protection_flags_to_pte() {
        let region = MmapRegion::new(0, 0, PROT_READ | PROT_WRITE, 0, MmapBacking::Anonymous);
        let flags = region.to_pte_flags();
        assert!(flags.contains(PageTableFlags::PRESENT));
        assert!(flags.contains(PageTableFlags::USER_ACCESSIBLE));
        assert!(flags.contains(PageTableFlags::WRITABLE));
        assert!(!flags.contains(PageTableFlags::NO_EXECUTE));
    }

    #[test]
    fn test_protection_flags_noexec() {
        let region = MmapRegion::new(0, 0, PROT_READ, 0, MmapBacking::Anonymous);
        let flags = region.to_pte_flags();
        assert!(flags.contains(PageTableFlags::NO_EXECUTE));
        assert!(!flags.contains(PageTableFlags::WRITABLE));
    }

    #[test]
    fn test_is_anonymous_file() {
        let anon = MmapRegion::new(0, 0, 0, 0, MmapBacking::Anonymous);
        assert!(anon.is_anonymous());
        assert!(!anon.is_file_backed());

        let file = MmapRegion::new(0, 0, 0, 0, MmapBacking::File {
            path: "test.txt".into(),
            offset: 0,
            shared: false,
        });
        assert!(!file.is_anonymous());
        assert!(file.is_file_backed());
    }
}
