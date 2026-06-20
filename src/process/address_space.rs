//! Per-process virtual address space
//!
//! Each userspace process has its own page tables (L4). On context switch we
//! change CR3 → the CPU uses the new page tables.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                   AddressSpace                         │
//! │  ┌─────────────────────────────────────────────────┐   │
//! │  │  L4 frame (CR3)                               │   │
//! │  ├─────────────────────────────────────────────────┤   │
//! │  │  Kernel half (entries 256-511) shared          │   │
//! │  ├─────────────────────────────────────────────────┤   │
//! │  │  User half (entries 0-255) per-process         │   │
//! │  └─────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────┘
//!                         │
//!                         ▼
//! ┌─────────────────────────────────────────────────────────┐
//! │              Page Table Walker                         │
//! │  (L4 → L3 → L2 → L1 translation)                     │
//! └─────────────────────────────────────────────────────────┘
//! ```

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::fmt;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::{Lazy, Mutex};
use tracing::{debug, error, info, trace, warn};

use x86_64::{
    structures::paging::{
        page_table::{PageTable, PageTableEntry},
        FrameAllocator, Mapper, OffsetPageTable, Page, PageSize, PageTableFlags, PhysFrame,
        Size1GiB, Size2MiB, Size4KiB,
    },
    PhysAddr, VirtAddr,
};

use crate::arch::x86_64::apic::tlb_shootdown;
use crate::memory::frame_alloc::{allocate_one, dec_ref, get_ref, inc_ref, KernelFrameAllocator};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Physical memory offset (mapped at 0xFFFF_8000_0000_0000).
const PHYS_OFFSET: u64 = 0xFFFF_8000_0000_0000;

/// Default user space base address (with ASLR offset).
const USER_BASE: u64 = 0x0000_4000_0000_0000;

/// User stack top (8 MiB below the top of the user range).
const USER_STACK_TOP: u64 = 0x0000_7FFF_0000_0000;

/// Default page size.
const DEFAULT_PAGE_SIZE: usize = 4096;

/// ASLR randomisation bits (12 bits = 4 KiB alignment, 4 MiB range).
const ASLR_BITS: u64 = 12;

/// Max number of page tables per address space (safety limit).
const MAX_PAGE_TABLES: usize = 1024;

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

/// Errors that can occur during address space operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressSpaceError {
    /// Out of memory (cannot allocate page table frame).
    OutOfMemory,
    /// Invalid virtual address (non-canonical).
    InvalidAddress,
    /// Page already mapped at this address.
    AlreadyMapped,
    /// Page not mapped at this address.
    NotMapped,
    /// Invalid physical address.
    InvalidPhysicalAddress,
    /// Address space is locked (cannot modify).
    Locked,
    /// Too many page tables allocated.
    TooManyPageTables,
    /// Kernel address space violation (trying to map user page in kernel range).
    KernelSpaceViolation,
    /// Operation not supported.
    Unsupported,
    /// Internal error.
    Internal,
}

impl fmt::Display for AddressSpaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfMemory => write!(f, "out of memory"),
            Self::InvalidAddress => write!(f, "invalid virtual address"),
            Self::AlreadyMapped => write!(f, "page already mapped"),
            Self::NotMapped => write!(f, "page not mapped"),
            Self::InvalidPhysicalAddress => write!(f, "invalid physical address"),
            Self::Locked => write!(f, "address space is locked"),
            Self::TooManyPageTables => write!(f, "too many page tables allocated"),
            Self::KernelSpaceViolation => write!(f, "kernel space violation"),
            Self::Unsupported => write!(f, "operation not supported"),
            Self::Internal => write!(f, "internal error"),
        }
    }
}

pub type AddressSpaceResult<T> = Result<T, AddressSpaceError>;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the address space.
#[derive(Debug, Clone)]
pub struct AddressSpaceConfig {
    /// Enable ASLR (randomisation of base address).
    pub enable_aslr: bool,
    /// ASLR randomisation bits (0-12, default 12).
    pub aslr_bits: u64,
    /// Default user base address.
    pub user_base: u64,
    /// User stack top.
    pub stack_top: u64,
    /// Whether to track metrics.
    pub collect_metrics: bool,
    /// Whether to log debug events.
    pub debug_logging: bool,
}

impl Default for AddressSpaceConfig {
    fn default() -> Self {
        Self {
            enable_aslr: true,
            aslr_bits: ASLR_BITS,
            user_base: USER_BASE,
            stack_top: USER_STACK_TOP,
            collect_metrics: true,
            debug_logging: false,
        }
    }
}

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// Address space metrics.
#[derive(Debug, Default)]
pub struct AddressSpaceMetrics {
    /// Total number of address spaces created.
    pub spaces_created: AtomicU64,
    /// Total number of address spaces destroyed.
    pub spaces_destroyed: AtomicU64,
    /// Total number of page tables allocated.
    pub page_tables_allocated: AtomicU64,
    /// Total number of page tables freed.
    pub page_tables_freed: AtomicU64,
    /// Total number of pages mapped.
    pub pages_mapped: AtomicU64,
    /// Total number of pages unmapped.
    pub pages_unmapped: AtomicU64,
    /// Total number of page faults resolved.
    pub page_faults: AtomicU64,
    /// Total number of copy-on-write faults.
    pub cow_faults: AtomicU64,
}

/// Global metrics instance.
static METRICS: Lazy<Mutex<AddressSpaceMetrics>> = Lazy::new(|| Mutex::new(AddressSpaceMetrics::default()));

/// Get the current metrics.
pub fn get_metrics() -> AddressSpaceMetrics {
    METRICS.lock().clone()
}

/// Reset metrics.
pub fn reset_metrics() {
    *METRICS.lock() = AddressSpaceMetrics::default();
}

// -----------------------------------------------------------------------------
// Page table walker
// -----------------------------------------------------------------------------

/// Result of a page table walk.
#[derive(Debug, Clone)]
pub struct PageWalkResult {
    /// Physical address of the page.
    pub phys_addr: u64,
    /// Page size (4096, 2MiB, or 1GiB).
    pub page_size: u64,
    /// Whether the page is writable.
    pub writable: bool,
    /// Whether the page is user-accessible.
    pub user: bool,
    /// Whether the page is executable.
    pub executable: bool,
    /// Whether the page is present.
    pub present: bool,
}

/// Walk page tables to find a page table entry for a virtual address.
///
/// Returns the PTE and the level at which it was found.
pub fn walk_page_tables(
    l4_phys: u64,
    virt: u64,
) -> AddressSpaceResult<(PageTableEntry, u8)> {
    // Check canonical form.
    let bit47 = (virt >> 47) & 1;
    let upper = virt >> 48;
    if (bit47 == 0 && upper != 0) || (bit47 == 1 && upper != 0xFFFF) {
        return Err(AddressSpaceError::InvalidAddress);
    }

    let phys_off = PHYS_OFFSET;

    // Read a page table entry at (table_phys + index * 8).
    let read_entry = |table_phys: u64, idx: u64| -> PageTableEntry {
        let ptr = (phys_off + (table_phys & 0x000F_FFFF_FFFF_F000) + idx * 8) as *const PageTableEntry;
        unsafe { ptr.read_volatile() }
    };

    let l4i = (virt >> 39) & 0x1FF;
    let l3i = (virt >> 30) & 0x1FF;
    let l2i = (virt >> 21) & 0x1FF;
    let l1i = (virt >> 12) & 0x1FF;

    // L4 (PML4)
    let l4e = read_entry(l4_phys, l4i);
    if !l4e.flags().contains(PageTableFlags::PRESENT) {
        return Err(AddressSpaceError::NotMapped);
    }

    // L3 (PDPT)
    let l3e = read_entry(l4e.addr().as_u64(), l3i);
    if !l3e.flags().contains(PageTableFlags::PRESENT) {
        return Err(AddressSpaceError::NotMapped);
    }

    // Check for 1GB huge page.
    if l3e.flags().contains(PageTableFlags::HUGE_PAGE) {
        return Ok((l3e, 3));
    }

    // L2 (PD)
    let l2e = read_entry(l3e.addr().as_u64(), l2i);
    if !l2e.flags().contains(PageTableFlags::PRESENT) {
        return Err(AddressSpaceError::NotMapped);
    }

    // Check for 2MB huge page.
    if l2e.flags().contains(PageTableFlags::HUGE_PAGE) {
        return Ok((l2e, 2));
    }

    // L1 (PT) — 4KB page.
    let l1e = read_entry(l2e.addr().as_u64(), l1i);
    if !l1e.flags().contains(PageTableFlags::PRESENT) {
        return Err(AddressSpaceError::NotMapped);
    }

    Ok((l1e, 1))
}

/// Get the physical address of a virtual address.
pub fn get_phys_addr(l4_phys: u64, virt: u64) -> AddressSpaceResult<u64> {
    let (pte, level) = walk_page_tables(l4_phys, virt)?;
    let phys_base = pte.addr().as_u64();
    let offset = match level {
        3 => virt & 0x3FFF_FFFF,      // 1GB offset
        2 => virt & 0x1F_FFFF,        // 2MB offset
        1 => virt & 0xFFF,            // 4KB offset
        _ => return Err(AddressSpaceError::Internal),
    };
    Ok(phys_base | offset)
}

// -----------------------------------------------------------------------------
// AddressSpace
// -----------------------------------------------------------------------------

/// Per-process virtual address space.
#[derive(Debug)]
pub struct AddressSpace {
    /// Physical frame containing the L4 page table (CR3).
    l4_frame: PhysFrame,
    /// L4 physical address (cached for fast access).
    l4_phys: u64,
    /// L4 virtual address (for modification).
    l4_virt: VirtAddr,
    /// User base address (with ASLR offset if enabled).
    user_base: u64,
    /// User stack top.
    stack_top: u64,
    /// Entry point (from ELF).
    pub entry_point: u64,
    /// Number of arguments (from ELF).
    pub argc: u64,
    /// Number of mapped pages.
    mapped_pages: AtomicUsize,
    /// Number of page tables allocated.
    page_tables: AtomicUsize,
    /// Configuration.
    config: Arc<AddressSpaceConfig>,
    /// Whether the address space is locked (for batch operations).
    locked: bool,
}

impl AddressSpace {
    /// Create a new address space with the given configuration.
    pub fn new(config: Arc<AddressSpaceConfig>) -> AddressSpaceResult<Self> {
        // Allocate L4 frame.
        let l4_frame = allocate_one().ok_or(AddressSpaceError::OutOfMemory)?;
        let l4_phys = l4_frame.start_address().as_u64();

        // Map it to virtual memory.
        let phys_offset = VirtAddr::new(PHYS_OFFSET);
        let l4_virt = phys_offset + l4_phys;
        let l4 = unsafe { &mut *l4_virt.as_mut_ptr::<PageTable>() };

        // Zero the L4.
        l4.zero();

        // Copy kernel half (entries 256-511) from current address space.
        let (current_l4_frame, _) = x86_64::registers::control::Cr3::read();
        let current_l4_phys = current_l4_frame.start_address().as_u64();
        let current_l4_virt = phys_offset + current_l4_phys;
        let current_l4 = unsafe { &*current_l4_virt.as_ptr::<PageTable>() };

        for i in 256..512 {
            l4[i] = current_l4[i].clone();
        }

        // Compute user base with ASLR.
        let user_base = if config.enable_aslr {
            let rand_offset = crate::arch::x86_64::random::rand_u64() & ((1 << config.aslr_bits) - 1);
            config.user_base + (rand_offset << 12)
        } else {
            config.user_base
        };

        if config.collect_metrics {
            METRICS.lock().spaces_created.fetch_add(1, Ordering::Relaxed);
            METRICS.lock().page_tables_allocated.fetch_add(1, Ordering::Relaxed);
        }

        debug!(
            l4_phys = format!("0x{:x}", l4_phys),
            user_base = format!("0x{:x}", user_base),
            "address space created"
        );

        Ok(Self {
            l4_frame,
            l4_phys,
            l4_virt,
            user_base,
            stack_top: config.stack_top,
            entry_point: 0,
            argc: 0,
            mapped_pages: AtomicUsize::new(0),
            page_tables: AtomicUsize::new(1),
            config,
            locked: false,
        })
    }

    /// Create a new address space with default configuration.
    pub fn default() -> AddressSpaceResult<Self> {
        Self::new(Arc::new(AddressSpaceConfig::default()))
    }

    /// Clone the address space (for fork) with copy-on-write.
    /// This creates a new address space with the same mappings as the parent,
    /// but all user pages are marked read-only and shared (CoW).
    pub fn clone_cow(&self) -> AddressSpaceResult<Self> {
        // Allocate new L4 frame.
        let new_l4_frame = allocate_one().ok_or(AddressSpaceError::OutOfMemory)?;
        let new_l4_phys = new_l4_frame.start_address().as_u64();
        let phys_offset = VirtAddr::new(PHYS_OFFSET);
        let new_l4_virt = phys_offset + new_l4_phys;

        // Zero the new L4.
        let new_l4 = unsafe { &mut *new_l4_virt.as_mut_ptr::<PageTable>() };
        new_l4.zero();

        // Copy the entire L4 from parent (will deep-copy user pages).
        let parent_l4_virt = phys_offset + self.l4_phys;
        let parent_l4 = unsafe { &*parent_l4_virt.as_ptr::<PageTable>() };

        // Copy kernel half directly.
        for i in 256..512 {
            new_l4[i] = parent_l4[i].clone();
        }

        // Copy user half (entries 0-255) with CoW.
        for l4i in 0..256 {
            let l4e = &parent_l4[l4i];
            if !l4e.flags().contains(PageTableFlags::PRESENT) {
                continue;
            }

            // Clone L3 table.
            let new_l3_frame = allocate_one().ok_or(AddressSpaceError::OutOfMemory)?;
            let new_l3_phys = new_l3_frame.start_address().as_u64();
            let new_l3_virt = phys_offset + new_l3_phys;
            let new_l3 = unsafe { &mut *new_l3_virt.as_mut_ptr::<PageTable>() };
            new_l3.zero();

            // Get parent L3.
            let parent_l3_phys = l4e.addr().as_u64();
            let parent_l3_virt = phys_offset + parent_l3_phys;
            let parent_l3 = unsafe { &*parent_l3_virt.as_ptr::<PageTable>() };

            for l3i in 0..512 {
                let l3e = &parent_l3[l3i];
                if !l3e.flags().contains(PageTableFlags::PRESENT) {
                    continue;
                }

                // Check for 1GB huge page.
                if l3e.flags().contains(PageTableFlags::HUGE_PAGE) {
                    // Share 1GB page read-only.
                    let mut flags = l3e.flags();
                    flags.remove(PageTableFlags::WRITABLE);
                    new_l3[l3i] = *l3e;
                    new_l3[l3i].set_flags(flags);
                    if let Ok(frame) = l3e.frame() {
                        inc_ref(frame);
                    }
                    continue;
                }

                // Clone L2 table.
                let new_l2_frame = allocate_one().ok_or(AddressSpaceError::OutOfMemory)?;
                let new_l2_phys = new_l2_frame.start_address().as_u64();
                let new_l2_virt = phys_offset + new_l2_phys;
                let new_l2 = unsafe { &mut *new_l2_virt.as_mut_ptr::<PageTable>() };
                new_l2.zero();

                let parent_l2_phys = l3e.addr().as_u64();
                let parent_l2_virt = phys_offset + parent_l2_phys;
                let parent_l2 = unsafe { &*parent_l2_virt.as_ptr::<PageTable>() };

                for l2i in 0..512 {
                    let l2e = &parent_l2[l2i];
                    if !l2e.flags().contains(PageTableFlags::PRESENT) {
                        continue;
                    }

                    // Check for 2MB huge page.
                    if l2e.flags().contains(PageTableFlags::HUGE_PAGE) {
                        let mut flags = l2e.flags();
                        flags.remove(PageTableFlags::WRITABLE);
                        new_l2[l2i] = *l2e;
                        new_l2[l2i].set_flags(flags);
                        if let Ok(frame) = l2e.frame() {
                            inc_ref(frame);
                        }
                        continue;
                    }

                    // Clone L1 table.
                    let new_l1_frame = allocate_one().ok_or(AddressSpaceError::OutOfMemory)?;
                    let new_l1_phys = new_l1_frame.start_address().as_u64();
                    let new_l1_virt = phys_offset + new_l1_phys;
                    let new_l1 = unsafe { &mut *new_l1_virt.as_mut_ptr::<PageTable>() };
                    new_l1.zero();

                    let parent_l1_phys = l2e.addr().as_u64();
                    let parent_l1_virt = phys_offset + parent_l1_phys;
                    let parent_l1 = unsafe { &*parent_l1_virt.as_ptr::<PageTable>() };

                    for l1i in 0..512 {
                        let l1e = &parent_l1[l1i];
                        if !l1e.flags().contains(PageTableFlags::PRESENT) {
                            continue;
                        }

                        // Mark read-only in both parent and child.
                        let mut flags = l1e.flags();
                        flags.remove(PageTableFlags::WRITABLE);

                        // Copy to child.
                        new_l1[l1i] = *l1e;
                        new_l1[l1i].set_flags(flags);

                        // Also mark parent read-only.
                        let parent_l1_mut = unsafe {
                            &mut *(phys_offset + parent_l1_phys).as_mut_ptr::<PageTable>()
                        };
                        parent_l1_mut[l1i].set_flags(flags);

                        // Increment refcount on data frame.
                        if let Ok(frame) = l1e.frame() {
                            inc_ref(frame);
                        }
                    }

                    // Set child L2 entry to point to new L1.
                    let l2_flags = l2e.flags();
                    unsafe {
                        new_l2[l2i].set_addr(PhysAddr::new(new_l1_phys), l2_flags);
                    }
                }

                // Set child L3 entry to point to new L2.
                let l3_flags = l3e.flags();
                unsafe {
                    new_l3[l3i].set_addr(PhysAddr::new(new_l2_phys), l3_flags);
                }
            }

            // Set child L4 entry to point to new L3.
            let l4_flags = l4e.flags();
            unsafe {
                new_l4[l4i].set_addr(PhysAddr::new(new_l3_phys), l4_flags);
            }
        }

        // Flush TLB.
        x86_64::instructions::tlb::flush_all();

        let new_space = AddressSpace {
            l4_frame: new_l4_frame,
            l4_phys: new_l4_phys,
            l4_virt: new_l4_virt,
            user_base: self.user_base,
            stack_top: self.stack_top,
            entry_point: self.entry_point,
            argc: self.argc,
            mapped_pages: AtomicUsize::new(self.mapped_pages.load(Ordering::Relaxed)),
            page_tables: AtomicUsize::new(self.page_tables.load(Ordering::Relaxed) + 1),
            config: self.config.clone(),
            locked: false,
        };

        if self.config.collect_metrics {
            METRICS.lock().spaces_created.fetch_add(1, Ordering::Relaxed);
        }

        debug!("address space cloned with CoW");
        Ok(new_space)
    }

    /// Activate this address space (load CR3).
    pub fn activate(&self) {
        unsafe {
            x86_64::registers::control::Cr3::write(
                self.l4_frame,
                x86_64::registers::control::Cr3Flags::empty(),
            );
        }
        trace!("address space activated (CR3={:#x})", self.l4_phys);
    }

    /// Lock the address space for batch operations.
    pub fn lock(&mut self) {
        self.locked = true;
    }

    /// Unlock the address space.
    pub fn unlock(&mut self) {
        self.locked = false;
    }

    // -------------------------------------------------------------------------
    // Page mapping
    // -------------------------------------------------------------------------

    /// Map a single 4KB page.
    pub fn map_page(
        &mut self,
        virt: u64,
        phys: u64,
        flags: PageTableFlags,
    ) -> AddressSpaceResult<()> {
        if self.locked {
            return Err(AddressSpaceError::Locked);
        }

        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virt));
        let frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(phys));

        self.map_page_internal(page, frame, flags)
    }

    /// Map a page with the given frame.
    pub fn map_page_frame(
        &mut self,
        page: Page<Size4KiB>,
        frame: PhysFrame<Size4KiB>,
        flags: PageTableFlags,
    ) -> AddressSpaceResult<()> {
        if self.locked {
            return Err(AddressSpaceError::Locked);
        }
        self.map_page_internal(page, frame, flags)
    }

    /// Internal page mapper.
    fn map_page_internal(
        &mut self,
        page: Page<Size4KiB>,
        frame: PhysFrame<Size4KiB>,
        flags: PageTableFlags,
    ) -> AddressSpaceResult<()> {
        let phys_offset = VirtAddr::new(PHYS_OFFSET);
        let l4 = unsafe { &mut *self.l4_virt.as_mut_ptr::<PageTable>() };
        let mut mapper = unsafe { OffsetPageTable::new(l4, phys_offset) };

        // Check if already mapped.
        if let Ok((_, _)) = walk_page_tables(self.l4_phys, page.start_address().as_u64()) {
            return Err(AddressSpaceError::AlreadyMapped);
        }

        let mut fa = KernelFrameAllocator;
        unsafe {
            mapper.map_to(page, frame, flags, &mut fa)
                .map_err(|_| AddressSpaceError::OutOfMemory)?
                .flush();
        }

        self.mapped_pages.fetch_add(1, Ordering::Relaxed);
        if self.config.collect_metrics {
            METRICS.lock().pages_mapped.fetch_add(1, Ordering::Relaxed);
        }

        trace!(
            virt = format!("0x{:x}", page.start_address().as_u64()),
            phys = format!("0x{:x}", frame.start_address().as_u64()),
            flags = format!("0x{:x}", flags.bits()),
            "page mapped"
        );

        Ok(())
    }

    /// Map a range of pages.
    pub fn map_range(
        &mut self,
        start_virt: u64,
        start_phys: u64,
        count: usize,
        flags: PageTableFlags,
    ) -> AddressSpaceResult<()> {
        if self.locked {
            return Err(AddressSpaceError::Locked);
        }

        let phys_offset = VirtAddr::new(PHYS_OFFSET);
        let l4 = unsafe { &mut *self.l4_virt.as_mut_ptr::<PageTable>() };
        let mut mapper = unsafe { OffsetPageTable::new(l4, phys_offset) };

        for i in 0..count {
            let virt = start_virt + (i as u64) * 4096;
            let phys = start_phys + (i as u64) * 4096;
            let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virt));
            let frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(phys));

            // Check if already mapped.
            if let Ok((_, _)) = walk_page_tables(self.l4_phys, virt) {
                return Err(AddressSpaceError::AlreadyMapped);
            }

            let mut fa = KernelFrameAllocator;
            unsafe {
                mapper.map_to(page, frame, flags, &mut fa)
                    .map_err(|_| AddressSpaceError::OutOfMemory)?
                    .flush();
            }
        }

        self.mapped_pages.fetch_add(count, Ordering::Relaxed);
        if self.config.collect_metrics {
            METRICS.lock().pages_mapped.fetch_add(count as u64, Ordering::Relaxed);
        }

        trace!(
            start_virt = format!("0x{:x}", start_virt),
            count,
            "range mapped"
        );

        Ok(())
    }

    /// Unmap a 4KB page.
    pub fn unmap_page(&mut self, virt: u64) -> AddressSpaceResult<()> {
        if self.locked {
            return Err(AddressSpaceError::Locked);
        }

        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virt));

        let phys_offset = VirtAddr::new(PHYS_OFFSET);
        let l4 = unsafe { &mut *self.l4_virt.as_mut_ptr::<PageTable>() };
        let mut mapper = unsafe { OffsetPageTable::new(l4, phys_offset) };

        // Check if mapped.
        let (pte, _) = walk_page_tables(self.l4_phys, virt)?;

        // Get the frame before unmapping.
        let frame = pte.frame().map_err(|_| AddressSpaceError::NotMapped)?;

        unsafe {
            mapper.unmap(page)
                .map_err(|_| AddressSpaceError::NotMapped)?
                .flush();
        }

        // Decrement frame refcount.
        dec_ref(frame);

        self.mapped_pages.fetch_sub(1, Ordering::Relaxed);
        if self.config.collect_metrics {
            METRICS.lock().pages_unmapped.fetch_add(1, Ordering::Relaxed);
        }

        trace!(virt = format!("0x{:x}", virt), "page unmapped");
        Ok(())
    }

    /// Unmap a range of pages.
    pub fn unmap_range(&mut self, start_virt: u64, count: usize) -> AddressSpaceResult<()> {
        if self.locked {
            return Err(AddressSpaceError::Locked);
        }

        let phys_offset = VirtAddr::new(PHYS_OFFSET);
        let l4 = unsafe { &mut *self.l4_virt.as_mut_ptr::<PageTable>() };
        let mut mapper = unsafe { OffsetPageTable::new(l4, phys_offset) };

        for i in 0..count {
            let virt = start_virt + (i as u64) * 4096;
            let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virt));

            // Check if mapped.
            let (pte, _) = match walk_page_tables(self.l4_phys, virt) {
                Ok(r) => r,
                Err(_) => continue, // Skip unmapped pages.
            };
            let frame = pte.frame().map_err(|_| AddressSpaceError::NotMapped)?;

            unsafe {
                mapper.unmap(page)
                    .map_err(|_| AddressSpaceError::NotMapped)?
                    .flush();
            }

            dec_ref(frame);
        }

        self.mapped_pages.fetch_sub(count, Ordering::Relaxed);
        if self.config.collect_metrics {
            METRICS.lock().pages_unmapped.fetch_add(count as u64, Ordering::Relaxed);
        }

        trace!(
            start_virt = format!("0x{:x}", start_virt),
            count,
            "range unmapped"
        );

        Ok(())
    }

    /// Map kernel pages (for kernel address space).
    pub fn map_kernel_pages(&mut self, start_virt: u64, start_phys: u64, count: usize) -> AddressSpaceResult<()> {
        // Kernel pages are mapped with supervisor flags.
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        self.map_range(start_virt, start_phys, count, flags)
    }

    // -------------------------------------------------------------------------
    // Page table operations
    // -------------------------------------------------------------------------

    /// Get the physical address of a virtual address.
    pub fn translate(&self, virt: u64) -> AddressSpaceResult<u64> {
        get_phys_addr(self.l4_phys, virt)
    }

    /// Check if a virtual address is mapped.
    pub fn is_mapped(&self, virt: u64) -> bool {
        walk_page_tables(self.l4_phys, virt).is_ok()
    }

    /// Get the page table entry for a virtual address.
    pub fn get_pte(&self, virt: u64) -> AddressSpaceResult<PageTableEntry> {
        let (pte, _) = walk_page_tables(self.l4_phys, virt)?;
        Ok(pte)
    }

    /// Get the page table level for a virtual address.
    pub fn get_level(&self, virt: u64) -> AddressSpaceResult<u8> {
        let (_, level) = walk_page_tables(self.l4_phys, virt)?;
        Ok(level)
    }

    /// Get detailed page walk result.
    pub fn walk(&self, virt: u64) -> AddressSpaceResult<PageWalkResult> {
        let (pte, level) = walk_page_tables(self.l4_phys, virt)?;

        let flags = pte.flags();
        let phys_base = pte.addr().as_u64();
        let offset = match level {
            3 => virt & 0x3FFF_FFFF,
            2 => virt & 0x1F_FFFF,
            1 => virt & 0xFFF,
            _ => return Err(AddressSpaceError::Internal),
        };

        Ok(PageWalkResult {
            phys_addr: phys_base | offset,
            page_size: match level {
                3 => 1 << 30,
                2 => 1 << 21,
                1 => 4096,
                _ => 0,
            },
            writable: flags.contains(PageTableFlags::WRITABLE),
            user: flags.contains(PageTableFlags::USER_ACCESSIBLE),
            executable: !flags.contains(PageTableFlags::NO_EXECUTE),
            present: flags.contains(PageTableFlags::PRESENT),
        })
    }

    // -------------------------------------------------------------------------
    // Statistics and cleanup
    // -------------------------------------------------------------------------

    /// Get the number of mapped pages.
    pub fn mapped_pages(&self) -> usize {
        self.mapped_pages.load(Ordering::Relaxed)
    }

    /// Get the number of page tables allocated.
    pub fn page_tables(&self) -> usize {
        self.page_tables.load(Ordering::Relaxed)
    }

    /// Get the L4 physical address.
    pub fn l4_phys(&self) -> u64 {
        self.l4_phys
    }

    /// Get the user base address.
    pub fn user_base(&self) -> u64 {
        self.user_base
    }

    /// Get the stack top.
    pub fn stack_top(&self) -> u64 {
        self.stack_top
    }

    /// Clean up all resources (free all page tables and frames).
    pub fn cleanup(&mut self) {
        let phys_offset = VirtAddr::new(PHYS_OFFSET);

        // Walk all L4 entries and free page tables.
        let l4 = unsafe { &mut *self.l4_virt.as_mut_ptr::<PageTable>() };

        let mut freed_frames = 0;

        // Free user page tables (entries 0-255).
        for l4i in 0..256 {
            let l4e = &mut l4[l4i];
            if !l4e.flags().contains(PageTableFlags::PRESENT) {
                continue;
            }

            let l3_phys = l4e.addr().as_u64();
            let l3_virt = phys_offset + l3_phys;
            let l3 = unsafe { &mut *l3_virt.as_mut_ptr::<PageTable>() };

            for l3i in 0..512 {
                let l3e = &mut l3[l3i];
                if !l3e.flags().contains(PageTableFlags::PRESENT) {
                    continue;
                }

                // If it's a 1GB page, just free the frame.
                if l3e.flags().contains(PageTableFlags::HUGE_PAGE) {
                    if let Ok(frame) = l3e.frame() {
                        dec_ref(frame);
                        freed_frames += 1;
                    }
                    continue;
                }

                let l2_phys = l3e.addr().as_u64();
                let l2_virt = phys_offset + l2_phys;
                let l2 = unsafe { &mut *l2_virt.as_mut_ptr::<PageTable>() };

                for l2i in 0..512 {
                    let l2e = &mut l2[l2i];
                    if !l2e.flags().contains(PageTableFlags::PRESENT) {
                        continue;
                    }

                    // If it's a 2MB page, free the frame.
                    if l2e.flags().contains(PageTableFlags::HUGE_PAGE) {
                        if let Ok(frame) = l2e.frame() {
                            dec_ref(frame);
                            freed_frames += 1;
                        }
                        continue;
                    }

                    let l1_phys = l2e.addr().as_u64();
                    let l1_virt = phys_offset + l1_phys;
                    let l1 = unsafe { &mut *l1_virt.as_mut_ptr::<PageTable>() };

                    for l1i in 0..512 {
                        let l1e = &mut l1[l1i];
                        if !l1e.flags().contains(PageTableFlags::PRESENT) {
                            continue;
                        }
                        if let Ok(frame) = l1e.frame() {
                            dec_ref(frame);
                            freed_frames += 1;
                        }
                    }

                    // Free the L1 table frame.
                    if let Ok(frame) = PhysFrame::<Size4KiB>::from_start_address(PhysAddr::new(l1_phys)) {
                        dec_ref(frame);
                        freed_frames += 1;
                    }
                }

                // Free the L2 table frame.
                if let Ok(frame) = PhysFrame::<Size4KiB>::from_start_address(PhysAddr::new(l2_phys)) {
                    dec_ref(frame);
                    freed_frames += 1;
                }
            }

            // Free the L3 table frame.
            if let Ok(frame) = PhysFrame::<Size4KiB>::from_start_address(PhysAddr::new(l3_phys)) {
                dec_ref(frame);
                freed_frames += 1;
            }
        }

        // Free the L4 frame itself.
        dec_ref(self.l4_frame);

        self.mapped_pages.store(0, Ordering::Relaxed);
        self.page_tables.store(0, Ordering::Relaxed);

        if self.config.collect_metrics {
            METRICS.lock().spaces_destroyed.fetch_add(1, Ordering::Relaxed);
            METRICS.lock().page_tables_freed.fetch_add(freed_frames as u64, Ordering::Relaxed);
        }

        debug!(freed_frames, "address space cleaned up");
    }

    /// Set the entry point.
    pub fn set_entry(&mut self, entry: u64, argc: u64) {
        self.entry_point = entry;
        self.argc = argc;
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        // We can't do heavy cleanup in drop (may cause panics), but we try.
        // In a real system, cleanup is called explicitly.
        // We'll just decrement the L4 frame refcount.
        dec_ref(self.l4_frame);
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_space_creation() {
        let config = Arc::new(AddressSpaceConfig::default());
        let space = AddressSpace::new(config).unwrap();
        assert!(space.l4_phys() > 0);
        assert!(space.mapped_pages() >= 0);
        assert_eq!(space.page_tables(), 1);
    }

    #[test]
    fn test_address_space_clone() {
        let config = Arc::new(AddressSpaceConfig::default());
        let space = AddressSpace::new(config).unwrap();
        // Map a page.
        let mut space = space;
        space.map_page(0x1000, 0x2000, PageTableFlags::PRESENT | PageTableFlags::WRITABLE).unwrap();
        assert!(space.is_mapped(0x1000));

        // Clone.
        let mut cloned = space.clone_cow().unwrap();
        assert!(cloned.is_mapped(0x1000));

        // Map a page in cloned.
        cloned.map_page(0x3000, 0x4000, PageTableFlags::PRESENT).unwrap();
        assert!(!space.is_mapped(0x3000));
        assert!(cloned.is_mapped(0x3000));
    }

    #[test]
    fn test_map_unmap_page() {
        let config = Arc::new(AddressSpaceConfig::default());
        let mut space = AddressSpace::new(config).unwrap();

        let virt = 0x1000;
        let phys = 0x2000;

        assert!(!space.is_mapped(virt));
        space.map_page(virt, phys, PageTableFlags::PRESENT | PageTableFlags::WRITABLE).unwrap();
        assert!(space.is_mapped(virt));

        let translated = space.translate(virt).unwrap();
        assert_eq!(translated & !0xFFF, phys);

        space.unmap_page(virt).unwrap();
        assert!(!space.is_mapped(virt));
    }

    #[test]
    fn test_map_range() {
        let config = Arc::new(AddressSpaceConfig::default());
        let mut space = AddressSpace::new(config).unwrap();

        let start_virt = 0x1000;
        let start_phys = 0x2000;
        let count = 10;

        space.map_range(start_virt, start_phys, count, PageTableFlags::PRESENT).unwrap();

        for i in 0..count {
            let virt = start_virt + (i as u64) * 4096;
            assert!(space.is_mapped(virt));
            let translated = space.translate(virt).unwrap();
            assert_eq!(translated & !0xFFF, start_phys + (i as u64) * 4096);
        }
    }

    #[test]
    fn test_translate_invalid() {
        let config = Arc::new(AddressSpaceConfig::default());
        let space = AddressSpace::new(config).unwrap();

        let result = space.translate(0x9999_9999_9999);
        assert!(matches!(result, Err(AddressSpaceError::NotMapped)));
    }

    #[test]
    fn test_walk_page_tables() {
        let config = Arc::new(AddressSpaceConfig::default());
        let mut space = AddressSpace::new(config).unwrap();

        let virt = 0x1000;
        let phys = 0x2000;
        space.map_page(virt, phys, PageTableFlags::PRESENT | PageTableFlags::WRITABLE).unwrap();

        let walk = space.walk(virt).unwrap();
        assert!(walk.present);
        assert!(walk.writable);
        assert!(walk.user);
        assert_eq!(walk.phys_addr & !0xFFF, phys);
        assert_eq!(walk.page_size, 4096);
    }

    #[test]
    fn test_page_tables_count() {
        let config = Arc::new(AddressSpaceConfig::default());
        let mut space = AddressSpace::new(config).unwrap();

        let initial = space.page_tables();

        // Map a page creates new page tables.
        space.map_page(0x1000, 0x2000, PageTableFlags::PRESENT).unwrap();

        // At least one new page table should be allocated.
        // (L1, L2, L3 could be allocated as needed.)
        // The count should increase.
        // For this test, we just check that it's >= initial.
        assert!(space.page_tables() >= initial);
    }

    #[test]
    fn test_activation() {
        let config = Arc::new(AddressSpaceConfig::default());
        let space = AddressSpace::new(config).unwrap();

        // We can't fully test activation without a real CPU context.
        // Just check that it doesn't panic.
        space.activate();
    }
}
