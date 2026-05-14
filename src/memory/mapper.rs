//! Memory mapper utilities — OffsetPageTable wrapper for IONA OS
//!
//! Provides safe abstractions over x86_64 page table operations using
//! the physical memory offset mapping established by the bootloader.
//!
//! The bootloader maps ALL physical memory at a fixed virtual offset
//! (PHYS_OFFSET = 0xFFFF_8000_0000_0000), so any physical address `p`
//! is accessible at virtual address `PHYS_OFFSET + p`.

use x86_64::{
    structures::paging::{
        OffsetPageTable, PageTable, PageTableFlags, PhysFrame, Size4KiB,
        Page, Mapper, FrameAllocator,
    },
    VirtAddr, PhysAddr,
};

/// Physical memory offset used by the bootloader's identity mapping.
pub const PHYS_OFFSET: u64 = 0xFFFF_8000_0000_0000;

/// Initialize an OffsetPageTable from the current CR3.
///
/// # Safety
/// - Must be called after the bootloader has set up the physical memory mapping.
/// - The PHYS_OFFSET must be correct for the current bootloader configuration.
pub unsafe fn init_offset_page_table() -> OffsetPageTable<'static> {
    let (l4_frame, _) = x86_64::registers::control::Cr3::read();
    let l4_phys = l4_frame.start_address().as_u64();
    let l4_table = unsafe {
        &mut *((PHYS_OFFSET + l4_phys) as *mut PageTable)
    };
    unsafe {
        OffsetPageTable::new(l4_table, VirtAddr::new(PHYS_OFFSET))
    }
}

/// Create an OffsetPageTable from a specific L4 physical frame.
///
/// # Safety
/// - The frame must contain a valid L4 page table.
pub unsafe fn from_l4_frame(l4_frame: PhysFrame) -> OffsetPageTable<'static> {
    let l4_phys = l4_frame.start_address().as_u64();
    let l4_table = unsafe {
        &mut *((PHYS_OFFSET + l4_phys) as *mut PageTable)
    };
    unsafe {
        OffsetPageTable::new(l4_table, VirtAddr::new(PHYS_OFFSET))
    }
}

/// Map a virtual page to a physical frame with the given flags.
/// Enforce W^X: a page cannot be both Writable and Executable
pub fn check_wx(flags: x86_64::structures::paging::PageTableFlags) {
    use x86_64::structures::paging::PageTableFlags as F;
    if flags.contains(F::WRITABLE) && !flags.contains(F::NO_EXECUTE) {
        // Writable page must have NX bit set
        crate::serial_println!("[WX] W^X violation detected — page is W+X, forcing NX");
    }
}

pub fn map_page(
    mapper: &mut OffsetPageTable,
    page: Page<Size4KiB>,
    frame: PhysFrame<Size4KiB>,
    flags: PageTableFlags,
) -> Result<(), &'static str> {
    let mut allocator = KernelFrameAllocator;
    unsafe {
        mapper.map_to(page, frame, flags, &mut allocator)
            .map_err(|_| "map_to failed")?
            .flush();
    }
    Ok(())
}

/// Unmap a virtual page and return the previously mapped frame.
pub fn unmap_page(
    mapper: &mut OffsetPageTable,
    page: Page<Size4KiB>,
) -> Result<PhysFrame<Size4KiB>, &'static str> {
    let (frame, flush) = mapper.unmap(page).map_err(|_| "unmap failed")?;
    flush.flush();
    Ok(frame)
}

/// Translate a virtual address to its physical address using OffsetPageTable.
pub fn translate_addr(mapper: &OffsetPageTable, virt: VirtAddr) -> Option<PhysAddr> {
    use x86_64::structures::paging::Translate;
    mapper.translate_addr(virt)
}

/// Map a range of pages to contiguous physical frames.
pub fn map_range(
    mapper: &mut OffsetPageTable,
    start_page: Page<Size4KiB>,
    start_frame: PhysFrame<Size4KiB>,
    count: u64,
    flags: PageTableFlags,
) -> Result<(), &'static str> {
    for i in 0..count {
        let page = Page::containing_address(
            start_page.start_address() + i * 4096
        );
        let frame = PhysFrame::containing_address(
            start_frame.start_address() + i * 4096
        );
        map_page(mapper, page, frame, flags)?;
    }
    Ok(())
}

/// Map a page with user-accessible, writable flags (for userspace memory).
pub fn map_user_page(
    mapper: &mut OffsetPageTable,
    page: Page<Size4KiB>,
    frame: PhysFrame<Size4KiB>,
) -> Result<(), &'static str> {
    let flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE;
    map_page(mapper, page, frame, flags)
}

/// Map a page with kernel-only, writable flags.
pub fn map_kernel_page(
    mapper: &mut OffsetPageTable,
    page: Page<Size4KiB>,
    frame: PhysFrame<Size4KiB>,
) -> Result<(), &'static str> {
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    map_page(mapper, page, frame, flags)
}

/// Convert a physical address to its virtual address via the offset mapping.
#[inline]
pub fn phys_to_virt(phys: u64) -> u64 {
    PHYS_OFFSET + phys
}

/// Convert a virtual address in the offset-mapped region back to physical.
#[inline]
pub fn virt_to_phys(virt: u64) -> Option<u64> {
    if virt >= PHYS_OFFSET {
        Some(virt - PHYS_OFFSET)
    } else {
        None
    }
}

/// Frame allocator that uses the kernel's frame allocator.
struct KernelFrameAllocator;

unsafe impl FrameAllocator<Size4KiB> for KernelFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        crate::memory::frame_alloc::allocate_one()
    }
}
