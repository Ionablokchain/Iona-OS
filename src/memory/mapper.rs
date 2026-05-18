//! Memory mapper utilities — OffsetPageTable wrapper for IONA OS.
//!
//! Provides safe abstractions over `x86_64` page table operations using
//! the physical memory offset mapping established by the bootloader.
//!
//! The bootloader maps ALL physical memory at a fixed virtual offset
//! (`PHYS_OFFSET = 0xFFFF_8000_0000_0000`), so any physical address `p`
//! is accessible at virtual address `PHYS_OFFSET + p`.

use x86_64::{
    structures::paging::{
        OffsetPageTable, PageTable, PageTableFlags, PhysFrame, Size4KiB,
        Page, Mapper, FrameAllocator, Translate,
    },
    VirtAddr, PhysAddr,
};

/// Physical memory offset used by the bootloader's identity mapping.
pub const PHYS_OFFSET: u64 = 0xFFFF_8000_0000_0000;

// -----------------------------------------------------------------------------
// OffsetPageTable constructors
// -----------------------------------------------------------------------------

/// Initialises an `OffsetPageTable` from the current CR3 register.
///
/// # Safety
/// - Must be called after the bootloader has established the physical memory
///   mapping and the current page table is valid.
/// - `PHYS_OFFSET` must match the bootloader's mapping.
pub unsafe fn init_offset_page_table() -> OffsetPageTable<'static> {
    let (l4_frame, _) = x86_64::registers::control::Cr3::read();
    let l4_phys = l4_frame.start_address().as_u64();
    let l4_table = &mut *((PHYS_OFFSET + l4_phys) as *mut PageTable);
    OffsetPageTable::new(l4_table, VirtAddr::new(PHYS_OFFSET))
}

/// Creates an `OffsetPageTable` from a specific L4 physical frame.
///
/// # Safety
/// - `l4_frame` must contain a valid L4 page table.
pub unsafe fn from_l4_frame(l4_frame: PhysFrame) -> OffsetPageTable<'static> {
    let l4_phys = l4_frame.start_address().as_u64();
    let l4_table = &mut *((PHYS_OFFSET + l4_phys) as *mut PageTable);
    OffsetPageTable::new(l4_table, VirtAddr::new(PHYS_OFFSET))
}

// -----------------------------------------------------------------------------
// W^X enforcement
// -----------------------------------------------------------------------------

/// Error returned when a page would be mapped with both WRITABLE and !NO_EXECUTE,
/// violating the W^X security policy.
const ERR_WX_VIOLATION: &str = "W^X violation: page cannot be both writable and executable";

/// Checks that `flags` do **not** contain both `WRITABLE` and executable
/// (i.e. missing `NO_EXECUTE`).
///
/// Returns `Ok(())` if the combination is safe, otherwise returns an error.
pub fn check_wx(flags: PageTableFlags) -> Result<(), &'static str> {
    if flags.contains(PageTableFlags::WRITABLE) && !flags.contains(PageTableFlags::NO_EXECUTE) {
        crate::serial_println!("[WX] W^X violation detected — page is W+X, rejecting");
        return Err(ERR_WX_VIOLATION);
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Page mapping helpers
// -----------------------------------------------------------------------------

/// Internal helper: maps a page, enforcing W^X and using a kernel frame allocator.
fn map_page_internal(
    mapper: &mut OffsetPageTable,
    page: Page<Size4KiB>,
    frame: PhysFrame<Size4KiB>,
    flags: PageTableFlags,
) -> Result<(), &'static str> {
    // Security: enforce W^X
    check_wx(flags)?;

    // Use a lightweight wrapper around the global frame allocator.
    let mut allocator = KernelFrameAllocator;

    unsafe {
        mapper
            .map_to(page, frame, flags, &mut allocator)
            .map_err(|_| "map_to failed")?
            .flush();
    }

    Ok(())
}

/// Maps a virtual page to a physical frame with the given flags.
/// Enforces W^X: writable pages must have `NO_EXECUTE` set.
pub fn map_page(
    mapper: &mut OffsetPageTable,
    page: Page<Size4KiB>,
    frame: PhysFrame<Size4KiB>,
    flags: PageTableFlags,
) -> Result<(), &'static str> {
    map_page_internal(mapper, page, frame, flags)
}

/// Unmaps a virtual page and returns the previously mapped frame.
pub fn unmap_page(
    mapper: &mut OffsetPageTable,
    page: Page<Size4KiB>,
) -> Result<PhysFrame<Size4KiB>, &'static str> {
    let (frame, flush) = mapper.unmap(page).map_err(|_| "unmap failed")?;
    flush.flush();
    Ok(frame)
}

/// Translates a virtual address to its physical address using the page table.
pub fn translate_addr(mapper: &OffsetPageTable, virt: VirtAddr) -> Option<PhysAddr> {
    mapper.translate_addr(virt)
}

/// Maps a consecutive range of pages to contiguous physical frames.
///
/// # Errors
/// Returns an error if any single mapping fails (e.g., out of memory, already mapped).
pub fn map_range(
    mapper: &mut OffsetPageTable,
    start_page: Page<Size4KiB>,
    start_frame: PhysFrame<Size4KiB>,
    count: u64,
    flags: PageTableFlags,
) -> Result<(), &'static str> {
    check_wx(flags)?;

    for i in 0..count {
        let page = Page::containing_address(start_page.start_address() + i * 4096);
        let frame = PhysFrame::containing_address(start_frame.start_address() + i * 4096);
        map_page_internal(mapper, page, frame, flags)?;
    }
    Ok(())
}

/// Maps a page with user-accessible, writable flags (but non-executable).
pub fn map_user_page(
    mapper: &mut OffsetPageTable,
    page: Page<Size4KiB>,
    frame: PhysFrame<Size4KiB>,
) -> Result<(), &'static str> {
    let flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE; // safe default
    map_page(mapper, page, frame, flags)
}

/// Maps a page with kernel-only, writable flags (non-executable).
pub fn map_kernel_page(
    mapper: &mut OffsetPageTable,
    page: Page<Size4KiB>,
    frame: PhysFrame<Size4KiB>,
) -> Result<(), &'static str> {
    let flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_EXECUTE;
    map_page(mapper, page, frame, flags)
}

// -----------------------------------------------------------------------------
// Address conversion utilities
// -----------------------------------------------------------------------------

/// Converts a physical address to its virtual address via the offset mapping.
#[inline]
pub const fn phys_to_virt(phys: u64) -> u64 {
    PHYS_OFFSET + phys
}

/// Converts a virtual address (within the offset-mapped region) back to a
/// physical address. Returns `None` if the virtual address is outside the
/// physical mapping window.
#[inline]
pub fn virt_to_phys(virt: u64) -> Option<u64> {
    if virt >= PHYS_OFFSET {
        Some(virt - PHYS_OFFSET)
    } else {
        None
    }
}

// -----------------------------------------------------------------------------
// Kernel frame allocator (lightweight wrapper)
// -----------------------------------------------------------------------------

/// A zero-sized wrapper that delegates to the global kernel frame allocator.
struct KernelFrameAllocator;

unsafe impl FrameAllocator<Size4KiB> for KernelFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        crate::memory::frame_alloc::allocate_one()
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phys_to_virt_conversion() {
        assert_eq!(phys_to_virt(0), PHYS_OFFSET);
        assert_eq!(phys_to_virt(4096), PHYS_OFFSET + 4096);
    }

    #[test]
    fn test_virt_to_phys_in_range() {
        assert_eq!(virt_to_phys(PHYS_OFFSET), Some(0));
        assert_eq!(virt_to_phys(PHYS_OFFSET + 0x1000), Some(0x1000));
    }

    #[test]
    fn test_virt_to_phys_out_of_range() {
        assert_eq!(virt_to_phys(0), None);
        assert_eq!(virt_to_phys(PHYS_OFFSET - 1), None);
    }

    #[test]
    fn test_check_wx_safe_flags() {
        // Writable + NO_EXECUTE is safe
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
        assert!(check_wx(flags).is_ok());

        // Executable but not writable is safe
        let flags = PageTableFlags::PRESENT;
        assert!(check_wx(flags).is_ok());
    }

    #[test]
    fn test_check_wx_violation() {
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        assert!(check_wx(flags).is_err());

        // Explicitly executable (no NX) + writable
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        assert!(check_wx(flags).is_err());
    }

    #[test]
    fn test_user_page_flags_are_safe() {
        let flags = PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::USER_ACCESSIBLE
            | PageTableFlags::NO_EXECUTE;
        assert!(check_wx(flags).is_ok());
    }

    #[test]
    fn test_kernel_page_flags_are_safe() {
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
        assert!(check_wx(flags).is_ok());
    }
}
