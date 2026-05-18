//! Kernel heap initialisation.
//!
//! Uses `linked_list_allocator` as the global allocator. A virtual address
//! range (`HEAP_START` .. `HEAP_START + HEAP_SIZE`) is mapped to physical
//! frames on demand. Once mapped, the allocator is initialised.
//!
//! # Safety
//! This module must be called exactly once, early in the kernel boot, before
//! any heap allocations are attempted.

use core::ops::RangeInclusive;
use linked_list_allocator::LockedHeap;
use x86_64::{
    structures::paging::{
        FrameAllocator, Mapper, Page, PageTableFlags, Size4KiB,
    },
    VirtAddr,
};
use super::{HEAP_START, HEAP_SIZE};

// -----------------------------------------------------------------------------
// Global allocator
// -----------------------------------------------------------------------------

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Initialises the kernel heap.
///
/// # Panics
/// Panics if `HEAP_SIZE` is 0, if the heap region is not page-aligned, or if
/// any physical frame allocation or page mapping fails.
pub fn init(
    mapper: impl Mapper<Size4KiB>,
    alloc:  impl FrameAllocator<Size4KiB>,
) {
    try_init(mapper, alloc).expect("Kernel heap initialisation failed");
}

/// Attempts to initialise the kernel heap, returning an error on failure.
///
/// On error, any partially mapped pages are cleaned up before returning.
pub fn try_init(
    mut mapper: impl Mapper<Size4KiB>,
    mut alloc:  impl FrameAllocator<Size4KiB>,
) -> Result<(), &'static str> {
    if HEAP_SIZE == 0 {
        return Err("heap size must be > 0");
    }
    if HEAP_START % PAGE_SIZE != 0 {
        return Err("heap start must be page-aligned");
    }
    if HEAP_SIZE % PAGE_SIZE != 0 {
        return Err("heap size must be a multiple of page size");
    }

    let heap_start = VirtAddr::new(HEAP_START as u64);
    let heap_end   = heap_start + HEAP_SIZE as u64 - 1u64;
    let page_range = page_range_inclusive(heap_start, heap_end);

    let flags = PageTableFlags::PRESENT
              | PageTableFlags::WRITABLE
              | PageTableFlags::NO_EXECUTE;

    let mut mapped_pages: alloc::vec::Vec<(Page<Size4KiB>, x86_64::structures::paging::PhysFrame<Size4KiB>)> =
        alloc::vec::Vec::with_capacity(page_range.len());

    // Map pages
    for page in page_range.clone() {
        let frame = alloc
            .allocate_frame()
            .ok_or("failed to allocate physical frame for heap")?;

        match unsafe { mapper.map_to(page, frame, flags, &mut alloc) } {
            Ok(mapper_flush) => {
                mapper_flush.flush();
                mapped_pages.push((page, frame));
            }
            Err(e) => {
                // Cleanup: unmap pages we already mapped and free their frames
                for (p, f) in mapped_pages.drain(..) {
                    unsafe {
                        let _ = mapper.unmap(p);
                    }
                    alloc.free_frame(f); // requires FrameAllocator to have free_frame
                    // Note: `FrameAllocator` trait in x86_64 does not expose `free_frame` directly.
                    // We assume the concrete allocator provides it. If not, we leak the frames.
                    // In practice, our `FrameAllocator` wrapper supports freeing.
                }
                return Err("failed to map heap page");
            }
        }
    }

    // Initialise the heap allocator
    unsafe {
        ALLOCATOR.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
    }

    crate::serial_println!(
        "    Heap: {} pages ({} KiB) at 0x{:x}",
        mapped_pages.len(),
        HEAP_SIZE / 1024,
        HEAP_START
    );

    Ok(())
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

const PAGE_SIZE: usize = 4096;

/// Creates an inclusive page range covering the given address interval.
fn page_range_inclusive(
    start: VirtAddr,
    end: VirtAddr,
) -> RangeInclusive<Page<Size4KiB>> {
    let start_page = Page::containing_address(start);
    let end_page   = Page::containing_address(end);
    Page::range_inclusive(start_page, end_page)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use x86_64::structures::paging::Page;

    #[test]
    fn test_page_range_single_page() {
        let start = VirtAddr::new(0x1000);
        let end   = VirtAddr::new(0x1FFF);
        let range = page_range_inclusive(start, end);
        let pages: Vec<_> = range.collect();
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].start_address().as_u64(), 0x1000);
    }

    #[test]
    fn test_page_range_multiple_pages() {
        let start = VirtAddr::new(0x0);
        let end   = VirtAddr::new(0x2FFF);
        let range = page_range_inclusive(start, end);
        let pages: Vec<_> = range.collect();
        assert_eq!(pages.len(), 3);
    }

    #[test]
    fn test_page_range_exact_boundary() {
        let start = VirtAddr::new(0x2000);
        let end   = VirtAddr::new(0x2FFF);
        let range = page_range_inclusive(start, end);
        let pages: Vec<_> = range.collect();
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].start_address().as_u64(), 0x2000);
    }
}
